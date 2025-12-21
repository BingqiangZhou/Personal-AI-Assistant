"""
播客音频转录服务

提供音频下载、格式转换、文件切割、API转录和结果合并的完整功能
"""

import asyncio
import aiohttp
import aiofiles
import os
import pathlib
import tempfile
import hashlib
import json
import time
from typing import List, Dict, Optional, Tuple, AsyncGenerator
from dataclasses import dataclass
from urllib.parse import urlparse
import logging
from datetime import datetime

import ffmpeg
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.config import settings
from app.core.database import async_session_factory
from app.domains.podcast.models import TranscriptionTask, PodcastEpisode, TranscriptionStatus
from app.core.exceptions import ValidationError, DatabaseError


logger = logging.getLogger(__name__)


@dataclass
class AudioChunk:
    """音频分片信息"""
    index: int
    file_path: str
    start_time: float  # 开始时间（秒）
    duration: float  # 时长（秒）
    file_size: int  # 文件大小（字节）
    transcript: Optional[str] = None  # 转录结果


@dataclass
class TranscriptionProgress:
    """转录进度信息"""
    task_id: int
    status: TranscriptionStatus
    progress: float  # 0-100
    message: str
    current_chunk: int = 0
    total_chunks: int = 0


class AudioDownloader:
    """音频文件下载器"""

    def __init__(self, timeout: int = 300, chunk_size: int = 8192):
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """异步上下文管理器入口"""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'Personal-AI-Assistant/1.0'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()

    async def download_file(self, url: str, destination: str, progress_callback=None) -> Tuple[str, int]:
        """
        下载文件到指定位置

        Args:
            url: 下载URL
            destination: 保存路径
            progress_callback: 进度回调函数

        Returns:
            Tuple[str, int]: (文件路径, 文件大小)
        """
        if not self.session:
            raise RuntimeError("AudioDownloader must be used as async context manager")

        # 确保目录存在
        os.makedirs(os.path.dirname(destination), exist_ok=True)

        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to download audio file: HTTP {response.status}"
                    )

                # 获取文件大小
                content_length = response.headers.get('content-length')
                total_size = int(content_length) if content_length else 0

                # 下载文件
                downloaded = 0
                async with aiofiles.open(destination, 'wb') as f:
                    async for chunk in response.content.iter_chunked(self.chunk_size):
                        await f.write(chunk)
                        downloaded += len(chunk)

                        # 调用进度回调
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            await progress_callback(progress)

                logger.info(f"Successfully downloaded file to {destination}, size: {downloaded} bytes")
                return destination, downloaded

        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail="Download timeout"
            )
        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            # 清理部分下载的文件
            if os.path.exists(destination):
                os.remove(destination)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Download failed: {str(e)}"
            )


class AudioConverter:
    """音频格式转换器"""

    @staticmethod
    async def convert_to_mp3(input_path: str, output_path: str, progress_callback=None) -> Tuple[str, float]:
        """
        将音频文件转换为MP3格式

        Args:
            input_path: 输入文件路径
            output_path: 输出MP3文件路径
            progress_callback: 进度回调函数

        Returns:
            Tuple[str, float]: (输出文件路径, 转换耗时)
        """
        start_time = time.time()

        try:
            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 构建FFmpeg命令
            ffmpeg_proc = (
                ffmpeg
                .input(input_path)
                .output(
                    output_path,
                    acodec='mp3',
                    ac=1,  # 单声道
                    ar='16000',  # 16kHz采样率
                    ab='64k',  # 64kbps比特率
                    f='mp3'
                )
                .overwrite_output()
                .global_args('-loglevel', 'quiet')
            )

            # 执行转换
            if progress_callback:
                await progress_callback(0)

            # 使用子进程执行FFmpeg
            cmd = ffmpeg_proc.compile()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown FFmpeg error"
                raise RuntimeError(f"FFmpeg conversion failed: {error_msg}")

            if progress_callback:
                await progress_callback(100)

            duration = time.time() - start_time
            logger.info(f"Successfully converted {input_path} to {output_path} in {duration:.2f}s")

            return output_path, duration

        except Exception as e:
            logger.error(f"Audio conversion failed: {str(e)}")
            # 清理输出文件
            if os.path.exists(output_path):
                os.remove(output_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Audio conversion failed: {str(e)}"
            )


class AudioSplitter:
    """音频文件切割器"""

    @staticmethod
    async def split_mp3(
        input_path: str,
        output_dir: str,
        chunk_size_mb: int = 10,
        progress_callback=None
    ) -> List[AudioChunk]:
        """
        将MP3文件切割成指定大小的片段

        Args:
            input_path: 输入MP3文件路径
            output_dir: 输出目录
            chunk_size_mb: 每个片段的大小（MB）
            progress_callback: 进度回调函数

        Returns:
            List[AudioChunk]: 切割后的音频片段列表
        """
        try:
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)

            # 获取文件信息
            file_size = os.path.getsize(input_path)
            chunk_size_bytes = chunk_size_mb * 1024 * 1024

            # 使用FFmpeg获取音频时长
            probe = ffmpeg.probe(input_path)
            duration = float(probe['streams'][0]['duration'])

            # 计算需要切割的段数
            num_chunks = max(1, (file_size + chunk_size_bytes - 1) // chunk_size_bytes)
            chunk_duration = duration / num_chunks

            chunks = []
            base_name = os.path.splitext(os.path.basename(input_path))[0]

            for i in range(num_chunks):
                start_time = i * chunk_duration
                output_path = os.path.join(
                    output_dir,
                    f"{base_name}_chunk_{i+1:03d}.mp3"
                )

                # 使用FFmpeg切割
                (
                    ffmpeg
                    .input(input_path, ss=start_time, t=chunk_duration)
                    .output(output_path, c='copy')
                    .overwrite_output()
                    .global_args('-loglevel', 'quiet')
                    .run()
                )

                # 获取切割后的文件大小
                chunk_file_size = os.path.getsize(output_path)

                chunk = AudioChunk(
                    index=i + 1,
                    file_path=output_path,
                    start_time=start_time,
                    duration=chunk_duration,
                    file_size=chunk_file_size
                )
                chunks.append(chunk)

                # 更新进度
                if progress_callback:
                    progress = ((i + 1) / num_chunks) * 100
                    await progress_callback(progress)

            logger.info(f"Successfully split {input_path} into {len(chunks)} chunks")
            return chunks

        except Exception as e:
            logger.error(f"Audio splitting failed: {str(e)}")
            # 清理已创建的文件
            for chunk in locals().get('chunks', []):
                if os.path.exists(chunk.file_path):
                    os.remove(chunk.file_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Audio splitting failed: {str(e)}"
            )


class SiliconFlowTranscriber:
    """硅基流动API转录服务"""

    def __init__(self, api_key: str, api_url: str, max_concurrent: int = 4):
        self.api_key = api_key
        self.api_url = api_url
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """异步上下文管理器入口"""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=600)  # 10分钟超时
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'Authorization': f'Bearer {self.api_key}'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()

    async def transcribe_chunk(
        self,
        chunk: AudioChunk,
        model: str = "FunAudioLLM/SenseVoiceSmall"
    ) -> str:
        """
        转录单个音频片段

        Args:
            chunk: 音频片段
            model: 转录模型名称

        Returns:
            str: 转录文本
        """
        async with self.semaphore:  # 限制并发数
            if not self.session:
                raise RuntimeError("Transcriber must be used as async context manager")

            try:
                # 准备文件上传
                data = aiohttp.FormData()
                data.add_field('model', model)
                data.add_field(
                    'file',
                    open(chunk.file_path, 'rb'),
                    filename=os.path.basename(chunk.file_path),
                    content_type='audio/mpeg'
                )

                # 发送请求
                async with self.session.post(self.api_url, data=data) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Transcription API error: {response.status} - {error_text}")
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Transcription API error: {response.status}"
                        )

                    result = await response.json()
                    transcript = result.get('text', '')

                    logger.info(f"Successfully transcribed chunk {chunk.index}")
                    return transcript

            except asyncio.TimeoutError:
                logger.error(f"Transcription timeout for chunk {chunk.index}")
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Transcription timeout for chunk {chunk.index}"
                )
            except Exception as e:
                logger.error(f"Transcription failed for chunk {chunk.index}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Transcription failed: {str(e)}"
                )

    async def transcribe_chunks(
        self,
        chunks: List[AudioChunk],
        model: str = "FunAudioLLM/SenseVoiceSmall",
        progress_callback=None
    ) -> List[AudioChunk]:
        """
        并发转录多个音频片段

        Args:
            chunks: 音频片段列表
            model: 转录模型名称
            progress_callback: 进度回调函数

        Returns:
            List[AudioChunk]: 包含转录结果的音频片段列表
        """
        start_time = time.time()

        # 创建转录任务
        tasks = []
        for chunk in chunks:
            task = asyncio.create_task(
                self.transcribe_chunk(chunk, model),
                name=f"transcribe_chunk_{chunk.index}"
            )
            tasks.append(task)

        # 执行并发转录
        results = []
        completed = 0

        for coro in asyncio.as_completed(tasks):
            try:
                transcript = await coro

                # 找到对应的chunk并更新
                chunk_index = int(asyncio.current_task().get_name().split('_')[-1]) - 1
                chunks[chunk_index].transcript = transcript
                results.append(chunks[chunk_index])

                completed += 1
                if progress_callback:
                    progress = (completed / len(chunks)) * 100
                    await progress_callback(progress)

            except Exception as e:
                logger.error(f"Chunk transcription failed: {str(e)}")
                # 继续处理其他chunks

        duration = time.time() - start_time
        logger.info(f"Completed transcription of {len(results)} chunks in {duration:.2f}s")

        return results


class PodcastTranscriptionService:
    """播客转录主服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.temp_dir = getattr(settings, 'TRANSCRIPTION_TEMP_DIR', './temp/transcription')
        self.storage_dir = getattr(settings, 'TRANSCRIPTION_STORAGE_DIR', './storage/podcasts')
        self.chunk_size_mb = getattr(settings, 'TRANSCRIPTION_CHUNK_SIZE_MB', 10)
        self.max_threads = getattr(settings, 'TRANSCRIPTION_MAX_THREADS', 4)
        self.api_url = getattr(settings, 'TRANSCRIPTION_API_URL', 'https://api.siliconflow.cn/v1/audio/transcriptions')
        self.api_key = getattr(settings, 'TRANSCRIPTION_API_KEY', None)

        if not self.api_key:
            raise ValidationError("TRANSCRIPTION_API_KEY is not configured")

    def _get_episode_storage_path(self, episode: PodcastEpisode) -> str:
        """获取播客单集的存储路径"""
        # 清理播客名称和分集名称
        podcast_name = self._sanitize_filename(episode.subscription.title)
        episode_name = self._sanitize_filename(episode.title)

        return os.path.join(
            self.storage_dir,
            podcast_name,
            episode_name
        )

    def _sanitize_filename(self, filename: str) -> str:
        """清理文件名，移除非法字符"""
        import re
        # 移除或替换非法字符
        filename = re.sub(r'[<>:"/\\|?*]', '', filename)
        filename = filename.replace(' ', '_')
        return filename[:100]  # 限制长度

    def _get_file_hash(self, file_path: str) -> str:
        """计算文件的MD5哈希"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    async def update_task_progress(
        self,
        task_id: int,
        status: TranscriptionStatus,
        progress: float,
        message: str,
        error_message: Optional[str] = None
    ):
        """更新任务进度"""
        update_data = {
            'status': status,
            'progress_percentage': progress,
            'updated_at': datetime.utcnow()
        }

        if error_message:
            update_data['error_message'] = error_message

        # 设置开始时间
        if status == TranscriptionStatus.DOWNLOADING and not await self._get_task_field(task_id, 'started_at'):
            update_data['started_at'] = datetime.utcnow()

        # 设置完成时间
        if status in [TranscriptionStatus.COMPLETED, TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
            update_data['completed_at'] = datetime.utcnow()

        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.id == task_id)
            .values(**update_data)
        )

        await self.db.execute(stmt)
        await self.db.commit()

        logger.info(f"Updated task {task_id}: status={status}, progress={progress:.1f}%")

    async def _get_task_field(self, task_id: int, field: str):
        """获取任务的指定字段"""
        stmt = select(getattr(TranscriptionTask, field)).where(TranscriptionTask.id == task_id)
        result = await self.db.execute(stmt)
        return result.scalar()

    async def _update_task_progress_with_session(
        self,
        session: AsyncSession,
        task_id: int,
        status: TranscriptionStatus,
        progress: float,
        message: str,
        error_message: Optional[str] = None
    ):
        """使用指定的数据库会话更新任务进度（用于后台任务）"""
        update_data = {
            'status': status,
            'progress_percentage': progress,
            'updated_at': datetime.utcnow()
        }

        if error_message:
            update_data['error_message'] = error_message

        # 设置开始时间
        if status == TranscriptionStatus.DOWNLOADING:
            # Check if started_at is None using a query
            stmt_check = select(TranscriptionTask.started_at).where(TranscriptionTask.id == task_id)
            result = await session.execute(stmt_check)
            started_at = result.scalar()
            if not started_at:
                update_data['started_at'] = datetime.utcnow()

        # 设置完成时间
        if status in [TranscriptionStatus.COMPLETED, TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
            update_data['completed_at'] = datetime.utcnow()

        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.id == task_id)
            .values(**update_data)
        )

        await session.execute(stmt)
        await session.commit()

        logger.info(f"Updated task {task_id}: status={status}, progress={progress:.1f}%")

    async def start_transcription(self, episode_id: int, model: Optional[str] = None, force: bool = False) -> TranscriptionTask:
        """启动转录任务"""
        # 检查是否已存在转录任务
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        existing_task = result.scalar_one_or_none()

        if existing_task:
            if force:
                # Force mode: delete existing task and create new one (regardless of status)
                await self.db.delete(existing_task)
                await self.db.flush()
                await self.db.commit()  # Commit the delete to release the unique constraint
            elif existing_task.status not in [TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
                # Task exists with non-failed/cancelled status and force=false: raise error
                raise ValidationError(
                    f"Transcription task already exists for episode {episode_id} with status {existing_task.status}"
                )
            # If task exists with failed/cancelled status and force=false: allow the insert to continue below

        # 获取播客单集信息
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        # 使用指定的模型或默认模型
        transcription_model = model or getattr(settings, 'TRANSCRIPTION_MODEL', 'FunAudioLLM/SenseVoiceSmall')

        # 创建新的转录任务
        task = TranscriptionTask(
            episode_id=episode_id,
            original_audio_url=episode.audio_url,
            chunk_size_mb=self.chunk_size_mb,
            model_used=transcription_model
        )

        self.db.add(task)
        await self.db.commit()
        await self.db.refresh(task)

        # 启动后台转录任务
        asyncio.create_task(self._execute_transcription(task.id))

        logger.info(f"Started transcription task {task.id} for episode {episode_id}")
        return task

    async def _execute_transcription(self, task_id: int):
        """执行转录任务（后台运行）"""
        # Create a new database session for this background task
        async with async_session_factory() as session:
            try:
                # 获取任务信息
                stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
                result = await session.execute(stmt)
                task = result.scalar_one_or_none()

                if not task:
                    logger.error(f"Transcription task {task_id} not found")
                    return

                # 获取播客单集信息
                stmt = select(PodcastEpisode).where(PodcastEpisode.id == task.episode_id)
                result = await session.execute(stmt)
                episode = result.scalar_one_or_none()

                if not episode:
                    await self._update_task_progress_with_session(
                        session, task_id,
                        TranscriptionStatus.FAILED,
                        0,
                        "Episode not found"
                    )
                    return

                # 创建临时目录
                temp_episode_dir = os.path.join(self.temp_dir, f"episode_{task.episode_id}")
                os.makedirs(temp_episode_dir, exist_ok=True)

                # 步骤1：下载音频文件
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.DOWNLOADING,
                    5,
                    "Downloading audio file..."
                )

                download_start = time.time()
                original_file = os.path.join(temp_episode_dir, f"original{os.path.splitext(task.original_audio_url)[-1]}")

                async with AudioDownloader() as downloader:
                    async def download_progress(progress):
                        await self._update_task_progress_with_session(
                            session,
                            task_id,
                            TranscriptionStatus.DOWNLOADING,
                            5 + (progress * 0.15),  # 5-20%
                            f"Downloading... {progress:.1f}%"
                        )

                    file_path, file_size = await downloader.download_file(
                        task.original_audio_url,
                        original_file,
                        download_progress
                    )

                download_time = time.time() - download_start

                # 步骤2：转换为MP3
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.CONVERTING,
                    20,
                    "Converting to MP3..."
                )

                converted_file = os.path.join(temp_episode_dir, "converted.mp3")

                async def convert_progress(progress):
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        TranscriptionStatus.CONVERTING,
                        20 + (progress * 0.15),  # 20-35%
                        f"Converting... {progress:.1f}%"
                    )

                _, conversion_time = await AudioConverter.convert_to_mp3(
                    file_path,
                    converted_file,
                    convert_progress
                )

                # 步骤3：切割音频文件
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.SPLITTING,
                    35,
                    "Splitting audio file..."
                )

                split_dir = os.path.join(temp_episode_dir, "chunks")

                async def split_progress(progress):
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        TranscriptionStatus.SPLITTING,
                        35 + (progress * 0.10),  # 35-45%
                        f"Splitting... {progress:.1f}%"
                    )

                chunks = await AudioSplitter.split_mp3(
                    converted_file,
                    split_dir,
                    task.chunk_size_mb,
                    split_progress
                )

                # 步骤4：转录音频片段
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.TRANSCRIBING,
                    45,
                    f"Transcribing {len(chunks)} audio chunks..."
                )

                transcription_start = time.time()

                async def transcribe_progress(progress):
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        TranscriptionStatus.TRANSCRIBING,
                        45 + (progress * 0.50),  # 45-95%
                        f"Transcribing... {progress:.1f}%"
                    )

                async with SiliconFlowTranscriber(
                    self.api_key,
                    self.api_url,
                    self.max_threads
                ) as transcriber:
                    transcribed_chunks = await transcriber.transcribe_chunks(
                        chunks,
                        task.model_used,
                        transcribe_progress
                    )

                transcription_time = time.time() - transcription_start

                # 步骤5：合并转录结果
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.MERGING,
                    95,
                    "Merging transcription results..."
                )

                # 按顺序合并转录文本
                sorted_chunks = sorted(transcribed_chunks, key=lambda x: x.index)
                full_transcript = "\n\n".join([
                    chunk.transcript.strip() for chunk in sorted_chunks
                    if chunk.transcript and chunk.transcript.strip()
                ])

                # 步骤6：保存结果到永久存储
                storage_path = self._get_episode_storage_path(episode)
                os.makedirs(storage_path, exist_ok=True)

                # 保存原始音频文件
                final_audio_path = os.path.join(storage_path, "original.mp3")
                os.replace(converted_file, final_audio_path)

                # 保存转录文本
                transcript_path = os.path.join(storage_path, "transcript.txt")
                async with aiofiles.open(transcript_path, 'w', encoding='utf-8') as f:
                    await f.write(full_transcript)

                # 更新数据库
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.COMPLETED,
                    100,
                    "Transcription completed successfully"
                )

                # 更新任务详细信息
                task_update = {
                    'status': TranscriptionStatus.COMPLETED,
                    'progress_percentage': 100.0,
                    'transcript_content': full_transcript,
                    'transcript_word_count': len(full_transcript.split()),
                    'original_file_path': final_audio_path,
                    'original_file_size': file_size,
                    'download_time': download_time,
                    'conversion_time': conversion_time,
                    'transcription_time': transcription_time,
                    'chunk_info': {
                        'total_chunks': len(chunks),
                        'chunks': [
                            {
                                'index': chunk.index,
                                'start_time': chunk.start_time,
                                'duration': chunk.duration,
                                'transcript': chunk.transcript
                            }
                            for chunk in sorted_chunks
                        ]
                    },
                    'completed_at': datetime.utcnow()
                }

                stmt = (
                    update(TranscriptionTask)
                    .where(TranscriptionTask.id == task_id)
                    .values(**task_update)
                )
                await session.execute(stmt)

                # 更新播客单集的转录信息
                episode_update = {
                    'transcript_content': full_transcript,
                    'transcript_url': f"file://{transcript_path}",
                    'status': 'completed'
                }

                stmt = (
                    update(PodcastEpisode)
                    .where(PodcastEpisode.id == episode_id)
                    .values(**episode_update)
                )
                await session.execute(stmt)

                await session.commit()

                logger.info(f"Successfully completed transcription for episode {episode_id}")

            except Exception as e:
                logger.error(f"Transcription failed for task {task_id}: {str(e)}", exc_info=True)
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    TranscriptionStatus.FAILED,
                    0,
                    f"Transcription failed: {str(e)}",
                    str(e)
                )
            finally:
                # 清理临时文件
                try:
                    import shutil
                    temp_episode_dir = os.path.join(self.temp_dir, f"episode_{task.episode_id}")
                    if os.path.exists(temp_episode_dir):
                        shutil.rmtree(temp_episode_dir)
                        logger.info(f"Cleaned up temporary directory: {temp_episode_dir}")
                except Exception as e:
                    logger.error(f"Failed to clean up temporary files: {str(e)}")

    async def get_transcription_status(self, task_id: int) -> Optional[TranscriptionTask]:
        """获取转录任务状态"""
        stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_episode_transcription(self, episode_id: int) -> Optional[TranscriptionTask]:
        """获取播客单集的转录信息"""
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def cancel_transcription(self, task_id: int) -> bool:
        """取消转录任务"""
        task = await self.get_transcription_status(task_id)
        if not task:
            return False

        if task.status in [TranscriptionStatus.COMPLETED, TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
            return False

        await self.update_task_progress(
            task_id,
            TranscriptionStatus.CANCELLED,
            task.progress_percentage,
            "Transcription cancelled by user"
        )

        return True


class AISummaryService:
    """AI总结服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.api_key = getattr(settings, 'OPENAI_API_KEY', None)
        self.api_url = getattr(settings, 'OPENAI_API_BASE_URL', 'https://api.openai.com/v1')
        self.default_model = getattr(settings, 'SUMMARY_MODEL', 'gpt-4o-mini')

        if not self.api_key:
            raise ValidationError("OPENAI_API_KEY is not configured")

    async def generate_summary(
        self,
        episode_id: int,
        model: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> TranscriptionTask:
        """
        为播客单集生成AI总结

        Args:
            episode_id: 播客单集ID
            model: 使用的AI模型，如果不指定则使用默认模型
            custom_prompt: 自定义提示词

        Returns:
            TranscriptionTask: 更新后的转录任务
        """
        # 获取转录任务
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        task = result.scalar_one_or_none()

        if not task:
            raise ValidationError(f"No transcription task found for episode {episode_id}")

        if not task.transcript_content or not task.transcript_content.strip():
            raise ValidationError(f"No transcript content available for episode {episode_id}")

        # 检查是否已有总结（除非强制重新生成）
        if task.summary_content and not custom_prompt:
            return task

        # 获取播客单集信息
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        # 使用指定的模型或默认模型
        summary_model = model or self.default_model

        # 构建总结提示词
        if not custom_prompt:
            custom_prompt = f"""
请为以下播客内容生成一个简洁但信息丰富的总结。播客标题：{episode.title}

总结内容应该包括：
1. 主要话题和核心观点
2. 关键信息或要点
3. 适合的听众群体
4. 总结长度控制在200-500字之间

播客转录内容：
{task.transcript_content}
"""

        try:
            start_time = time.time()

            # 调用AI API生成总结
            summary_content = await self._call_openai_api(summary_model, custom_prompt)

            processing_time = time.time() - start_time

            # 更新数据库
            update_data = {
                'summary_content': summary_content,
                'summary_model_used': summary_model,
                'summary_word_count': len(summary_content.split()),
                'summary_processing_time': processing_time,
                'summary_error_message': None,
                'updated_at': datetime.utcnow()
            }

            stmt = (
                update(TranscriptionTask)
                .where(TranscriptionTask.id == task.id)
                .values(**update_data)
            )
            await self.db.execute(stmt)

            # 更新播客单集的总结信息
            episode_update = {
                'description': summary_content[:500] + '...' if len(summary_content) > 500 else summary_content,
                'status': 'summarized'
            }

            stmt = (
                update(PodcastEpisode)
                .where(PodcastEpisode.id == episode_id)
                .values(**episode_update)
            )
            await self.db.execute(stmt)

            await self.db.commit()
            await self.db.refresh(task)

            logger.info(f"Successfully generated summary for episode {episode_id} using model {summary_model}")
            return task

        except Exception as e:
            logger.error(f"Failed to generate summary for episode {episode_id}: {str(e)}")

            # 更新错误信息
            error_update = {
                'summary_error_message': str(e),
                'updated_at': datetime.utcnow()
            }

            stmt = (
                update(TranscriptionTask)
                .where(TranscriptionTask.id == task.id)
                .values(**error_update)
            )
            await self.db.execute(stmt)
            await self.db.commit()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate AI summary: {str(e)}"
            )

    async def _call_openai_api(self, model: str, prompt: str) -> str:
        """调用OpenAI API生成总结"""
        timeout = aiohttp.ClientTimeout(total=300)  # 5分钟超时

        async with aiohttp.ClientSession(timeout=timeout) as session:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            data = {
                'model': model,
                'messages': [
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'max_tokens': 1000,
                'temperature': 0.7
            }

            async with session.post(f"{self.api_url}/chat/completions", headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"OpenAI API error: {response.status} - {error_text}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"AI summary API error: {response.status}"
                    )

                result = await response.json()

                if 'choices' not in result or not result['choices']:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Invalid response from AI API"
                    )

                summary = result['choices'][0]['message']['content']
                return summary.strip()

    async def regenerate_summary(
        self,
        episode_id: int,
        model: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> TranscriptionTask:
        """重新生成AI总结"""
        # 先清除现有总结
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        task = result.scalar_one_or_none()

        if task:
            update_data = {
                'summary_content': None,
                'summary_model_used': None,
                'summary_word_count': None,
                'summary_processing_time': None,
                'summary_error_message': None,
                'updated_at': datetime.utcnow()
            }

            stmt = (
                update(TranscriptionTask)
                .where(TranscriptionTask.id == task.id)
                .values(**update_data)
            )
            await self.db.execute(stmt)
            await self.db.commit()

        # 生成新的总结
        return await self.generate_summary(episode_id, model, custom_prompt)