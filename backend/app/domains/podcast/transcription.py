"""
播客音频转录服务

提供音频下载、格式转换、文件切割、API转录和结果合并的完整功能
"""

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import aiofiles
import aiohttp
import ffmpeg
from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.domains.ai.models import ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.podcast.models import (
    PodcastEpisode,
    TranscriptionStatus,
    TranscriptionStep,
    TranscriptionTask,
)
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService


logger = logging.getLogger(__name__)


def log_with_timestamp(level: str, message: str, task_id: int = None):
    """
    输出带时间戳的日志

    Args:
        level: 日志级别 (INFO, WARNING, ERROR, DEBUG)
        message: 日志消息
        task_id: 任务ID（可选）
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    task_info = f"[Task:{task_id}] " if task_id is not None else ""
    formatted_message = f"{timestamp} {task_info}{message}"

    if level == "INFO":
        logger.info(formatted_message)
    elif level == "WARNING":
        logger.warning(formatted_message)
    elif level == "ERROR":
        logger.error(formatted_message)
    elif level == "DEBUG":
        logger.debug(formatted_message)
    else:
        logger.info(formatted_message)


@dataclass
class AudioChunk:
    """音频分片信息"""
    index: int
    file_path: str
    start_time: float  # 开始时间（秒）
    duration: float  # 时长（秒）
    file_size: int  # 文件大小（字节）
    transcript: str | None = None  # 转录结果


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
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        """异步上下文管理器入口"""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        # 使用完整的浏览器头部以绕过 CDN 防护（Cloudflare等）
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()

    async def download_file(self, url: str, destination: str, progress_callback=None) -> tuple[str, int]:
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

        # 处理 lizhi.fm 的 CDN URL
        original_url = url
        if 'cdn.lizhi.fm' in url:
            url = url.replace('cdn.lizhi.fm', 'cdn.gzlzfm.com')
            logger.info(f"🔄 [CDN REPLACEMENT] Replaced CDN URL: {original_url[:80]}... -> {url[:80]}...")

        # 准备请求头
        request_headers = dict(self.session.headers)
        # 为 lizhi.fm 添加 Referer
        if 'lizhi.fm' in original_url or 'lizhi.fm' in url or 'gzlzfm.com' in url:
            request_headers['Referer'] = 'https://www.lizhi.fm/'
            logger.info("📋 [HEADERS] Added Referer for lizhi.fm: https://www.lizhi.fm/")

        # 输出请求头信息用于调试
        logger.info(f"📤 [HTTP REQUEST] URL: {url}")
        logger.info(f"📤 [HTTP REQUEST] Headers: {request_headers}")

        try:
            async with self.session.get(url, headers=request_headers) as response:
                # ℹ️ 输出响应头信息
                logger.info(f"ℹ️ [Response Headers] {dict(response.headers)}")

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
                first_chunk_logged = False
                async with aiofiles.open(destination, 'wb') as f:
                    async for chunk in response.content.iter_chunked(self.chunk_size):
                        # ℹ️ 输出第一个chunk的前200字节
                        if not first_chunk_logged:
                            preview = chunk[:200]
                            logger.info(f"ℹ️ [Response Body Preview] First 200 bytes: {preview}")
                            first_chunk_logged = True

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

    async def download_file_with_fallback(
        self,
        url: str,
        destination: str,
        progress_callback=None
    ) -> tuple[str, int]:
        """
        文件下载（直接使用 aiohttp，无回退）

        Args:
            url: 下载URL
            destination: 保存路径
            progress_callback: 进度回调函数

        Returns:
            Tuple[str, int]: (文件路径, 文件大小)

        Raises:
            HTTPException: 如果下载失败
        """
        # 直接使用 aiohttp 下载
        logger.info(f"📥 [DOWNLOAD] Starting download for: {url[:100]}...")
        try:
            file_path, file_size = await self.download_file(url, destination, progress_callback)
            logger.info(f"✅ [DOWNLOAD] Download succeeded: {file_size} bytes")
            return file_path, file_size

        except Exception as e:
            logger.error(f"❌ [DOWNLOAD] Download failed: {type(e).__name__}: {str(e)}")
            if isinstance(e, HTTPException):
                raise
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Download failed: {str(e)}"
                )


# Note: Browser fallback download has been removed.
# The download now uses only aiohttp with proper headers and retry logic.


class AudioConverter:
    """音频格式转换器"""

    @staticmethod
    async def convert_to_mp3(input_path: str, output_path: str, progress_callback=None) -> tuple[str, float]:
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
            # 验证输入文件存在
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"Input file not found: {input_path}")

            input_size = os.path.getsize(input_path)
            logger.info(f"🎧 [CONVERT] Starting conversion: {input_path} ({input_size/1024/1024:.2f} MB) -> {output_path}")

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
                .global_args('-loglevel', 'error')  # Changed from 'quiet' to 'error' for debugging
            )

            # 执行转换
            if progress_callback:
                await progress_callback(0)

            # 使用子进程执行FFmpeg
            cmd = ffmpeg_proc.compile()
            logger.debug(f"🎧 [CONVERT] FFmpeg command: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace') if stderr else "Unknown FFmpeg error"
                logger.error(f"🎧 [CONVERT] FFmpeg failed with return code {process.returncode}")
                logger.error(f"🎧 [CONVERT] FFmpeg stderr: {error_msg}")
                raise RuntimeError(f"FFmpeg conversion failed (code {process.returncode}): {error_msg}")

            # Verify output file was created
            if not os.path.exists(output_path):
                raise RuntimeError(f"FFmpeg completed successfully but output file not found: {output_path}")

            output_size = os.path.getsize(output_path)
            if output_size == 0:
                os.remove(output_path)
                raise RuntimeError(f"FFmpeg created empty output file: {output_path}")

            if progress_callback:
                await progress_callback(100)

            duration = time.time() - start_time
            logger.info(f"✅ [CONVERT] Successfully converted {input_path} to {output_path}")
            logger.info(f"✅ [CONVERT] Input: {input_size/1024/1024:.2f} MB -> Output: {output_size/1024/1024:.2f} MB, Time: {duration:.2f}s")

            return output_path, duration

        except Exception as e:
            logger.error(f"❌ [CONVERT] Audio conversion failed: {type(e).__name__}: {str(e)}")
            logger.error(f"❌ [CONVERT] Input: {input_path} (exists: {os.path.exists(input_path)}), Output: {output_path} (exists: {os.path.exists(output_path)})")
            # 清理输出文件（保留用于调试）
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                    logger.debug(f"🧹 [CONVERT] Removed partial output file: {output_path}")
                except Exception as cleanup_error:
                    logger.warning(f"⚠️ [CONVERT] Failed to remove partial output: {cleanup_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Audio conversion failed: {str(e)}"
            )


class AudioSplitter:
    """音频文件切割器"""

    @staticmethod
    async def split_mp3_by_duration(
        input_path: str,
        output_dir: str,
        chunk_duration_seconds: int = 300,
        progress_callback=None
    ) -> list[AudioChunk]:
        """
        将MP3文件按时间长度切割成片段（推荐用于转录）

        Args:
            input_path: 输入MP3文件路径
            output_dir: 输出目录
            chunk_duration_seconds: 每个片段的时长（秒），默认300秒（5分钟）
            progress_callback: 进度回调函数

        Returns:
            List[AudioChunk]: 切割后的音频片段列表
        """
        try:
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)

            # 使用FFmpeg获取音频时长
            probe = ffmpeg.probe(input_path)
            duration = float(probe['streams'][0]['duration'])

            # 计算需要切割的段数
            num_chunks = max(1, int(duration // chunk_duration_seconds) + (1 if duration % chunk_duration_seconds > 0 else 0))
            actual_chunk_duration = duration / num_chunks

            chunks = []
            base_name = os.path.splitext(os.path.basename(input_path))[0]

            for i in range(num_chunks):
                start_time = i * chunk_duration_seconds
                # 最后一段的时长可能不同
                end_time = min(start_time + chunk_duration_seconds, duration)
                segment_duration = end_time - start_time

                output_path = os.path.join(
                    output_dir,
                    f"{base_name}_chunk_{i+1:03d}.mp3"
                )

                # 使用FFmpeg切割 - 使用时间参数而非文件大小
                (
                    ffmpeg
                    .input(input_path, ss=start_time, t=segment_duration)
                    .output(
                        output_path,
                        acodec='mp3',
                        ac=1,  # 单声道
                        ar='16000',  # 16kHz采样率
                        ab='64k'  # 64kbps比特率
                    )
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
                    duration=segment_duration,
                    file_size=chunk_file_size
                )
                chunks.append(chunk)

                # 更新进度
                if progress_callback:
                    progress = ((i + 1) / num_chunks) * 100
                    await progress_callback(progress)

            logger.info(f"Successfully split {input_path} into {len(chunks)} chunks by time ({chunk_duration_seconds}s each)")
            return chunks

        except Exception as e:
            logger.error(f"Audio splitting by time failed: {str(e)}")
            # 清理已创建的文件
            for chunk in locals().get('chunks', []):
                if os.path.exists(chunk.file_path):
                    os.remove(chunk.file_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Audio splitting by time failed: {str(e)}"
            )

    @staticmethod
    async def split_mp3(
        input_path: str,
        output_dir: str,
        chunk_size_mb: int = 10,
        progress_callback=None
    ) -> list[AudioChunk]:
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
            # 验证输入文件存在
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"Input file not found: {input_path}")

            input_size = os.path.getsize(input_path)
            logger.info(f"🔪 [SPLIT] Starting split: {input_path} ({input_size/1024/1024:.2f} MB) into {chunk_size_mb}MB chunks")

            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"🔪 [SPLIT] Output directory: {output_dir}")

            # 获取文件信息
            file_size = os.path.getsize(input_path)
            chunk_size_bytes = chunk_size_mb * 1024 * 1024

            # 使用FFmpeg获取音频时长
            try:
                probe = ffmpeg.probe(input_path)
                duration = float(probe['streams'][0]['duration'])
                logger.info(f"🔪 [SPLIT] Input duration: {duration:.2f}s")
            except Exception as e:
                logger.error(f"🔪 [SPLIT] FFmpeg probe failed: {e}")
                raise RuntimeError(f"Failed to probe input file: {e}")

            # 计算需要切割的段数
            num_chunks = max(1, (file_size + chunk_size_bytes - 1) // chunk_size_bytes)
            chunk_duration = duration / num_chunks

            logger.info(f"🔪 [SPLIT] Will create {num_chunks} chunks, ~{chunk_duration:.2f}s each")

            chunks = []
            base_name = os.path.splitext(os.path.basename(input_path))[0]

            for i in range(num_chunks):
                start_time = i * chunk_duration
                output_path = os.path.join(
                    output_dir,
                    f"{base_name}_chunk_{i+1:03d}.mp3"
                )

                logger.debug(f"🔪 [SPLIT] Creating chunk {i+1}/{num_chunks}: {output_path} (start: {start_time:.2f}s, duration: {chunk_duration:.2f}s)")

                # 使用FFmpeg切割 - 捕获输出用于调试
                try:
                    # 构建FFmpeg命令
                    ffmpeg_cmd = (
                        ffmpeg
                        .input(input_path, ss=start_time, t=chunk_duration)
                        .output(output_path, c='copy')
                        .overwrite_output()
                        .global_args('-loglevel', 'error')  # Changed from 'quiet' to 'error'
                        .compile()
                    )

                    # 使用子进程执行以捕获错误
                    process = await asyncio.create_subprocess_exec(
                        *ffmpeg_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await process.communicate()

                    if process.returncode != 0:
                        error_msg = stderr.decode('utf-8', errors='replace') if stderr else "Unknown error"
                        raise RuntimeError(f"FFmpeg split failed (code {process.returncode}): {error_msg}")

                except Exception as e:
                    logger.error(f"🔪 [SPLIT] Failed to create chunk {i+1}: {e}")
                    raise

                # 验证输出文件被创建
                if not os.path.exists(output_path):
                    raise RuntimeError(f"FFmpeg completed but output file not created: {output_path}")

                chunk_file_size = os.path.getsize(output_path)
                if chunk_file_size == 0:
                    os.remove(output_path)
                    raise RuntimeError(f"FFmpeg created empty chunk: {output_path}")

                chunk = AudioChunk(
                    index=i + 1,
                    file_path=output_path,
                    start_time=start_time,
                    duration=chunk_duration,
                    file_size=chunk_file_size
                )
                chunks.append(chunk)

                logger.debug(f"🔪 [SPLIT] Created chunk {i+1}: {chunk_file_size/1024:.2f} KB")

                # 更新进度
                if progress_callback:
                    progress = ((i + 1) / num_chunks) * 100
                    await progress_callback(progress)

            total_output_size = sum(c.file_size for c in chunks)
            logger.info(f"✅ [SPLIT] Successfully split {input_path} into {len(chunks)} chunks ({total_output_size/1024/1024:.2f} MB total)")
            return chunks

        except Exception as e:
            logger.error(f"❌ [SPLIT] Audio splitting failed: {type(e).__name__}: {str(e)}")
            logger.error(f"❌ [SPLIT] Input: {input_path} (exists: {os.path.exists(input_path)}), Output dir: {output_dir}")
            # 清理已创建的文件
            for chunk in locals().get('chunks', []):
                if os.path.exists(chunk.file_path):
                    try:
                        os.remove(chunk.file_path)
                        logger.debug(f"🧹 [SPLIT] Removed partial chunk: {chunk.file_path}")
                    except Exception as cleanup_error:
                        logger.warning(f"⚠️ [SPLIT] Failed to remove partial chunk: {cleanup_error}")
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
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        """异步上下文管理器入口"""
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=600)  # 10分钟超时

        # Debug logging for API configuration
        logger.info(f"🔑 [API DEBUG] API URL: {self.api_url}")
        logger.info(f"🔑 [API DEBUG] API Key (first 12 chars): {self.api_key[:12]}...")
        logger.info(f"🔑 [API DEBUG] API Key (last 4 chars): ...{self.api_key[-4::]}")

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
        model: str = "FunAudioLLM/SenseVoiceSmall",
        ai_repo=None,
        config_db_id: int | None = None
    ) -> AudioChunk:
        """
        转录单个音频片段

        Args:
            chunk: 音频片段
            model: 转录模型名称
            ai_repo: AI模型配置仓库（用于记录统计）
            config_db_id: AI模型配置数据库ID

        Returns:
            AudioChunk: 包含转录结果的音频片段
        """
        async with self.semaphore:  # 限制并发数
            if not self.session:
                raise RuntimeError("Transcriber must be used as async context manager")

            max_retries = 3
            base_delay = 2  # seconds

            for attempt in range(max_retries):
                chunk_start = time.time()
                attempt_succeeded = False
                try:
                    logger.info(f"🎤 [CHUNK {chunk.index:03d}] Starting transcription (Attempt {attempt+1}/{max_retries}), file={os.path.basename(chunk.file_path)}, size={chunk.file_size} bytes, model={model}")

                    # 准备文件上传 (Re-open file for each attempt)
                    data = aiohttp.FormData()
                    data.add_field('model', model)
                    data.add_field(
                        'file',
                        open(chunk.file_path, 'rb'),
                        filename=os.path.basename(chunk.file_path),
                        content_type='audio/mpeg'
                    )

                    # 详细输出请求信息
                    logger.info(f"📡 [REQUEST] URL: {self.api_url}")
                    logger.info(f"📡 [REQUEST] Model: {model}")
                    logger.info(f"📡 [REQUEST] API Key (first 15 chars): {self.api_key[:15]}...")
                    logger.info(f"📡 [REQUEST] API Key (last 5 chars): ...{self.api_key[-5:]}")
                    logger.info(f"📡 [REQUEST] API Key length: {len(self.api_key)}")

                    # 发送请求
                    async with self.session.post(self.api_url, data=data) as response:
                        chunk_elapsed = time.time() - chunk_start

                        if response.status != 200:
                            error_text = await response.text()
                            logger.error(f"❌ [CHUNK {chunk.index:03d}] API error (Attempt {attempt+1}): {response.status} - {error_text}")

                            # 记录本次尝试失败
                            if ai_repo and config_db_id:
                                try:
                                    await ai_repo.increment_usage(config_db_id, success=False)
                                    logger.debug(f"📊 [STATS] Recorded failure for chunk {chunk.index}, attempt {attempt+1}")
                                except Exception as stats_error:
                                    logger.warning(f"⚠️ [STATS] Failed to record failure stats: {stats_error}")

                            if attempt < max_retries - 1:
                                delay = base_delay * (2 ** attempt)
                                logger.info(f"⏳ [CHUNK {chunk.index:03d}] Retrying in {delay}s...")
                                await asyncio.sleep(delay)
                                continue
                            else:
                                chunk.transcript = None
                                return chunk

                        result = await response.json()
                        transcript = result.get('text', '')
                        transcript_len = len(transcript)

                        chunk_elapsed = time.time() - chunk_start
                        logger.info(f"✅ [CHUNK {chunk.index:03d}] Success! Got {transcript_len} chars in {chunk_elapsed:.2f}s")

                        # 记录本次尝试成功
                        if ai_repo and config_db_id:
                            try:
                                await ai_repo.increment_usage(config_db_id, success=True)
                                logger.debug(f"📊 [STATS] Recorded success for chunk {chunk.index}, attempt {attempt+1}")
                            except Exception as stats_error:
                                logger.warning(f"⚠️ [STATS] Failed to record success stats: {stats_error}")

                        chunk.transcript = transcript
                        return chunk

                except Exception as e:
                    chunk_elapsed = time.time() - chunk_start
                    logger.error(f"❌ [CHUNK {chunk.index:03d}] Failed attempt {attempt+1} after {chunk_elapsed:.2f}s: {str(e)}")

                    # 记录本次尝试失败
                    if ai_repo and config_db_id:
                        try:
                            await ai_repo.increment_usage(config_db_id, success=False)
                            logger.debug(f"📊 [STATS] Recorded failure for chunk {chunk.index}, attempt {attempt+1} (exception)")
                        except Exception as stats_error:
                            logger.warning(f"⚠️ [STATS] Failed to record failure stats: {stats_error}")

                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        logger.info(f"⏳ [CHUNK {chunk.index:03d}] Retrying in {delay}s...")
                        await asyncio.sleep(delay)
                    else:
                        chunk.transcript = None
                        return chunk

            return chunk


    async def transcribe_chunks(
        self,
        chunks: list[AudioChunk],
        model: str = "FunAudioLLM/SenseVoiceSmall",
        progress_callback=None,
        ai_repo=None,
        config_db_id: int | None = None
    ) -> list[AudioChunk]:
        """
        并发转录多个音频片段

        Args:
            chunks: 音频分片列表
            model: 转录模型名称
            progress_callback: 进度回调函数
            ai_repo: AI模型配置仓库（用于记录统计）
            config_db_id: AI模型配置数据库ID

        Note:
            统计记录在 transcribe_chunk 方法中每次API调用后立即进行，
            包括重试尝试，因此这里不需要重复记录。
        """
        start_time = time.time()

        # 创建转录任务（传入 ai_repo 和 config_db_id）
        tasks = [
            asyncio.create_task(self.transcribe_chunk(chunk, model, ai_repo, config_db_id))
            for chunk in chunks
        ]

        # 执行并发转录
        results = []
        completed = 0

        for coro in asyncio.as_completed(tasks):
            try:
                # transcribe_chunk now returns the chunk itself
                chunk = await coro
                results.append(chunk)

                completed += 1
                if progress_callback:
                    progress = (completed / len(chunks)) * 100
                    await progress_callback(progress)

            except Exception as e:
                logger.error(f"Unexpected error in transcribe_chunks sequence: {str(e)}")

        duration = time.time() - start_time
        # Ensure correct order
        results.sort(key=lambda x: x.index)

        success_count = sum(1 for c in results if c.transcript is not None)
        logger.info(f"Completed transcription of {success_count}/{len(chunks)} chunks in {duration:.2f}s")

        return results



class PodcastTranscriptionService:
    """播客转录主服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        # 进度缓存，减少数据库操作频率
        self._progress_cache: dict[str, dict[str, float]] = {}

        # Get path from settings - use absolute path if configured, otherwise resolve relative path
        temp_dir_config = getattr(settings, 'TRANSCRIPTION_TEMP_DIR', './temp/transcription')
        storage_dir_config = getattr(settings, 'TRANSCRIPTION_STORAGE_DIR', './storage/podcasts')

        # Use configured path directly (supports both absolute and relative)
        # In Docker, these will be absolute paths like /app/temp/transcription
        # In local dev, these will be relative paths that get resolved
        self.temp_dir = os.path.abspath(temp_dir_config)
        self.storage_dir = os.path.abspath(storage_dir_config)

        # Log for debugging (use debug level to reduce noise)
        logger.debug(f"📁 [TRANSCRIPTION] temp_dir = {self.temp_dir} (from config: {temp_dir_config})")
        logger.debug(f"📁 [TRANSCRIPTION] storage_dir = {self.storage_dir} (from config: {storage_dir_config})")
        logger.debug(f"📁 [TRANSCRIPTION] cwd = {os.getcwd()}")

        self.chunk_size_mb = getattr(settings, 'TRANSCRIPTION_CHUNK_SIZE_MB', 10)
        self.max_threads = getattr(settings, 'TRANSCRIPTION_MAX_THREADS', 4)
        # API configuration is now dynamic, but we keep defaults for fallback
        self.default_api_url = getattr(settings, 'TRANSCRIPTION_API_URL', 'https://api.siliconflow.cn/v1/audio/transcriptions')
        self.default_api_key = getattr(settings, 'TRANSCRIPTION_API_KEY', None)

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
        error_message: str | None = None
    ):
        """更新任务进度"""
        update_data = {
            'status': status,
            'progress_percentage': progress,
            'updated_at': datetime.now(timezone.utc)
        }

        if error_message:
            update_data['error_message'] = error_message

        # 设置开始时间
        if status == 'downloading' and not await self._get_task_field(task_id, 'started_at'):
            update_data['started_at'] = datetime.now(timezone.utc)

        # 设置完成时间
        if status in [TranscriptionStatus.COMPLETED, TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
            update_data['completed_at'] = datetime.now(timezone.utc)

        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.id == task_id)
            .values(**update_data)
        )

        await self.db.execute(stmt)
        await self.db.commit()

        # 使用节流器减少日志输出
        if _progress_throttle.should_log(task_id, str(status), progress):
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
        step: TranscriptionStep,  # 现在是 step 而不是 status
        progress: float,
        message: str,
        error_message: str | None = None
    ):
        """使用指定的数据库会话更新任务进度和步骤"""
        from app.domains.podcast.models import TranscriptionStatus

        # 使用内存缓存减少数据库读取频率
        # 只有当进度变化超过1%时才真正更新数据库
        cache_key = f"{task_id}_{step}"
        if cache_key not in self._progress_cache:
            self._progress_cache[cache_key] = {'last_db_update': 0.0, 'last_log': 0.0}

        cached = self._progress_cache[cache_key]
        progress_delta = abs(progress - cached['last_db_update'])

        # 只在进度变化超过1%时才更新数据库
        if progress_delta < 1.0 and int(progress) != 100:
            return  # 跳过此次更新

        update_data = {
            'current_step': step,
            'progress_percentage': progress,
            'updated_at': datetime.now(timezone.utc)
        }

        if error_message:
            update_data['error_message'] = error_message

        # 设置开始时间（第一次执行时）
        stmt_check = select(TranscriptionTask.started_at).where(TranscriptionTask.id == task_id)
        result = await session.execute(stmt_check)
        started_at = result.scalar()
        if not started_at:
            update_data['started_at'] = datetime.now(timezone.utc)
            update_data['status'] = TranscriptionStatus.IN_PROGRESS

        # Try to update chunk_info with the debug message
        if message:
            stmt_info = select(TranscriptionTask.chunk_info).where(TranscriptionTask.id == task_id)
            result_info = await session.execute(stmt_info)
            current_chunk_info = result_info.scalar() or {}

            if not isinstance(current_chunk_info, dict):
                current_chunk_info = {}

            # Update debug_message
            current_chunk_info['debug_message'] = message
            update_data['chunk_info'] = current_chunk_info

        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.id == task_id)
            .values(**update_data)
        )

        await session.execute(stmt)
        await session.commit()

        # 更新缓存
        cached['last_db_update'] = progress

        # 基于进度变化判断是否需要记录日志
        log_delta = abs(progress - cached['last_log'])
        # 只在进度变化超过5%或完成时才记录日志
        if log_delta >= 5.0 or int(progress) == 100:
            # 使用简化的日志格式
            if int(progress) == 100:
                logger.info(f"✅ [PROGRESS] Task {task_id}: {step} - COMPLETED")
            else:
                logger.info(f"📊 [PROGRESS] Task {task_id}: {step} - {progress:.1f}%")
            cached['last_log'] = progress

    async def _set_task_final_status(
        self,
        session: AsyncSession,
        task_id: int,
        status: TranscriptionStatus,  # COMPLETED 或 FAILED
        error_message: str | None = None
    ):
        """设置任务的最终状态（COMPLETED 或 FAILED）"""
        update_data = {
            'status': status,
            'updated_at': datetime.now(timezone.utc)
        }

        if status in [TranscriptionStatus.COMPLETED, TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
            update_data['completed_at'] = datetime.now(timezone.utc)

        if error_message:
            update_data['error_message'] = error_message

        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.id == task_id)
            .values(**update_data)
        )

        await session.execute(stmt)
        await session.commit()

        logger.info(f"Set task {task_id} final status: {status}")

    async def create_transcription_task_record(self, episode_id: int, model: str | None = None, force: bool = False) -> tuple[TranscriptionTask, int | None]:
        """
        创建转录任务记录（不立即执行）
        
        Returns:
            Tuple[TranscriptionTask, Optional[int]]: (任务对象, 模型配置DB ID)
        """
        logger.info(f"🎬 [TRANSCRIPTION PREPARE] episode_id={episode_id}, model={model}, force={force}")

        # 检查是否已存在转录任务
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        existing_task = result.scalar_one_or_none()

        if existing_task:
            logger.info(f"🔄 [TRANSCRIPTION] Existing task found: id={existing_task.id}, status={existing_task.status}")
            if force:
                # Force mode: delete existing task and create new one (regardless of status)
                logger.info(f"🗑️ [TRANSCRIPTION] Force mode: deleting existing task {existing_task.id}")
                await self.db.delete(existing_task)
                await self.db.flush()
                await self.db.commit()  # Commit the delete to release the unique constraint
            elif existing_task.status not in [TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
                # Task exists with non-failed/cancelled status and force=false: raise error
                logger.warning(f"⚠️ [TRANSCRIPTION] Task already exists with status {existing_task.status}")
                raise ValidationError(
                    f"Transcription task already exists for episode {episode_id} with status {existing_task.status}. Use force=true to retry."
                )
            else:
                # Task exists with failed/cancelled status and force=false: delete it and create new one
                logger.info(f"🗑️ [TRANSCRIPTION] Removing failed/cancelled task {existing_task.id} before creating new one")
                await self.db.delete(existing_task)
                await self.db.flush()
                await self.db.commit()  # Commit the delete to release the unique constraint
                logger.info("✅ [TRANSCRIPTION] Failed/cancelled task removed, ready to create new one")

        # 获取播客单集信息
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if not episode:
            logger.error(f"❌ [TRANSCRIPTION] Episode {episode_id} not found")
            raise ValidationError(f"Episode {episode_id} not found")

        logger.info(f"📺 [TRANSCRIPTION] Episode found: title='{episode.title}', audio_url='{episode.audio_url}'")

        # 确定使用的模型
        ai_repo = AIModelConfigRepository(self.db)

        # 1. 如果指定了模型名称，尝试查找
        model_config = None
        if model:
            model_config = await ai_repo.get_by_name(model)
            logger.info(f"🔍 [TRANSCRIPTION] Looking for model by name '{model}': {model_config is not None}")
            # 检查指定模型是否存在且活跃
            if not model_config or not model_config.is_active or model_config.model_type != ModelType.TRANSCRIPTION:
                raise ValidationError(f"Transcription model '{model}' not found or not active")

        # 2. 如果未指定或未找到，按优先级获取转录模型
        if not model_config:
            active_models = await ai_repo.get_active_models_by_priority(ModelType.TRANSCRIPTION)
            if active_models:
                model_config = active_models[0]  # 使用优先级最高的模型
                logger.info(f"🔍 [TRANSCRIPTION] Using highest priority model: {model_config.model_id} (priority={model_config.priority})")
            else:
                # 如果没有找到任何活跃的转录模型，抛出错误
                raise ValidationError("No active transcription model found")

        # 确定最终使用的模型ID字符串 (传递给API的model参数)
        transcription_model = model_config.model_id
        logger.info(f"🤖 [TRANSCRIPTION] Final model to use: '{transcription_model}'")

        # 创建新的转录任务
        logger.info("📝 [TRANSCRIPTION] Creating TranscriptionTask in database...")
        task = TranscriptionTask(
            episode_id=episode_id,
            original_audio_url=episode.audio_url,
            chunk_size_mb=self.chunk_size_mb,
            model_used=transcription_model  # 这里存储的是API模型ID (如 whisper-1)，不是数据库ID
        )

        self.db.add(task)
        await self.db.commit()
        await self.db.refresh(task)

        logger.info(f"✅ [TRANSCRIPTION] Task created in DB: id={task.id}, status={task.status}")

        config_db_id = model_config.id if model_config else None
        return task, config_db_id

    async def start_transcription(self, episode_id: int, model: str | None = None, force: bool = False) -> TranscriptionTask:
        """启动转录任务"""
        # 1. 创建任务记录
        task, config_db_id = await self.create_transcription_task_record(episode_id, model=model, force=force)

        logger.info(f"🎯 [TRANSCRIPTION] Task {task.id} created successfully. config_db_id={config_db_id}")

        return task


    async def execute_transcription_task(self, task_id: int, session, config_db_id: int | None = None):
        """执行转录任务（后台运行）"""
        log_with_timestamp("INFO", "🎬 [EXECUTE START] Transcription task starting...", task_id)
        log_with_timestamp("INFO", f"📋 [EXECUTE] config_db_id={config_db_id}", task_id)
        log_with_timestamp("INFO", f"📋 [EXECUTE] asyncio event loop running: {asyncio.get_event_loop().is_running()}", task_id)

        try:
            logger.info(f"🔗 [EXECUTE] Using provided database session for task {task_id}")

            # 初始化 AI 模型配置仓库（用于记录统计）
            ai_repo = AIModelConfigRepository(session)
            # 获取任务信息
            stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
            result = await session.execute(stmt)
            task = result.scalar_one_or_none()

            if not task:
                logger.error(f"❌ [EXECUTE] Transcription task {task_id} not found in database")
                return

            # 检查任务是否已经完成，避免重复执行
            if task.status == TranscriptionStatus.COMPLETED:
                log_with_timestamp("INFO", f"✅ [SKIP] Task {task_id} already completed, skipping execution", task_id)
                log_with_timestamp("INFO", f"📄 [SKIP] Transcript has {task.transcript_word_count or 0} words", task_id)
                return

            # 检查任务是否已取消或失败且不应重试
            if task.status == TranscriptionStatus.CANCELLED:
                log_with_timestamp("WARNING", f"⚠️ [SKIP] Task {task_id} was cancelled, skipping execution", task_id)
                return

            # 获取播客单集信息 (预加载subscription关系以避免lazy load)
            from sqlalchemy.orm import selectinload
            stmt = select(PodcastEpisode).options(
                selectinload(PodcastEpisode.subscription)
            ).where(PodcastEpisode.id == task.episode_id)
            result = await session.execute(stmt)
            episode = result.scalar_one_or_none()

            if not episode:
                logger.error(f"transcription._execute_transcription: Episode {task.episode_id} not found for task {task_id}")
                await self._set_task_final_status(
                    session, task_id,
                    TranscriptionStatus.FAILED,
                    "Episode not found"
                )
                return

            # 获取转录配置
            api_url = self.default_api_url
            api_key = self.default_api_key

            if config_db_id:
                logger.info(f"transcription._execute_transcription: Using custom model config {config_db_id}")
                model_config = await ai_repo.get_by_id(config_db_id)
                if model_config and model_config.is_active:
                    api_url = model_config.api_url
                    # 获取API Key - 支持加密解密
                    if model_config.is_system and model_config.provider == 'siliconflow':
                         api_key = getattr(settings, 'TRANSCRIPTION_API_KEY', None) or model_config.api_key
                    elif model_config.is_system and model_config.provider == 'openai':
                         api_key = getattr(settings, 'OPENAI_API_KEY', None) or model_config.api_key
                    else:
                         # 用户自定义模型 - 需要解密
                         if model_config.api_key_encrypted and model_config.api_key:
                             from app.core.security import decrypt_data
                             try:
                                 api_key = decrypt_data(model_config.api_key)
                                 logger.info(f"🔑 [KEY] Decrypted API key for model {model_config.name} (first 10 chars): {api_key[:10]}...")
                             except Exception as e:
                                 logger.error(f"Failed to decrypt API key: {e}")
                                 api_key = model_config.api_key
                         else:
                             api_key = model_config.api_key

            if not api_key:
                 logger.error(f"transcription._execute_transcription: API Key missing for task {task_id}")
                 await self._set_task_final_status(
                    session, task_id,
                    TranscriptionStatus.FAILED,
                    "Transcription API Key not found"
                )
                 return

            # 创建临时目录
            temp_episode_dir = os.path.join(self.temp_dir, f"episode_{task.episode_id}")
            os.makedirs(temp_episode_dir, exist_ok=True)
            logger.info(f"transcription._execute_transcription: Created temp dir {temp_episode_dir}")

            # === 步骤跳过逻辑：根据 current_step 决定从哪一步开始 ===
            start_step = task.current_step
            log_with_timestamp("INFO", f"📍 [RESUME] Current step: {start_step}, will resume from this step", task_id)

            # 步骤执行顺序：DOWNLOADING -> CONVERTING -> SPLITTING -> TRANSCRIBING -> MERGING
            # 如果 current_step 在某个步骤之后，前面的步骤将被跳过

            # === 步骤1：下载音频文件（支持增量恢复） ===
            download_start = time.time()
            download_time = 0
            original_file = os.path.join(temp_episode_dir, f"original{os.path.splitext(task.original_audio_url)[-1]}")
            file_size = 0

            # 检查是否已下载
            if os.path.exists(original_file) and os.path.getsize(original_file) > 0:
                file_size = os.path.getsize(original_file)
                log_with_timestamp("INFO", f"⏭️ [STEP 1/6 DOWNLOAD] Skip! File already exists: {original_file} ({file_size/1024/1024:.2f} MB)", task_id)
                log_with_timestamp("INFO", "✅ [STEP 1/6 DOWNLOAD] Using existing downloaded file", task_id)
            else:
                log_with_timestamp("INFO", "📥 [STEP 1/6 DOWNLOAD] Starting audio download with fallback...", task_id)
                log_with_timestamp("INFO", f"📥 [STEP 1/6 DOWNLOAD] Source URL: {task.original_audio_url[:100]}...", task_id)
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    'downloading',
                    5,
                    "Downloading audio file..."
                )

                logger.info(f"📥 [STEP 1 DOWNLOAD] Target path: {original_file}")

                async with AudioDownloader() as downloader:
                    # 使用节流器减少日志
                    last_dl_progress = 0.0

                    async def download_progress(progress):
                        nonlocal last_dl_progress

                        # 每10%记录一次下载日志
                        if int(progress) // 10 > int(last_dl_progress) // 10:
                            logger.info(f"📥 [STEP 1 DOWNLOAD] Progress: {progress:.1f}%")
                            last_dl_progress = progress

                        await self._update_task_progress_with_session(
                            session,
                            task_id,
                            'downloading',
                            5 + (progress * 0.15),  # 5-20%
                            f"Downloading... {progress:.1f}%"
                        )

                    # 使用带回退机制的下载方法
                    file_path, file_size = await downloader.download_file_with_fallback(
                        task.original_audio_url,
                        original_file,
                        download_progress
                    )

                log_with_timestamp("INFO", f"✅ [STEP 1/6 DOWNLOAD] Download complete! Size: {file_size} bytes ({file_size/1024/1024:.2f} MB)", task_id)
                download_time = time.time() - download_start
                log_with_timestamp("INFO", f"⏱️ [STEP 1/6 DOWNLOAD] Time taken: {download_time:.2f}s", task_id)

            file_path = original_file  # 确保file_path指向正确的文件

            # === 步骤2：转换为MP3（支持增量恢复） ===
            conversion_time = 0
            converted_file = os.path.join(temp_episode_dir, "converted.mp3")

            log_with_timestamp("INFO", f"🔍 [STEP 2/6 CONVERT] Checking conversion status: {converted_file}", task_id)
            log_with_timestamp("INFO", f"🔍 [STEP 2/6 CONVERT] File exists: {os.path.exists(converted_file)}", task_id)

            # 检查是否已转换（更严格的验证）
            skip_conversion = False
            if os.path.exists(converted_file):
                converted_size = os.path.getsize(converted_file)
                log_with_timestamp("INFO", f"🔍 [STEP 2/6 CONVERT] Found existing file: {converted_size} bytes", task_id)
                # 验证文件大小合理（至少10KB，且不超过原始文件太多）
                if converted_size > 10240:  # 至少10KB
                    # 尝试用ffmpeg验证文件是否是有效的MP3
                    try:
                        import ffmpeg
                        probe = ffmpeg.probe(converted_file)
                        log_with_timestamp("INFO", f"🔍 [STEP 2/6 CONVERT] FFmpeg probe result: {probe}", task_id)
                        duration = probe.get('format', {}).get('duration') if probe else None
                        if duration:
                            skip_conversion = True
                            log_with_timestamp("INFO", f"⏭️ [STEP 2/6 CONVERT] Skip! Valid MP3 file already exists: {converted_file} ({converted_size/1024/1024:.2f} MB, {duration}s)", task_id)
                            log_with_timestamp("INFO", "✅ [STEP 2/6 CONVERT] Using existing converted file", task_id)
                        else:
                            log_with_timestamp("WARNING", f"⚠️ [STEP 2/6 CONVERT] File exists but invalid (no duration), re-converting: {converted_file}", task_id)
                    except Exception as e:
                        log_with_timestamp("WARNING", f"⚠️ [STEP 2/6 CONVERT] File exists but validation failed ({str(e)}), re-converting", task_id)
                    else:
                        log_with_timestamp("WARNING", f"⚠️ [STEP 2/6 CONVERT] File exists but too small ({converted_size} bytes), re-converting", task_id)
                else:
                    log_with_timestamp("INFO", "🔍 [STEP 2/6 CONVERT] File does not exist, will convert", task_id)

            if not skip_conversion:
                log_with_timestamp("INFO", "🔄 [STEP 2/6 CONVERT] Starting MP3 conversion...", task_id)
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    'converting',
                    20,
                    "Converting to MP3..."
                )

                async def convert_progress(progress):
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        'converting',
                        20 + (progress * 0.15),  # 20-35%
                        f"Converting... {progress:.1f}%"
                    )

                convert_start = time.time()
                _, conversion_time = await AudioConverter.convert_to_mp3(
                    file_path,
                    converted_file,
                    convert_progress
                )

                # Verify the converted file was actually created
                if not os.path.exists(converted_file):
                    error_msg = f"Conversion completed but output file not found: {converted_file}"
                    logger.error(f"❌ [STEP 2/6 CONVERT] {error_msg}")
                    logger.error(f"❌ [STEP 2/6 CONVERT] Input file: {file_path}, exists: {os.path.exists(file_path)}")
                    await self._set_task_final_status(
                        session, task_id,
                        TranscriptionStatus.FAILED,
                        "MP3 conversion failed - output file not created"
                    )
                    return

                converted_size = os.path.getsize(converted_file)
                log_with_timestamp("INFO", f"✅ [STEP 2/6 CONVERT] Conversion complete! Output: {converted_file} ({converted_size/1024/1024:.2f} MB), Time: {conversion_time:.2f}s", task_id)

            # Final verification before moving to STEP 3
            log_with_timestamp("INFO", f"🔍 [STEP 2->3] Final check: converted_file exists = {os.path.exists(converted_file)}, size = {os.path.getsize(converted_file) if os.path.exists(converted_file) else 0}", task_id)

            # === 步骤3：切割音频文件（支持增量恢复） ===
            # 首先验证converted_file确实存在且有效
            log_with_timestamp("INFO", "📋 [STEP 3/6 SPLIT] Starting split verification...", task_id)

            if not os.path.exists(converted_file):
                error_msg = f"Converted file not found: {converted_file}. Cannot proceed with split."
                logger.error(f"❌ [STEP 3/6 SPLIT] {error_msg}")
                logger.error(f"❌ [STEP 3/6 SPLIT] Working directory: {os.getcwd()}")
                logger.error(f"❌ [STEP 3/6 SPLIT] Temp dir exists: {os.path.exists(temp_episode_dir)}")
                if os.path.exists(temp_episode_dir):
                    files = os.listdir(temp_episode_dir)
                    logger.error(f"❌ [STEP 3/6 SPLIT] Files in temp dir: {files}")
                await self._set_task_final_status(
                    session, task_id,
                    TranscriptionStatus.FAILED,
                    "Converted audio file missing, cannot split"
                )
                return

            converted_file_size = os.path.getsize(converted_file)
            if converted_file_size == 0:
                error_msg = f"Converted file is empty: {converted_file}. Cannot proceed with split."
                logger.error(f"❌ [STEP 3/6 SPLIT] {error_msg}")
                await self._set_task_final_status(
                    session, task_id,
                    TranscriptionStatus.FAILED,
                    "Converted audio file is empty, cannot split"
                )
                return

            log_with_timestamp("INFO", f"📋 [STEP 3/6 SPLIT] Verified converted file exists: {converted_file} ({converted_file_size/1024/1024:.2f} MB)", task_id)

            split_dir = os.path.join(temp_episode_dir, "chunks")

            # 检查是否已分割
            if os.path.exists(split_dir) and os.path.isdir(split_dir):
                # 检查是否有chunk文件
                chunk_files = [f for f in os.listdir(split_dir) if f.startswith('chunk_') and f.endswith('.mp3')]
                if chunk_files:
                    log_with_timestamp("INFO", f"⏭️ [STEP 3/6 SPLIT] Skip! Chunks already exist: {len(chunk_files)} files found", task_id)
                    log_with_timestamp("INFO", "✅ [STEP 3/6 SPLIT] Using existing chunks", task_id)
                    # 重建chunks对象列表
                    chunks = []
                    for chunk_file in sorted(chunk_files):
                        chunk_path = os.path.join(split_dir, chunk_file)
                        # 从文件名解析chunk信息 (chunk_0001.mp3 -> index=1)
                        index = int(chunk_file.replace('chunk_', '').replace('.mp3', ''))
                        file_size = os.path.getsize(chunk_path)
                        chunks.append(AudioChunk(
                            index=index,
                            file_path=chunk_path,
                            start_time=0,  # 这些信息会从文件中获取
                            duration=0,
                            file_size=file_size,
                            transcript=None
                        ))
                else:
                    # 需要执行分割
                    log_with_timestamp("INFO", f"✂️ [STEP 3/6 SPLIT] Starting audio split with chunk_size_mb={task.chunk_size_mb}...", task_id)
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        'splitting',
                        35,
                        "Splitting audio file..."
                    )

                    async def split_progress(progress):
                        await self._update_task_progress_with_session(
                            session,
                            task_id,
                            'splitting',
                            35 + (progress * 0.10),  # 35-45%
                            f"Splitting... {progress:.1f}%"
                        )

                    chunks = await AudioSplitter.split_mp3(
                        converted_file,
                        split_dir,
                        task.chunk_size_mb,
                        split_progress
                    )
                    log_with_timestamp("INFO", f"✅ [STEP 3/6 SPLIT] Split complete! Created {len(chunks)} chunks", task_id)
            else:
                # 需要执行分割
                log_with_timestamp("INFO", f"✂️ [STEP 3/6 SPLIT] Starting audio split with chunk_size_mb={task.chunk_size_mb}...", task_id)
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    'splitting',
                    35,
                    "Splitting audio file..."
                )

                async def split_progress(progress):
                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        'splitting',
                        35 + (progress * 0.10),  # 35-45%
                        f"Splitting... {progress:.1f}%"
                    )

                chunks = await AudioSplitter.split_mp3(
                    converted_file,
                    split_dir,
                    task.chunk_size_mb,
                    split_progress
                )
                log_with_timestamp("INFO", f"✅ [STEP 3/6 SPLIT] Split complete! Created {len(chunks)} chunks", task_id)

            # === 步骤4：转录音频片段（支持增量恢复） ===
            # 检查是否有已转录的片段
            chunks_to_transcribe = []
            already_transcribed = []
            for chunk in chunks:
                transcript_file = chunk.file_path.replace('.mp3', '.txt')
                if os.path.exists(transcript_file) and os.path.getsize(transcript_file) > 0:
                    # 加载已有的转录
                    async with aiofiles.open(transcript_file, encoding='utf-8') as f:
                        content = await f.read()
                    if content.strip():
                        chunk.transcript = content
                        already_transcribed.append(chunk)
                else:
                    chunks_to_transcribe.append(chunk)

            if already_transcribed:
                log_with_timestamp("INFO", f"⏭️ [STEP 4/6 TRANSCRIBE] Found {len(already_transcribed)} already transcribed chunks, skipping", task_id)

            log_with_timestamp("INFO", f"🤖 [STEP 4/6 TRANSCRIBE] Starting transcription of {len(chunks_to_transcribe)} remaining chunks...", task_id)
            log_with_timestamp("INFO", f"🤖 [STEP 4/6 TRANSCRIBE] Model: {task.model_used}", task_id)

            if chunks_to_transcribe:
                await self._update_task_progress_with_session(
                    session,
                    task_id,
                    'transcribing',
                    45,
                    f"Transcribing {len(chunks_to_transcribe)} audio chunks..."
                )

                transcription_start = time.time()

                # 使用节流器减少日志
                last_trans_progress = 0.0

                async def transcribe_progress(progress):
                    nonlocal last_trans_progress

                    # 每10%记录一次转录日志
                    if int(progress) // 10 > int(last_trans_progress) // 10:
                        logger.info(f"🤖 [STEP 4 TRANSCRIBE] Progress: {progress:.1f}%")
                        last_trans_progress = progress

                    await self._update_task_progress_with_session(
                        session,
                        task_id,
                        'transcribing',
                        45 + (progress * 0.50),  # 45-95%
                        f"Transcribing... {progress:.1f}%"
                    )

                async with SiliconFlowTranscriber(
                    api_key,
                    api_url,
                    self.max_threads
                ) as transcriber:
                    transcribed_chunks = await transcriber.transcribe_chunks(
                        chunks_to_transcribe,
                        task.model_used,
                        transcribe_progress,
                        ai_repo=ai_repo,
                        config_db_id=config_db_id
                    )

                # 合并已有转录和新转录
                all_chunks = already_transcribed + transcribed_chunks

                log_with_timestamp("INFO", "✅ [STEP 4/6 TRANSCRIBE] Transcription chunks finished!", task_id)

                # Log transcription results summary
                success_count = sum(1 for c in all_chunks if c.transcript)
                failed_count = len(all_chunks) - success_count
                log_with_timestamp("INFO", f"📊 [STEP 4/6 TRANSCRIBE] Results: {success_count} succeeded, {failed_count} failed out of {len(all_chunks)} total", task_id)

                transcription_time = time.time() - transcription_start
                log_with_timestamp("INFO", f"⏱️ [STEP 4/6 TRANSCRIBE] Time taken: {transcription_time:.2f}s", task_id)
            else:
                # 所有片段都已转录
                all_chunks = already_transcribed
                log_with_timestamp("INFO", "✅ [STEP 4/6 TRANSCRIBE] All chunks already transcribed! Skipping transcription", task_id)
                success_count = len(all_chunks)
                failed_count = 0
                transcription_time = 0

            # 步骤5：合并转录结果
            log_with_timestamp("INFO", "🔗 [STEP 5/6 MERGE] Merging transcription results...", task_id)
            await self._update_task_progress_with_session(
                session,
                task_id,
                'merging',
                95,
                "Merging transcription results..."
            )

            # 按顺序合并转录文本
            sorted_chunks = sorted(all_chunks, key=lambda x: x.index)
            full_transcript = "\n\n".join([
                chunk.transcript.strip() for chunk in sorted_chunks
                if chunk.transcript and chunk.transcript.strip()
            ])

            log_with_timestamp("INFO", f"📄 [STEP 5/6 MERGE] Merged transcript: {len(full_transcript)} chars, {len(full_transcript.split())} words", task_id)
            log_with_timestamp("INFO", f"📄 [STEP 5/6 MERGE] Preview: {full_transcript[:150]}...", task_id)

            # 步骤6：保存结果到永久存储
            storage_path = self._get_episode_storage_path(episode)
            os.makedirs(storage_path, exist_ok=True)

            # 保存原始音频文件
            final_audio_path = os.path.join(storage_path, "original.mp3")

            # Verify converted file exists before copying
            if not os.path.exists(converted_file):
                error_msg = f"Converted audio file not found: {converted_file}"
                logger.error(f"❌ [STEP 6 SAVE] {error_msg}")
                logger.error(f"❌ [STEP 6 SAVE] Working directory: {os.getcwd()}")
                logger.error(f"❌ [STEP 6 SAVE] Absolute path: {os.path.abspath(converted_file)}")
                # List files in temp directory for debugging
                if os.path.exists(temp_episode_dir):
                    files = os.listdir(temp_episode_dir)
                    logger.error(f"❌ [STEP 6 SAVE] Files in temp dir: {files}")
                else:
                    logger.error(f"❌ [STEP 6 SAVE] Temp directory does not exist: {temp_episode_dir}")
                raise FileNotFoundError(error_msg)

            # Move audio file to permanent storage
            # Use shutil.move instead of os.replace to handle cross-device moves (e.g., Docker volumes)
            # 使用 shutil.move 而非 os.replace，以处理跨设备移动（如 Docker 卷）
            import shutil
            try:
                shutil.move(converted_file, final_audio_path)
            except OSError as e:
                logger.warning(f"⚠️ [STEP 6 SAVE] shutil.move failed ({e}), trying copy + delete")
                shutil.copy2(converted_file, final_audio_path)
                try:
                    os.remove(converted_file)
                except OSError:
                    logger.warning(f"⚠️ [STEP 6 SAVE] Could not remove source file: {converted_file}")

            # 保存转录文本
            transcript_path = os.path.join(storage_path, "transcript.txt")
            async with aiofiles.open(transcript_path, 'w', encoding='utf-8') as f:
                await f.write(full_transcript)

            log_with_timestamp("INFO", f"💾 [STEP 6/6 SAVE] Transcript saved to: {transcript_path}", task_id)

            # 更新任务详细信息
            task_update = {
                'status': TranscriptionStatus.COMPLETED,
                'current_step': 'merging',  # 保持最后的步骤
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
                'completed_at': datetime.now(timezone.utc)
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
                .where(PodcastEpisode.id == task.episode_id)
                .values(**episode_update)
            )
            await session.execute(stmt)

            await session.commit()

            total_time = time.time() - download_start
            log_with_timestamp("INFO", f"✅ [TRANSCRIPTION COMPLETE] Successfully completed transcription for episode {task.episode_id}", task_id)
            log_with_timestamp("INFO", f"✅ [TRANSCRIPTION COMPLETE] Total time: {total_time:.2f}s (download:{download_time:.2f}s, convert:{conversion_time:.2f}s, transcribe:{transcription_time:.2f}s)", task_id)
            log_with_timestamp("INFO", f"✅ [TRANSCRIPTION COMPLETE] Transcript: {len(full_transcript)} chars, {len(full_transcript.split())} words", task_id)

            # 触发AI总结
            log_with_timestamp("INFO", f"🤖 [AI SUMMARY] Scheduling AI summary for episode {task.episode_id}", task_id)
            await self._schedule_ai_summary(session, task_id)
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"❌ [EXECUTE ERROR] Transcription failed for task {task_id}: {str(e)}")
            logger.error(f"❌ [EXECUTE ERROR] Traceback:\n{error_trace}")
            await self._set_task_final_status(
                session,
                task_id,
                TranscriptionStatus.FAILED,
                f"Transcription failed: {str(e)}"
            )
        finally:
            # Only clean up temporary files if the task completed successfully
            # Failed or interrupted tasks should keep their temp files for incremental recovery
            try:
                # Re-fetch task status to see if it completed successfully
                stmt_check = select(TranscriptionTask.status).where(TranscriptionTask.id == task_id)
                result_check = await session.execute(stmt_check)
                final_status = result_check.scalar()

                if final_status == TranscriptionStatus.COMPLETED:
                    import shutil
                    temp_episode_dir = os.path.join(self.temp_dir, f"episode_{task.episode_id}")
                    if os.path.exists(temp_episode_dir):
                        shutil.rmtree(temp_episode_dir)
                        logger.info(f"🧹 [CLEANUP] Cleaned up temporary directory for successful task {task_id}: {temp_episode_dir}")
                else:
                    temp_episode_dir = os.path.join(self.temp_dir, f"episode_{task.episode_id}")
                    if os.path.exists(temp_episode_dir):
                        logger.info(f"⏸️ [CLEANUP] Preserving temporary directory for task {task_id} (status={final_status}): {temp_episode_dir}")
            except Exception as e:
                logger.error(f"⚠️ [CLEANUP] Error during cleanup: {str(e)}")

    async def get_transcription_status(self, task_id: int) -> TranscriptionTask | None:
        """获取转录任务状态"""
        stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_episode_transcription(self, episode_id: int) -> TranscriptionTask | None:
        """获取播客单集的转录信息"""
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def _schedule_ai_summary(self, session: AsyncSession, task_id: int):
        """调度AI总结任务"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # 获取转录任务
            log_with_timestamp("INFO", f"🔍 [AI SUMMARY] Getting transcription task {task_id}", task_id)
            stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
            result = await session.execute(stmt)
            task = result.scalar_one_or_none()
            
            if not task:
                log_with_timestamp("ERROR", f"❌ [AI SUMMARY] Transcription task {task_id} not found", task_id)
                return
            
            log_with_timestamp("INFO", f"✅ [AI SUMMARY] Found transcription task {task_id} for episode {task.episode_id}", task_id)
            
            # 使用DatabaseBackedAISummaryService生成总结
            summary_service = DatabaseBackedAISummaryService(session)
            log_with_timestamp("INFO", f"🤖 [AI SUMMARY] Starting AI summary generation for episode {task.episode_id}", task_id)
            
            # 调用AI总结服务
            summary_result = await summary_service.generate_summary(task.episode_id)

            # 计算字数
            word_count = len(summary_result['summary_content'].split())

            log_with_timestamp("INFO", f"✅ [AI SUMMARY] Successfully generated summary for episode {task.episode_id}", task_id)
            log_with_timestamp("INFO", f"✅ [AI SUMMARY] Summary: {len(summary_result['summary_content'])} chars, {word_count} words", task_id)
            log_with_timestamp("INFO", f"✅ [AI SUMMARY] Processing time: {summary_result['processing_time']:.2f}s, Model: {summary_result['model_name']}", task_id)

            # 🔥 关键修复: 刷新session中的task对象，确保AI摘要立即可见
            # 这是因为 summary_service.generate_summary() 内部使用了独立的db session提交
            # 我们需要刷新当前session中的task对象
            try:
                await session.refresh(task)
                log_with_timestamp("INFO", "🔄 [AI SUMMARY] Refreshed task object from database, summary_content is now available", task_id)
            except Exception as refresh_error:
                log_with_timestamp("WARNING", f"⚠️ [AI SUMMARY] Failed to refresh task: {refresh_error}", task_id)
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            error_msg = str(e)
            log_with_timestamp("ERROR", f"❌ [AI SUMMARY] Failed to generate summary for task {task_id}: {error_msg}", task_id)
            logger.error(f"❌ [AI SUMMARY] Traceback: {error_trace}")
            
            # 不要尝试在同一个会话中再次提交，因为前面可能已经提交或回滚了
            # 这里只记录错误，不修改数据库
            log_with_timestamp("ERROR", f"❌ [AI SUMMARY] Cannot update task {task_id} with error info in current transaction", task_id)
    
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

