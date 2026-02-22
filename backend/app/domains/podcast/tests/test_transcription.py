"""
转录功能测试
"""

import os
import tempfile
from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import HTTPException, ValidationError
from app.domains.podcast.models import (
    TranscriptionStatus,
)
from app.domains.podcast.transcription import (
    AudioChunk,
    AudioConverter,
    AudioDownloader,
    AudioSplitter,
    PodcastTranscriptionService,
    SiliconFlowTranscriber,
)


class TestAudioDownloader:
    """音频下载器测试"""

    @pytest.mark.asyncio
    async def test_download_success(self):
        """测试成功下载"""
        # 模拟下载内容
        test_content = b"fake audio content"

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session

            # 模拟响应
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'content-length': str(len(test_content))}

            # 模拟内容流
            async def content_iter():
                yield test_content

            mock_response.content.iter_chunked.return_value = content_iter()
            mock_session.get.return_value.__aenter__.return_value = mock_response

            # 测试下载
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            try:
                downloader = AudioDownloader()
                async with downloader:
                    file_path, file_size = await downloader.download_file(
                        "http://example.com/audio.mp3",
                        tmp_path
                    )

                assert file_path == tmp_path
                assert file_size == len(test_content)
                assert os.path.exists(tmp_path)

                with open(tmp_path, 'rb') as f:
                    assert f.read() == test_content
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_download_http_error(self):
        """测试HTTP错误"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session

            mock_response = AsyncMock()
            mock_response.status = 404
            mock_session.get.return_value.__aenter__.return_value = mock_response

            downloader = AudioDownloader()
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            try:
                async with downloader:
                    with pytest.raises(HTTPException) as exc_info:
                        await downloader.download_file(
                            "http://example.com/audio.mp3",
                            tmp_path
                        )

                assert exc_info.value.status_code == 400
                assert "Failed to download audio file" in str(exc_info.value.detail)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)


class TestAudioConverter:
    """音频转换器测试"""

    @pytest.mark.asyncio
    async def test_convert_to_mp3(self):
        """测试MP3转换"""
        # 创建临时输入文件
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as input_file:
            input_file.write(b"fake wav content")
            input_path = input_file.name

        with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as output_file:
            output_path = output_file.name

        try:
            # 模拟FFmpeg进程
            with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (b"", b"")
                mock_process.returncode = 0
                mock_subprocess.return_value = mock_process

                # 模拟probe
                with patch('ffmpeg.probe') as mock_probe:
                    mock_probe.return_value = {
                        'streams': [{'duration': '100.0'}]
                    }

                    _, duration = await AudioConverter.convert_to_mp3(
                        input_path,
                        output_path
                    )

                    assert duration >= 0
                    assert mock_subprocess.called
        finally:
            for path in [input_path, output_path]:
                if os.path.exists(path):
                    os.remove(path)


class TestAudioSplitter:
    """音频分割器测试"""

    @pytest.mark.asyncio
    async def test_split_mp3(self):
        """测试MP3分割"""
        # 创建临时文件
        test_content = b"fake mp3 content" * 1000  # 创建较大的文件
        with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as input_file:
            input_file.write(test_content)
            input_path = input_file.name

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # 模拟FFmpeg probe和split
                with patch('ffmpeg.probe') as mock_probe:
                    mock_probe.return_value = {
                        'streams': [{'duration': '200.0'}]
                    }

                    with patch('ffmpeg.run'):
                        chunks = await AudioSplitter.split_mp3(
                            input_path,
                            temp_dir,
                            chunk_size_mb=1  # 1MB chunks
                        )

                        # 应该有多个chunks
                        assert len(chunks) > 1

                        # 验证chunk属性
                        for i, chunk in enumerate(chunks):
                            assert chunk.index == i + 1
                            assert chunk.start_time >= 0
                            assert chunk.duration > 0
                            assert os.path.exists(chunk.file_path)
            finally:
                if os.path.exists(input_path):
                    os.remove(input_path)


class TestSiliconFlowTranscriber:
    """硅基流动转录器测试"""

    @pytest.mark.asyncio
    async def test_transcribe_chunk(self):
        """测试单个chunk转录"""
        # 创建测试chunk
        chunk = AudioChunk(
            index=1,
            file_path="/tmp/test_chunk.mp3",
            start_time=0.0,
            duration=30.0,
            file_size=1024
        )

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session

            # 模拟API响应
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"text": "这是转录测试文本"}
            mock_session.post.return_value.__aenter__.return_value = mock_response

            transcriber = SiliconFlowTranscriber(
                api_key="test_key",
                api_url="https://api.test.com/transcriptions"
            )

            async with transcriber:
                transcript = await transcriber.transcribe_chunk(chunk)
                assert transcript == "这是转录测试文本"


class TestPodcastTranscriptionService:
    """转录服务测试"""

    @pytest.fixture
    async def mock_db(self):
        """模拟数据库会话"""
        return AsyncMock(spec=AsyncSession)

    @pytest.fixture
    def mock_settings(self):
        """模拟设置"""
        settings_mock = Mock()
        settings_mock.TRANSCRIPTION_API_KEY = "test_api_key"
        settings_mock.TRANSCRIPTION_API_URL = "https://api.test.com"
        settings_mock.TRANSCRIPTION_CHUNK_SIZE_MB = 10
        settings_mock.TRANSCRIPTION_MAX_THREADS = 4
        settings_mock.TRANSCRIPTION_TEMP_DIR = "/tmp/transcription"
        settings_mock.TRANSCRIPTION_STORAGE_DIR = "/storage/podcasts"
        return settings_mock

    @pytest.mark.asyncio
    async def test_start_transcription_new_task(self, mock_db):
        """测试启动新转录任务"""
        # 模拟播客单集
        mock_episode = Mock()
        mock_episode.id = 1
        mock_episode.audio_url = "http://example.com/audio.mp3"

        # 模拟数据库查询
        mock_db.scalar = AsyncMock()
        mock_db.scalar.side_effect = [
            None,  # 没有现有任务
            mock_episode  # 返回播客单集
        ]

        # 模拟数据库添加
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        # 模拟执行转录任务（直接patch以避免实际执行）
        with patch('asyncio.create_task'):
            service = PodcastTranscriptionService(mock_db)

            with patch.object(service, '_execute_transcription'):
                task = await service.start_transcription(episode_id=1)

                assert task.episode_id == 1
                assert task.original_audio_url == "http://example.com/audio.mp3"
                assert task.status == TranscriptionStatus.PENDING

    @pytest.mark.asyncio
    async def test_start_transcription_existing_task(self, mock_db):
        """测试启动已存在转录任务"""
        # 模拟现有任务
        existing_task = Mock()
        existing_task.status = TranscriptionStatus.PENDING

        mock_db.scalar = AsyncMock(return_value=existing_task)

        service = PodcastTranscriptionService(mock_db)

        with pytest.raises(ValidationError) as exc_info:
            await service.start_transcription(episode_id=1)

        assert "already exists" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_transcription_status(self, mock_db):
        """测试获取转录状态"""
        # 模拟任务
        mock_task = Mock()
        mock_task.id = 1
        mock_task.episode_id = 1
        mock_task.status = TranscriptionStatus.COMPLETED
        mock_task.progress_percentage = 100.0

        mock_db.scalar = AsyncMock(return_value=mock_task)

        service = PodcastTranscriptionService(mock_db)
        task = await service.get_transcription_status(task_id=1)

        assert task.id == 1
        assert task.status == TranscriptionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_get_episode_transcription(self, mock_db):
        """测试获取播客单集转录"""
        # 模拟任务
        mock_task = Mock()
        mock_task.episode_id = 1
        mock_task.status = TranscriptionStatus.COMPLETED

        mock_db.scalar = AsyncMock(return_value=mock_task)

        service = PodcastTranscriptionService(mock_db)
        task = await service.get_episode_transcription(episode_id=1)

        assert task.episode_id == 1
        assert task.status == TranscriptionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_cancel_transcription(self, mock_db):
        """测试取消转录任务"""
        # 模拟进行中的任务
        mock_task = Mock()
        mock_task.status = TranscriptionStatus.TRANSCRIBING
        mock_task.progress_percentage = 50.0

        mock_db.scalar = AsyncMock(return_value=mock_task)

        service = PodcastTranscriptionService(mock_db)

        # Patch update_task_progress to avoid actual DB update
        with patch.object(service, 'update_task_progress'):
            success = await service.cancel_transcription(task_id=1)
            assert success

    @pytest.mark.asyncio
    async def test_cancel_completed_transcription(self, mock_db):
        """测试取消已完成的转录任务"""
        # 模拟已完成的任务
        mock_task = Mock()
        mock_task.status = TranscriptionStatus.COMPLETED

        mock_db.scalar = AsyncMock(return_value=mock_task)

        service = PodcastTranscriptionService(mock_db)
        success = await service.cancel_transcription(task_id=1)
        assert not success

    def test_get_episode_storage_path(self, mock_db):
        """测试获取播客单集存储路径"""
        # 模拟播客单集
        mock_episode = Mock()
        mock_episode.subscription.title = "Test Podcast & More"
        mock_episode.title = "Episode 1: Introduction"

        service = PodcastTranscriptionService(mock_db)
        path = service._get_episode_storage_path(mock_episode)

        expected = "/storage/podcasts/Test_Podcast___More/Episode_1__Introduction"
        assert path == expected

    def test_sanitize_filename(self, mock_db):
        """测试文件名清理"""
        service = PodcastTranscriptionService(mock_db)

        # 测试特殊字符
        filename = service._sanitize_filename('Test:File/Name<>|?*')
        assert filename == "TestFileName"

        # 测试长度限制
        long_name = "a" * 200
        assert len(service._sanitize_filename(long_name)) <= 100
