"""
手动测试转录功能
用于验证转录服务的基本功能
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from app.core.config import settings
from app.domains.podcast.transcription import (
    PodcastTranscriptionService,
    AudioDownloader,
    AudioConverter,
    AudioSplitter,
    SiliconFlowTranscriber
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_audio_downloader():
    """测试音频下载器"""
    logger.info("Testing AudioDownloader...")

    # 使用一个测试音频URL（请替换为实际的测试音频URL）
    test_url = "https://www.soundjay.com/misc/sounds/bell-ringing-05.wav"

    async with AudioDownloader() as downloader:
        try:
            # 创建进度回调
            async def progress_callback(progress):
                logger.info(f"Download progress: {progress:.1f}%")

            # 下载文件
            file_path, file_size = await downloader.download_file(
                test_url,
                "./temp/test_download.wav",
                progress_callback
            )

            logger.info(f"Successfully downloaded to {file_path}, size: {file_size} bytes")
            return True
        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            return False


async def test_audio_converter():
    """测试音频转换器"""
    logger.info("Testing AudioConverter...")

    # 假设已有一个WAV文件
    input_path = "./temp/test_download.wav"
    output_path = "./temp/test_converted.mp3"

    if not os.path.exists(input_path):
        logger.error(f"Input file not found: {input_path}")
        return False

    try:
        # 创建进度回调
        async def progress_callback(progress):
            logger.info(f"Conversion progress: {progress:.1f}%")

        # 转换文件
        converted_path, duration = await AudioConverter.convert_to_mp3(
            input_path,
            output_path,
            progress_callback
        )

        logger.info(f"Successfully converted to {converted_path} in {duration:.2f}s")
        return True
    except Exception as e:
        logger.error(f"Conversion failed: {str(e)}")
        return False


async def test_audio_splitter():
    """测试音频分割器"""
    logger.info("Testing AudioSplitter...")

    input_path = "./temp/test_converted.mp3"
    output_dir = "./temp/test_chunks"

    if not os.path.exists(input_path):
        logger.error(f"Input file not found: {input_path}")
        return False

    try:
        # 创建进度回调
        async def progress_callback(progress):
            logger.info(f"Splitting progress: {progress:.1f}%")

        # 分割文件
        chunks = await AudioSplitter.split_mp3(
            input_path,
            output_dir,
            chunk_size_mb=1,  # 1MB chunks for testing
            progress_callback
        )

        logger.info(f"Successfully split into {len(chunks)} chunks")
        for i, chunk in enumerate(chunks):
            logger.info(f"  Chunk {chunk.index}: {chunk.file_path}, {chunk.duration:.2f}s")

        return True
    except Exception as e:
        logger.error(f"Splitting failed: {str(e)}")
        return False


async def test_silicon_flow_transcriber():
    """测试硅基流动转录器"""
    logger.info("Testing SiliconFlowTranscriber...")

    # 检查API密钥
    api_key = getattr(settings, 'TRANSCRIPTION_API_KEY', None)
    if not api_key:
        logger.warning("No TRANSCRIPTION_API_KEY configured, skipping transcription test")
        return True

    # 查找第一个chunk文件
    chunk_dir = "./temp/test_chunks"
    if not os.path.exists(chunk_dir):
        logger.error(f"No chunk directory found: {chunk_dir}")
        return False

    chunk_files = [f for f in os.listdir(chunk_dir) if f.endswith('.mp3')]
    if not chunk_files:
        logger.error("No MP3 chunks found")
        return False

    from app.domains.podcast.transcription import AudioChunk

    # 创建测试chunk
    chunk = AudioChunk(
        index=1,
        file_path=os.path.join(chunk_dir, chunk_files[0]),
        start_time=0.0,
        duration=30.0,
        file_size=os.path.getsize(os.path.join(chunk_dir, chunk_files[0]))
    )

    try:
        async with SiliconFlowTranscriber(
            api_key=api_key,
            api_url=getattr(settings, 'TRANSCRIPTION_API_URL', 'https://api.siliconflow.cn/v1/audio/transcriptions'),
            max_concurrent=1
        ) as transcriber:
            transcript = await transcriber.transcribe_chunk(chunk)
            logger.info(f"Transcription result: {transcript[:100]}...")
            return True
    except Exception as e:
        logger.error(f"Transcription failed: {str(e)}")
        return False


async def main():
    """主测试函数"""
    logger.info("Starting transcription service tests...")

    # 创建临时目录
    os.makedirs("./temp", exist_ok=True)

    # 运行测试
    test_results = {}

    # 1. 测试下载
    test_results['download'] = await test_audio_downloader()

    # 2. 测试转换（如果下载成功）
    if test_results.get('download'):
        test_results['convert'] = await test_audio_converter()
    else:
        test_results['convert'] = False
        logger.warning("Skipping conversion test due to download failure")

    # 3. 测试分割（如果转换成功）
    if test_results.get('convert'):
        test_results['split'] = await test_audio_splitter()
    else:
        test_results['split'] = False
        logger.warning("Skipping splitting test due to conversion failure")

    # 4. 测试转录（如果分割成功）
    if test_results.get('split'):
        test_results['transcribe'] = await test_silicon_flow_transcriber()
    else:
        test_results['transcribe'] = False
        logger.warning("Skipping transcription test due to splitting failure")

    # 输出测试结果
    logger.info("\n=== Test Results ===")
    for test_name, result in test_results.items():
        status = "PASS" if result else "FAIL"
        logger.info(f"{test_name.title()}: {status}")

    # 清理临时文件（可选）
    # import shutil
    # if os.path.exists("./temp"):
    #     shutil.rmtree("./temp")
    #     logger.info("Cleaned up temporary files")


if __name__ == "__main__":
    asyncio.run(main())