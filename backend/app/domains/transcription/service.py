import asyncio
import logging
import os
import tempfile
from pathlib import Path
from uuid import UUID

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.domains.podcast.models import ProcessingStatus
from app.domains.podcast.repository import EpisodeRepository
from app.domains.transcription.models import Transcript
from app.domains.transcription.repository import TranscriptRepository

logger = logging.getLogger(__name__)
settings = get_settings()


class TranscriptionService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = TranscriptRepository(session)
        self.episode_repo = EpisodeRepository(session)

    async def download_audio(self, url: str, dest_dir: str | None = None) -> str:
        """Download audio file from URL to a local path.

        Args:
            url: The audio file URL.
            dest_dir: Destination directory. Defaults to temp dir.

        Returns:
            Local file path of the downloaded audio.
        """
        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(prefix="poddigest_")

        filename = url.split("/")[-1].split("?")[0] or "audio.mp3"
        dest_path = os.path.join(dest_dir, filename)

        async with aiohttp.ClientSession() as http_session:
            async with http_session.get(url, timeout=aiohttp.ClientTimeout(total=300)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Failed to download audio: HTTP {resp.status}")
                with open(dest_path, "wb") as f:
                    async for chunk in resp.content.iter_chunked(8192):
                        f.write(chunk)

        logger.info(f"Downloaded audio to {dest_path}")
        return dest_path

    async def chunk_audio(self, audio_path: str, chunk_duration: int = 600) -> list[str]:
        """Split audio file into chunks using ffmpeg.

        Args:
            audio_path: Path to the audio file.
            chunk_duration: Duration of each chunk in seconds (default 10 min).

        Returns:
            List of chunk file paths.
        """
        output_dir = tempfile.mkdtemp(prefix="poddigest_chunks_")
        output_pattern = os.path.join(output_dir, "chunk_%04d.mp3")

        cmd = [
            "ffmpeg", "-i", audio_path,
            "-f", "segment",
            "-segment_time", str(chunk_duration),
            "-c", "copy",
            "-ar", "16000",
            "-ac", "1",
            output_pattern,
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"ffmpeg chunking failed: {stderr.decode()}")
            raise RuntimeError(f"ffmpeg chunking failed: {stderr.decode()}")

        chunks = sorted([
            os.path.join(output_dir, f)
            for f in os.listdir(output_dir)
            if f.startswith("chunk_")
        ])
        logger.info(f"Split audio into {len(chunks)} chunks")
        return chunks

    async def transcribe(
        self,
        audio_path: str,
        provider_config: dict | None = None,
        language: str | None = None,
    ) -> dict:
        """Transcribe audio file using OpenAI Whisper API.

        Args:
            audio_path: Path to the audio file.
            provider_config: Provider configuration with api_key, base_url.
            language: Language hint for transcription.

        Returns:
            Dict with 'text', 'language', 'duration', 'word_count'.
        """
        import json

        base_url = (provider_config or {}).get("base_url", "https://api.openai.com/v1")
        api_key = (provider_config or {}).get("api_key", "")
        model = (provider_config or {}).get("model", settings.WHISPER_MODEL)

        url = f"{base_url.rstrip('/')}/audio/transcriptions"

        # Prepare multipart form data
        filename = os.path.basename(audio_path)
        data = aiohttp.FormData()
        data.add_field("file", open(audio_path, "rb"), filename=filename, content_type="audio/mpeg")
        data.add_field("model", model)
        if language:
            data.add_field("language", language)
        data.add_field("response_format", "verbose_json")

        headers = {"Authorization": f"Bearer {api_key}"}

        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                url, data=data, headers=headers,
                timeout=aiohttp.ClientTimeout(total=600),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"Whisper API error ({resp.status}): {error_text}")
                result = await resp.json()

        text = result.get("text", "")
        word_count = len(text.split()) if text else 0

        return {
            "text": text,
            "language": result.get("language", language),
            "duration": result.get("duration"),
            "word_count": word_count,
        }

    async def transcribe_episode(self, episode_id: UUID) -> Transcript:
        """Full pipeline: download audio, chunk, transcribe, save transcript.

        Args:
            episode_id: The episode ID to transcribe.

        Returns:
            The Transcript record.
        """
        episode = await self.episode_repo.get(episode_id)
        if episode is None:
            raise ValueError(f"Episode {episode_id} not found")

        if not episode.audio_url:
            raise ValueError(f"Episode {episode_id} has no audio URL")

        # Get or create transcript record
        transcript = await self.repo.get_by_episode(episode_id)
        if transcript is None:
            transcript = await self.repo.create({
                "episode_id": episode_id,
                "status": ProcessingStatus.PROCESSING,
            })
        else:
            await self.repo.update(transcript.id, {"status": ProcessingStatus.PROCESSING})

        # Update episode status
        await self.episode_repo.update_status(episode_id, transcript_status=ProcessingStatus.PROCESSING)

        try:
            # Get provider config from settings domain
            provider_config = await self._get_provider_config()

            # Download audio
            audio_path = await self.download_audio(episode.audio_url)

            # Chunk audio
            chunks = await self.chunk_audio(audio_path)

            # Transcribe each chunk and combine
            full_text_parts = []
            total_duration = 0

            for chunk_path in chunks:
                result = await self.transcribe(chunk_path, provider_config)
                if result.get("text"):
                    full_text_parts.append(result["text"])
                if result.get("duration"):
                    total_duration += result["duration"]

            full_text = "\n".join(full_text_parts)
            word_count = len(full_text.split()) if full_text else 0

            # Update transcript
            transcript = await self.repo.update(transcript.id, {
                "content": full_text,
                "language": result.get("language"),
                "duration": total_duration or None,
                "word_count": word_count,
                "model_used": (provider_config or {}).get("model", settings.WHISPER_MODEL),
                "status": ProcessingStatus.COMPLETED,
            })

            # Update episode status
            await self.episode_repo.update_status(episode_id, transcript_status=ProcessingStatus.COMPLETED)

            # Cleanup temp files
            try:
                import shutil
                shutil.rmtree(os.path.dirname(audio_path), ignore_errors=True)
                if chunks:
                    shutil.rmtree(os.path.dirname(chunks[0]), ignore_errors=True)
            except Exception:
                pass

            await self.session.flush()
            return transcript

        except Exception as e:
            logger.error(f"Transcription failed for episode {episode_id}: {e}")
            await self.repo.update(transcript.id, {"status": ProcessingStatus.FAILED})
            await self.episode_repo.update_status(episode_id, transcript_status=ProcessingStatus.FAILED)
            await self.session.flush()
            raise

    async def _get_provider_config(self) -> dict | None:
        """Get the active AI provider configuration for transcription."""
        from app.domains.settings.repository import SettingsRepository

        settings_repo = SettingsRepository(self.session)
        provider = await settings_repo.get_active_provider()
        if provider is None:
            return None

        from app.core.security import decrypt_api_key
        api_key = decrypt_api_key(provider.encrypted_api_key)

        # Get default model config
        model_config = await settings_repo.get_default_model(provider.id)

        return {
            "base_url": provider.base_url,
            "api_key": api_key,
            "model": model_config.model_name if model_config else settings.WHISPER_MODEL,
        }

    async def get_transcript(self, episode_id: UUID) -> Transcript | None:
        """Get transcript for an episode."""
        return await self.repo.get_by_episode(episode_id)
