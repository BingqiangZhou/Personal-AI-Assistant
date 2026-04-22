import json
import logging
from uuid import UUID

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.domains.podcast.models import ProcessingStatus
from app.domains.podcast.repository import EpisodeRepository
from app.domains.summary.models import Summary
from app.domains.summary.repository import SummaryRepository

logger = logging.getLogger(__name__)
settings = get_settings()

SUMMARY_PROMPT = """You are an expert podcast summarizer. Given the following transcript of a podcast episode, generate a comprehensive summary.

Please provide:
1. A detailed summary of the episode content
2. Key topics discussed (as a JSON array of strings)
3. Key highlights and takeaways (as a JSON array of strings)

Format your response as a JSON object with keys: "summary", "key_topics", "highlights"

Transcript:
{transcript}
"""


class SummaryService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = SummaryRepository(session)
        self.episode_repo = EpisodeRepository(session)

    async def generate_summary(
        self,
        transcript: str,
        provider_config: dict | None = None,
    ) -> dict:
        """Generate a summary from transcript text using configured LLM.

        Args:
            transcript: The transcript text.
            provider_config: Provider configuration with api_key, base_url, model.

        Returns:
            Dict with 'content', 'key_topics', 'highlights'.
        """
        base_url = (provider_config or {}).get("base_url", "https://api.openai.com/v1")
        api_key = (provider_config or {}).get("api_key", "")
        model = (provider_config or {}).get("model", "gpt-4o-mini")
        temperature = (provider_config or {}).get("temperature", 0.3)
        max_tokens = (provider_config or {}).get("max_tokens", 4096)

        url = f"{base_url.rstrip('/')}/chat/completions"

        prompt = SUMMARY_PROMPT.format(transcript=transcript)

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a helpful podcast summarization assistant. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                url, json=payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"LLM API error ({resp.status}): {error_text}")
                result = await resp.json()

        content = result["choices"][0]["message"]["content"]

        # Try to parse as JSON
        try:
            parsed = json.loads(content)
            summary_text = parsed.get("summary", content)
            key_topics = parsed.get("key_topics", [])
            highlights = parsed.get("highlights", [])
        except (json.JSONDecodeError, AttributeError):
            summary_text = content
            key_topics = []
            highlights = []

        return {
            "content": summary_text,
            "key_topics": key_topics,
            "highlights": highlights,
        }

    async def summarize_episode(self, episode_id: UUID) -> Summary:
        """Full pipeline: get transcript, generate summary, save.

        Args:
            episode_id: The episode ID to summarize.

        Returns:
            The Summary record.
        """
        episode = await self.episode_repo.get(episode_id)
        if episode is None:
            raise ValueError(f"Episode {episode_id} not found")

        # Get transcript
        from app.domains.transcription.repository import TranscriptRepository

        transcript_repo = TranscriptRepository(self.session)
        transcript = await transcript_repo.get_by_episode(episode_id)
        if transcript is None or not transcript.content:
            raise ValueError(f"No transcript available for episode {episode_id}")

        # Get or create summary record
        summary = await self.repo.get_by_episode(episode_id)
        if summary is None:
            summary = await self.repo.create({
                "episode_id": episode_id,
                "status": ProcessingStatus.PROCESSING,
            })
        else:
            await self.repo.update(summary.id, {"status": ProcessingStatus.PROCESSING})

        # Update episode status
        await self.episode_repo.update_status(episode_id, summary_status=ProcessingStatus.PROCESSING)

        try:
            # Get provider config
            provider_config = await self._get_provider_config()

            # Generate summary
            result = await self.generate_summary(transcript.content, provider_config)

            # Update summary
            summary = await self.repo.update(summary.id, {
                "content": result["content"],
                "key_topics": result["key_topics"],
                "highlights": result["highlights"],
                "model_used": (provider_config or {}).get("model"),
                "provider": (provider_config or {}).get("provider_name"),
                "status": ProcessingStatus.COMPLETED,
            })

            # Update episode status
            await self.episode_repo.update_status(episode_id, summary_status=ProcessingStatus.COMPLETED)

            await self.session.flush()
            return summary

        except Exception as e:
            logger.error(f"Summarization failed for episode {episode_id}: {e}")
            await self.repo.update(summary.id, {"status": ProcessingStatus.FAILED})
            await self.episode_repo.update_status(episode_id, summary_status=ProcessingStatus.FAILED)
            await self.session.flush()
            raise

    async def _get_provider_config(self) -> dict | None:
        """Get the active AI provider configuration for summarization."""
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
            "model": model_config.model_name if model_config else "gpt-4o-mini",
            "temperature": model_config.temperature if model_config else 0.3,
            "max_tokens": model_config.max_tokens if model_config else 4096,
            "provider_name": provider.name,
        }

    async def get_summary(self, episode_id: UUID) -> Summary | None:
        """Get summary for an episode."""
        return await self.repo.get_by_episode(episode_id)
