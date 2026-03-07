"""Handlers for summary generation tasks."""

from __future__ import annotations

import logging

from app.domains.podcast.services.summary_workflow_service import SummaryWorkflowService


logger = logging.getLogger(__name__)


async def generate_pending_summaries_handler(session) -> dict:
    """Generate summaries for pending episodes."""
    workflow = SummaryWorkflowService(session)
    return await workflow.generate_pending_summaries_run()
