"""
kubeforge/ai/copilot.py
────────────────────────
The AI Co-Pilot — the brain of KubeForge.

Takes raw ThreatEvents from the scanner, sends them to the LLM,
and enriches each event with:
  • Plain-language summary
  • Risk explanation
  • Step-by-step recommendations
  • Numeric risk score (1–10)

Also produces executive summaries for full scan cycles.

Design principle: if OpenAI is unavailable, the platform keeps running —
we just skip AI enrichment and log a warning. Security never goes down
because the AI is slow or unreachable.
"""

import json
import asyncio
from typing import Optional

from openai import AsyncOpenAI, OpenAIError

from kubeforge.models.threat import ThreatEvent, ScanSummary
from kubeforge.ai.prompts import (
    SYSTEM_PROMPT_HE,
    SYSTEM_PROMPT_EN,
    THREAT_ANALYSIS_TEMPLATE,
    SCAN_SUMMARY_TEMPLATE,
)
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("ai.copilot")


class CoPilot:
    """
    AI Co-Pilot for KubeForge.
    Wraps OpenAI API calls with retry logic and graceful degradation.
    """

    def __init__(self):
        self._client: Optional[AsyncOpenAI] = None
        self._system_prompt = (
            SYSTEM_PROMPT_HE
            if settings.copilot_language == "hebrew"
            else SYSTEM_PROMPT_EN
        )
        self._enabled = bool(settings.openai_api_key)

        if not self._enabled:
            logger.warning("copilot_disabled", reason="OPENAI_API_KEY not set")

    @property
    def client(self) -> AsyncOpenAI:
        """Lazy-init the OpenAI client."""
        if self._client is None:
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    async def _call_llm(self, user_message: str, max_tokens: int = 500) -> Optional[str]:
        """
        Low-level LLM call with error handling.
        Returns the response text or None on failure.
        """
        if not self._enabled:
            return None

        try:
            response = await self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=max_tokens,
                temperature=0.2,  # low temperature = more consistent, factual answers
            )
            return response.choices[0].message.content

        except OpenAIError as exc:
            logger.error("openai_call_failed", error=str(exc))
            return None

    async def analyze_threat(self, event: ThreatEvent) -> ThreatEvent:
        """
        Enrich a ThreatEvent with AI analysis.
        Modifies the event in place and returns it.
        """
        prompt = THREAT_ANALYSIS_TEMPLATE.format(
            title=event.title,
            category=event.category.value,
            severity=event.severity.value,
            location=event.location,
            raw_evidence=event.raw_evidence[:200],  # don't send too much to LLM
            description=event.description,
        )

        raw_response = await self._call_llm(prompt, max_tokens=600)
        if not raw_response:
            return event

        try:
            # Strip markdown code fences if the LLM added them
            clean = raw_response.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(clean)

            event.ai_summary = data.get("summary", "")
            event.ai_recommendation = "\n".join(data.get("recommendations", []))
            event.ai_risk_score = int(data.get("risk_score", 5))

            logger.info(
                "threat_analyzed",
                event_id=event.id,
                risk_score=event.ai_risk_score,
            )

        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("copilot_parse_error", error=str(exc), raw=raw_response[:200])

        return event

    async def analyze_scan(self, summary: ScanSummary) -> str:
        """
        Generate an executive summary for a completed scan cycle.
        Returns the summary text (or an empty string if AI is unavailable).
        """
        prompt = SCAN_SUMMARY_TEMPLATE.format(
            total_files=summary.total_files_scanned,
            total_threats=summary.total_threats_found,
            by_severity=json.dumps(summary.threats_by_severity, ensure_ascii=False),
            duration=round(summary.duration_seconds, 1),
        )

        result = await self._call_llm(prompt, max_tokens=300)
        return result or "AI summary unavailable — check OPENAI_API_KEY configuration."

    async def enrich_summary(self, summary: ScanSummary) -> ScanSummary:
        """
        Enrich all high/critical events in a summary with AI analysis.
        Runs analyses concurrently for speed.
        """
        urgent_events = [e for e in summary.events if e.is_urgent()]

        if urgent_events:
            logger.info("enriching_events", count=len(urgent_events))
            tasks = [self.analyze_threat(event) for event in urgent_events]
            await asyncio.gather(*tasks)

        return summary


# Singleton
copilot = CoPilot()
