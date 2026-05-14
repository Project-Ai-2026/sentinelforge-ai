import logging

from ai_analysis.ollama_client import ask_ollama

logger = logging.getLogger(__name__)

_MAX_IOC_LEN = 2048


def _sanitize(value: str) -> str:
    return value[:_MAX_IOC_LEN].replace("\n", " ").replace("\r", " ")


def generate_ioc_summary(ioc: str, ioc_type: str) -> dict:
    safe_ioc      = _sanitize(ioc)
    safe_ioc_type = _sanitize(ioc_type)

    prompt = f"""Analyze this IOC briefly.

IOC: {safe_ioc}
Type: {safe_ioc_type}

Return:
- Threat relevance
- Key telemetry to review
- Next investigation step

Keep response under 150 words."""

    logger.debug("Generating IOC summary for %s (%s)", safe_ioc, safe_ioc_type)
    summary = ask_ollama(prompt)

    return {"ai_summary": summary}
