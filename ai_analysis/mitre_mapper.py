import logging

from ai_analysis.ollama_client import ask_ollama

logger = logging.getLogger(__name__)

_MAX_LEN = 2048


def _sanitize(value: str) -> str:
    return value[:_MAX_LEN].replace("\n", " ").replace("\r", " ")


def generate_mitre_mapping(ioc: str, ioc_type: str, ai_summary: str) -> dict:
    safe_ioc      = _sanitize(ioc)
    safe_ioc_type = _sanitize(ioc_type)
    safe_summary  = _sanitize(ai_summary)

    prompt = f"""Map this cyber finding to likely MITRE ATT&CK tactics and techniques.

IOC: {safe_ioc}
IOC Type: {safe_ioc_type}

AI Summary:
{safe_summary}

Return:
- Likely MITRE tactics
- Likely MITRE techniques
- Why the mapping may apply
- Confidence level
- Recommended telemetry to validate

Do not invent a threat actor.
Keep response under 200 words."""

    logger.debug("Generating MITRE mapping for %s (%s)", safe_ioc, safe_ioc_type)
    mapping = ask_ollama(prompt)

    return {"mitre_mapping": mapping}
