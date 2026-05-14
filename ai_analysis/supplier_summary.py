import json
import logging

from ai_analysis.ollama_client import ask_ollama

logger = logging.getLogger(__name__)

_MAX_FIELD_LEN = 512


def _sanitize_profile(profile: dict) -> dict:
    sanitized = {}
    for key, value in profile.items():
        if isinstance(value, str):
            sanitized[key] = value[:_MAX_FIELD_LEN].replace("\n", " ").replace("\r", " ")
        else:
            sanitized[key] = value
    return sanitized


def generate_supplier_summary(profile: dict, resilience: dict) -> dict:
    safe_profile = _sanitize_profile(profile)

    prompt = f"""Analyze this supplier cyber resilience profile.

Supplier Profile:
{json.dumps(safe_profile, indent=2)}

Resilience Assessment:
{json.dumps(resilience, indent=2)}

Return:
- Overall cyber resilience assessment
- Key supply-chain risks
- Recommended mitigation priorities

Keep response under 200 words."""

    logger.debug("Generating supplier summary for: %s", safe_profile.get("supplier_name", "unknown"))
    summary = ask_ollama(prompt)

    return {"ai_supplier_summary": summary}
