from ai_analysis.ollama_client import ask_ollama


def generate_mitre_mapping(ioc: str, ioc_type: str, ai_summary: str) -> dict:
    prompt = f"""
Map this cyber finding to likely MITRE ATT&CK tactics and techniques.

IOC: {ioc}
IOC Type: {ioc_type}

AI Summary:
{ai_summary}

Return:
- Likely MITRE tactics
- Likely MITRE techniques
- Why the mapping may apply
- Confidence level
- Recommended telemetry to validate

Do not invent a threat actor.
Keep response under 200 words.
"""

    mapping = ask_ollama(prompt)

    return {
        "mitre_mapping": mapping
    }
