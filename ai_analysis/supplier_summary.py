import json

from ai_analysis.ollama_client import ask_ollama


def generate_supplier_summary(profile: dict,
                              resilience: dict) -> dict:

    prompt = f"""
Analyze this supplier cyber resilience profile.

Supplier Profile:
{json.dumps(profile, indent=2)}

Resilience Assessment:
{json.dumps(resilience, indent=2)}

Return:
- Overall cyber resilience assessment
- Key supply-chain risks
- Recommended mitigation priorities

Keep response under 200 words.
"""

    summary = ask_ollama(prompt)

    return {
        "ai_supplier_summary": summary
    }
