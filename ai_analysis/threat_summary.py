from ai_analysis.ollama_client import ask_ollama

def generate_ioc_summary(ioc: str, ioc_type: str) -> dict:
    prompt = f"""
Analyze this IOC briefly.

IOC: {ioc}
Type: {ioc_type}

Return:
- Threat relevance
- Key telemetry to review
- Next investigation step

Keep response under 150 words.
"""

    summary = ask_ollama(prompt)

    return {
        "ai_summary": summary
    }
