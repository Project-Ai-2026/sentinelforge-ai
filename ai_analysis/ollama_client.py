import logging
import os

import ollama
from dotenv import load_dotenv

from ai_analysis.onemin_client import ask_1min

load_dotenv()

logger = logging.getLogger(__name__)


def ask_ollama_local(prompt: str, model: str = "qwen:latest") -> str:
    try:
        response = ollama.chat(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cyber threat intelligence and supply chain resilience analyst."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        content = response.get("message", {}).get("content", "")
        if not content:
            logger.warning("Ollama returned an empty response for model %s", model)
            return "No response from local AI model."
        return content
    except Exception as e:
        logger.error("Ollama request failed: %s", e)
        return f"Local AI request failed: {e}"


def ask_ollama(prompt: str) -> str:
    provider = os.getenv("AI_PROVIDER", "ollama").lower()

    if provider == "1min":
        return ask_1min(prompt)

    return ask_ollama_local(prompt)
