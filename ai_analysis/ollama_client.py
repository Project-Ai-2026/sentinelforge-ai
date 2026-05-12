import os
import ollama
from dotenv import load_dotenv

from ai_analysis.onemin_client import ask_1min

load_dotenv()

def ask_ollama_local(prompt: str, model: str = "qwen:latest") -> str:
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

    return response["message"]["content"]


def ask_ollama(prompt: str) -> str:
    provider = os.getenv("AI_PROVIDER", "ollama").lower()

    if provider == "1min":
        return ask_1min(prompt)

    return ask_ollama_local(prompt)
