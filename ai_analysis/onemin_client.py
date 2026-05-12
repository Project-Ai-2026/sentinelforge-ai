import os
import requests
from dotenv import load_dotenv

load_dotenv()

def ask_1min(prompt: str) -> str:
    api_key = os.getenv("ONE_MIN_API_KEY")

    if not api_key:
        return "ERROR: ONE_MIN_API_KEY is missing from .env"

    url = "https://api.1min.ai/api/chat-with-ai"

    headers = {
        "Content-Type": "application/json",
        "API-KEY": api_key
    }

    payload = {
        "type": "UNIFY_CHAT_WITH_AI",
        "model": "gpt-4o-mini",
        "promptObject": {
            "prompt": prompt
        },
        "temperature": 0.1,
        "max_tokens": 250
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=60
        )

        if response.status_code != 200:
            return f"1min.ai API error {response.status_code}: {response.text}"

        data = response.json()

        try:
            return data["aiRecord"]["aiRecordDetail"]["resultObject"][0]
        except Exception:
            return str(data)

    except Exception as e:
        return f"1min.ai request failed: {str(e)}"
