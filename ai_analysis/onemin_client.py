import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_API_URL = "https://api.1min.ai/api/chat-with-ai"
_MODEL   = "gpt-4o-mini"


def ask_1min(prompt: str) -> str:
    api_key = os.getenv("ONE_MIN_API_KEY")

    if not api_key:
        logger.error("ONE_MIN_API_KEY is not set")
        return "ERROR: ONE_MIN_API_KEY is missing from .env"

    headers = {
        "Content-Type": "application/json",
        "API-KEY": api_key
    }

    payload = {
        "type": "UNIFY_CHAT_WITH_AI",
        "model": _MODEL,
        "promptObject": {"prompt": prompt},
        "temperature": 0.1,
        "max_tokens": 250
    }

    try:
        response = requests.post(_API_URL, headers=headers, json=payload, timeout=60)

        if response.status_code != 200:
            logger.warning("1min.ai returned status %s", response.status_code)
            return f"1min.ai API error {response.status_code}: {response.text}"

        data = response.json()

        try:
            return data["aiRecord"]["aiRecordDetail"]["resultObject"][0]
        except (KeyError, IndexError, TypeError) as parse_err:
            logger.error("Unexpected 1min.ai response structure: %s | raw: %s", parse_err, data)
            return f"1min.ai response parse error: {parse_err}"

    except Exception as e:
        logger.error("1min.ai request failed: %s", e)
        return f"1min.ai request failed: {e}"
