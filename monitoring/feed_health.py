import logging
import requests
import time

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "SentinelForge-AI/1.0"}


def check_feed_health(name: str, url: str, timeout: int = 10) -> dict:
    start = time.time()

    try:
        response = requests.get(url, timeout=timeout, stream=True, headers=_HEADERS)
        response.close()
        latency = round(time.time() - start, 2)

        if response.status_code == 200:
            status = "UP"
        elif response.status_code == 401:
            status = "AUTH_FAILED"
        elif response.status_code == 403:
            status = "FORBIDDEN"
        elif response.status_code == 429:
            status = "RATE_LIMITED"
        elif response.status_code >= 500:
            status = "PROVIDER_ERROR"
        else:
            status = "DEGRADED"

        return {
            "feed": name,
            "status": status,
            "status_code": response.status_code,
            "latency_seconds": latency
        }

    except requests.exceptions.Timeout:
        latency = round(time.time() - start, 2)
        logger.warning("Feed %s timed out after %.2fs", name, latency)
        return {"feed": name, "status": "TIMEOUT", "latency_seconds": latency}

    except Exception as e:
        logger.error("Feed %s check failed: %s", name, e)
        return {"feed": name, "status": "ERROR", "error": str(e), "latency_seconds": None}
