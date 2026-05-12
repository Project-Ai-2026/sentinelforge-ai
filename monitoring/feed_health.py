import requests
import time

def check_feed_health(name: str, url: str, timeout: int = 10) -> dict:
    start = time.time()

    try:
        response = requests.get(url, timeout=timeout)
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
        return {"feed": name, "status": "TIMEOUT"}

    except Exception as e:
        return {"feed": name, "status": "ERROR", "error": str(e)}
