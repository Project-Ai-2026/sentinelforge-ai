import logging

from monitoring.feed_health import check_feed_health

logger = logging.getLogger(__name__)

_FEEDS = [
    {"name": "URLhaus",  "url": "https://urlhaus.abuse.ch/downloads/json/"},
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
]

_SEVERITY_MAP = {
    "UP":             ("Informational", "No action required."),
    "RATE_LIMITED":   ("Medium",        "Pause feed, retry later, and use alternate sources."),
    "AUTH_FAILED":    ("High",          "Check API key configuration."),
    "FORBIDDEN":      ("High",          "Access denied. Verify credentials or IP allowlist."),
    "TIMEOUT":        ("Medium",        "Retry feed and monitor for recurring issues."),
    "PROVIDER_ERROR": ("Medium",        "Provider may be down. Continue with backup feeds."),
    "DEGRADED":       ("Medium",        "Feed returned an unexpected status. Monitor closely."),
    "ERROR":          ("High",          "Feed check failed with an exception. Investigate immediately."),
}


def evaluate_health(result: dict) -> dict:
    status = result.get("status", "UNKNOWN")
    severity, action = _SEVERITY_MAP.get(status, ("Low", "Review manually."))

    return {
        "feed": result.get("feed"),
        "status": status,
        "severity": severity,
        "recommended_action": action,
        "details": result
    }


def run_workflow_health_agent() -> list:
    results = []
    for feed in _FEEDS:
        try:
            raw = check_feed_health(feed["name"], feed["url"])
            results.append(evaluate_health(raw))
        except Exception as e:
            logger.error("Unexpected error checking feed %s: %s", feed["name"], e)
            results.append(evaluate_health({
                "feed": feed["name"],
                "status": "ERROR",
                "error": str(e)
            }))
    return results
