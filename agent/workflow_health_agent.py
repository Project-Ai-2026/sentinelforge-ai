from monitoring.feed_health import check_feed_health

def evaluate_health(result: dict) -> dict:
    status = result.get("status")

    if status == "UP":
        severity = "Informational"
        action = "No action required."
    elif status == "RATE_LIMITED":
        severity = "Medium"
        action = "Pause feed, retry later, and use alternate sources."
    elif status == "AUTH_FAILED":
        severity = "High"
        action = "Check API key configuration."
    elif status == "TIMEOUT":
        severity = "Medium"
        action = "Retry feed and monitor for recurring issues."
    elif status == "PROVIDER_ERROR":
        severity = "Medium"
        action = "Provider may be down. Continue with backup feeds."
    else:
        severity = "Low"
        action = "Review manually."

    return {
        "feed": result.get("feed"),
        "status": status,
        "severity": severity,
        "recommended_action": action,
        "details": result
    }

def run_workflow_health_agent() -> list:
    feeds = [
        {"name": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/json/"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}
    ]

    return [
        evaluate_health(check_feed_health(feed["name"], feed["url"]))
        for feed in feeds
    ]
