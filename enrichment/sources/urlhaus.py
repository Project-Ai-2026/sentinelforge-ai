import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
_URL_URL  = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausEnricher(BaseEnricher):
    source = "urlhaus"
    supported_ioc_types = ["domain", "url"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("URLHAUS_API_KEY")
        if not api_key:
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    error="URLHAUS_API_KEY not configured — free key at abuse.ch")
        headers = {"Auth-Key": api_key}
        try:
            if ioc_type == "url":
                resp = requests.post(_URL_URL, data={"url": ioc}, headers=headers, timeout=10)
            else:
                resp = requests.post(_HOST_URL, data={"host": ioc}, headers=headers, timeout=10)

            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            data   = resp.json()
            status = data.get("query_status", "")

            if status == "no_results":
                return EnrichmentResult(source=self.source, verdict="benign", score=5,
                                        raw=data)

            urls = data.get("urls", []) or []
            active = [u for u in urls if u.get("url_status") == "online"]

            if active:
                verdict, score = "malicious", 90
            elif urls:
                verdict, score = "suspicious", 50
            else:
                verdict, score = "benign", 5

            tags = list({u.get("threat", "") for u in urls if u.get("threat")})

            logger.debug("URLhaus: %s → %s", ioc, verdict)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags,
                                    raw={"query_status": status, "url_count": len(urls),
                                         "active_count": len(active)})

        except Exception as e:
            logger.error("URLhaus enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
