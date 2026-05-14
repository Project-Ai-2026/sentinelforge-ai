import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher(BaseEnricher):
    source = "abuseipdb"
    supported_ioc_types = ["ip"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    error="ABUSEIPDB_API_KEY not configured")
        try:
            resp = requests.get(
                _URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ioc, "maxAgeInDays": 90},
                timeout=10
            )
            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            data  = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score >= 75:
                verdict = "malicious"
            elif score >= 25:
                verdict = "suspicious"
            else:
                verdict = "benign"

            tags = []
            if data.get("usageType"):
                tags.append(data["usageType"])
            if data.get("isp"):
                tags.append(data["isp"])
            if data.get("countryCode"):
                tags.append(f"country:{data['countryCode']}")

            logger.debug("AbuseIPDB: %s → %s (score=%s)", ioc, verdict, score)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags, raw=data)

        except Exception as e:
            logger.error("AbuseIPDB enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
