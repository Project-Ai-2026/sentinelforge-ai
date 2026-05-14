import base64
import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


def _endpoint(ioc_type: str, ioc: str) -> str:
    if ioc_type == "ip":
        return f"{_BASE}/ip_addresses/{ioc}"
    if ioc_type == "domain":
        return f"{_BASE}/domains/{ioc}"
    if ioc_type in ("md5", "sha1", "sha256"):
        return f"{_BASE}/files/{ioc}"
    # url
    encoded = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
    return f"{_BASE}/urls/{encoded}"


class VirusTotalEnricher(BaseEnricher):
    source = "virustotal"
    supported_ioc_types = ["ip", "domain", "url", "md5", "sha1", "sha256"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    error="VIRUSTOTAL_API_KEY not configured")
        try:
            resp = requests.get(
                _endpoint(ioc_type, ioc),
                headers={"x-apikey": api_key},
                timeout=15
            )

            if resp.status_code == 404:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        raw={"message": "Not found in VirusTotal"})

            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1

            score = round((malicious + suspicious) / total * 100)

            if malicious > 0:
                verdict = "malicious"
            elif suspicious > 0:
                verdict = "suspicious"
            elif total > 1:
                verdict = "benign"
            else:
                verdict = "unknown"

            tags = attrs.get("tags", [])

            logger.debug("VirusTotal: %s → %s (score=%s)", ioc, verdict, score)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags, raw=stats)

        except Exception as e:
            logger.error("VirusTotal enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
