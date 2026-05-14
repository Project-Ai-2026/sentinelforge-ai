import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1/indicators"

_TYPE_MAP = {
    "ip":     "IPv4",
    "domain": "domain",
    "url":    "url",
    "md5":    "file",
    "sha1":   "file",
    "sha256": "file",
}


class AlienVaultEnricher(BaseEnricher):
    source = "alienvault"
    supported_ioc_types = ["ip", "domain", "url", "md5", "sha1", "sha256"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    error="OTX_API_KEY not configured")
        try:
            otx_type = _TYPE_MAP.get(ioc_type, "IPv4")
            resp = requests.get(
                f"{_BASE}/{otx_type}/{ioc}/general",
                headers={"X-OTX-API-KEY": api_key},
                timeout=15
            )

            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            data         = resp.json()
            pulse_count  = data.get("pulse_info", {}).get("count", 0)
            reputation   = data.get("reputation", 0)

            score = min(pulse_count * 10, 100)

            if pulse_count >= 5 or reputation < -1:
                verdict = "malicious"
            elif pulse_count > 0:
                verdict = "suspicious"
            else:
                verdict = "benign"

            tags = []
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                if pulse.get("name"):
                    tags.append(pulse["name"])

            logger.debug("AlienVault OTX: %s → %s (pulses=%s)", ioc, verdict, pulse_count)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags,
                                    raw={"pulse_count": pulse_count, "reputation": reputation})

        except Exception as e:
            logger.error("AlienVault enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
