import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseEnricher(BaseEnricher):
    source = "greynoise"
    supported_ioc_types = ["ip"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("GREYNOISE_API_KEY")
        headers = {"Accept": "application/json"}
        if api_key:
            headers["key"] = api_key
        try:
            resp = requests.get(
                _URL.format(ip=ioc),
                headers=headers,
                timeout=10
            )

            if resp.status_code == 404:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        raw={"message": "IP not found in GreyNoise"})

            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            data           = resp.json()
            classification = data.get("classification", "unknown").lower()
            noise          = data.get("noise", False)
            riot           = data.get("riot", False)

            if classification == "malicious":
                verdict, score = "malicious", 80
            elif classification == "benign" or riot:
                verdict, score = "benign", 10
            elif noise:
                verdict, score = "suspicious", 50
            else:
                verdict, score = "unknown", None

            tags = []
            if data.get("name"):
                tags.append(data["name"])
            if noise:
                tags.append("internet-scanner")
            if riot:
                tags.append("riot-benign")

            logger.debug("GreyNoise: %s → %s", ioc, verdict)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags, raw=data)

        except Exception as e:
            logger.error("GreyNoise enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
