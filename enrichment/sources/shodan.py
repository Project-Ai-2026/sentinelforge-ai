import logging
import os

import requests

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)

_URL = "https://api.shodan.io/shodan/host/{ip}"


class ShodanEnricher(BaseEnricher):
    source = "shodan"
    supported_ioc_types = ["ip"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    error="SHODAN_API_KEY not configured")
        try:
            resp = requests.get(
                _URL.format(ip=ioc),
                params={"key": api_key},
                timeout=15
            )

            if resp.status_code == 404:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        raw={"message": "IP not indexed by Shodan"})

            if resp.status_code != 200:
                return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                        error=f"HTTP {resp.status_code}")

            data  = resp.json()
            ports = data.get("ports", [])
            tags  = [f"port:{p}" for p in ports]

            if data.get("org"):
                tags.append(data["org"])
            if data.get("country_name"):
                tags.append(f"country:{data['country_name']}")

            vulns = list(data.get("vulns", {}).keys())
            if vulns:
                tags += [f"vuln:{v}" for v in vulns[:5]]

            verdict = "suspicious" if vulns else "unknown"
            score   = min(len(vulns) * 15, 90) if vulns else None

            logger.debug("Shodan: %s → %s (ports=%s, vulns=%s)", ioc, verdict, len(ports), len(vulns))
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags,
                                    raw={"ports": ports, "vulns": vulns,
                                         "org": data.get("org"), "country": data.get("country_name")})

        except Exception as e:
            logger.error("Shodan enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
