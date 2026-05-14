import logging
from datetime import datetime, timezone

import whois

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)


def _age_days(date_val) -> int | None:
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        if date_val.tzinfo is None:
            date_val = date_val.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - date_val).days
    return None


class WHOISEnricher(BaseEnricher):
    source = "whois"
    supported_ioc_types = ["domain"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        try:
            result = whois.whois(ioc)

            age = _age_days(result.creation_date)
            tags = []

            if result.registrar:
                tags.append(f"registrar:{result.registrar}")
            if result.country:
                tags.append(f"country:{result.country}")
            if age is not None:
                tags.append(f"domain-age:{age}d")

            # Newly registered domains (< 30 days) are suspicious
            if age is not None and age < 30:
                verdict, score = "suspicious", 60
            else:
                verdict, score = "unknown", None

            raw = {
                "registrar":      result.registrar,
                "creation_date":  str(result.creation_date),
                "expiration_date": str(result.expiration_date),
                "name_servers":   result.name_servers,
                "country":        result.country,
                "domain_age_days": age,
            }

            logger.debug("WHOIS: %s → %s (age=%s days)", ioc, verdict, age)
            return EnrichmentResult(source=self.source, verdict=verdict, score=score,
                                    tags=tags, raw=raw)

        except Exception as e:
            logger.error("WHOIS enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
