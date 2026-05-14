import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from cachetools import TTLCache

from enrichment.base import BaseEnricher, EnrichmentResult
from enrichment.sources.abuseipdb import AbuseIPDBEnricher
from enrichment.sources.alienvault import AlienVaultEnricher
from enrichment.sources.asn_lookup import ASNEnricher
from enrichment.sources.greynoise import GreyNoiseEnricher
from enrichment.sources.shodan import ShodanEnricher
from enrichment.sources.urlhaus import URLhausEnricher
from enrichment.sources.virustotal import VirusTotalEnricher
from enrichment.sources.whois_lookup import WHOISEnricher

logger = logging.getLogger(__name__)

_TTL_SECONDS: dict[str, int] = {
    "abuseipdb":  3_600,
    "greynoise":  3_600,
    "urlhaus":    1_800,
    "alienvault": 21_600,
    "virustotal": 86_400,
    "shodan":     86_400,
    "whois":      86_400,
    "asn":        86_400,
}

_ENRICHERS: list[BaseEnricher] = [
    AbuseIPDBEnricher(),
    GreyNoiseEnricher(),
    ShodanEnricher(),
    ASNEnricher(),
    WHOISEnricher(),
    URLhausEnricher(),
    VirusTotalEnricher(),
    AlienVaultEnricher(),
]

_caches: dict[str, TTLCache] = {
    e.source: TTLCache(maxsize=1024, ttl=_TTL_SECONDS.get(e.source, 3_600))
    for e in _ENRICHERS
}

_cache_lock = threading.Lock()


def _cache_get(source: str, ioc: str) -> EnrichmentResult | None:
    with _cache_lock:
        return _caches[source].get(ioc)


def _cache_set(source: str, ioc: str, result: EnrichmentResult) -> None:
    with _cache_lock:
        _caches[source][ioc] = result


def run_enrichment(ioc: str, ioc_type: str) -> list[EnrichmentResult]:
    applicable = [e for e in _ENRICHERS if ioc_type in e.supported_ioc_types]

    cached, to_run = [], []
    for enricher in applicable:
        hit = _cache_get(enricher.source, ioc)
        if hit is not None:
            logger.debug("Cache hit: %s for %s", enricher.source, ioc)
            cached.append(hit)
        else:
            to_run.append(enricher)

    fresh: list[EnrichmentResult] = []
    if to_run:
        with ThreadPoolExecutor(max_workers=len(to_run)) as pool:
            futures = {pool.submit(e.enrich, ioc, ioc_type): e for e in to_run}
            for future in as_completed(futures):
                enricher = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error("Enricher %s raised unexpectedly for %s: %s", enricher.source, ioc, exc)
                    result = EnrichmentResult(
                        source=enricher.source,
                        verdict="unknown",
                        score=None,
                        error=str(exc),
                    )
                _cache_set(enricher.source, ioc, result)
                fresh.append(result)

    return cached + fresh
