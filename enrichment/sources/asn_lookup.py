import logging

from ipwhois import IPWhois

from enrichment.base import BaseEnricher, EnrichmentResult

logger = logging.getLogger(__name__)


class ASNEnricher(BaseEnricher):
    source = "asn"
    supported_ioc_types = ["ip"]

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        try:
            result = IPWhois(ioc).lookup_rdap(depth=1)

            asn         = result.get("asn")
            asn_desc    = result.get("asn_description", "")
            country     = result.get("asn_country_code", "")
            network     = result.get("network", {})
            net_name    = network.get("name", "")

            tags = []
            if asn:
                tags.append(f"ASN{asn}")
            if asn_desc:
                tags.append(asn_desc)
            if country:
                tags.append(f"country:{country}")
            if net_name:
                tags.append(net_name)

            raw = {
                "asn":         asn,
                "description": asn_desc,
                "country":     country,
                "network":     net_name,
                "cidr":        network.get("cidr"),
            }

            logger.debug("ASN: %s → ASN%s (%s)", ioc, asn, asn_desc)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None,
                                    tags=tags, raw=raw)

        except Exception as e:
            logger.error("ASN enrichment failed for %s: %s", ioc, e)
            return EnrichmentResult(source=self.source, verdict="unknown", score=None, error=str(e))
