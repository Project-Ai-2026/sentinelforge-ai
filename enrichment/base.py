from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class EnrichmentResult:
    source:  str
    verdict: str        # malicious | suspicious | benign | unknown
    score:   int | None  # 0–100, None when enricher does not produce a score
    tags:    list[str] = field(default_factory=list)
    raw:     dict      = field(default_factory=dict)
    error:   str | None = None


class BaseEnricher(ABC):
    source: str
    supported_ioc_types: list[str]

    @abstractmethod
    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult: ...
