import json
import logging
import pathlib

from fastapi import APIRouter, HTTPException

from suppliers.apple_sc_scorer import calculate_apple_sc_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/apple-supply-chain", tags=["Apple Supply Chain"])

_DATA_FILE = (
    pathlib.Path(__file__).parent.parent
    / "datasets" / "apple_supply_chain" / "apple_suppliers.json"
)

_DISCLAIMER = (
    "Uses publicly available supplier data only. "
    "Does not represent Apple internal vendor risk data. "
    "Designed as a portfolio demonstration of supply chain cyber resilience engineering."
)


def _load() -> list[dict]:
    if not _DATA_FILE.exists():
        raise HTTPException(status_code=404, detail="Apple suppliers dataset not found.")
    with open(_DATA_FILE) as f:
        return json.load(f)


def _score_all(suppliers: list[dict]) -> list[dict]:
    result = []
    for s in suppliers:
        score = calculate_apple_sc_score(s)
        result.append({**s, **score})
    return result


@router.get("/suppliers")
def list_suppliers():
    """All Apple supply chain suppliers with resilience scores — sorted lowest to highest."""
    suppliers = _load()
    scored    = _score_all(suppliers)

    summary = [
        {
            "supplier_name":     s["supplier_name"],
            "known_as":          s.get("known_as"),
            "ticker":            s.get("ticker"),
            "category":          s.get("category"),
            "primary_regions":   s.get("primary_regions", []),
            "hq_country":        s.get("hq_country"),
            "resilience_score":  s["resilience_score"],
            "resilience_rating": s["resilience_rating"],
            "product_dependency": s.get("product_dependency"),
        }
        for s in sorted(scored, key=lambda x: x["resilience_score"])
    ]

    return {
        "disclaimer": _DISCLAIMER,
        "total":      len(summary),
        "suppliers":  summary,
    }


@router.get("/suppliers/{identifier}")
def get_supplier(identifier: str):
    """
    Detail view for a single supplier.
    identifier can be ticker (TSM), known_as (TSMC), or full supplier_name.
    """
    suppliers = _load()
    uid       = identifier.upper()

    match = next(
        (s for s in suppliers
         if (s.get("ticker") or "").upper() == uid
         or (s.get("known_as") or "").upper() == uid
         or (s.get("supplier_name") or "").upper() == uid),
        None,
    )

    if not match:
        raise HTTPException(status_code=404, detail=f"Supplier '{identifier}' not found.")

    score = calculate_apple_sc_score(match)

    return {
        "disclaimer": _DISCLAIMER,
        "supplier":   match,
        "resilience": score,
    }


@router.get("/risk-summary")
def risk_summary():
    """Aggregated risk view — breakdowns by category, region, rating, and critical suppliers."""
    suppliers = _load()
    scored    = _score_all(suppliers)

    by_category: dict[str, int] = {}
    by_region:   dict[str, int] = {}
    by_rating:   dict[str, int] = {}

    for s in scored:
        by_category[s.get("category", "Unknown")] = by_category.get(s.get("category", "Unknown"), 0) + 1
        for region in s.get("primary_regions", []):
            by_region[region] = by_region.get(region, 0) + 1
        by_rating[s["resilience_rating"]] = by_rating.get(s["resilience_rating"], 0) + 1

    scores      = [s["resilience_score"] for s in scored]
    avg_score   = round(sum(scores) / len(scores), 1) if scores else 0
    critical    = [s for s in scored if s["resilience_score"] <  40]
    weak        = [s for s in scored if 40 <= s["resilience_score"] < 60]
    moderate    = [s for s in scored if 60 <= s["resilience_score"] < 80]
    strong      = [s for s in scored if s["resilience_score"] >= 80]

    def _slim(items: list[dict]) -> list[dict]:
        return sorted(
            [{"known_as": s.get("known_as"), "score": s["resilience_score"],
              "category": s.get("category"), "rating": s["resilience_rating"]}
             for s in items],
            key=lambda x: x["score"]
        )

    return {
        "disclaimer":         _DISCLAIMER,
        "total_suppliers":    len(scored),
        "average_score":      avg_score,
        "by_category":        by_category,
        "by_region":          by_region,
        "by_rating":          by_rating,
        "critical_suppliers": _slim(critical),
        "weak_suppliers":     _slim(weak),
        "moderate_suppliers": _slim(moderate),
        "strong_suppliers":   _slim(strong),
    }


@router.get("/categories")
def list_categories():
    """Unique categories in the dataset."""
    suppliers  = _load()
    categories = sorted({s.get("category") for s in suppliers if s.get("category")})
    return {"categories": categories}
