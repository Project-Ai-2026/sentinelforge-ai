"""
Apple supply chain-specific resilience scoring.

Calibrated for large enterprise tech suppliers where industry-wide baselines
(no SBOM, internet-exposed services, high criticality) are universal and
would collapse all scores to zero if applied uniformly.

Scoring differentiates on:
  - Known incident history
  - Geopolitical manufacturing concentration
  - Category criticality within the Apple supply chain
  - Documented cyber risk factor severity
  - Positive resilience signals (geo diversification, certifications, etc.)
"""

_CATEGORY_CRITICALITY_PENALTY: dict[str, int] = {
    "Final Assembly":                  15,
    "Semiconductor Manufacturing":     15,
    "Display Manufacturing":           12,
    "Electronic Manufacturing Services": 10,
    "Wireless Components":              8,
    "Optical Components":               8,
    "Passive Components":               5,
    "Industrial / Materials":           4,
}

# Regions with elevated geopolitical / regulatory risk relevant to Apple supply chain
_GEO_RISK_REGIONS = {"China", "Taiwan", "Korea"}

_BASELINE = 70  # Enterprise tech baseline — above average security maturity assumed


def calculate_apple_sc_score(supplier: dict) -> dict:
    score   = _BASELINE
    reasons = []
    adjustments: dict[str, int] = {"baseline": _BASELINE}

    # ── Security review recency ────────────────────────────────────────────
    review_days = supplier.get("last_security_review_days", 365)
    if review_days > 180:
        score -= 10
        reasons.append(f"Security review is overdue — {review_days} days since last review (>180 threshold).")
        adjustments["review_penalty"] = -10
    elif review_days > 90:
        score -= 5
        reasons.append(f"Security review approaching threshold — {review_days} days (>90 days).")
        adjustments["review_penalty"] = -5
    else:
        adjustments["review_penalty"] = 0

    # ── Recent incidents ───────────────────────────────────────────────────
    incident_pen = 0
    if supplier.get("has_recent_incidents"):
        incident_pen = 20
        score -= incident_pen
        reasons.append("Documented recent security incident(s) on record.")
    adjustments["incident_penalty"] = -incident_pen

    # ── SBOM / AIBOM availability ──────────────────────────────────────────
    transparency_pen = 0
    if not supplier.get("sbom_available"):
        transparency_pen += 5
        reasons.append("SBOM not publicly available.")
    if not supplier.get("aibom_available"):
        transparency_pen += 3
        reasons.append("AIBOM not publicly available.")
    score -= transparency_pen
    adjustments["transparency_penalty"] = -transparency_pen

    # ── Known vulnerable dependencies ─────────────────────────────────────
    vuln_deps = supplier.get("known_vulnerable_dependencies", 0)
    dep_pen   = min(vuln_deps * 3, 9)
    if dep_pen:
        score -= dep_pen
        reasons.append(f"{vuln_deps} known vulnerable dependenc{'y' if vuln_deps == 1 else 'ies'} identified.")
    adjustments["dependency_penalty"] = -dep_pen

    # ── Category criticality ───────────────────────────────────────────────
    category = supplier.get("category", "")
    cat_pen  = _CATEGORY_CRITICALITY_PENALTY.get(category, 0)
    if cat_pen:
        score -= cat_pen
        reasons.append(f"Category '{category}' carries elevated criticality within the Apple supply chain.")
    adjustments["category_penalty"] = -cat_pen

    # ── Geopolitical manufacturing concentration ───────────────────────────
    regions      = set(supplier.get("primary_regions", []))
    risk_regions = regions & _GEO_RISK_REGIONS
    geo_pen      = 0
    if risk_regions:
        if not (regions - _GEO_RISK_REGIONS):
            geo_pen = 15
            reasons.append(
                f"Full manufacturing concentration in high-risk region(s): {', '.join(sorted(risk_regions))}."
            )
        else:
            geo_pen = 8
            reasons.append(
                f"Partial manufacturing concentration in high-risk region(s): {', '.join(sorted(risk_regions))}."
            )
        score -= geo_pen
    adjustments["geopolitical_penalty"] = -geo_pen

    # ── Documented cyber risk factors ─────────────────────────────────────
    cyber_factors = supplier.get("cyber_risk_factors", [])
    cyber_pen     = min(len(cyber_factors) * 4, 16)
    if cyber_pen:
        score -= cyber_pen
        reasons.append(f"{len(cyber_factors)} documented public cyber risk factor(s) identified.")
    adjustments["cyber_factor_penalty"] = -cyber_pen

    # ── Resilience signals — partial positive offset ───────────────────────
    resilience_signals = supplier.get("resilience_signals", [])
    bonus = min(len(resilience_signals) * 5, 20)
    if bonus:
        score += bonus
    adjustments["resilience_signal_bonus"] = bonus

    score = max(min(score, 100), 0)

    if score >= 80:
        rating = "Strong"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 40:
        rating = "Weak"
    else:
        rating = "Critical"

    return {
        "resilience_score":    score,
        "resilience_rating":   rating,
        "risk_reasons":        reasons,
        "cyber_risk_factors":  cyber_factors,
        "resilience_signals":  resilience_signals,
        "score_adjustments":   adjustments,
    }
