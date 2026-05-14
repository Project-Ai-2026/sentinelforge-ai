def calculate_resilience_score(profile: dict) -> dict:
    score = 100
    reasons = []

    if profile.get("business_criticality") == "High":
        score -= 15
        reasons.append("Supplier is business critical.")

    if profile.get("handles_sensitive_data"):
        score -= 15
        reasons.append("Supplier handles sensitive data.")

    if profile.get("internet_exposed_services"):
        score -= 15
        reasons.append("Supplier has internet-exposed services.")

    if profile.get("has_recent_incidents"):
        score -= 20
        reasons.append("Supplier has recent security incidents.")

    if not profile.get("sbom_available"):
        score -= 15
        reasons.append("SBOM is not available.")

    if not profile.get("aibom_available"):
        score -= 10
        reasons.append("AIBOM is not available.")

    vulnerable_dependencies = profile.get("known_vulnerable_dependencies", 0)
    if vulnerable_dependencies > 0:
        score -= vulnerable_dependencies * 5
        reasons.append(f"{vulnerable_dependencies} known vulnerable dependencies identified.")

    # Default to 365 (unknown = worst case) rather than 0 (reviewed today)
    review_age = profile.get("last_security_review_days", 365)
    if review_age > 90:
        score -= 10
        reasons.append("Security review is older than 90 days.")

    score = max(score, 0)

    if score >= 80:
        rating = "Strong"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 40:
        rating = "Weak"
    else:
        rating = "Critical"

    return {
        "resilience_score": score,
        "resilience_rating": rating,
        "risk_reasons": reasons
    }
