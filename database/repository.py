import json
import logging
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from database.models import (
    Company, EnrichmentResult, IntelligenceBook, IOCAnalysis, SECFiling
)

logger = logging.getLogger(__name__)


# ── IOC Analysis ─────────────────────────────────────────────────────────────

def save_analysis(db: Session, ioc: str, ioc_type: str, enrichments: list) -> IOCAnalysis:
    analysis = IOCAnalysis(ioc=ioc, ioc_type=ioc_type)
    db.add(analysis)
    db.flush()

    for result in enrichments:
        db.add(EnrichmentResult(
            analysis_id=analysis.id,
            source=result.source,
            verdict=result.verdict,
            score=result.score,
            tags=json.dumps(result.tags),
            raw=json.dumps(result.raw),
            error=result.error,
        ))

    db.commit()
    db.refresh(analysis)
    logger.debug("Saved analysis id=%s for ioc=%s", analysis.id, ioc)
    return analysis


def get_analyses(db: Session, page: int = 1, limit: int = 50) -> dict:
    offset = (page - 1) * limit
    total  = db.query(func.count(IOCAnalysis.id)).scalar()
    rows   = (
        db.query(IOCAnalysis)
        .order_by(IOCAnalysis.created_at.desc())
        .offset(offset).limit(limit).all()
    )

    analyses = []
    for row in rows:
        verdict_counts: dict[str, int] = {}
        for e in row.enrichments:
            verdict_counts[e.verdict] = verdict_counts.get(e.verdict, 0) + 1
        analyses.append({
            "id":             row.id,
            "ioc":            row.ioc,
            "ioc_type":       row.ioc_type,
            "created_at":     row.created_at.isoformat(),
            "verdict_summary": verdict_counts,
        })

    return {"total": total, "page": page, "limit": limit, "analyses": analyses}


def get_analysis_detail(db: Session, analysis_id: int) -> dict | None:
    row = db.query(IOCAnalysis).filter(IOCAnalysis.id == analysis_id).first()
    if not row:
        return None

    return {
        "id":         row.id,
        "ioc":        row.ioc,
        "ioc_type":   row.ioc_type,
        "created_at": row.created_at.isoformat(),
        "enrichments": [
            {
                "source":  e.source,
                "verdict": e.verdict,
                "score":   e.score,
                "tags":    json.loads(e.tags) if e.tags else [],
                "raw":     json.loads(e.raw)  if e.raw  else {},
                "error":   e.error,
            }
            for e in row.enrichments
        ],
    }


def get_stats(db: Session) -> dict:
    total = db.query(func.count(IOCAnalysis.id)).scalar()

    ioc_type_counts = dict(
        db.query(IOCAnalysis.ioc_type, func.count(IOCAnalysis.id))
        .group_by(IOCAnalysis.ioc_type).all()
    )
    verdict_counts = dict(
        db.query(EnrichmentResult.verdict, func.count(EnrichmentResult.id))
        .group_by(EnrichmentResult.verdict).all()
    )
    source_hits = dict(
        db.query(EnrichmentResult.source, func.count(EnrichmentResult.id))
        .filter(EnrichmentResult.error.is_(None))
        .group_by(EnrichmentResult.source).all()
    )

    return {
        "total_analyses":         total,
        "ioc_type_breakdown":     ioc_type_counts,
        "verdict_breakdown":      verdict_counts,
        "enrichment_source_hits": source_hits,
    }


# ── Companies ─────────────────────────────────────────────────────────────────

def upsert_company(db: Session, data: dict) -> Company:
    existing = db.query(Company).filter(Company.ticker == data["ticker"].upper()).first()
    if existing:
        for key, value in data.items():
            if key != "ticker":
                setattr(existing, key, value)
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    company = Company(**{**data, "ticker": data["ticker"].upper()})
    db.add(company)
    db.commit()
    db.refresh(company)
    logger.info("Inserted company %s", company.ticker)
    return company


def get_all_companies(db: Session) -> list[dict]:
    rows = db.query(Company).order_by(Company.name).all()
    return [_company_to_dict(c) for c in rows]


def get_company_by_ticker(db: Session, ticker: str) -> Company | None:
    return db.query(Company).filter(Company.ticker == ticker.upper()).first()


def _company_to_dict(c: Company) -> dict:
    return {
        "id":                           c.id,
        "name":                         c.name,
        "ticker":                       c.ticker,
        "cik":                          c.cik,
        "sector":                       c.sector,
        "region":                       c.region,
        "supplier_type":                c.supplier_type,
        "business_criticality":         c.business_criticality,
        "handles_sensitive_data":       c.handles_sensitive_data,
        "internet_exposed_services":    c.internet_exposed_services,
        "sbom_available":               c.sbom_available,
        "aibom_available":              c.aibom_available,
        "known_vulnerable_dependencies": c.known_vulnerable_dependencies,
        "last_security_review_days":    c.last_security_review_days,
        "created_at":                   c.created_at.isoformat() if c.created_at else None,
        "updated_at":                   c.updated_at.isoformat() if c.updated_at else None,
    }


# ── SEC Filings ───────────────────────────────────────────────────────────────

def save_sec_filing(db: Session, company_id: int, filing_data: dict) -> SECFiling:
    existing = (
        db.query(SECFiling)
        .filter(SECFiling.accession_number == filing_data.get("accession_number"))
        .first()
    )
    if existing:
        logger.debug("SEC filing already exists: %s", filing_data.get("accession_number"))
        return existing

    filing = SECFiling(company_id=company_id, **filing_data)
    db.add(filing)
    db.commit()
    db.refresh(filing)
    logger.info("Saved SEC filing %s for company_id=%s", filing_data.get("filing_type"), company_id)
    return filing


def get_company_filings(db: Session, company_id: int) -> list[dict]:
    rows = (
        db.query(SECFiling)
        .filter(SECFiling.company_id == company_id)
        .order_by(SECFiling.filing_date.desc())
        .all()
    )
    return [
        {
            "id":               f.id,
            "ticker":           f.ticker,
            "filing_type":      f.filing_type,
            "filing_date":      f.filing_date,
            "accession_number": f.accession_number,
            "filing_url":       f.filing_url,
            "ai_summary":       f.ai_summary,
            "risk_score":       f.risk_score,
            "created_at":       f.created_at.isoformat() if f.created_at else None,
        }
        for f in rows
    ]


# ── Intelligence Books ────────────────────────────────────────────────────────

def get_all_books(db: Session) -> list[dict]:
    rows = (
        db.query(IntelligenceBook)
        .order_by(IntelligenceBook.generated_at.desc())
        .all()
    )
    return [
        {
            "id":           b.id,
            "ticker":       b.ticker,
            "report_type":  b.report_type,
            "pdf_path":     b.pdf_path,
            "html_path":    b.html_path,
            "generated_at": b.generated_at.isoformat() if b.generated_at else None,
        }
        for b in rows
    ]


def get_supplier_risk_summary(db: Session) -> list[dict]:
    from suppliers.resilience_score import calculate_resilience_score
    companies = db.query(Company).all()
    results = []
    for c in companies:
        profile = {
            "business_criticality":          c.business_criticality,
            "handles_sensitive_data":        c.handles_sensitive_data,
            "internet_exposed_services":     c.internet_exposed_services,
            "has_recent_incidents":          False,
            "sbom_available":                c.sbom_available,
            "aibom_available":               c.aibom_available,
            "known_vulnerable_dependencies": c.known_vulnerable_dependencies,
            "last_security_review_days":     c.last_security_review_days,
        }
        resilience = calculate_resilience_score(profile)
        results.append({
            "ticker": c.ticker,
            "name":   c.name,
            "sector": c.sector,
            **resilience,
        })
    return sorted(results, key=lambda x: x["resilience_score"])
