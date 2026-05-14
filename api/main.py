import json
import logging
import pathlib

from dotenv import load_dotenv
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.logging_config import configure_logging
from database.session import get_db, init_db
from database.repository import (
    get_analyses, get_analysis_detail, get_stats, save_analysis,
    upsert_company, get_all_companies, get_company_by_ticker,
    save_sec_filing, get_company_filings,
    get_all_books, get_supplier_risk_summary,
)
from enrichment.ioc_classifier import classify_ioc
from enrichment.coordinator import run_enrichment
from ai_analysis.threat_summary import generate_ioc_summary
from ai_analysis.supplier_summary import generate_supplier_summary
from ai_analysis.mitre_mapper import generate_mitre_mapping
from agent.workflow_health_agent import run_workflow_health_agent
from suppliers.resilience_score import calculate_resilience_score

from api.apple_supply_chain import router as apple_sc_router

configure_logging()
logger = logging.getLogger(__name__)

_BASE             = pathlib.Path(__file__).parent.parent
_SUPPLIER_EXAMPLE = _BASE / "suppliers" / "example_supplier.json"
_COMPANIES_FILE   = _BASE / "datasets" / "companies" / "sample_companies.json"

app = FastAPI(title="SentinelForge AI", version="2.0")
app.include_router(apple_sc_router)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialised")


# ── Request models ────────────────────────────────────────────────────────────

class IOCRequest(BaseModel):
    ioc:        str  = Field(..., min_length=1, max_length=2048)
    include_ai: bool = True


# ── Core ─────────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    return {"message": "SentinelForge AI is running", "version": "2.0"}


# ── IOC Analysis ──────────────────────────────────────────────────────────────

@app.post("/analyze-ioc")
def analyze_ioc(request: IOCRequest, db: Session = Depends(get_db)):
    logger.info("IOC analysis: %s", request.ioc)
    ioc_type    = classify_ioc(request.ioc)
    enrichments = run_enrichment(request.ioc, ioc_type)

    try:
        analysis = save_analysis(db, request.ioc, ioc_type, enrichments)
    except Exception as e:
        logger.error("DB save failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    result = {
        "analysis_id": analysis.id,
        "ioc":         request.ioc,
        "ioc_type":    ioc_type,
        "status":      "ingested",
        "enrichment":  {
            r.source: {"verdict": r.verdict, "score": r.score, "tags": r.tags, "error": r.error}
            for r in enrichments
        },
    }

    if request.include_ai:
        try:
            result["ai_analysis"] = generate_ioc_summary(request.ioc, ioc_type)
            result["mitre"]       = generate_mitre_mapping(
                request.ioc, ioc_type, result["ai_analysis"]["ai_summary"]
            )
        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            raise HTTPException(status_code=502, detail=str(e))

    return result


@app.get("/iocs")
def list_iocs(page: int = 1, limit: int = 50, db: Session = Depends(get_db)):
    if page < 1 or not (1 <= limit <= 200):
        raise HTTPException(status_code=400, detail="page >= 1, 1 <= limit <= 200")
    return get_analyses(db, page=page, limit=limit)


@app.get("/iocs/{analysis_id}")
def get_ioc_detail(analysis_id: int, db: Session = Depends(get_db)):
    detail = get_analysis_detail(db, analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return detail


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    return get_stats(db)


# ── Companies ─────────────────────────────────────────────────────────────────

@app.post("/companies/seed")
def seed_companies(db: Session = Depends(get_db)):
    if not _COMPANIES_FILE.exists():
        raise HTTPException(status_code=404, detail="sample_companies.json not found")

    with open(_COMPANIES_FILE) as f:
        companies = json.load(f)

    seeded = []
    for c in companies:
        company = upsert_company(db, c)
        seeded.append({"ticker": company.ticker, "name": company.name})

    logger.info("Seeded %d companies", len(seeded))
    return {"seeded": len(seeded), "companies": seeded}


@app.get("/companies")
def list_companies(db: Session = Depends(get_db)):
    return {"companies": get_all_companies(db)}


@app.get("/companies/{ticker}")
def get_company(ticker: str, db: Session = Depends(get_db)):
    from suppliers.resilience_score import calculate_resilience_score
    company = get_company_by_ticker(db, ticker)
    if not company:
        raise HTTPException(status_code=404, detail=f"Company '{ticker}' not found")

    profile = {
        "business_criticality":          company.business_criticality,
        "handles_sensitive_data":        company.handles_sensitive_data,
        "internet_exposed_services":     company.internet_exposed_services,
        "has_recent_incidents":          False,
        "sbom_available":                company.sbom_available,
        "aibom_available":               company.aibom_available,
        "known_vulnerable_dependencies": company.known_vulnerable_dependencies,
        "last_security_review_days":     company.last_security_review_days,
    }

    return {
        "company":    {"id": company.id, "name": company.name, "ticker": company.ticker,
                       "cik": company.cik, "sector": company.sector, "region": company.region,
                       "supplier_type": company.supplier_type, **profile},
        "resilience": calculate_resilience_score(profile),
        "filings":    get_company_filings(db, company.id),
    }


@app.post("/companies/{ticker}/ingest-sec")
def ingest_sec(ticker: str, db: Session = Depends(get_db)):
    from integrations.sec_edgar.sec_client import ingest_company_sec

    company = get_company_by_ticker(db, ticker)
    if not company:
        raise HTTPException(status_code=404, detail=f"Company '{ticker}' not found. Seed first.")

    company_dict = {
        "name": company.name, "ticker": company.ticker, "cik": company.cik
    }

    try:
        filings = ingest_company_sec(company_dict)
    except Exception as e:
        logger.error("SEC ingestion failed for %s: %s", ticker, e)
        raise HTTPException(status_code=502, detail=str(e))

    saved = []
    for filing_data in filings:
        filing = save_sec_filing(db, company.id, filing_data)
        saved.append({"filing_type": filing.filing_type, "filing_date": filing.filing_date,
                      "risk_score": filing.risk_score})

    return {"ticker": ticker.upper(), "filings_ingested": len(saved), "filings": saved}


@app.post("/companies/{ticker}/generate-book")
def generate_book(ticker: str):
    from reports.book_builder import generate_book as _gen
    try:
        result = _gen(ticker)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("Book generation failed for %s: %s", ticker, e)
        raise HTTPException(status_code=500, detail=str(e))
    return result


# ── Reports ───────────────────────────────────────────────────────────────────

@app.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    return {"reports": get_all_books(db)}


@app.get("/reports/{book_id}/download")
def download_report(book_id: int, db: Session = Depends(get_db)):
    from database.models import IntelligenceBook
    book = db.query(IntelligenceBook).filter(IntelligenceBook.id == book_id).first()
    if not book:
        raise HTTPException(status_code=404, detail="Report not found")

    path = book.pdf_path or book.html_path
    if not path or not pathlib.Path(path).exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_type = "application/pdf" if path.endswith(".pdf") else "text/html"
    return FileResponse(path, media_type=media_type,
                        filename=pathlib.Path(path).name)


# ── Analytics ─────────────────────────────────────────────────────────────────

@app.post("/analytics/export")
def export_parquet():
    from analytics.export_to_parquet import export_all
    try:
        result = export_all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"exported": result}


@app.get("/analytics/supplier-risk")
def supplier_risk(db: Session = Depends(get_db)):
    return {"supplier_risk": get_supplier_risk_summary(db)}


@app.get("/analytics/ioc-trends")
def ioc_trends(db: Session = Depends(get_db)):
    from database.models import IOCAnalysis, EnrichmentResult
    from sqlalchemy import func

    by_type = dict(
        db.query(IOCAnalysis.ioc_type, func.count(IOCAnalysis.id))
        .group_by(IOCAnalysis.ioc_type).all()
    )
    by_verdict = dict(
        db.query(EnrichmentResult.verdict, func.count(EnrichmentResult.id))
        .group_by(EnrichmentResult.verdict).all()
    )
    malicious_iocs = (
        db.query(IOCAnalysis.ioc, IOCAnalysis.ioc_type, IOCAnalysis.created_at)
        .join(EnrichmentResult, EnrichmentResult.analysis_id == IOCAnalysis.id)
        .filter(EnrichmentResult.verdict == "malicious")
        .order_by(IOCAnalysis.created_at.desc())
        .limit(20).all()
    )

    return {
        "ioc_type_counts": by_type,
        "verdict_counts":  by_verdict,
        "recent_malicious": [
            {"ioc": i.ioc, "type": i.ioc_type, "seen": i.created_at.isoformat()}
            for i in malicious_iocs
        ],
    }


# ── Feed Health + Supplier (existing) ────────────────────────────────────────

@app.get("/health/feeds")
def health_feeds():
    try:
        return {"workflow_health": run_workflow_health_agent()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/supplier/example")
def supplier_example(db: Session = Depends(get_db)):
    if not _SUPPLIER_EXAMPLE.exists():
        raise HTTPException(status_code=404, detail="Example supplier file not found.")
    try:
        with open(_SUPPLIER_EXAMPLE) as f:
            profile = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    resilience = calculate_resilience_score(profile)
    try:
        ai_summary = generate_supplier_summary(profile, resilience)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {"supplier_profile": profile, "resilience_assessment": resilience, "ai_summary": ai_summary}
