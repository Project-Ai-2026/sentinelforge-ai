import logging
import pathlib

import pandas as pd

from database.session import SessionLocal
from database.models import Company, EnrichmentResult, IOCAnalysis, SECFiling

logger = logging.getLogger(__name__)

_PARQUET_DIR = pathlib.Path(__file__).parent.parent / "parquet_exports"
_PARQUET_DIR.mkdir(exist_ok=True)


def export_ioc_analyses() -> str:
    db   = SessionLocal()
    rows = []
    try:
        for a in db.query(IOCAnalysis).all():
            for e in a.enrichments:
                rows.append({
                    "analysis_id": a.id,
                    "ioc":         a.ioc,
                    "ioc_type":    a.ioc_type,
                    "created_at":  a.created_at,
                    "source":      e.source,
                    "verdict":     e.verdict,
                    "score":       e.score,
                    "error":       e.error,
                })
    finally:
        db.close()

    df   = pd.DataFrame(rows)
    path = _PARQUET_DIR / "ioc_analysis.parquet"
    df.to_parquet(path, index=False)
    logger.info("Exported %d IOC rows → %s", len(rows), path)
    return str(path)


def export_company_risk() -> str:
    db   = SessionLocal()
    rows = []
    try:
        for f in db.query(SECFiling).all():
            rows.append({
                "ticker":       f.ticker,
                "filing_type":  f.filing_type,
                "filing_date":  f.filing_date,
                "risk_score":   f.risk_score,
                "created_at":   f.created_at,
            })
        for c in db.query(Company).all():
            rows_c = {
                "ticker":                        c.ticker,
                "name":                          c.name,
                "sector":                        c.sector,
                "business_criticality":          c.business_criticality,
                "sbom_available":                c.sbom_available,
                "known_vulnerable_dependencies": c.known_vulnerable_dependencies,
            }
    finally:
        db.close()

    df   = pd.DataFrame(rows) if rows else pd.DataFrame()
    path = _PARQUET_DIR / "company_risk.parquet"
    df.to_parquet(path, index=False)
    logger.info("Exported %d company risk rows → %s", len(rows), path)
    return str(path)


def query_parquet(sql: str) -> pd.DataFrame:
    """Run a DuckDB SQL query against the exported Parquet files."""
    try:
        import duckdb
        con = duckdb.connect(":memory:")
        for pf in _PARQUET_DIR.glob("*.parquet"):
            con.execute(
                f"CREATE OR REPLACE VIEW {pf.stem} AS SELECT * FROM read_parquet('{pf}')"
            )
        return con.execute(sql).df()
    except ImportError:
        logger.warning("DuckDB not installed — cannot run Parquet queries")
        return pd.DataFrame()


def export_all() -> dict[str, str]:
    results = {}
    for name, fn in [("ioc_analysis", export_ioc_analyses),
                     ("company_risk", export_company_risk)]:
        try:
            results[name] = fn()
        except Exception as e:
            logger.error("Export failed for %s: %s", name, e)
            results[name] = f"ERROR: {e}"
    return results
