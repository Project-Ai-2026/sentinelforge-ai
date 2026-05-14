import logging
import re
import time

import requests
from bs4 import BeautifulSoup

from ai_analysis.ollama_client import ask_ollama

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "SentinelForge-AI research@sentinelforge.ai",
    "Accept-Encoding": "gzip, deflate",
}

_SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik}.json"
_ARCHIVES_URL    = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{doc}"


def _pad_cik(cik: str) -> str:
    return cik.lstrip("0").zfill(10)


def get_recent_filings(cik: str, form_type: str = "10-K", count: int = 2) -> list[dict]:
    padded = _pad_cik(cik)
    resp   = requests.get(_SUBMISSIONS_URL.format(cik=padded), headers=_HEADERS, timeout=15)
    resp.raise_for_status()

    data   = resp.json()
    recent = data.get("filings", {}).get("recent", {})
    forms  = recent.get("form",            [])
    dates  = recent.get("filingDate",      [])
    accns  = recent.get("accessionNumber", [])
    docs   = recent.get("primaryDocument", [])

    results = []
    for i, form in enumerate(forms):
        if form == form_type and len(results) < count:
            results.append({
                "form_type":        form,
                "filing_date":      dates[i] if i < len(dates) else "",
                "accession_number": accns[i]  if i < len(accns)  else "",
                "primary_doc":      docs[i]   if i < len(docs)   else "",
                "cik":              cik,
            })

    logger.info("Found %d %s filings for CIK %s", len(results), form_type, cik)
    return results


def get_filing_risk_text(cik: str, accession_number: str, primary_doc: str) -> str:
    accession_nodashes = accession_number.replace("-", "")
    cik_plain          = cik.lstrip("0")

    url  = _ARCHIVES_URL.format(cik=cik_plain, accession=accession_nodashes, doc=primary_doc)
    resp = requests.get(url, headers=_HEADERS, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.content, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s{2,}", " ", text)

    # Try to isolate Item 1A — Risk Factors
    match = re.search(r"item\s+1a\.?\s*risk\s+factors", text, re.IGNORECASE)
    if match:
        start     = match.start()
        # Stop before Item 1B or Item 2 to avoid capturing non-risk content
        end_match = re.search(r"item\s+1b\b|item\s+2\b", text[start + 100:], re.IGNORECASE)
        end       = start + 100 + end_match.start() if end_match else start + 6000
        risk_text = text[start:end]
    else:
        risk_text = text[:4000]

    return risk_text[:5000].strip()


def generate_filing_ai_summary(company_name: str, filing_type: str, risk_text: str) -> str:
    prompt = f"""Analyze this SEC {filing_type} risk section for {company_name}.

Risk Text:
{risk_text[:2500]}

Return a structured analysis:
- Top 3 cyber or supply-chain risks mentioned
- Overall risk level: Low | Medium | High | Critical
- Key third-party vendors or dependencies referenced
- Notable cybersecurity incident disclosures (if any)

Keep response under 200 words. Be specific — do not generalize."""

    return ask_ollama(prompt)


def score_filing_risk(ai_summary: str) -> int:
    summary_lower = ai_summary.lower()
    score = 50

    if "critical" in summary_lower:
        score += 30
    elif "high" in summary_lower:
        score += 20
    elif "medium" in summary_lower:
        score += 5
    elif "low" in summary_lower:
        score -= 10

    for keyword in ["breach", "cyberattack", "ransomware", "supply chain disruption",
                    "nation-state", "zero-day", "incident"]:
        if keyword in summary_lower:
            score += 8

    return min(max(score, 0), 100)


def ingest_company_sec(company: dict) -> list[dict]:
    cik    = company.get("cik", "")
    ticker = company.get("ticker", "")
    name   = company.get("name", "")

    if not cik:
        logger.warning("No CIK for %s — skipping SEC ingestion", ticker)
        return []

    results = []

    try:
        filings = get_recent_filings(cik, form_type="10-K", count=2)
        time.sleep(0.5)  # SEC courtesy rate-limit

        for filing in filings:
            try:
                risk_text = get_filing_risk_text(
                    cik, filing["accession_number"], filing["primary_doc"]
                )
                time.sleep(0.5)

                ai_summary = generate_filing_ai_summary(name, filing["form_type"], risk_text)
                risk_score = score_filing_risk(ai_summary)

                cik_plain          = cik.lstrip("0")
                accession_nodashes = filing["accession_number"].replace("-", "")
                filing_url = (
                    f"https://www.sec.gov/Archives/edgar/data/"
                    f"{cik_plain}/{accession_nodashes}/{filing['primary_doc']}"
                )

                results.append({
                    "ticker":            ticker,
                    "filing_type":       filing["form_type"],
                    "filing_date":       filing["filing_date"],
                    "accession_number":  filing["accession_number"],
                    "filing_url":        filing_url,
                    "risk_section_text": risk_text,
                    "ai_summary":        ai_summary,
                    "risk_score":        risk_score,
                })

                logger.info(
                    "Ingested %s for %s — risk_score=%d",
                    filing["form_type"], ticker, risk_score
                )

            except Exception as e:
                logger.error("Failed to process %s filing for %s: %s",
                             filing.get("form_type"), ticker, e)

    except Exception as e:
        logger.error("SEC ingestion failed for %s: %s", ticker, e)

    return results
