import logging
import pathlib
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from ai_analysis.ollama_client import ask_ollama
from database.models import Company, IntelligenceBook, SECFiling
from database.session import SessionLocal
from suppliers.resilience_score import calculate_resilience_score

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
_OUTPUT_DIR   = pathlib.Path(__file__).parent / "output"
_OUTPUT_DIR.mkdir(exist_ok=True)

_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=False)


def _executive_summary(company: dict, resilience: dict, filings: list[dict]) -> str:
    filing_highlights = "\n".join(
        f.get("ai_summary", "") for f in filings[:2] if f.get("ai_summary")
    )

    prompt = f"""Write a professional executive summary for a Cyber Resilience Intelligence Book.

Company: {company['name']} ({company['ticker']})
Sector: {company.get('sector', 'N/A')}
Resilience Score: {resilience['resilience_score']}/100
Rating: {resilience['resilience_rating']}
Known Risk Factors: {', '.join(resilience.get('risk_reasons', [])) or 'None identified'}

SEC Filing Highlights:
{filing_highlights[:1200] or 'No SEC filings ingested yet.'}

Write exactly 3 paragraphs:
1. Overall cyber resilience posture
2. Key supply-chain and operational risks
3. Priority actions for risk reduction

Tone: professional, concise, executive-ready. Do not use bullet points."""

    return ask_ollama(prompt)


def generate_book(ticker: str) -> dict:
    db = SessionLocal()
    try:
        company = db.query(Company).filter(Company.ticker == ticker.upper()).first()
        if not company:
            raise ValueError(f"Company '{ticker}' not found. Seed companies first via POST /companies/seed.")

        profile = {
            "name":                          company.name,
            "ticker":                        company.ticker,
            "cik":                           company.cik,
            "sector":                        company.sector,
            "region":                        company.region,
            "supplier_type":                 company.supplier_type,
            "business_criticality":          company.business_criticality,
            "handles_sensitive_data":        company.handles_sensitive_data,
            "internet_exposed_services":     company.internet_exposed_services,
            "sbom_available":                company.sbom_available,
            "aibom_available":               company.aibom_available,
            "known_vulnerable_dependencies": company.known_vulnerable_dependencies,
            "last_security_review_days":     company.last_security_review_days,
        }

        resilience = calculate_resilience_score(profile)

        filings = (
            db.query(SECFiling)
            .filter(SECFiling.company_id == company.id)
            .order_by(SECFiling.filing_date.desc())
            .limit(3).all()
        )
        filing_dicts = [
            {
                "filing_type":  f.filing_type,
                "filing_date":  f.filing_date,
                "filing_url":   f.filing_url,
                "ai_summary":   f.ai_summary or "No summary available.",
                "risk_score":   f.risk_score,
            }
            for f in filings
        ]

        exec_summary = _executive_summary(profile, resilience, filing_dicts)
        report_date  = datetime.utcnow().strftime("%Y-%m-%d")

        html = _jinja.get_template("book.html").render(
            company=profile,
            resilience=resilience,
            filings=filing_dicts,
            executive_summary=exec_summary,
            report_date=report_date,
            generated_by="SentinelForge AI",
        )

        slug         = f"{ticker.upper()}_{report_date}"
        html_path    = _OUTPUT_DIR / f"{slug}_resilience_book.html"
        html_path.write_text(html, encoding="utf-8")

        pdf_path = None
        try:
            from weasyprint import HTML as WP_HTML
            pdf_path = str(_OUTPUT_DIR / f"{slug}_resilience_book.pdf")
            WP_HTML(string=html).write_pdf(pdf_path)
            logger.info("PDF generated: %s", pdf_path)
        except ImportError:
            logger.warning("WeasyPrint not installed — HTML report only. "
                           "Install: sudo apt-get install libpango-1.0-0 libcairo2 && pip install weasyprint")
        except Exception as e:
            logger.error("PDF generation failed: %s", e)

        book = IntelligenceBook(
            company_id=company.id,
            ticker=ticker.upper(),
            report_type="Supply Chain Cyber Resilience Book",
            pdf_path=pdf_path,
            html_path=str(html_path),
            ai_summary=exec_summary,
        )
        db.add(book)
        db.commit()
        db.refresh(book)

        logger.info("Book generated for %s — id=%s", ticker, book.id)
        return {
            "book_id":     book.id,
            "company":     company.name,
            "ticker":      ticker.upper(),
            "report_type": book.report_type,
            "html_path":   str(html_path),
            "pdf_path":    pdf_path,
            "report_date": report_date,
            "status":      "generated",
        }

    finally:
        db.close()
