from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Existing tables ──────────────────────────────────────────────────────────

class IOCAnalysis(Base):
    __tablename__ = "ioc_analyses"

    id         = Column(Integer, primary_key=True, index=True)
    ioc        = Column(String, nullable=False, index=True)
    ioc_type   = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    enrichments = relationship(
        "EnrichmentResult", back_populates="analysis", cascade="all, delete-orphan"
    )


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id          = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("ioc_analyses.id"), nullable=False)
    source      = Column(String, nullable=False)
    verdict     = Column(String, nullable=False)
    score       = Column(Integer, nullable=True)
    tags        = Column(Text, nullable=True)
    raw         = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    analysis = relationship("IOCAnalysis", back_populates="enrichments")


# ── New tables ───────────────────────────────────────────────────────────────

class Company(Base):
    __tablename__ = "companies"

    id                           = Column(Integer, primary_key=True, index=True)
    name                         = Column(String, nullable=False)
    ticker                       = Column(String, unique=True, nullable=False, index=True)
    cik                          = Column(String, nullable=True)
    sector                       = Column(String, nullable=True)
    region                       = Column(String, nullable=True)
    supplier_type                = Column(String, nullable=True)
    business_criticality         = Column(String, nullable=True)
    handles_sensitive_data       = Column(Boolean, default=False)
    internet_exposed_services    = Column(Boolean, default=False)
    sbom_available               = Column(Boolean, default=False)
    aibom_available              = Column(Boolean, default=False)
    known_vulnerable_dependencies = Column(Integer, default=0)
    last_security_review_days    = Column(Integer, default=365)
    created_at                   = Column(DateTime, default=datetime.utcnow)
    updated_at                   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    filings = relationship("SECFiling",        back_populates="company", cascade="all, delete-orphan")
    books   = relationship("IntelligenceBook", back_populates="company", cascade="all, delete-orphan")


class SECFiling(Base):
    __tablename__ = "sec_filings"

    id               = Column(Integer, primary_key=True, index=True)
    company_id       = Column(Integer, ForeignKey("companies.id"), nullable=False)
    ticker           = Column(String, nullable=False, index=True)
    filing_type      = Column(String, nullable=False)
    filing_date      = Column(String, nullable=True)
    accession_number = Column(String, nullable=True, unique=True)
    filing_url       = Column(String, nullable=True)
    risk_section_text = Column(Text, nullable=True)
    ai_summary       = Column(Text, nullable=True)
    risk_score       = Column(Integer, nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)

    company = relationship("Company", back_populates="filings")


class IntelligenceBook(Base):
    __tablename__ = "intelligence_books"

    id           = Column(Integer, primary_key=True, index=True)
    company_id   = Column(Integer, ForeignKey("companies.id"), nullable=False)
    ticker       = Column(String, nullable=False, index=True)
    report_type  = Column(String, nullable=False)
    pdf_path     = Column(String, nullable=True)
    html_path    = Column(String, nullable=True)
    ai_summary   = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)

    company = relationship("Company", back_populates="books")
