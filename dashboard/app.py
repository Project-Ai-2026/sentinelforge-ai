import os

import pandas as pd
import requests
import streamlit as st

API_BASE = os.getenv("SENTINELFORGE_API_URL", "http://127.0.0.1:8001")

_VERDICT_ICON = {"malicious": "🔴", "suspicious": "🟡", "benign": "🟢", "unknown": "⚪"}
_RATING_COLOR = {"Critical": "🔴", "Weak": "🟠", "Moderate": "🟡", "Strong": "🟢"}

st.set_page_config(page_title="SentinelForge AI", page_icon="🛡️", layout="wide")
st.title("🛡️ SentinelForge AI")
st.subheader("AI-Assisted Threat Intelligence & Supply Chain Cyber Resilience")
st.markdown("---")

tabs = st.tabs([
    "IOC Analysis",
    "IOC History",
    "Company Intelligence",
    "Book Builder",
    "Analytics",
    "Apple Supply Chain",
    "Workflow Health",
    "Supplier Resilience",
])
tab_ioc, tab_hist, tab_company, tab_book, tab_analytics, tab_apple, tab_health, tab_supplier = tabs


# ── helpers ───────────────────────────────────────────────────────────────────

def _get(path: str, **params):
    return requests.get(f"{API_BASE}{path}", params=params, timeout=60)

def _post(path: str, **kwargs):
    return requests.post(f"{API_BASE}{path}", timeout=120, **kwargs)

def _conn_error():
    st.error(f"Cannot reach API at {API_BASE}. Is the server running?")


# ── Tab 1: IOC Analysis ───────────────────────────────────────────────────────
with tab_ioc:
    st.header("IOC Analysis")
    ioc        = st.text_input("Enter IOC", value="8.8.8.8",
                               help="IP, domain, URL, MD5, SHA1, or SHA256")
    include_ai = st.checkbox("Include AI analysis", value=True)

    if st.button("Analyze IOC"):
        ioc = ioc.strip()
        if not ioc:
            st.warning("Enter an IOC value first.")
        elif len(ioc) > 2048:
            st.error("IOC too long (max 2048 chars).")
        else:
            with st.spinner("Analyzing..."):
                try:
                    r = _post("/analyze-ioc", json={"ioc": ioc, "include_ai": include_ai})
                    if r.status_code == 200:
                        data = r.json()
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("IOC",         data.get("ioc"))
                        c2.metric("Type",        data.get("ioc_type"))
                        c3.metric("Status",      data.get("status"))
                        c4.metric("Analysis ID", data.get("analysis_id"))

                        enrichment = data.get("enrichment", {})
                        if enrichment:
                            st.markdown("### Enrichment Results")
                            rows = []
                            for src, r2 in enrichment.items():
                                v = r2.get("verdict", "unknown")
                                rows.append({
                                    "Source":  src,
                                    "Verdict": f"{_VERDICT_ICON.get(v,'⚪')} {v}",
                                    "Score":   r2.get("score") if r2.get("score") is not None else "—",
                                    "Tags":    ", ".join(r2.get("tags", [])) or "—",
                                    "Error":   r2.get("error") or "—",
                                })
                            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

                        if include_ai:
                            st.markdown("### AI Threat Summary")
                            st.write(data.get("ai_analysis", {}).get("ai_summary", "—"))
                            st.markdown("### MITRE ATT&CK Mapping")
                            st.write(data.get("mitre", {}).get("mitre_mapping", "—"))

                        with st.expander("Raw JSON"):
                            st.json(data)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()
                except Exception as e:
                    st.error(str(e))


# ── Tab 2: IOC History ────────────────────────────────────────────────────────
with tab_hist:
    st.header("IOC History")
    c1, c2 = st.columns([1, 4])
    page  = c1.number_input("Page", min_value=1, value=1, step=1)
    limit = c2.selectbox("Rows", [25, 50, 100], index=1)

    if st.button("Load History"):
        with st.spinner("Loading..."):
            try:
                r = _get("/iocs", page=page, limit=limit)
                if r.status_code == 200:
                    data     = r.json()
                    analyses = data.get("analyses", [])
                    st.caption(f"Page {page} · {len(analyses)} of {data.get('total', 0)} total")
                    if analyses:
                        rows = [{
                            "ID": a["id"], "IOC": a["ioc"], "Type": a["ioc_type"],
                            "🔴 Malicious":  a.get("verdict_summary", {}).get("malicious", 0),
                            "🟡 Suspicious": a.get("verdict_summary", {}).get("suspicious", 0),
                            "🟢 Benign":     a.get("verdict_summary", {}).get("benign", 0),
                            "Timestamp":    a["created_at"],
                        } for a in analyses]
                        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                    else:
                        st.info("No analyses recorded yet.")
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()
            except Exception as e:
                st.error(str(e))


# ── Tab 3: Company Intelligence ───────────────────────────────────────────────
with tab_company:
    st.header("Company Intelligence")

    c1, c2 = st.columns([2, 1])
    with c1:
        if st.button("Seed Company Dataset"):
            with st.spinner("Seeding..."):
                try:
                    r = _post("/companies/seed")
                    if r.status_code == 200:
                        d = r.json()
                        st.success(f"Seeded {d['seeded']} companies.")
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()

    try:
        r = _get("/companies")
        companies = r.json().get("companies", []) if r.status_code == 200 else []
    except Exception:
        companies = []

    tickers = [c["ticker"] for c in companies]
    if not tickers:
        st.info("No companies loaded. Click 'Seed Company Dataset' first.")
    else:
        selected = st.selectbox("Select Company", tickers,
                                format_func=lambda t: next(
                                    (c["name"] for c in companies if c["ticker"] == t), t))

        c1, c2 = st.columns(2)
        ingest_sec = c1.button("Ingest SEC Filings")
        view       = c2.button("View Profile")

        if ingest_sec:
            with st.spinner(f"Ingesting SEC filings for {selected}..."):
                try:
                    r = _post(f"/companies/{selected}/ingest-sec")
                    if r.status_code == 200:
                        d = r.json()
                        st.success(f"Ingested {d['filings_ingested']} filing(s) for {selected}.")
                        with st.expander("Filing details"):
                            st.json(d)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()
                except Exception as e:
                    st.error(str(e))

        if view:
            with st.spinner(f"Loading {selected}..."):
                try:
                    r = _get(f"/companies/{selected}")
                    if r.status_code == 200:
                        data       = r.json()
                        company    = data["company"]
                        resilience = data["resilience"]
                        filings    = data.get("filings", [])

                        rating = resilience.get("resilience_rating", "")
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Company",    company["name"])
                        c2.metric("Sector",     company.get("sector", "N/A"))
                        c3.metric("Score",      f"{resilience['resilience_score']}/100")
                        c4.metric("Rating",     f"{_RATING_COLOR.get(rating,'')} {rating}")

                        st.markdown("### Risk Factors")
                        for reason in resilience.get("risk_reasons", []):
                            st.write(f"- {reason}")

                        if filings:
                            st.markdown("### SEC Filings")
                            rows = [{
                                "Type":       f["filing_type"],
                                "Date":       f["filing_date"],
                                "Risk Score": f["risk_score"],
                                "Summary":    (f.get("ai_summary") or "")[:150] + "…",
                            } for f in filings]
                            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                        else:
                            st.info("No SEC filings yet — click 'Ingest SEC Filings' to populate.")

                        with st.expander("Raw JSON"):
                            st.json(data)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()
                except Exception as e:
                    st.error(str(e))


# ── Tab 4: Book Builder ───────────────────────────────────────────────────────
with tab_book:
    st.header("Intelligence Book Builder")
    st.markdown("Generates a **Cyber Resilience Intelligence Book** — executive summary, "
                "risk profile, SEC filing analysis, MITRE mappings, and mitigations — "
                "as HTML and (if WeasyPrint is installed) PDF.")

    try:
        r        = _get("/companies")
        companies = r.json().get("companies", []) if r.status_code == 200 else []
    except Exception:
        companies = []

    tickers = [c["ticker"] for c in companies]
    if not tickers:
        st.info("No companies loaded. Go to the Company Intelligence tab and seed the dataset.")
    else:
        book_ticker = st.selectbox(
            "Select Company for Book",
            tickers,
            format_func=lambda t: next((c["name"] for c in companies if c["ticker"] == t), t),
            key="book_ticker"
        )

        if st.button("Generate Intelligence Book"):
            with st.spinner(f"Generating book for {book_ticker} — this may take 60–90 seconds..."):
                try:
                    r = _post(f"/companies/{book_ticker}/generate-book")
                    if r.status_code == 200:
                        data = r.json()
                        st.success(f"Book generated — ID {data['book_id']}")

                        c1, c2, c3 = st.columns(3)
                        c1.metric("Company",     data["company"])
                        c2.metric("Report Date", data["report_date"])
                        c3.metric("Status",      data["status"])

                        st.markdown(f"**HTML report:** `{data['html_path']}`")
                        if data.get("pdf_path"):
                            st.markdown(f"**PDF report:** `{data['pdf_path']}`")
                            dl = _get(f"/reports/{data['book_id']}/download")
                            if dl.status_code == 200:
                                st.download_button(
                                    "⬇️ Download PDF",
                                    data=dl.content,
                                    file_name=f"{book_ticker}_resilience_book.pdf",
                                    mime="application/pdf"
                                )
                        else:
                            st.info("PDF not generated. Install WeasyPrint for PDF output: "
                                    "`sudo apt-get install libpango-1.0-0 libcairo2 && pip install weasyprint`")

                        with st.expander("Raw JSON"):
                            st.json(data)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.Timeout:
                    st.error("Request timed out — the AI model may be slow. Try again.")
                except requests.exceptions.ConnectionError:
                    _conn_error()
                except Exception as e:
                    st.error(str(e))

    st.markdown("---")
    st.markdown("### Past Reports")
    if st.button("Load Report History"):
        try:
            r = _get("/reports")
            if r.status_code == 200:
                reports = r.json().get("reports", [])
                if reports:
                    st.dataframe(pd.DataFrame(reports), use_container_width=True, hide_index=True)
                else:
                    st.info("No reports generated yet.")
            else:
                st.error(f"API {r.status_code}: {r.text}")
        except requests.exceptions.ConnectionError:
            _conn_error()


# ── Tab 5: Analytics ──────────────────────────────────────────────────────────
with tab_analytics:
    st.header("Analytics")

    c1, c2, c3 = st.columns(3)
    load_stats   = c1.button("Load IOC Stats")
    load_supply  = c2.button("Load Supplier Risk")
    export_pq    = c3.button("Export to Parquet")

    if load_stats:
        with st.spinner("Loading stats..."):
            try:
                r = _get("/stats")
                if r.status_code == 200:
                    data = r.json()
                    st.metric("Total IOCs Analysed", data.get("total_analyses", 0))

                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### IOC Type Breakdown")
                        ioc_data = data.get("ioc_type_breakdown", {})
                        if ioc_data:
                            st.bar_chart(pd.DataFrame.from_dict(ioc_data, orient="index", columns=["count"]))

                    with col2:
                        st.markdown("#### Verdict Breakdown")
                        vd = data.get("verdict_breakdown", {})
                        if vd:
                            st.bar_chart(pd.DataFrame.from_dict(vd, orient="index", columns=["count"]))

                    st.markdown("#### IOC Trends")
                    r2 = _get("/analytics/ioc-trends")
                    if r2.status_code == 200:
                        trends = r2.json()
                        malicious = trends.get("recent_malicious", [])
                        if malicious:
                            st.dataframe(pd.DataFrame(malicious), use_container_width=True, hide_index=True)
                        else:
                            st.info("No malicious IOCs recorded yet.")
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()

    if load_supply:
        with st.spinner("Loading supplier risk..."):
            try:
                r = _get("/analytics/supplier-risk")
                if r.status_code == 200:
                    risk_data = r.json().get("supplier_risk", [])
                    if risk_data:
                        df = pd.DataFrame(risk_data)
                        st.markdown("#### Supplier Risk Scores (lowest first)")
                        st.dataframe(df[["ticker", "name", "sector", "resilience_score", "resilience_rating"]],
                                     use_container_width=True, hide_index=True)
                        st.bar_chart(df.set_index("ticker")["resilience_score"])
                    else:
                        st.info("No companies loaded. Seed via Company Intelligence tab.")
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()

    if export_pq:
        with st.spinner("Exporting to Parquet..."):
            try:
                r = _post("/analytics/export")
                if r.status_code == 200:
                    result = r.json().get("exported", {})
                    st.success("Parquet export complete.")
                    for name, path in result.items():
                        st.write(f"- `{name}`: `{path}`")
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()


# ── Tab 6: Apple Supply Chain ─────────────────────────────────────────────────
with tab_apple:
    st.header("🍎 Apple Public Supply Chain Cyber Resilience")
    st.caption(
        "Uses publicly available supplier data only. "
        "Does not represent Apple internal vendor risk data. "
        "Designed as a portfolio demonstration of supply chain cyber resilience engineering."
    )

    view_mode = st.radio("View", ["Risk Summary", "All Suppliers", "Supplier Detail"], horizontal=True)

    if view_mode == "Risk Summary":
        if st.button("Load Risk Summary"):
            with st.spinner("Scoring suppliers..."):
                try:
                    r = _get("/apple-supply-chain/risk-summary")
                    if r.status_code == 200:
                        data = r.json()

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Total Suppliers", data["total_suppliers"])
                        c2.metric("Avg Resilience Score", data["average_score"])
                        c3.metric("Critical",  len(data.get("critical_suppliers", [])))
                        c4.metric("Weak",      len(data.get("weak_suppliers", [])))

                        st.markdown("---")
                        col1, col2 = st.columns(2)

                        with col1:
                            st.markdown("#### Suppliers by Category")
                            cat_data = data.get("by_category", {})
                            if cat_data:
                                st.bar_chart(pd.DataFrame.from_dict(
                                    cat_data, orient="index", columns=["count"]
                                ))

                        with col2:
                            st.markdown("#### Suppliers by Region")
                            region_data = data.get("by_region", {})
                            if region_data:
                                st.bar_chart(pd.DataFrame.from_dict(
                                    region_data, orient="index", columns=["count"]
                                ))

                        st.markdown("#### Rating Distribution")
                        rating_data = data.get("by_rating", {})
                        if rating_data:
                            st.bar_chart(pd.DataFrame.from_dict(
                                rating_data, orient="index", columns=["count"]
                            ))

                        if data.get("critical_suppliers"):
                            st.markdown("#### 🔴 Critical Suppliers")
                            st.dataframe(
                                pd.DataFrame(data["critical_suppliers"]),
                                use_container_width=True, hide_index=True
                            )

                        if data.get("weak_suppliers"):
                            st.markdown("#### 🟠 Weak Suppliers")
                            st.dataframe(
                                pd.DataFrame(data["weak_suppliers"]),
                                use_container_width=True, hide_index=True
                            )

                        with st.expander("Raw JSON"):
                            st.json(data)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()

    elif view_mode == "All Suppliers":
        if st.button("Load All Suppliers"):
            with st.spinner("Scoring suppliers..."):
                try:
                    r = _get("/apple-supply-chain/suppliers")
                    if r.status_code == 200:
                        data      = r.json()
                        suppliers = data.get("suppliers", [])

                        if suppliers:
                            df = pd.DataFrame(suppliers)

                            st.markdown("#### Resilience Scores — All Suppliers (lowest first)")
                            chart_df = df.set_index("known_as")["resilience_score"].sort_values()
                            st.bar_chart(chart_df)

                            st.markdown("#### Supplier Table")
                            display_cols = [
                                "known_as", "category", "hq_country",
                                "resilience_score", "resilience_rating", "product_dependency"
                            ]
                            available = [c for c in display_cols if c in df.columns]
                            st.dataframe(df[available], use_container_width=True, hide_index=True)
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()

    else:  # Supplier Detail
        identifier = st.text_input(
            "Enter ticker or short name", value="TSMC",
            help="Examples: TSMC, TSM, Foxconn, AVGO, Qualcomm"
        )
        if st.button("Look Up Supplier"):
            with st.spinner(f"Loading {identifier}..."):
                try:
                    r = _get(f"/apple-supply-chain/suppliers/{identifier}")
                    if r.status_code == 200:
                        data       = r.json()
                        supplier   = data["supplier"]
                        resilience = data["resilience"]

                        rating = resilience.get("resilience_rating", "")
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Supplier",   supplier.get("known_as"))
                        c2.metric("Category",   supplier.get("category"))
                        c3.metric("Score",      f"{resilience['resilience_score']}/100")
                        c4.metric("Rating",     f"{_RATING_COLOR.get(rating,'')} {rating}")

                        st.markdown("### Apple Relationship")
                        st.write(supplier.get("apple_relationship", "—"))

                        st.markdown("### Product Dependency")
                        st.write(supplier.get("product_dependency", "—"))

                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("### 🔴 Cyber Risk Factors")
                            for factor in resilience.get("cyber_risk_factors", []):
                                st.write(f"- {factor}")

                        with col2:
                            st.markdown("### 🟢 Resilience Signals")
                            for signal in resilience.get("resilience_signals", []):
                                st.write(f"- {signal}")

                        st.markdown("### Risk Reasons (Scoring Breakdown)")
                        for reason in resilience.get("risk_reasons", []):
                            st.write(f"- {reason}")

                        adj = resilience.get("score_adjustments", {})
                        if adj:
                            st.markdown("### Score Adjustments")
                            adj_df = pd.DataFrame([
                                {"Factor": k.replace("_", " ").title(), "Points": v}
                                for k, v in adj.items()
                            ])
                            st.dataframe(adj_df, use_container_width=True, hide_index=True)

                        st.markdown("### Data Sources")
                        for source in supplier.get("data_sources", []):
                            st.write(f"- {source}")

                        with st.expander("Raw JSON"):
                            st.json(data)

                    elif r.status_code == 404:
                        st.warning(f"Supplier '{identifier}' not found. Try: TSMC, Foxconn, AVGO, JBL, GLW")
                    else:
                        st.error(f"API {r.status_code}: {r.text}")
                except requests.exceptions.ConnectionError:
                    _conn_error()


# ── Tab 7: Workflow Health ─────────────────────────────────────────────────────
with tab_health:
    st.header("Workflow Health Agent")
    if st.button("Check Feed Health"):
        with st.spinner("Checking feeds..."):
            try:
                r = _get("/health/feeds")
                if r.status_code == 200:
                    health = r.json().get("workflow_health", [])
                    for feed in health:
                        st.markdown(f"### {feed.get('feed')}")
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Status",   feed.get("status"))
                        c2.metric("Severity", feed.get("severity"))
                        c3.metric("Latency",  str(feed.get("details", {}).get("latency_seconds", "N/A")))
                        st.write(feed.get("recommended_action", ""))
                    with st.expander("Raw JSON"):
                        st.json(r.json())
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()


# ── Tab 7: Supplier Resilience ─────────────────────────────────────────────────
with tab_supplier:
    st.header("Supplier Cyber Resilience")
    if st.button("Analyze Example Supplier"):
        with st.spinner("Analyzing..."):
            try:
                r = _get("/supplier/example")
                if r.status_code == 200:
                    data       = r.json()
                    profile    = data.get("supplier_profile", {})
                    resilience = data.get("resilience_assessment", {})
                    ai_summary = data.get("ai_summary", {})
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Supplier", profile.get("supplier_name"))
                    c2.metric("Score",    resilience.get("resilience_score"))
                    c3.metric("Rating",   resilience.get("resilience_rating"))
                    st.markdown("### Risk Reasons")
                    for r2 in resilience.get("risk_reasons", []):
                        st.write(f"- {r2}")
                    st.markdown("### AI Supplier Risk Summary")
                    st.write(ai_summary.get("ai_supplier_summary", "—"))
                    with st.expander("Raw JSON"):
                        st.json(data)
                else:
                    st.error(f"API {r.status_code}: {r.text}")
            except requests.exceptions.ConnectionError:
                _conn_error()
