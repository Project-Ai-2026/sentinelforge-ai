import requests
import streamlit as st

API_BASE = "http://127.0.0.1:8001"

st.set_page_config(
    page_title="SentinelForge AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentinelForge AI")
st.subheader("AI-Assisted Threat Intelligence & Supply Chain Cyber Resilience")

st.markdown("---")

tab1, tab2, tab3 = st.tabs([
    "IOC Analysis",
    "Workflow Health",
    "Supplier Resilience"
])

with tab1:
    st.header("IOC Analysis")

    ioc = st.text_input(
        "Enter IOC",
        value="8.8.8.8",
        help="IP, domain, URL, MD5, SHA1, or SHA256"
    )

    include_ai = st.checkbox("Include AI analysis", value=True)

    if st.button("Analyze IOC"):
        with st.spinner("Analyzing IOC..."):
            try:
                response = requests.post(
                    f"{API_BASE}/analyze-ioc",
                    json={
                        "ioc": ioc,
                        "include_ai": include_ai
                    },
                    timeout=120
                )

                if response.status_code == 200:
                    data = response.json()

                    col1, col2, col3 = st.columns(3)
                    col1.metric("IOC", data.get("ioc", "N/A"))
                    col2.metric("IOC Type", data.get("ioc_type", "N/A"))
                    col3.metric("Status", data.get("status", "N/A"))

                    st.markdown("### AI Threat Summary")
                    ai_summary = (
                        data.get("ai_analysis", {})
                        .get("ai_summary", "No AI summary returned.")
                    )
                    st.write(ai_summary)

                    st.markdown("### MITRE ATT&CK Mapping")
                    mitre = (
                        data.get("mitre", {})
                        .get("mitre_mapping", "No MITRE mapping returned.")
                    )
                    st.write(mitre)

                    with st.expander("Raw JSON"):
                        st.json(data)

                else:
                    st.error(f"API error {response.status_code}: {response.text}")

            except Exception as e:
                st.error(f"Request failed: {e}")

with tab2:
    st.header("Workflow Health Agent")

    if st.button("Check Feed Health"):
        with st.spinner("Checking external feeds..."):
            try:
                response = requests.get(
                    f"{API_BASE}/health/feeds",
                    timeout=60
                )

                if response.status_code == 200:
                    data = response.json()
                    health = data.get("workflow_health", [])

                    for feed in health:
                        status = feed.get("status", "UNKNOWN")
                        severity = feed.get("severity", "Unknown")

                        st.markdown(f"### {feed.get('feed')}")
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Status", status)
                        col2.metric("Severity", severity)
                        col3.metric(
                            "Latency",
                            str(feed.get("details", {}).get("latency_seconds", "N/A"))
                        )

                        st.write(feed.get("recommended_action", ""))

                    with st.expander("Raw JSON"):
                        st.json(data)

                else:
                    st.error(f"API error {response.status_code}: {response.text}")

            except Exception as e:
                st.error(f"Request failed: {e}")

with tab3:
    st.header("Supplier Cyber Resilience")

    if st.button("Analyze Example Supplier"):
        with st.spinner("Analyzing supplier resilience..."):
            try:
                response = requests.get(
                    f"{API_BASE}/supplier/example",
                    timeout=120
                )

                if response.status_code == 200:
                    data = response.json()

                    profile = data.get("supplier_profile", {})
                    resilience = data.get("resilience_assessment", {})
                    ai_summary = data.get("ai_summary", {})

                    col1, col2, col3 = st.columns(3)
                    col1.metric("Supplier", profile.get("supplier_name", "N/A"))
                    col2.metric("Resilience Score", resilience.get("resilience_score", "N/A"))
                    col3.metric("Rating", resilience.get("resilience_rating", "N/A"))

                    st.markdown("### Risk Reasons")
                    for reason in resilience.get("risk_reasons", []):
                        st.write(f"- {reason}")

                    st.markdown("### AI Supplier Risk Summary")
                    st.write(
                        ai_summary.get(
                            "ai_supplier_summary",
                            "No AI supplier summary returned."
                        )
                    )

                    with st.expander("Raw JSON"):
                        st.json(data)

                else:
                    st.error(f"API error {response.status_code}: {response.text}")

            except Exception as e:
                st.error(f"Request failed: {e}")
