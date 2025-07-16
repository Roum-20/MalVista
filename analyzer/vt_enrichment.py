import streamlit as st
from utils import auth, file_utils, export_iocs, scoring
from analyzer import static_analysis, mitre_mapping, vt_enrichment

# -------------------------
# User Authentication
# -------------------------
if not auth.login():
    st.stop()
auth.logout()

# -------------------------
# Page Title & Upload
# -------------------------
st.title("🧪 MalVista - Malware Analysis & Threat Mapping")
uploaded_file = st.file_uploader("Upload a PE file", type=["exe", "dll", "bin"])

vt_api_key = st.text_input("🔑 Optional VirusTotal API Key", type="password")

if uploaded_file:
    file_path = file_utils.save_uploaded_file(uploaded_file)
    st.success("✅ File uploaded successfully!")

    # -------------------------
    # Static Analysis
    # -------------------------
    st.subheader("🧬 Static Analysis")
    try:
        hashes, strings = static_analysis.perform_static_analysis(file_path)
        st.write("🔐 File Hashes:")
        for algo, h in hashes.items():
            st.write(f"- {algo}: `{h}`")

        st.write("🔎 Extracted Strings (Top 100):")
        st.code("\n".join(strings[:100]))
    except Exception as e:
        st.error(f"❌ Static analysis failed: {e}")
        st.stop()

    # -------------------------
    # MITRE Mapping
    # -------------------------
    st.subheader("🎯 MITRE ATT&CK Techniques")
    mitre_hits = []
    try:
        mitre_hits = mitre_mapping.map_techniques(strings)
        if mitre_hits:
            for hit in mitre_hits:
                st.write(f"- {hit}")
        else:
            st.info("✅ No techniques detected.")
    except Exception as e:
        st.error(f"❌ MITRE mapping failed: {e}")

    # -------------------------
    # VirusTotal Enrichment
    # -------------------------
    st.subheader("🧪 VirusTotal Results")
    vt_data = None
    if vt_api_key and hashes.get("SHA256"):
        try:
            vt_data = vt_enrichment.query_virustotal(hashes["SHA256"], vt_api_key)
        except Exception as e:
            st.warning(f"⚠️ VirusTotal lookup failed: {e}")

    if vt_data and "last_analysis_results" in vt_data:
        scans = vt_data.get("last_analysis_results", {})
        positives = sum(1 for result in scans.values() if result.get("category") == "malicious")
        total = len(scans)
        st.write(f"Detection Ratio: {positives}/{total}")
        st.write("🔍 Detections:")
        for vendor, result in scans.items():
            if result.get("category") == "malicious":
                st.write(f"- **{vendor}**: {result.get('result')}")
    else:
        st.info("ℹ️ VirusTotal data not available or API key not provided.")

    # -------------------------
    # Scoring
    # -------------------------
    st.subheader("🛡️ Risk Score")
    try:
        risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
        st.metric("Overall Risk Score", f"{risk_score} / 100")
    except Exception as e:
        st.error(f"❌ Risk scoring failed: {e}")

    # -------------------------
    # Export IOCs
    # -------------------------
    st.subheader("📤 Export IOCs")
    try:
        csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
        with open(csv_path, "rb") as f:
            st.download_button("⬇️ Download CSV", f, file_name="iocs.csv")

        pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits)
        with open(pdf_path, "rb") as f:
            st.download_button("⬇️ Download PDF Report", f, file_name="report.pdf")
    except Exception as e:
        st.error(f"❌ Export failed: {e}")
