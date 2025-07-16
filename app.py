import streamlit as st
import os

from modules import (
    pe_parser,
    signature_scanner,
    mitre_mapper,
    vt_checker,
    export_iocs,
    static_analysis,
    scoring,
)
from utils import auth

# Set page config
st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")

# Authenticate user
if not auth.login():
    st.stop()

st.title("🧠 MalVista - Malware Analysis & Threat Scoring")

# VirusTotal API key input
vt_api_key = st.sidebar.text_input("🔑 VirusTotal API Key", type="password")

# File uploader
file_path = None
uploaded_file = st.file_uploader("📂 Upload a PE file (e.g., .exe)", type=["exe", "dll"])

if uploaded_file:
    with open(f"uploads/{uploaded_file.name}", "wb") as f:
        f.write(uploaded_file.getbuffer())
    file_path = f"uploads/{uploaded_file.name]"
    st.success("✅ File uploaded successfully!")

# Analyze when file and API key are provided
if file_path and vt_api_key:
    st.subheader("📊 Static Analysis")

    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.write("🔢 File Hashes:")
    st.json(hashes)

    st.write("🧵 Extracted Strings (Top 100):")
    for s in strings[:100]:
        st.text(s)

    # VT check
    st.subheader("🛡️ VirusTotal Enrichment")
    vt_data = vt_checker.query_virustotal(hashes["SHA256"], vt_api_key)

    if vt_data:
        positives = vt_data.get("positives", 0)
        total = vt_data.get("total", 1)
        st.write(f"Detection Ratio: {positives}/{total}")

        detected = {
            vendor: result["result"]
            for vendor, result in vt_data.get("scans", {}).items()
            if result.get("detected")
        }
        if detected:
            st.write("🔍 Detections:")
            st.json(detected)
        else:
            st.info("✅ No detections found by vendors.")
    else:
        st.warning("⚠️ Could not fetch data from VirusTotal.")

    # Signature scan
    st.subheader("🔎 Signature-Based Detection")
    signatures = signature_scanner.scan_signatures(strings)
    st.write(signatures if signatures else "No signature matches.")

    # MITRE Mapping
    st.subheader("🎯 MITRE ATT&CK Techniques")
    mitre_hits = mitre_mapper.map_to_mitre(strings)
    st.write(mitre_hits if mitre_hits else "No techniques detected.")

    # Scoring
    st.subheader("📈 Risk Scoring")
    risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
    st.metric("Overall Risk Score", f"{risk_score}/100")

    # IOC Export (CSV)
    st.subheader("📤 Export IOCs")
    csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
    with open(csv_path, "rb") as f:
        st.download_button("⬇️ Download CSV Report", f, file_name=os.path.basename(csv_path))

# Logout button
auth.logout()
