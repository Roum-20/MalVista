import streamlit as st
import os

from utils import auth
from modules import (
    pe_parser,
    static_analysis,
    signature_scanner,
    mitre_mapper,
    vt_checker,
    export_iocs,
    scoring
)

st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🧠 MalVista - Automated Malware Analysis")

# Handle login
if not auth.login():
    st.stop()
auth.logout()

# File upload
uploaded_file = st.file_uploader("Upload a Windows PE file (EXE/DLL)", type=["exe", "dll"])
vt_api_key = st.text_input("🔑 Optional: Enter your VirusTotal API Key", type="password")

if uploaded_file:
    file_path = os.path.join("uploads", uploaded_file.name)
    os.makedirs("uploads", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())
    st.success(f"✅ File saved to {file_path}")

    # PE Info
    st.subheader("📋 PE Header Info")
    pe_info = pe_parser.parse_pe(file_path)
    st.json(pe_info)

    # Static Analysis
    st.subheader("🧬 Static Analysis")
    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.write("🔑 Hashes:")
    st.json(hashes)
    st.write("🧵 Extracted Strings (Top 100):")
    st.text("\n".join(strings[:100]))

    # Signature-based Detection
    st.subheader("🛡️ Signature-Based Detection")
    sig_hits = signature_scanner.scan_file(file_path)
    if sig_hits:
        st.error("🚨 Known Malware Signature Detected!")
        st.json(sig_hits)
    else:
        st.success("✅ No signature-based malware detected.")

    # 🎯 MITRE Mapping
st.subheader("🎯 MITRE ATT&CK Techniques")

try:
    mitre_hits = mitre_mapper.map_to_mitre(strings)
except Exception as e:
    st.error(f"❌ MITRE mapping failed: {str(e)}")
    mitre_hits = []

if mitre_hits and isinstance(mitre_hits, list):
    st.write("Mapped Techniques:")
    for technique in mitre_hits:
        st.write(f"- {technique}")
else:
    st.write("✅ No techniques detected.")

    # VirusTotal Enrichment
   
st.subheader("🦠 VirusTotal Results")

if vt_data:
    scans = vt_data.get("scans", {})
    if scans:
        st.write("🔍 Detections:")
        for vendor, result in scans.items():
            if isinstance(result, dict):  # Ensure it's a dictionary
                st.write(f"- **{vendor}**: {result.get('result', 'No result')}")
            else:
                st.write(f"- **{vendor}**: {result}")
    else:
        st.info("✅ No detections reported.")
else:
    st.warning("⚠️ VirusTotal data not available or key was not provided.")


    # Risk Scoring
    st.subheader("📊 Risk Scoring")
    risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
    st.metric("Malware Risk Score", f"{risk_score} / 100")

    # Export IOCs
    st.subheader("📤 Export IOCs")
    csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
    st.download_button("⬇️ Download IOC Report (CSV)", open(csv_path, "rb"), file_name="iocs_report.csv")
