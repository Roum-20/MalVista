import streamlit as st
import os
import sys

# Ensure modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'modules')))

# Local imports
from modules import pe_parser, signature_scanner, mitre_mapper, vt_checker, export_iocs, static_analysis
import auth

# Set page config
st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🧠 MalVista - Malware Analysis and Threat Intel Dashboard")

# --- Authentication ---
if not auth.login():
    st.stop()
auth.logout()

# --- File Upload ---
uploaded_file = st.file_uploader("Upload a PE File (.exe, .dll)", type=["exe", "dll"])
if uploaded_file:
    file_path = os.path.join("uploads", uploaded_file.name)
    os.makedirs("uploads", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"Uploaded {uploaded_file.name}")

    # --- API Key Input ---
    vt_api_key = st.text_input("🔑 Enter your VirusTotal API Key", type="password")

    # --- Static Analysis ---
    st.subheader("📊 Static Analysis")
    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.write("**File Hashes:**", hashes)
    st.write("**Extracted Strings (Top 100):**")
    st.code("\n".join(strings[:100]), language='text')

    # --- Signature Scanning ---
    st.subheader("🧬 Signature-Based Detection")
    signatures_detected = signature_scanner.scan_signatures(strings)
    if signatures_detected:
        st.warning("⚠️ Suspicious Patterns Detected:")
        for sig in signatures_detected:
            st.write(f"- {sig}")
    else:
        st.success("✅ No suspicious signatures found.")

    # --- MITRE Mapping ---
    st.subheader("🛰️ MITRE ATT&CK Mapping")
    mitre_hits = mitre_mapper.map_to_mitre(signatures_detected)
    if mitre_hits:
        for technique in mitre_hits:
            st.write(f"- {technique}")
    else:
        st.info("ℹ️ No MITRE techniques matched.")

    # --- VirusTotal Analysis ---
    st.subheader("🧪 VirusTotal Analysis")
    vt_data = None
    if vt_api_key:
        vt_data = vt_checker.query_virustotal(hashes["sha256"], vt_api_key)
        if vt_data:
            detection_ratio = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            st.write("**Detection Ratio:**", detection_ratio)
        else:
            st.error("❌ Failed to fetch VirusTotal results.")
    else:
        st.info("ℹ️ VirusTotal API key not provided.")

    # --- PDF Report Export ---
    if st.button("📄 Export PDF Report"):
        pdf_path = export_iocs.export_pdf_report(
            file_path=file_path,
            hashes=hashes,
            strings=strings[:100],
            vt_data=vt_data,
            mitre_techniques=mitre_hits
        )
        if pdf_path:
            st.success("📁 PDF Report Generated")
            with open(pdf_path, "rb") as f:
                st.download_button("📥 Download PDF", f, file_name=os.path.basename(pdf_path))
