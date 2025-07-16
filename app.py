import streamlit as st
import os

# Import modules
from analyzer import static_analysis, mitre_mapping, vt_enrichment
from utils import export_iocs, file_utils
from utils.auth import login, logout

# Set Streamlit config
st.set_page_config(page_title="MalVista - Malware Analysis Dashboard", layout="wide")

# User Authentication
if not login():
    st.stop()

logout()

# 🔑 VirusTotal API Key input
st.sidebar.header("🔑 VirusTotal API Key")
if "vt_api_key" not in st.session_state:
    st.session_state["vt_api_key"] = ""

vt_input = st.sidebar.text_input("Enter your VirusTotal API Key", type="password", value=st.session_state["vt_api_key"])
if vt_input:
    st.session_state["vt_api_key"] = vt_input

# Main Dashboard
st.title("🔬 MalVista: Malware Analysis & IOC Generator")

uploaded_file = st.file_uploader("Upload a PE File (.exe, .dll)", type=["exe", "dll"])

if uploaded_file:
    with st.spinner("Analyzing file..."):
        file_path = file_utils.save_uploaded_file(uploaded_file)

        # Static Analysis
        st.subheader("🧬 Static Analysis")
        hashes, strings = static_analysis.perform_static_analysis(file_path)
        st.code(f"MD5: {hashes['md5']}\nSHA1: {hashes['sha1']}\nSHA256: {hashes['sha256']}")
        st.text_area("Extracted Strings (Top 100):", "\n".join(strings[:100]), height=250)

        # VirusTotal Scan
        st.subheader("🛡️ VirusTotal Scan")
        vt_data = None
        if st.session_state["vt_api_key"]:
            vt_data = vt_enrichment.check_virustotal(hashes['sha256'], st.session_state["vt_api_key"])
            if vt_data and "error" not in vt_data:
                st.write(f"Detection Ratio: `{vt_data['detection_ratio']}`")
                st.write(f"[🔗 View on VirusTotal]({vt_data['permalink']})")
            else:
                st.warning(f"VirusTotal error: {vt_data.get('error', 'Unknown error')}")
        else:
            st.info("Please provide a VirusTotal API key in the sidebar.")

        # MITRE Mapping
        st.subheader("🧠 MITRE ATT&CK Mapping")
        mitre_hits = mitre_mapping.map_to_mitre(file_path)
        if mitre_hits:
            for technique in mitre_hits:
                st.write(f"- **{technique['id']}**: {technique['name']}")
        else:
            st.info("No techniques detected.")

        # Export Section
        st.subheader("📁 Export IOCs")
        if st.button("📤 Export to CSV & PDF"):
            csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
            pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits)

            if os.path.exists(csv_path):
                st.success("✅ CSV report generated.")
                with open(csv_path, "rb") as f:
                    st.download_button("Download CSV", f, file_name=os.path.basename(csv_path))

            if os.path.exists(pdf_path):
                st.success("✅ PDF report generated.")
                with open(pdf_path, "rb") as f:
                    st.download_button("Download PDF", f, file_name=os.path.basename(pdf_path))
