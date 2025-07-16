import streamlit as st
import os
from modules import pe_parser, signature_scanner, mitre_mapper, vt_checker, export_iocs, static_analysis, scoring
from utils import auth

# ---------------- Authentication ----------------
if not auth.login():
    st.stop()
auth.logout()

# ---------------- Page Setup ----------------
st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🧠 MalVista - Automated Malware Analysis")

# ---------------- File Upload ----------------
uploaded_file = st.file_uploader("Upload a suspicious PE file", type=["exe", "dll"])
vt_api_key = st.text_input("🔑 Optional: Enter your VirusTotal API Key", type="password")

if uploaded_file:
    file_path = os.path.join("uploads", uploaded_file.name)
    os.makedirs("uploads", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success("✅ File uploaded")

    # ---------------- Static Analysis ----------------
    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.subheader("📦 File Hashes")
    st.json(hashes)

    st.subheader("🧵 Extracted Strings (Top 100)")
    st.text("\n".join(strings[:100]))

    # ---------------- Signature Scanning ----------------
    signatures = signature_scanner.scan_for_signatures(strings)
    st.subheader("🧩 Suspicious Signature Matches")
    if signatures:
        for sig in signatures:
            st.write(f"- {sig}")
    else:
        st.write("✅ No known malicious signatures found.")

    # ---------------- MITRE Mapping ----------------
    mitre_hits = mitre_mapper.map_to_mitre_techniques(strings)
    st.subheader("🎯 MITRE ATT&CK Techniques")
    if mitre_hits:
        for tech in mitre_hits:
            st.write(f"- {tech}")
    else:
        st.write("✅ No techniques detected.")

    # ---------------- VirusTotal Enrichment ----------------
    vt_data = None
    if vt_api_key:
        st.subheader("🧪 VirusTotal Analysis")
        vt_data = vt_checker.query_virustotal(hashes["SHA256"], vt_api_key)
        if vt_data and isinstance(vt_data, dict):
            scans = vt_data.get("scans", {})
            if scans:
                st.write("🔍 Detections:")
                for vendor, result in scans.items():
                    if result.get("detected"):
                        st.write(f"- **{vendor}**: {result.get('result')}")
                    else:
                        st.write("✅ No detections found.")
                    else:
                        st.write("⚠️ Could not retrieve data from VirusTotal.")
                    else:
                        st.info("ℹ️ Skipping VirusTotal lookup (no API key provided)")

    # ---------------- Risk Scoring ----------------
    risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
    st.subheader(f"💣 Threat Risk Score: {risk_score}/100")

    # ---------------- Export IOCs ----------------
    st.subheader("🧾 Export Indicators of Compromise")
    csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
    st.download_button("⬇️ Download CSV", open(csv_path, "rb"), file_name="malvista_iocs.csv")

    pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits)
    st.download_button("⬇️ Download PDF", open(pdf_path, "rb"), file_name="malvista_report.pdf")
