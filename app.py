import streamlit as st
from modules import (
    pe_parser, signature_scanner, mitre_mapper,
    vt_checker, export_iocs, static_analysis, scoring
)
from utils import auth

st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")

# 🟢 Authenticate user
if not auth.login():
    st.stop()
auth.logout()

st.title("🧠 MalVista: Automated Malware Analysis Platform")

# 🔑 VirusTotal API Key
vt_api_key = st.sidebar.text_input("🔑 VirusTotal API Key", type="password")

# 📁 File Upload
uploaded_file = st.file_uploader("Upload a PE file for analysis", type=["exe", "dll"])
if uploaded_file:
    with open(f"temp/{uploaded_file.name}", "wb") as f:
        f.write(uploaded_file.read())

    file_path = f"temp/{uploaded_file.name}"

    # 🧬 Static Analysis
    st.subheader("🧬 Static Analysis")
    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.write("🔢 Hashes:", hashes)
    st.text_area("📜 Extracted Strings (Top 100)", "\n".join(strings[:100]), height=300)

    # 🧠 Signature-based Detection
    st.subheader("🧠 Signature Scanner")
    sig_hits = signature_scanner.scan_with_signatures(file_path)
    if sig_hits:
        st.error(f"⚠️ Signatures matched: {sig_hits}")
    else:
        st.success("✅ No known malicious signatures detected.")

    # 🎯 MITRE Mapping
    st.subheader("🎯 MITRE ATT&CK Techniques")
    mitre_hits = mitre_mapper.map_techniques(file_path)
    if mitre_hits:
        for hit in mitre_hits:
            st.write(f"🔸 {hit}")
    else:
        st.info("No techniques detected.")

    # 🛡️ VirusTotal Enrichment
    st.subheader("🛡️ VirusTotal Enrichment")
    vt_data = None
    if vt_api_key:
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
            st.success("✅ No detections found by vendors.")
    else:
        st.warning("⚠️ Could not fetch data from VirusTotal.")

    # 📊 Risk Score
    st.subheader("📊 Risk Scoring")
    risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
    st.metric("Final Risk Score", f"{risk_score}/100")

    # 📁 Export
    st.subheader("📤 Export")
    if st.button("📄 Export to PDF & CSV"):
        csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
        pdf_path = export_iocs.export_to_pdf(
            file_path, hashes, strings, vt_data, mitre_hits, risk_score
        )
        st.success("📁 Reports generated successfully.")
        st.download_button("⬇️ Download PDF", open(pdf_path, "rb"), file_name="MalVista_Report.pdf")
        st.download_button("⬇️ Download CSV", open(csv_path, "rb"), file_name="MalVista_IOCs.csv")
