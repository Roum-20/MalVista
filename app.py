import streamlit as st
import os
from modules import static_analysis, signature_scanner, mitre_mapper, vt_checker, export_iocs, scoring
from utils import auth

# ----------------- App Config -----------------
st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🧠 MalVista - Automated Malware Analysis Dashboard")

# ----------------- Authentication -----------------
if not auth.login():
    st.stop()
auth.logout()

# ----------------- File Upload -----------------
uploaded_file = st.file_uploader("📁 Upload a PE file", type=["exe", "dll"])
vt_api_key = st.text_input("🔑 Optional VirusTotal API Key", type="password")

if uploaded_file:
    file_path = os.path.join("uploads", uploaded_file.name)
    os.makedirs("uploads", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"✅ Uploaded: {uploaded_file.name}")

    # ---------------- Static Analysis ----------------
    st.subheader("🧬 Static Analysis")
    hashes, strings = static_analysis.perform_static_analysis(file_path)
    st.json(hashes)

    st.subheader("🔎 Extracted Strings (Top 100)")
    st.code("\n".join(strings[:100]), language="text")

    # ---------------- Signature Scan ----------------
    st.subheader("🧬 Signature Scan")
    sig_results = signature_scanner.scan_file(file_path)
    if sig_results:
        for sig in sig_results:
            st.write(f"- {sig}")
    else:
        st.write("✅ No known malicious signatures detected.")

    # ---------------- MITRE ATT&CK Mapping ----------------
    st.subheader("🎯 MITRE ATT&CK Techniques")
    mitre_hits = mitre_mapper.map_to_mitre(strings)
    if mitre_hits:
        for t in mitre_hits:
            st.write(f"- {t}")
    else:
        st.write("✅ No techniques detected.")

    # ---------------- VirusTotal Enrichment ----------------
    vt_data = None
    if vt_api_key:
        st.subheader("🧪 VirusTotal Analysis")
        vt_data = vt_checker.query_virustotal(hashes["SHA256"], vt_api_key)

        if isinstance(vt_data, dict):
            scans = vt_data.get("scans", {})
            if scans:
                st.write("🔍 Detections:")
                for vendor, result in scans.items():
                    if result.get("detected"):
                        st.write(f"- **{vendor}**: {result.get('result')}")
            else:
                st.write("✅ No detections found.")
        else:
            st.warning("⚠️ VirusTotal returned unexpected data or no data found.")
    else:
        st.info("ℹ️ Skipping VirusTotal lookup (no API key provided)")

    # ---------------- Risk Score ----------------
    st.subheader("⚠️ Risk Score")
    score = scoring.calculate_score(hashes, vt_data, mitre_hits)
    st.metric("Overall Risk Score", f"{score} / 100")

    # ---------------- Export PDF & CSV ----------------
    st.subheader("📤 Export Results")
    csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
    pdf_path = export_iocs.export_pdf_report(file_path, hashes, strings, vt_data, mitre_hits, score)

    with open(csv_path, "rb") as f:
        st.download_button("📥 Download CSV", f, file_name=os.path.basename(csv_path))

    with open(pdf_path, "rb") as f:
        st.download_button("📄 Download PDF Report", f, file_name=os.path.basename(pdf_path))
