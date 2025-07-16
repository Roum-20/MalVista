import streamlit as st
import os
import tempfile

from analyzer import static_analysis, mitre_mapping, vt_enrichment
from utils import export_iocs, scoring

st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🔬 MalVista - Automated Malware Analysis Toolkit")

uploaded_file = st.file_uploader("Upload a PE File (EXE/DLL)", type=["exe", "dll"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        file_path = tmp.name

    st.success("File uploaded and saved temporarily.")

    # Parse PE and extract info
    st.subheader("🧠 Static Analysis")
    hashes = static_analysis.get_hashes(file_path)
    imports = static_analysis.get_imports(file_path)

    st.write("🔐 **Hashes:**")
    for k, v in hashes.items():
        st.code(f"{k}: {v}")

    st.write("📦 **Imports:**")
    for entry in imports:
        if isinstance(entry, tuple):
            dll, funcs = entry
            st.write(f"**{dll}**: {', '.join(funcs)}")
        else:
            st.write(entry)

    # MITRE Mapping
    st.subheader("🧠 MITRE ATT&CK Mapping")
    mitre_hits = mitre_mapping.map_to_mitre(imports)
    if mitre_hits:
        for tid, desc, tactic in mitre_hits:
            st.write(f"- **{tid}** ({tactic}): {desc}")
    else:
        st.info("No techniques detected.")

    # VirusTotal
    st.subheader("🧪 VirusTotal Report")
    vt_data = vt_enrichment.query_virustotal(hashes.get("sha256", ""))
    if vt_data:
        positives = vt_data.get("positives", "N/A")
        total = vt_data.get("total", "N/A")
        st.write(f"**Detection Ratio:** {positives}/{total}")
        st.write("**Engine Results:**")
        for engine, result in vt_data.get("results", {}).items():
            st.write(f"- {engine}: {result}")
    else:
        st.warning("No VirusTotal data found (may require API key).")

    # Risk Score
    st.subheader("⚠️ Risk Score")
    risk_score = scoring.calculate_risk(mitre_hits, vt_data)
    st.write(f"**Calculated Risk Score:** {risk_score}")

    # Export Options
    st.subheader("📤 Export Indicators of Compromise (IOCs)")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📄 Export to PDF"):
            pdf_path = export_iocs.export_iocs_to_pdf(
                file_path, hashes, [], vt_data, mitre_hits, imports, risk_score)
            st.success("PDF exported!")
            st.download_button("Download PDF", open(pdf_path, "rb"), file_name="malvista_report.pdf")

    with col2:
        if st.button("🧾 Export to TXT"):
            txt_path = export_iocs.export_iocs_to_txt(
                file_path, hashes, [], imports, mitre_hits, vt_data, risk_score)
            st.success("TXT exported!")
            st.download_button("Download TXT", open(txt_path, "rb"), file_name="malvista_iocs.txt")

    with col3:
        if st.button("📊 Export to CSV"):
            csv_path = export_iocs.export_iocs_to_csv(
                file_path, hashes, [], vt_data, mitre_hits)
            st.success("CSV exported!")
            st.download_button("Download CSV", open(csv_path, "rb"), file_name="malvista_iocs.csv")
