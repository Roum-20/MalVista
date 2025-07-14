import streamlit as st
from analyzer import static_analysis, vt_enrichment, mitre_mapping
from utils import file_utils, scoring, export_iocs
import os

st.set_page_config(page_title="MalScanX", layout="wide")
st.title("🧪 MalVista - Malware Analysis Dashboard")

uploaded_file = st.file_uploader("Upload a PE file (.exe, .dll)", type=["exe", "dll"])
api_key = st.text_input("VirusTotal API Key (optional)", type="password")

if uploaded_file:
    st.success(f"Uploaded: {uploaded_file.name}")
    file_path = file_utils.save_uploaded_file(uploaded_file)

    hashes = static_analysis.get_hashes(file_path)
    strings = static_analysis.extract_strings(file_path)
    imports = static_analysis.get_imports(file_path)
    mitre_hits = mitre_mapping.map_to_mitre(strings)

    st.subheader("📄 File Hashes")
    st.json(hashes)

    st.subheader("🔍 PE Imports")
    for entry in imports:
        if isinstance(entry, tuple):
            dll, funcs = entry
            st.markdown(f"**{dll}**: {', '.join(funcs[:5])}...")
        else:
            st.warning(f"Import parsing error: {entry}")

    st.subheader("🎯 MITRE ATT&CK Mapping")
    if mitre_hits:
        for tid, desc, tactic in mitre_hits:
            st.markdown(f"- **{tid}** ({tactic}): {desc}")
    else:
        st.info("No MITRE techniques detected from strings.")

    vt_data = None
    if api_key:
        with st.spinner("Querying VirusTotal..."):
            vt_data = vt_enrichment.enrich_virustotal(file_path, api_key)

            if vt_data:
                st.subheader("🦠 VirusTotal Results")
                st.json(vt_data)

    st.subheader("⚠️ Risk Assessment")
    risk = scoring.score_sample(imports, strings, vt_data)
    st.write(risk)

    st.subheader("📤 Export IOCs")
    if st.button("Export to CSV & PDF"):
        csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
        pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits)
        st.success("Exported!")

        with open(csv_path, "rb") as f:
            st.download_button("Download CSV", f.read(), file_name=os.path.basename(csv_path))

        with open(pdf_path, "rb") as f:
            st.download_button("Download PDF", f.read(), file_name=os.path.basename(pdf_path))

      
