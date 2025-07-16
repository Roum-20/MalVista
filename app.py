import streamlit as st
from utils import auth
from utils import file_utils, export_iocs, scoring
from analyzer import static_analysis, mitre_mapping, vt_enrichment

# Set page config
st.set_page_config(page_title="MalVista - Malware Analysis Toolkit", layout="wide")

# Authentication
if not auth.login():
    st.stop()
auth.logout()

st.title("🧠 MalVista: Malware Analysis & Threat Intel")

# Input: VT API Key
vt_api_key = st.sidebar.text_input("🔑 VirusTotal API Key", type="password")

uploaded_file = st.file_uploader("📤 Upload a PE file (EXE/DLL)", type=["exe", "dll"])
if uploaded_file:
    with st.spinner("Processing..."):
        # Save file
        file_path = file_utils.save_uploaded_file(uploaded_file)
        st.success("✅ File uploaded successfully.")

        # Perform Static Analysis
        hashes, strings = static_analysis.perform_static_analysis(file_path)
        st.subheader("🧬 Static Analysis")
        st.json(hashes)

        st.subheader("📜 Extracted Strings (Top 100)")
        st.code("\n".join(strings[:100]))

        # VirusTotal Enrichment
        vt_data = None
        if vt_api_key and "SHA256" in hashes:
            try:
                vt_data = vt_enrichment.query_virustotal(hashes["SHA256"], vt_api_key)
                st.subheader("🛡️ VirusTotal Results")
                if vt_data:
                    st.write(vt_data)
                else:
                    st.warning("No data returned from VirusTotal.")
            except Exception as e:
                st.error(f"VirusTotal Error: {e}")
        else:
            st.warning("Provide VT API key or ensure SHA256 is available.")

        # MITRE Mapping
        mitre_hits = mitre_mapping.map_to_mitre(strings)
        st.subheader("🎯 MITRE ATT&CK Techniques")
        if mitre_hits:
            st.table(mitre_hits)
        else:
            st.write("No techniques detected.")

        # Scoring
        risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
        st.subheader("🔢 Risk Score")
        st.metric("Malicious Confidence", f"{risk_score}%")

        # Export Button
        if st.button("📤 Export Report"):
            csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
            st.success(f"Report exported to: {csv_path}")
            with open(csv_path, "rb") as f:
                st.download_button("Download CSV", f, file_name="malvista_report.csv", mime="text/csv")
