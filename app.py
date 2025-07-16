import streamlit as st
from utils import auth
from utils import file_utils, export_iocs, scoring
from analyzer import static_analysis, vt_enrichment, mitre_mapping

st.set_page_config(page_title="MalVista", layout="wide")
st.title("🛡️ MalVista - Malware Static Analysis and Threat Intelligence")

# Authenticate
if not auth.login():
    st.stop()
auth.logout()

# File Upload
uploaded_file = st.file_uploader("📂 Upload a PE file", type=["exe", "dll"])
vt_api_key = st.text_input("🔑 VirusTotal API Key (Optional)", type="password")

if uploaded_file:
    with st.spinner("Analyzing file..."):
        # Save file
        file_path = file_utils.save_uploaded_file(uploaded_file)

        # Static Analysis
        hashes, strings = static_analysis.perform_static_analysis(file_path)
        st.subheader("🧬 Hashes")
        for htype, hval in hashes.items():
            st.write(f"**{htype}**: `{hval}`")

        st.subheader("📝 Extracted Strings (Top 100)")
        for s in strings[:100]:
            st.text(s)

        # VirusTotal
        vt_data = None
        if vt_api_key:
            vt_data = vt_enrichment.query_virustotal(hashes["SHA256"], vt_api_key)
            if vt_data:
                st.subheader("🧪 VirusTotal Results")
                st.write(f"**Detection Ratio**: {vt_data.get('positives', 'N/A')}/{vt_data.get('total', 'N/A')}")
                scans = vt_data.get("scans", {})
                if scans:
                    for vendor, result in scans.items():
                        st.write(f"- **{vendor}**: {result.get('result')}")
                else:
                    st.write("No individual vendor results available.")
            else:
                st.warning("⚠️ No VirusTotal data found or invalid API key.")
        else:
            st.info("🔐 Provide API key to retrieve VirusTotal results.")

        # MITRE Mapping
        mitre_hits = mitre_mapping.map_techniques(strings)
        st.subheader("🎯 MITRE ATT&CK Techniques")
        if mitre_hits:
            for tech in mitre_hits:
                st.write(f"- **{tech['technique']}** ({tech['id']}): {tech['description']}")
        else:
            st.write("✅ No techniques detected.")

        # Scoring
        risk_score = scoring.calculate_score(hashes, vt_data, mitre_hits)
        st.subheader(f"🔥 Risk Score: {risk_score}/10")

        # Export
        csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
        pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits)

        st.success("✅ IOC Exports Ready")
        with open(csv_path, "rb") as f:
            st.download_button("⬇️ Download CSV", f, file_name="iocs.csv")
        with open(pdf_path, "rb") as f:
            st.download_button("⬇️ Download PDF", f, file_name="report.pdf")
