import streamlit as st
from analyzer import static_analysis, mitre_mapping, vt_enrichment
from utils import auth, export_iocs, file_utils, scoring

st.set_page_config(page_title="MalVista - Malware Analysis", layout="wide")
st.title("🛡️ MalVista: Automated Malware Analysis & Threat Mapping")

# --- Authentication ---
if not auth.login():
    st.stop()
auth.logout()

# --- VirusTotal API Key ---
vt_api_key = st.sidebar.text_input("🔑 Enter your VirusTotal API Key", type="password")
if not vt_api_key:
    st.warning("⚠️ Please enter your VirusTotal API key to continue.")
    st.stop()

# --- File Upload ---
uploaded_file = st.file_uploader("📁 Upload a suspicious PE file (.exe, .dll)", type=["exe", "dll"])
if uploaded_file:
    with st.spinner("Analyzing file..."):
        # Save uploaded file
        file_path = file_utils.save_uploaded_file(uploaded_file)

        # Static Analysis
        hashes, strings = static_analysis.perform_static_analysis(file_path)
        st.subheader("🔍 Static Analysis")
        st.json(hashes)
        st.text_area("Extracted Strings (Top 100)", "\n".join(strings[:100]), height=300)

        # VirusTotal Enrichment
        vt_data = vt_enrichment.query_virustotal(hashes["SHA256"], vt_api_key)
        st.subheader("🧪 VirusTotal Enrichment")
        if vt_data:
            positives = vt_data.get("positives", 0)
            total = vt_data.get("total", 0)
            st.write(f"Detection Ratio: {positives}/{total}")
            st.json(vt_data)
        else:
            st.warning("No VirusTotal data available or invalid API key.")

        # MITRE ATT&CK Mapping (simulated)
        mitre_hits = mitre_mapping.map_to_mitre_techniques(strings)
        st.subheader("🎯 MITRE ATT&CK Mapping")
        if mitre_hits:
            st.write("Detected Techniques:")
            for hit in mitre_hits:
                st.markdown(f"- {hit}")
        else:
            st.info("No MITRE techniques detected.")

        # Scoring
        risk_score = scoring.calculate_risk_score(vt_data, mitre_hits)
        st.subheader("📊 Risk Score")
        st.metric("Malware Risk Score", f"{risk_score}/10")

        # Export IOCs to CSV
        if st.button("📤 Export IOCs as CSV"):
            csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits)
            st.success("IOCs exported successfully!")
            st.download_button("Download CSV", open(csv_path, "rb").read(), file_name="iocs_report.csv")

        # Export Full Report as PDF
        if st.button("📝 Export Report as PDF"):
            pdf_path = export_iocs.export_report_pdf(file_path, hashes, strings, vt_data, mitre_hits, risk_score)
            st.success("PDF report generated successfully!")
            st.download_button("Download PDF", open(pdf_path, "rb").read(), file_name="malvista_report.pdf")
