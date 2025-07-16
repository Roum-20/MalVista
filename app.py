import os
import streamlit as st
from modules import pe_parser, signature_scanner, mitre_mapper, vt_checker, export_iocs

st.set_page_config(page_title="MalVista", layout="wide")

def analyze_file(file):
    # Save uploaded file
    file_path = os.path.join("uploads", file.name)
    os.makedirs("uploads", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(file.read())

    # Perform analysis
    hashes = pe_parser.get_hashes(file_path)
    imports = pe_parser.get_imports(file_path)
    vt_data = vt_checker.check_virustotal(hashes.get("md5", ""))
    matched_rules, mitre_hits, risk_score = signature_scanner.analyze_file(file_path)

    # Display results
    st.subheader("Analysis Results")
    st.markdown(f"**File:** `{file.name}`")
    
    with st.expander("File Hashes"):
        for k, v in hashes.items():
            st.code(f"{k}: {v}", language="text")

    with st.expander("Imports"):
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                st.text(f"{dll}: {', '.join(funcs)}")
            else:
                st.text(str(entry))

    with st.expander("YARA Rule Matches"):
        if matched_rules:
            for rule in matched_rules:
                st.success(rule)
        else:
            st.warning("No matches found.")

    with st.expander("MITRE ATT&CK Techniques"):
        if mitre_hits:
            for tid, desc, tactic in mitre_hits:
                st.info(f"{tid} ({tactic}): {desc}")
        else:
            st.warning("No techniques detected.")

    with st.expander("VirusTotal Results"):
        if vt_data:
            st.text(f"Detection Ratio: {vt_data.get('detection_ratio', 'N/A')}")
            for engine, result in vt_data.get("results", {}).items():
                st.text(f"{engine}: {result}")
        else:
            st.warning("No VirusTotal data found.")

    st.metric("Risk Score", str(risk_score))

    # Export
    with st.expander("📄 Export Reports"):
        csv_path = export_iocs.export_iocs_to_csv(file_path, hashes, vt_data, mitre_hits)
        pdf_path = export_iocs.export_iocs_to_pdf(file_path, hashes, vt_data, mitre_hits, imports, risk_score)
        txt_path = export_iocs.export_iocs_to_txt(file_path, hashes, imports, mitre_hits, vt_data, risk_score)

        st.download_button("Download CSV", open(csv_path, "rb"), file_name=os.path.basename(csv_path))
        st.download_button("Download PDF", open(pdf_path, "rb"), file_name=os.path.basename(pdf_path))
        st.download_button("Download TXT", open(txt_path, "rb"), file_name=os.path.basename(txt_path))

# Streamlit UI
st.title("🧪 MalVista - Malware Static Analyzer")

uploaded_file = st.file_uploader("Upload a PE file (exe/dll)", type=["exe", "dll"])

if uploaded_file:
    analyze_file(uploaded_file)
