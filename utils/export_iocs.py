def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits):
    from fpdf import FPDF
    import os
    from datetime import datetime

    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]
    pdf_path = f"report/{name}_iocs.pdf"
    os.makedirs("report", exist_ok=True)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    def safe(text):
        return str(text).encode("latin-1", "ignore").decode("latin-1")

    pdf.cell(0, 10, safe("MalVista - Malware Analysis Report"), ln=1)
    pdf.cell(0, 10, safe(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), ln=1)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, safe("File Hashes"), ln=1)
    pdf.set_font("Arial", size=12)
    for k, v in hashes.items():
        pdf.cell(0, 10, safe(f"{k}: {v}"), ln=1)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, safe("Strings (first 20)"), ln=1)
    pdf.set_font("Arial", size=12)
    for s in strings[:20]:
        pdf.cell(0, 10, safe(s), ln=1)

    if vt_data:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, safe("VirusTotal Results"), ln=1)
        pdf.set_font("Arial", size=12)
        for k, v in vt_data.items():
            pdf.cell(0, 10, safe(f"{k}: {v}"), ln=1)

    if mitre_hits:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, safe("MITRE ATT&CK Mapping"), ln=1)
        pdf.set_font("Arial", size=12)
        for tid, desc, tactic in mitre_hits:
            pdf.cell(0, 10, safe(f"{tid} ({tactic}): {desc}"), ln=1)

    pdf.output(pdf_path)
    return pdf_path
