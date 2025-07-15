from fpdf import FPDF
import os
import csv
from datetime import datetime

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]
    csv_path = f"report/{name}_iocs.csv"
    os.makedirs("report", exist_ok=True)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Section", "Key", "Value"])
        for k, v in hashes.items():
            writer.writerow(["Hashes", k, v])
        for s in strings[:20]:
            writer.writerow(["Strings", "String", s])
        if vt_data:
            for k, v in vt_data.items():
                writer.writerow(["VirusTotal", k, v])
        for tid, desc, tactic in mitre_hits:
            writer.writerow(["MITRE", f"{tid} ({tactic})", desc])
    return csv_path

def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits):
    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]
    pdf_path = f"report/{name}_iocs.pdf"
    os.makedirs("report", exist_ok=True)

    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("DejaVu", "", "fonts/DejaVuSans.ttf", uni=True)
    pdf.set_font("DejaVu", size=12)

    pdf.cell(0, 10, "🛡 MalVista - Malware Analysis Report", ln=1)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)

    pdf.set_font("DejaVu", style="B", size=12)
    pdf.cell(0, 10, "📄 File Hashes", ln=1)
    pdf.set_font("DejaVu", size=12)
    for k, v in hashes.items():
        pdf.cell(0, 10, f"{k}: {v}", ln=1)

    pdf.set_font("DejaVu", style="B", size=12)
    pdf.cell(0, 10, "🧵 Strings (first 20)", ln=1)
    pdf.set_font("DejaVu", size=12)
    for s in strings[:20]:
        pdf.cell(0, 10, s[:80], ln=1)

    if vt_data:
        pdf.set_font("DejaVu", style="B", size=12)
        pdf.cell(0, 10, "🦠 VirusTotal Results", ln=1)
        pdf.set_font("DejaVu", size=12)
        for k, v in vt_data.items():
            pdf.cell(0, 10, f"{k}: {v}"[:80], ln=1)

    if mitre_hits:
        pdf.set_font("DejaVu", style="B", size=12)
        pdf.cell(0, 10, "🎯 MITRE ATT&CK Mapping", ln=1)
        pdf.set_font("DejaVu", size=12)
        for tid, desc, tactic in mitre_hits:
            pdf.cell(0, 10, f"{tid} ({tactic}): {desc}"[:80], ln=1)

    pdf.output(pdf_path)
    return pdf_path
