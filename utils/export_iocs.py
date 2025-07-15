import os
import csv
from fpdf import FPDF


def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    csv_path = os.path.splitext(file_path)[0] + "_iocs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IOC Type", "Value"])

        for k, v in hashes.items():
            writer.writerow([f"Hash ({k})", v])

        for s in strings[:100]:
            writer.writerow(["Extracted String", s])

        if vt_data:
            for engine, result in vt_data.get("results", {}).items():
                writer.writerow([f"VT Detection - {engine}", result])

        for tid, desc, tactic in mitre_hits:
            writer.writerow(["MITRE ATT&CK", f"{tid} ({tactic}): {desc}"])

    return csv_path


def sanitize(text):
    """Remove characters that can't be encoded in Latin-1 for FPDF"""
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', 'ignore').decode('latin-1')


def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits, imports=[], risk_score="N/A"):
    pdf_path = os.path.splitext(file_path)[0] + "_iocs.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)

    # Title
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "MalVista - Malware IOC Report", ln=True, align="C")

    # Hashes
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, sanitize("File Hashes:"), ln=True)
    pdf.set_font("Arial", "", 11)
    for k, v in hashes.items():
        pdf.multi_cell(0, 8, sanitize(f"{k}: {v}"))

    # Strings
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, sanitize("Extracted Strings (Top 100):"), ln=True)
    pdf.set_font("Arial", "", 10)
    for s in strings[:100]:
        pdf.multi_cell(0, 5, sanitize(s))

    # Imports
    if imports:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, sanitize("PE Imports:"), ln=True)
        pdf.set_font("Arial", "", 10)
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                pdf.multi_cell(0, 6, sanitize(f"{dll}: {', '.join(funcs[:5])}"))
            else:
                pdf.multi_cell(0, 6, sanitize(str(entry)))

    # MITRE Mapping
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, sanitize("MITRE ATT&CK Mapping:"), ln=True)
    pdf.set_font("Arial", "", 10)
    if mitre_hits:
        for tid, desc, tactic in mitre_hits:
            pdf.multi_cell(0, 6, sanitize(f"{tid} ({tactic}): {desc}"))
    else:
        pdf.multi_cell(0, 6, sanitize("No MITRE techniques detected."))

    # VirusTotal Data
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, sanitize("VirusTotal Results:"), ln=True)
    pdf.set_font("Arial", "", 10)
    if vt_data:
        for engine, result in vt_data.get("results", {}).items():
            pdf.multi_cell(0, 6, sanitize(f"{engine}: {result}"))
    else:
        pdf.multi_cell(0, 6, sanitize("No VirusTotal data available."))

    # Risk Score
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, sanitize("Risk Score:"), ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 8, sanitize(str(risk_score)))

    pdf.output(pdf_path)
    return pdf_path
