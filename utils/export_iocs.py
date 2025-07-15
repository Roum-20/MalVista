import csv
import os
from fpdf import FPDF

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    csv_path = os.path.splitext(file_path)[0] + "_iocs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IOC Type", "Value"])
        for k, v in hashes.items():
            writer.writerow([f"Hash ({k})", v])
        for s in strings[:100]:
            writer.writerow(["String", s])
        if vt_data:
            for engine, result in vt_data.get("results", {}).items():
                writer.writerow([f"VT:{engine}", result])
        for tid, desc, tactic in mitre_hits:
            writer.writerow(["MITRE", f"{tid} ({tactic}): {desc}"])
    return csv_path


def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits):
    pdf_path = os.path.splitext(file_path)[0] + "_iocs.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "MalVista IOC Report", ln=True)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "File Hashes:", ln=True)
    pdf.set_font("Arial", "", 12)
    for k, v in hashes.items():
        try:
            pdf.multi_cell(0, 10, f"{k}: {v}")
        except:
            pdf.multi_cell(0, 10, f"{k}: [Encoding error]")

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "MITRE Mapping:", ln=True)
    pdf.set_font("Arial", "", 12)
    for tid, desc, tactic in mitre_hits:
        try:
            pdf.multi_cell(0, 10, f"{tid} ({tactic}): {desc}")
        except:
            pdf.multi_cell(0, 10, f"{tid} ({tactic}): [Encoding error]")

    if vt_data:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "VirusTotal Detections:", ln=True)
        pdf.set_font("Arial", "", 12)
        for engine, result in vt_data.get("results", {}).items():
            pdf.multi_cell(0, 10, f"{engine}: {result}")

    pdf.output(pdf_path)
    return pdf_path
