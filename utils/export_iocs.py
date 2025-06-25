import csv
from fpdf import FPDF

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    csv_path = file_path + "_iocs.csv"
    with open(csv_path, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Value"])
        for htype, val in hashes.items():
            writer.writerow([htype, val])
        if vt_data:
            for k, v in vt_data.items():
                writer.writerow(["VT_" + k, v])
        for tid, desc, _ in mitre_hits:
            writer.writerow(["MITRE", f"{tid}: {desc}"])
        for s in strings[:100]:
            writer.writerow(["String", s])
    return csv_path

def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits):
    pdf_path = file_path + "_iocs.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="MalScanX - IOC Report", ln=True, align='C')
    pdf.set_font("Arial", size=8)
    for k, v in hashes.items():
        pdf.cell(200, 6, txt=f"{k}: {v}", ln=True)
    if vt_data:
        pdf.ln()
        pdf.cell(200, 10, txt="VirusTotal:", ln=True)
        for k, v in vt_data.items():
            pdf.cell(200, 6, txt=f"{k}: {v}", ln=True)
    pdf.ln()
    pdf.cell(200, 10, txt="MITRE Techniques:", ln=True)
    for tid, desc, _ in mitre_hits:
        pdf.cell(200, 6, txt=f"{tid}: {desc}", ln=True)
    pdf.ln()
    pdf.cell(200, 10, txt="Strings:", ln=True)
    for s in strings[:100]:
        pdf.cell(200, 5, txt=s[:90], ln=True)
    pdf.output(pdf_path)
    return pdf_path
