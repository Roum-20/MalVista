from fpdf import FPDF
import os
import textwrap

def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "MalVista - IOC Report", ln=True)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"File: {os.path.basename(file_path)}", ln=True)

    # Hashes
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Hashes:", ln=True)
    pdf.set_font("Arial", "", 11)
    for k, v in hashes.items():
        wrapped = textwrap.wrap(f"{k}: {v}", width=90)
        for line in wrapped:
            pdf.cell(0, 10, line, ln=True)

    # VirusTotal
    if vt_data:
        pdf.ln(5)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "VirusTotal:", ln=True)
        pdf.set_font("Arial", "", 11)
        for k, v in vt_data.items():
            value = str(v)
            wrapped = textwrap.wrap(f"{k}: {value}", width=90)
            for line in wrapped:
                pdf.cell(0, 10, line, ln=True)

    # MITRE Techniques
    if mitre_hits:
        pdf.ln(5)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "MITRE Techniques:", ln=True)
        pdf.set_font("Arial", "", 11)
        for tid, desc, tactic in mitre_hits:
            text = f"{tid} ({tactic}): {desc}"
            wrapped = textwrap.wrap(text, width=90)
            for line in wrapped:
                pdf.cell(0, 10, line, ln=True)

    output_path = f"{os.path.splitext(file_path)[0]}_report.pdf"
    pdf.output(output_path)
    return output_path
