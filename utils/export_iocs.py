import os
import csv
import re
from fpdf import FPDF

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    csv_path = os.path.splitext(file_path)[0] + "_iocs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IOC Type", "Value"])

        for k, v in hashes.items():
            writer.writerow([f"Hash ({k})", v])

        for s in strings[:100]:
            writer.writerow(["Extracted String", clean_text(s)])

        if vt_data:
            for engine, result in vt_data.get("results", {}).items():
                writer.writerow([f"VT-{engine}", result])

        for tid, desc, tactic in mitre_hits:
            writer.writerow(["MITRE", f"{tid} ({tactic}): {desc}"])

    return csv_path


def clean_text(text: str) -> str:
    """Keep only printable ASCII (0x20–0x7E) and common whitespace."""
    # replace sequences of whitespace with a single space
    printable = re.sub(r"[^\x20-\x7E\n]+", "", text)
    return re.sub(r"\s+", " ", printable).strip()


def sanitize(text: str) -> str:
    """Drop anything not Latin-1 before sending to FPDF."""
    if not isinstance(text, str):
        text = str(text)
    return text.encode("latin-1", "ignore").decode("latin-1")


def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits, imports=[], risk_score="N/A"):
    pdf_path = os.path.splitext(file_path)[0] + "_iocs.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)

    def write_section(title, lines, font_size=11, bold=False, bullet=False):
        pdf.set_font("Arial", "B" if bold else "", 12 if bold else font_size)
        pdf.cell(0, 8, sanitize(title), ln=True)
        pdf.set_font("Arial", "", font_size)
        for line in lines:
            line = sanitize(clean_text(line))
            pdf.multi_cell(0, font_size + 2, line)

    # Title
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "MalVista - Malware IOC Report", ln=True, align="C")

    # File Hashes
    write_section("File Hashes:", [f"{k}: {v}" for k, v in hashes.items()])

    # Extracted Strings
    write_section(
        "Extracted Strings (Top 100):",
        strings[:100],
        font_size=9
    )

    # PE Imports
    if imports:
        imps = []
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                imps.append(f"{dll}: {', '.join(funcs[:5])}")
            else:
                imps.append(str(entry))
        write_section("PE Imports:", imps, font_size=10)

    # MITRE ATT&CK
    mitre_lines = [f"{tid} ({tactic}): {desc}" for tid, desc, tactic in mitre_hits] or ["No techniques detected."]
    write_section("MITRE ATT&CK Mapping:", mitre_lines, font_size=10)

    # VirusTotal
    if vt_data:
        vt_lines = [f"{e}: {r}" for e, r in vt_data.get("results", {}).items()]
    else:
        vt_lines = ["No VirusTotal data available."]
    write_section("VirusTotal Results:", vt_lines, font_size=10)

    # Risk Score
    write_section("Risk Score:", [str(risk_score)], font_size=11, bold=True)

    pdf.output(pdf_path)
    return pdf_path
