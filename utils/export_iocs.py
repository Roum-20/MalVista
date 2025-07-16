import os
import csv
import re
from fpdf import FPDF

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits):
    csv_path = os.path.splitext(file_path)[0] + "_iocs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IOC Type", "Value"])

        # Hashes
        for k, v in hashes.items():
            writer.writerow([f"Hash ({k})", v])

        # MITRE ATT&CK
        if mitre_hits:
            for tid, desc, tactic in mitre_hits:
                writer.writerow(["MITRE", f"{tid} ({tactic}): {desc}"])
        else:
            writer.writerow(["MITRE", "No techniques detected."])

        # VirusTotal
        if vt_data:
            detection_ratio = vt_data.get("detection_ratio", "N/A")
            writer.writerow(["VT Detection Ratio", detection_ratio])
            for engine, result in vt_data.get("results", {}).items():
                writer.writerow([f"VT-{engine}", result])
        else:
            writer.writerow(["VirusTotal", "No VT data available."])

    return csv_path


def clean_text(text: str) -> str:
    return re.sub(r"[^\x20-\x7E\n]+", "", text).strip()


def sanitize(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text.encode("latin-1", "ignore").decode("latin-1")


def export_iocs_to_pdf(file_path, hashes, strings, vt_data, mitre_hits, imports=[], risk_score="N/A"):
    pdf_path = os.path.splitext(file_path)[0] + "_iocs.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)

    def write_section(title, lines, font_size=11, bold=False):
        pdf.set_font("Arial", "B" if bold else "", 12 if bold else font_size)
        pdf.cell(0, 8, sanitize(title), ln=True)
        pdf.set_font("Arial", "", font_size)
        for line in lines:
            pdf.multi_cell(0, font_size + 2, sanitize(line))

    # Title
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "MalVista - Malware IOC Report", ln=True, align="C")

    # File Hashes
    write_section("File Hashes:", [f"{k}: {v}" for k, v in hashes.items()])

    # PE Imports
    if imports:
        imps = []
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                imps.append(f"{dll}: {', '.join(funcs)}")
            else:
                imps.append(str(entry))
        write_section("PE Imports:", imps, font_size=10)

    # MITRE ATT&CK Mapping
    if mitre_hits:
        mitre_lines = [f"{tid} ({tactic}): {desc}" for tid, desc, tactic in mitre_hits]
    else:
        mitre_lines = ["No techniques detected."]
    write_section("MITRE ATT&CK Mapping:", mitre_lines, font_size=10)

    # VirusTotal Results
    vt_lines = []
    if vt_data:
        detection_ratio = vt_data.get("detection_ratio", "N/A")
        vt_lines.append(f"Detection Ratio: {detection_ratio}")
        for engine, result in vt_data.get("results", {}).items():
            vt_lines.append(f"{engine}: {result}")
    else:
        vt_lines = ["No VirusTotal data available."]
    write_section("VirusTotal Results:", vt_lines, font_size=10)

    # Risk Score
    write_section("Risk Score:", [str(risk_score)], font_size=11, bold=True)

    pdf.output(pdf_path)
    return pdf_path


def export_iocs_to_txt(file_path, hashes, strings, imports, mitre_hits, vt_data=None, risk_score="N/A"):
    txt_path = os.path.splitext(file_path)[0] + "_iocs.txt"
    os.makedirs(os.path.dirname(txt_path), exist_ok=True)

    with open(txt_path, "w", encoding="utf-8") as f:
        # File Hashes
        f.write("File Hashes:\n")
        for k, v in hashes.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")

        # PE Imports
        f.write("PE Imports:\n")
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                f.write(f"  {dll}: {', '.join(funcs)}\n")
            else:
                f.write(f"  {entry}\n")
        f.write("\n")

        # MITRE ATT&CK
        f.write("MITRE ATT&CK Mapping:\n")
        if mitre_hits:
            for tid, desc, tactic in mitre_hits:
                f.write(f"  {tid} ({tactic}): {desc}\n")
        else:
            f.write("  No techniques detected.\n")
        f.write("\n")

        # VirusTotal
        f.write("VirusTotal Results:\n")
        if vt_data:
            f.write(f"  Detection Ratio: {vt_data.get('detection_ratio', 'N/A')}\n")
            for engine, result in vt_data.get("results", {}).items():
                f.write(f"  {engine}: {result}\n")
        else:
            f.write("  No VirusTotal data available.\n")
        f.write("\n")

        # Risk Score
        f.write(f"Risk Score:\n  {risk_score}\n")

    return txt_path
