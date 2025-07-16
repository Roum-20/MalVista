import os
import csv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def export_iocs_to_csv(file_path, hashes, strings, vt_data, mitre_hits, output_dir="exports"):
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.splitext(os.path.basename(file_path))[0]
    csv_path = os.path.join(output_dir, f"{filename}_iocs.csv")

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IOC Type", "Value"])

        # Hashes
        for htype, hval in hashes.items():
            writer.writerow([htype, hval])

        # Strings (top 100)
        for s in strings[:100]:
            writer.writerow(["String", s])

        # VirusTotal
        if vt_data:
            writer.writerow(["VT Positives", vt_data.get("positives", "N/A")])
            writer.writerow(["VT Total", vt_data.get("total", "N/A")])
            scans = vt_data.get("scans", {})
            for vendor, result in scans.items():
                if result.get("detected"):
                    writer.writerow([f"VT - {vendor}", result.get("result")])

        # MITRE Techniques
        if mitre_hits:
            for technique in mitre_hits:
                writer.writerow(["MITRE Technique", technique])

    return csv_path


def export_iocs_to_pdf(file_path, hashes, strings, vt_data=None, mitre_hits=None, output_dir="exports"):
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.splitext(os.path.basename(file_path))[0]
    pdf_path = os.path.join(output_dir, f"{filename}_report.pdf")

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "📄 MalVista PDF Report")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Analyzed File: {os.path.basename(file_path)}")
    y -= 25

    c.setFont("Helvetica", 10)
    c.drawString(50, y, "🧬 Hashes:")
    y -= 18
    for htype, hval in hashes.items():
        c.drawString(60, y, f"{htype}: {hval}")
        y -= 15

    y -= 10
    c.setFont("Helvetica", 10)
    c.drawString(50, y, "🧵 Extracted Strings (Top 100):")
    y -= 18
    for s in strings[:100]:
        c.drawString(60, y, s)
        y -= 13
        if y < 50:
            c.showPage()
            y = height - 40

    if vt_data:
        y -= 10
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "🛡️ VirusTotal Scan Results:")
        y -= 18
        c.drawString(60, y, f"Detections: {vt_data.get('positives', 'N/A')} / {vt_data.get('total', 'N/A')}")
        y -= 15
        for vendor, result in vt_data.get("scans", {}).items():
            if result.get("detected"):
                c.drawString(60, y, f"{vendor}: {result.get('result')}")
                y -= 13
                if y < 50:
                    c.showPage()
                    y = height - 40

    if mitre_hits:
        y -= 10
        c.setFont("Helvetica", 10)
        c.drawString(50, y, "🎯 MITRE ATT&CK Techniques:")
        y -= 18
        for technique in mitre_hits:
            c.drawString(60, y, f"- {technique}")
            y -= 13
            if y < 50:
                c.showPage()
                y = height - 40

    c.save()
    return pdf_path
