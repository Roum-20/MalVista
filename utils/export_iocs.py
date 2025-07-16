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
    pdf.cell(0, 10, "🔍 ForenSage - Malware Analysis Summary", ln=True, align="C")
    pdf.ln(5)

    # File Hashes
    write_section("🧾 File Hashes:", [f"{k.upper()}: {v}" for k, v in hashes.items()])

    # PE Imports
    if imports:
        import_lines = []
        for entry in imports:
            if isinstance(entry, tuple):
                dll, funcs = entry
                import_lines.append(f"{dll}: {', '.join(funcs)}")
            else:
                import_lines.append(str(entry))
        write_section("📦 PE Imports:", import_lines, font_size=10)

    # MITRE ATT&CK Mapping
    if mitre_hits:
        mitre_lines = [f"{tid} ({tactic}): {desc}" for tid, desc, tactic in mitre_hits]
    else:
        mitre_lines = ["No techniques detected."]
    write_section("🧠 MITRE ATT&CK Mapping:", mitre_lines, font_size=10)

    # VirusTotal Results
    vt_lines = []
    if vt_data:
        detection_ratio = vt_data.get("detection_ratio", "N/A")
        vt_lines.append(f"Detection Ratio: {detection_ratio}")
        for engine, result in vt_data.get("results", {}).items():
            vt_lines.append(f"{engine}: {result}")
    else:
        vt_lines.append("No VirusTotal data available.")
    write_section("🧪 VirusTotal Results:", vt_lines, font_size=10)

    # Extracted Strings
    if strings:
        sample_strings = strings[:100]
        write_section("📜 Extracted Strings (Top 100):", sample_strings, font_size=9)

    # Risk Score
    write_section("⚠️ Risk Score:", [str(risk_score)], font_size=11, bold=True)

    pdf.output(pdf_path)
    return pdf_path
