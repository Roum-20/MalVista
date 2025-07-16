import os
import csv

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
