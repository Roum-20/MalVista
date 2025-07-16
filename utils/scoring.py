def calculate_score(hashes, vt_data=None, mitre_hits=None):
    """
    Calculate a basic malware risk score out of 100.
    - Based on VirusTotal detection ratio
    - Based on presence of MITRE ATT&CK techniques
    - Based on suspicious strings (optional)
    """

    score = 0

    # 1. Score from VirusTotal
    if vt_data:
        detected = vt_data.get("positives", 0)
        total = vt_data.get("total", 1)
        vt_score = (detected / total) * 60  # Max 60 points
        score += vt_score

    # 2. Score from MITRE techniques
    if mitre_hits:
        mitre_score = min(len(mitre_hits) * 10, 30)  # Max 30 points
        score += mitre_score

    # 3. Bonus if suspicious API calls found in strings
    suspicious_indicators = ["CreateFileW", "DeleteFileW", "WritePrivateProfileStringW"]
    if "strings" in hashes:
        if any(s in hashes["strings"] for s in suspicious_indicators):
            score += 10  # Max 10 points

    return round(min(score, 100), 2)
