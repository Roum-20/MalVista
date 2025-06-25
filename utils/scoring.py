def score_sample(imports, strings, vt_data):
    score = 0
    if vt_data:
        score += vt_data.get("malicious", 0) * 2
        score += vt_data.get("suspicious", 0)

    for s in strings:
        if any(x in s.lower() for x in ["keylogger", "stealer", "cmd.exe", "powershell"]):
            score += 2

    for entry in imports:
        if isinstance(entry, tuple):
            dll, funcs = entry
            if "advapi32.dll" in dll.lower() or "wininet.dll" in dll.lower():
                score += 1

    return "High" if score > 10 else "Medium" if score > 5 else "Low"
