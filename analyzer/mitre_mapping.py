# analyzer/mitre_mapping.py

MITRE_TECHNIQUES = {
    "DeleteFileW": {
        "id": "T1070.004",
        "technique": "Indicator Removal on Host: File Deletion",
        "description": "Malware often deletes files to hide artifacts or clean up after execution."
    },
    "CreateFileW": {
        "id": "T1055.001",
        "technique": "Process Injection: Dynamic-link Library Injection",
        "description": "Malware may write DLLs to disk before injection."
    },
    "SetFileAttributesW": {
        "id": "T1222.001",
        "technique": "File and Directory Permissions Modification: Windows File Permissions",
        "description": "Malware modifies file attributes to hide from users or AVs."
    },
    "GetProcAddress": {
        "id": "T1055",
        "technique": "Process Injection",
        "description": "Used to locate functions for malicious use."
    },
    "LoadLibraryA": {
        "id": "T1055.001",
        "technique": "DLL Injection",
        "description": "Malicious code loading via DLL."
    },
    # Add more keywords and techniques here as needed
}


def map_techniques(extracted_strings):
    detected_techniques = []

    for s in extracted_strings:
        for keyword, data in MITRE_TECHNIQUES.items():
            if keyword in s:
                technique_info = {
                    "id": data["id"],
                    "technique": data["technique"],
                    "description": data["description"]
                }
                if technique_info not in detected_techniques:
                    detected_techniques.append(technique_info)

    return detected_techniques
