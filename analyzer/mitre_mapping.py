tactic_techniques = {
    "Execution": [("T1059.001", "PowerShell"), ("T1059.003", "Windows Command Shell")],
    "Persistence": [("T1547.001", "Registry Run Keys")],
    "Privilege Escalation": [("T1055", "Process Injection")],
    "Credential Access": [("T1056.001", "Keylogging")],
    "Discovery": [("T1049", "System Network Configuration")],
    "Command and Control": [("T1071.001", "Web C2: HTTP")]
}

def map_to_mitre(strings):
    matches = []
    for s in strings:
        for tactic, techniques in tactic_techniques.items():
            for tid, name in techniques:
                if name.lower() in s.lower():
                    matches.append((tid, name, tactic))
    return list(set(matches))
