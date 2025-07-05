
## MalVista
Malvista is a Streamlit-based interactive malware analysis framework.
It provides static analysis, VirusTotal enrichment, MITRE ATT&CK mapping,
IOC export, and risk scoring — all in one dashboard.

## 🚀 Features
- ✅ Upload `.exe` or `.dll` files (multiple uploads supported)
- 🔍 Extract PE imports and embedded strings
- 🔐 Calculate file hashes (MD5, SHA1, SHA256)
- 🧠 MITRE ATT&CK mapping from suspicious strings
- 🦠 VirusTotal integration (with API key)
- 📤 Export IOCs to CSV and PDF
- 📊 Risk assessment (High / Medium / Low)
- 🌙 Dark mode UI by default
- 🧪 Safe sample EXE/DLLs included for demo/testing



## 🛠️ Installation
1. Install dependencies:
```bash
   pip install -r requirements.txt
   ```
. Run the app:
```bash
   streamlit run app.py
   ```

## Usage:
- Launch the app in your browser.
- Upload a PE file (.exe or .dll).
- (Optional) Enter your VirusTotal API key for enrichment.
- View detailed analysis results in the dashboard.
- Export IOCs for further investigation.

## 📌 Notes:
- VirusTotal API key is required for querying VT. Get yours at https://www.virustotal.com.
- Always run malware analysis in a secure, isolated environment.

## ⚠️Legal Notice:
This tool is intended only for authorized testing and educational purposes.


