import vt
import time
import streamlit as st

def enrich_virustotal(file_path, api_key):
    try:
        client = vt.Client(api_key)

        with open(file_path, "rb") as f:
            analysis = client.scan_file(f)

        analysis_id = analysis.id
        while True:
            analysis = client.get_object(f"/analyses/{analysis_id}")
            if analysis.status == "completed":
                break
            time.sleep(5)

        sha256 = analysis.meta["file_info"]["sha256"]
        file_obj = client.get_object(f"/files/{sha256}")
        client.close()

        return {
            "malicious": file_obj.stats.get("malicious", 0),
            "suspicious": file_obj.stats.get("suspicious", 0),
            "undetected": file_obj.stats.get("undetected", 0),
            "permalink": f"https://www.virustotal.com/gui/file/{file_obj.id}"
        }

    except vt.error.WrongCredentialsError:
        client.close()
        st.error("❌ Invalid VirusTotal API key. Please check and re-enter it.")
        return None

    except vt.error.APIError as e:
        client.close()
        st.error(f"❌ VirusTotal API error: {str(e)}")
        return None

    except Exception as e:
        client.close()
        st.error(f"⚠️ Unexpected error: {e}")
        return None
