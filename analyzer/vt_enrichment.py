import vt
from vt.error import APIError

def enrich_virustotal(file_path, api_key):
    try:
        with vt.Client(api_key) as client:
            with open(file_path, "rb") as f:
                print("🚀 Submitting file to VirusTotal...")
                analysis = client.scan_file(f, wait_for_completion=True)
                print("✅ Scan completed. Fetching results...")

                # Get analysis results using analysis ID
                analysis_id = analysis.id
                result = client.get_object(f"/analyses/{analysis_id}")
                return result.to_dict()

    except APIError as e:
        if "Wrong credentials" in str(e):
            print("❌ Invalid API Key for VirusTotal.")
        else:
            print(f"❌ VirusTotal API error: {e}")
        return None
    except Exception as ex:
        print(f"❌ Unexpected error: {ex}")
        return None

