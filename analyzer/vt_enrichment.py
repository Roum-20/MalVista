import requests

def query_virustotal(sha256_hash, api_key):
    if not api_key:
        return {}
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
    except Exception as e:
        print(f"VT query error: {e}")
    return {}
