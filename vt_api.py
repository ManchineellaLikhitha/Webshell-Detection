import requests
import os
import time

API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": API_KEY}
upload_url = "https://www.virustotal.com/api/v3/files"

# 1. Scan a file from disk (used in upload)
def scan_virustotal(filepath):
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        res = requests.post(upload_url, headers=headers, files=files)

    if res.status_code != 200:
        return f"❌ VirusTotal API error: {res.status_code}"

    return fetch_vt_results(res.json()['data']['id'])

# 2. Scan a file from memory (used in URL scanning)
def scan_virustotal_bytes(file_obj, filename):
    files = {"file": (filename, file_obj)}
    res = requests.post(upload_url, headers=headers, files=files)

    if res.status_code != 200:
        return f"❌ VirusTotal API error: {res.status_code}"

    return fetch_vt_results(res.json()['data']['id'])

# 3. Shared function to fetch result
def fetch_vt_results(file_id):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    for _ in range(15):  # up to 30 seconds
        time.sleep(2)
        res = requests.get(analysis_url, headers=headers).json()
        if res['data']['attributes']['status'] == 'completed':
            stats = res['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            if malicious > 0 or suspicious > 0:
                return f"⛔ Malicious ✅ | Engines flagged: {malicious + suspicious}"
            return "Clean ✅ | VirusTotal reports 0 malicious engines"
    return "Scan timeout ❌"
