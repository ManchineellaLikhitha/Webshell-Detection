from vt_api import scan_virustotal_bytes
import os, requests
from io import BytesIO

def download_and_scan(url):
    try:
        filename = url.split("/")[-1]
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return f"❌ Failed to fetch file: Status code {response.status_code}"

        buffer_path = os.path.join("buffer/url", filename)
        os.makedirs(os.path.dirname(buffer_path), exist_ok=True)

        with open(buffer_path, "wb") as f:
            f.write(response.content)

        result = scan_virustotal_bytes(BytesIO(response.content), filename)
        return result

    except Exception as e:
        return f"❌ Error: {e}"
