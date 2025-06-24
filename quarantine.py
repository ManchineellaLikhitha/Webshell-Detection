# === quarantine.py ===
import os
import shutil
import time

def quarantine_file(filepath):
    quarantine_dir = 'quarantine'
    os.makedirs(quarantine_dir, exist_ok=True)
    filename = os.path.basename(filepath)
    destination = os.path.join(quarantine_dir, filename)

    # Try moving with retries in case the file is locked
    for attempt in range(3):
        try:
            shutil.move(filepath, destination)
            print(f"[Quarantine] File moved: {destination}")
            break
        except PermissionError:
            print(f"[Retry {attempt+1}/3] File in use, retrying...")
            time.sleep(1)
        except Exception as e:
            print(f"[Error] Could not quarantine: {e}")
            break

def delete_quarantined_file(filename):
    path = os.path.join('quarantine', filename)
    if os.path.exists(path):
        os.remove(path)
        print(f"[Quarantine] Deleted: {path}")
