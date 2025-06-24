import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import scan_file
from quarantine import quarantine_file
import os

class UploadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"Detected new file: {event.src_path}")
            result = scan_file(event.src_path)
            print(f"Scan result: {result}")
            if "Malicious" in result:
                quarantine_file(event.src_path)
                print("File quarantined due to malicious code.")


def start_watching():
    path = "uploads"
    event_handler = UploadHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=False)
    observer.start()
    print("🟢 Real-time scan watching started on /uploads")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()