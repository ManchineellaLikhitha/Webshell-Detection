# 🛡️ WebShell Detector — Malicious File Scanner

A smart and modern web application built using Flask for scanning files before they enter your system. It uses both **local scanning** (pattern-based) and **VirusTotal API** for powerful dynamic threat detection.

---

## 📌 Features

- 🔐 User Authentication (Register/Login)
- 📂 Upload and scan files via local or VirusTotal method
- 🔗 Scan download links before downloading to the system
- 🦠 Detects malicious code patterns and counts them
- 📊 Dashboard with dynamic charts (Chart.js)
- 👤 Profile page with user's scan history
- 🧾 Full scan history with timestamps
- ⚠️ Quarantine system to isolate malicious files
- 🗂️ Buffer uploads for safe preview
- ✨ Stylish dark theme UI with Bootstrap

---

## 💻 Tech Stack

| Category         | Technologies                      |
|------------------|-----------------------------------|
| Backend          | Flask, Python, SQLite             |
| Frontend         | HTML5, CSS3, Bootstrap 5, Chart.js |
| External API     | [VirusTotal API](https://www.virustotal.com/) |
| File Handling    | Watchdog, OS, shutil              |

---

## 🚀 Getting Started

### 1. Clone this Repo

```bash
git clone https://github.com/yourusername/webshell-detector.git
cd webshell-detector
```
### 2. Set Up Environment
```bash
python -m venv venv
venv\Scripts\activate      # For Windows
pip install -r requirements.txt
```
### 3. Set Your VirusTotal API Key
```bash
API_KEY = 'your_virustotal_api_key'
```
### 4.Run the App
```bash
python app.py
```
---
### Sample URL's to Test
| URL                                                 | Description               |
| --------------------------------------------------- | ------------------------- |
| `https://www.eicar.org/download/eicar.com`          | Standard EICAR test virus |
| `https://www.africau.edu/images/default/sample.pdf` | Safe test PDF             |
| `https://www.w3.org/TR/PNG/iso_8859-1.txt`          | Safe text file            |

---
### 🧠 Project Highlights
- Uses real-time VirusTotal API for trusted malware reports
- Implements quarantine folder for isolation
- Scan results are visualized and saved in database
- Profile dashboard to track user activity
---
### Project Structure
```bash
webshell-detector/
│
├── app.py
├── scanner.py
├── vt_api.py
├── quarantine.py
├── safe_downloader.py
├── utils/
│   └── ...helper functions
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── results.html
│   ├── check_url.html
│   └── profile.html
├── static/
│   ├── css/
│   ├── js/
│   └── screenshots/
├── uploads/
├── quarantine/
├── buffer/
├── webshell.db
└── README.md
```
### ✍️ Resume Points
- Built a complete web app that detects malicious code/files using Flask and VirusTotal API.
- Implemented dashboard, user profiles, and scanning system with real-time analytics and quarantine logic.
- Integrated chart visualizations and dynamic scanning using both local logic and external malware engines.
 ---
