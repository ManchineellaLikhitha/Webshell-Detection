from flask import Flask, render_template, request, redirect, session, flash
import os
import sqlite3
from scanner import scan_file
from quarantine import quarantine_file
from vt_api import scan_virustotal
from safe_downloader import download_and_scan

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# === LOGIN ===
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('webshell.db')
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user'] = username
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

# === REGISTER ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fname = request.form['first_name']
        lname = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            return render_template('register.html', error="Passwords do not match")

        conn = sqlite3.connect('webshell.db')
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        if cur.fetchone():
            return render_template('register.html', error="Username already exists")
        cur.execute("INSERT INTO users (first_name, last_name, email, username, password) VALUES (?, ?, ?, ?, ?)",
                    (fname, lname, email, username, password))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('register.html')

# === DASHBOARD ===
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    conn = sqlite3.connect('webshell.db')
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scan_results WHERE status = 'clean'")
    clean = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_results WHERE status = 'malicious'")
    malicious = cur.fetchone()[0]
    total = clean + malicious
    cur.execute("SELECT filename, result, timestamp FROM scan_results ORDER BY timestamp DESC LIMIT 5")
    recent_results = cur.fetchall()
    conn.close()
    return render_template('dashboard.html', total=total, clean=clean, malicious=malicious, recent_results=recent_results)

# === UPLOAD SCAN ===
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect('/')
    if request.method == 'POST':
        uploaded_file = request.files['file']
        scan_method = request.form.get('scan_with', 'local')

        if uploaded_file.filename == '':
            flash("No file selected")
            return redirect('/upload')

        # Save to buffer
        buffer_path = os.path.join('buffer/uploads', uploaded_file.filename)
        os.makedirs(os.path.dirname(buffer_path), exist_ok=True)
        uploaded_file.save(buffer_path)

        # Run scan
        if scan_method == 'vt':
            result = scan_virustotal(buffer_path)
        else:
            result = scan_file(buffer_path)

        result_lower = result.lower()

        # Classify the scan result
        if result_lower.startswith("clean"):
            status = "clean"
            os.makedirs('uploads', exist_ok=True)
            os.replace(buffer_path, os.path.join('uploads', uploaded_file.filename))
        elif result_lower.startswith("⛔ malicious") or "malicious ✅" in result_lower:
            status = "malicious"
            quarantine_file(buffer_path)
        elif "timeout" in result_lower or "error" in result_lower or "failed" in result_lower:
            status = "error"
            if os.path.exists(buffer_path):
                os.remove(buffer_path)
        else:
            status = "unknown"
            if os.path.exists(buffer_path):
                os.remove(buffer_path)

        # Save to database (only known statuses)
        if status in ['clean', 'malicious', 'error']:
            conn = sqlite3.connect('webshell.db')
            cur = conn.cursor()
            cur.execute("INSERT INTO scan_results (filename, result, status) VALUES (?, ?, ?)",
                        (uploaded_file.filename, result, status))
            conn.commit()
            conn.close()

        flash(f"Scan Result: {result}")
        return redirect('/dashboard')

    return render_template('upload.html')

# === URL LINK SCAN ===
@app.route('/check_url', methods=['GET', 'POST'])
def check_url():
    if 'user' not in session:
        return redirect('/')
    if request.method == 'POST':
        file_url = request.form['file_url']
        result = download_and_scan(file_url)

        status = 'error'
        result_lower = result.lower()
        filename = file_url.split('/')[-1]

        if result_lower.startswith("clean"):
            status = "clean"
        elif result_lower.startswith("⛔ malicious") or "malicious ✅" in result_lower:
            status = "malicious"
        elif "timeout" in result_lower or "error" in result_lower or "failed" in result_lower:
            status = "error"
        else:
            status = "unknown"

        # Save only if valid status
        if status in ['clean', 'malicious', 'error']:
            conn = sqlite3.connect('webshell.db')
            cur = conn.cursor()
            cur.execute("INSERT INTO scan_results (filename, result, status) VALUES (?, ?, ?)",
                        (filename, result, status))
            conn.commit()
            conn.close()

        flash(f"Scan Result: {result}")
        return redirect('/dashboard')

    return render_template('check_url.html')

# === SCAN HISTORY ===
@app.route('/results')
def results():
    if 'user' not in session:
        return redirect('/')
    conn = sqlite3.connect('webshell.db')
    cur = conn.cursor()
    cur.execute("SELECT filename, result, timestamp FROM scan_results ORDER BY timestamp DESC")
    results = cur.fetchall()
    conn.close()
    return render_template('results.html', results=results)
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/')

    username = session['user']
    conn = sqlite3.connect('webshell.db')
    cur = conn.cursor()

    # Get user info
    cur.execute("SELECT first_name, last_name, email, username FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return "User not found"

    user_data = {
        "first_name": user_row[0],
        "last_name": user_row[1],
        "email": user_row[2],
        "username": user_row[3]
    }

    # Get stats
    cur.execute("SELECT COUNT(*) FROM scan_results WHERE status='clean'")
    clean = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_results WHERE status='malicious'")
    malicious = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_results WHERE status='error'")
    errors = cur.fetchone()[0]
    total = clean + malicious

    stats = {
        "total": total,
        "clean": clean,
        "malicious": malicious,
        "errors": errors
    }

    # Recent scans
    cur.execute("SELECT filename, result, timestamp FROM scan_results ORDER BY timestamp DESC LIMIT 5")
    recent_scans = cur.fetchall()
    conn.close()

    return render_template("profile.html", user_data=user_data, stats=stats, recent_scans=recent_scans)



# === LOGOUT ===
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
