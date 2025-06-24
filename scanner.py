# === scanner.py (optional local fallback scanner) ===
import re

MALICIOUS_PATTERNS = [
    r'(?<![#/])\beval\s*\(',
    r'(?<![#/])\bsystem\s*\(',
    r'(?<![#/])\bexec\s*\(',
    r'(?<![#/])\bbase64_decode\s*\(',
    r'(?<![#/])\bshell_exec\s*\(',
    r'(?<![#/])\bpassthru\s*\(',
    r'(?<![#/])cmd\.exe',
    r'(?<![#/])os\.popen'
]

MALICIOUS_WORDS = [
    "eval", "exec", "base64", "shell", "system", "passthru", "cmd", "os"
]

def scan_file(filepath):
    detected_patterns = []
    matched_words = {}

    try:
        with open(filepath, 'r', errors='ignore') as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                code_line = line.strip()
                for pattern in MALICIOUS_PATTERNS:
                    if re.search(pattern, code_line, re.IGNORECASE):
                        detected_patterns.append(f"Line {i+1}: {pattern}")

                for word in MALICIOUS_WORDS:
                    count = len(re.findall(rf'\b{word}\b', code_line, re.IGNORECASE))
                    if count > 0:
                        matched_words[word] = matched_words.get(word, 0) + count

    except Exception as e:
        return f"Scan error: {e}"

    if detected_patterns:
        result = "Malicious ✅"
        result += " | Patterns: " + ", ".join(detected_patterns)
        if matched_words:
            word_details = ", ".join([f"{w}({c})" for w, c in matched_words.items()])
            result += f" | Malicious words: {word_details}"
        return result
    elif matched_words:
        return f"Clean ✅ | Malicious word count: {sum(matched_words.values())}"
    else:
        return "Clean ✅ | No threats found"
