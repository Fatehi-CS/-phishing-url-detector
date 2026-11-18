import os
import base64
import requests
from flask import Flask, render_template, request

app = Flask(__name__)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def analyze_url(url):
    warnings = []
    
    if url.startswith("http://"):
        warnings.append("Uses unencrypted HTTP protocol instead of HTTPS.")
    if "@" in url:
        warnings.append("Contains '@' symbol, often used to obscure the true destination.")
    if url.count("-") > 3:
        warnings.append("Domain contains multiple hyphens, a common phishing pattern.")
    if len(url) > 75:
        warnings.append("URL length is unusually long.")

    if not API_KEY:
        return "unknown", "Configuration Error: API Key is missing.", warnings

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {
        "x-apikey": API_KEY,
        "User-Agent": "PhishingDetectorApp/1.0"
    }

    try:
        base_vt = "https://virustotal.com"
        response = requests.get(base_vt + url_id, headers=headers, timeout=5)
        
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0 or suspicious > 0:
                total_flags = malicious + suspicious
                return "danger", f"DANGER! Flagged as malicious or suspicious by {total_flags} security vendors.", warnings
            else:
                return "safe", "SAFE: No malicious activity detected across global databases.", warnings
        elif response.status_code == 404:
            if len(warnings) >= 2:
                return "danger", "SUSPICIOUS: URL not in database and shows multiple phishing indicators.", warnings
            return "unknown", "NOTICE: URL not found in database yet. Proceed with caution.", warnings
        else:
            return "unknown", f"Scan notice (Status: {response.status_code}). Relying on heuristic check.", warnings
            
    except Exception:
        if len(warnings) > 0:
            return "danger", "HEURISTIC ALERT: Potential phishing indicators detected locally.", warnings
        return "safe", "HEURISTIC CHECK PASSED: No obvious phishing patterns detected.", warnings

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        user_url = request.form.get("url", "").strip()
        if user_url:
            if not user_url.startswith(("http://", "https://")):
                user_url = "http://" + user_url
            status, message, warnings = analyze_url(user_url)
            result = {
                "status": status,
                "message": message,
                "warnings": warnings,
                "url": user_url
            }
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
