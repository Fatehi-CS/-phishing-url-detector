import os
import base64
import requests
from flask import Flask, render_template, request

app = Flask(__name__)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def analyze_url(url):
    warnings = []
    
    # Local Rule-Based Heuristics
    if url.startswith("http://"):
        warnings.append("Uses unencrypted HTTP protocol instead of HTTPS.")
    if "@" in url:
        warnings.append("Contains '@' symbol, often used to obscure the true destination.")
    if url.count("-") > 3:
        warnings.append("Domain contains multiple hyphens, a common phishing pattern.")
    if len(url) > 75:
        warnings.append("URL length is unusually long.")

    # VirusTotal API Global Check
    if not API_KEY:
        return "unknown", "Configuration Error: API Key is missing.", warnings

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(f"https://virustotal.com{url_id}", headers=headers)
        
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
            return "unknown", "UNKNOWN: URL not found in database yet. Proceed with caution.", warnings
        else:
            return "unknown", "Scan failed temporarily. Please try again later.", warnings
            
    except Exception:
        return "unknown", "Connection error while contacting the security server.", warnings

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        user_url = request.form.get("url", "").strip()
        if user_url:
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
