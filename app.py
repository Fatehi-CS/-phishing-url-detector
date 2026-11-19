from flask import Flask, render_template, request
import requests
import os
import base64
import re

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

def heuristic_url_check(url):
    reasons = []
    score = 0
    if not url.startswith("https://"):
        reasons.append("Uses unencrypted HTTP protocol instead of HTTPS.")
        score += 30
    if len(url) > 75:
        reasons.append("Excessive URL length (often used to hide malicious redirects).")
        score += 20
    if "@" in url or "-" in url.split("//")[-1].split("/"):
        reasons.append("Suspicious characters (@ or hyphens) in domain structure.")
        score += 25
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        reasons.append("Uses raw IP address instead of a standard domain name.")
        score += 35
    return score, reasons

@app.route("/", methods=["GET", "POST"])
def index():
    active_tab = "url"
    url_result = None
    ai_analysis = None
    error = None
    input_url = ""
    input_message = ""

    if request.method == "POST":
        scan_type = request.form.get("scan_type", "url")
        active_tab = scan_type

        if scan_type == "url":
            input_url = request.form.get("url", "").strip()
            if not input_url:
                error = "Please enter a valid URL to scan."
            else:
                if not input_url.startswith(("http://", "https://")):
                    input_url = "http://" + input_url
                
                h_score, h_reasons = heuristic_url_check(input_url)
                vt_malicious = 0
                vt_status = "Heuristic Check Only"

                if VIRUSTOTAL_API_KEY:
                    try:
                        url_id = base64.urlsafe_b64encode(input_url.encode()).decode().strip("=")
                        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                        vt_res = requests.get(f"https://virustotal.com{url_id}", headers=headers, timeout=8)
                        if vt_res.status_code == 200:
                            stats = vt_res.json()["data"]["attributes"]["last_analysis_stats"]
                            vt_malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                            vt_status = f"VirusTotal Flagged: {vt_malicious} security vendors"
                    except Exception:
                        vt_status = "VirusTotal fallback active (Heuristic used)"

                is_danger = (vt_malicious > 0) or (h_score >= 40)
                url_result = {
                    "url": input_url,
                    "is_danger": is_danger,
                    "vt_status": vt_status,
                    "reasons": h_reasons if h_reasons else ["No obvious structural anomalies detected."]
                }

        elif scan_type == "message":
            input_message = request.form.get("message", "").strip()
            if not input_message:
                error = "Please paste a suspicious email, WhatsApp, or SMS text."
            elif not GEMINI_API_KEY:
                error = "GEMINI_API_KEY is not configured in server environment variables."
            else:
                try:
                    api_url = f"https://googleapis.com{GEMINI_API_KEY}"
                    prompt = (
                        "You are an expert Cybersecurity & Phishing Analyst. Analyze the following message/email for scam, phishing, or social engineering tactics. "
                        "Reply in the SAME language as the message (Arabic or English). Structure your report clearly:\n"
                        "1. Verdict (Safe / Suspicious / High-Risk Phishing)\n"
                        "2. Risk Level (0% - 100%)\n"
                        "3. Detected Red Flags\n"
                        "4. Security Advice\n\n"
                        f"Message:\n{input_message}"
                    )
                    res = requests.post(api_url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=15)
                    data = res.json()
                    if "candidates" in data and len(data["candidates"]) > 0:
                        ai_analysis = data["candidates"]["content"]["parts"]["text"]
                    else:
                        error = "AI engine could not process the request right now."
                except Exception:
                    error = "Network error while connecting to AI engine."

    return render_template("index.html", active_tab=active_tab, url_result=url_result, ai_analysis=ai_analysis, error=error, input_url=input_url, input_message=input_message)

if __name__ == "__main__":
    app.run(debug=True)
