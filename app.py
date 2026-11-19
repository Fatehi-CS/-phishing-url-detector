from flask import Flask, render_template, request
import requests
import os
import base64
import re

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

def heuristic_url_check(url):
    reasons = []
    score = 0
    if not url.startswith("https://"):
        reasons.append("Uses unencrypted HTTP protocol instead of HTTPS.")
        score += 30
    if len(url) > 75:
        reasons.append("Excessive URL length (often used to hide malicious redirects).")
        score += 20
    domain_part = url.split("//")[-1].split("/")[0]
    if "@" in url or "-" in domain_part:
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
                        vt_endpoint = "https://virustotal.com" + "/api/v3/urls/" + url_id
                        vt_res = requests.get(vt_endpoint, headers=headers, timeout=8)
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
            elif not OPENROUTER_API_KEY:
                error = "OPENROUTER_API_KEY is not configured in server environment variables."
            else:
                try:
                    api_url = "https://openrouter.ai" + "/api/v1/chat/completions"
                    headers = {
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://vercel.app",
                        "X-Title": "Digital Shield"
                    }
                    prompt = (
                        "You are an expert Cybersecurity & Phishing Analyst for 'Digital Shield'. Analyze the following message/email for scam, phishing, or social engineering tactics. "
                        "Reply in the SAME language as the message (Arabic or English). Structure your report clearly:\n"
                        "1. Verdict (Safe / Suspicious / High-Risk Phishing)\n"
                        "2. Risk Level (0% - 100%)\n"
                        "3. Detected Red Flags\n"
                        "4. Security Advice\n\n"
                        f"Message:\n{input_message}"
                    )
                    payload = {
                        "model": "openrouter/free",
                        "messages": [{"role": "user", "content": prompt}]
                    }
                    res = requests.post(api_url, headers=headers, json=payload, timeout=20)
                    data = res.json()
                    if "choices" in data and len(data["choices"]) > 0:
                        ai_analysis = data["choices"][0]["message"]["content"]
                    else:
                        err_msg = data.get("error", {}).get("message", "Unknown API response")
                        error = f"AI engine error: {err_msg}"
                except Exception:
                    error = "Network error while connecting to AI engine."

    return render_template("index.html", active_tab=active_tab, url_result=url_result, ai_analysis=ai_analysis, error=error, input_url=input_url, input_message=input_message)

if __name__ == "__main__":
    app.run(debug=True)
