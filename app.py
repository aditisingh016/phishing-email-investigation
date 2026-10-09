
import csv
import hashlib
import io
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html import escape
from urllib.parse import urlparse

from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB limit

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard | Email Investigation</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#131b2e;--line:#293651;
--text:#eef3ff;--muted:#a4b1cb;--blue:#6da8ff;--red:#ff7185;--green:#6de0b1}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:22px max(5%,calc((100% - 1120px)/2));border-bottom:1px solid var(--line);
display:flex;justify-content:space-between;align-items:center;gap:16px}
.brand{font-size:23px;font-weight:800;letter-spacing:-.7px}
.brand span{color:var(--blue)}
header small,.muted{color:var(--muted)}
main{max-width:1120px;margin:42px auto;padding:0 22px}
h1{font-size:clamp(30px,5vw,48px);line-height:1.12;margin:12px 0}
h2{font-size:20px;margin:0 0 12px}
p{color:var(--muted)}
.eyebrow{color:var(--blue);font-weight:700;text-transform:uppercase;letter-spacing:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin:22px 0}
label{display:block;font-weight:700;margin:14px 0 8px}
textarea,input[type=file]{width:100%;background:#0b1223;color:var(--text);
border:1px solid var(--line);border-radius:10px;padding:14px}
textarea{min-height:180px;resize:vertical}
button,.download{display:inline-block;background:var(--blue);color:#071225;
border:0;border-radius:10px;padding:12px 18px;font-weight:800;cursor:pointer;
text-decoration:none;margin:10px 8px 0 0}
button:hover,.download:hover{filter:brightness(1.08)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.metric{background:#0b1223;border:1px solid var(--line);border-radius:12px;padding:16px}
.metric strong{display:block;font-size:22px;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);
overflow-wrap:anywhere}
th{color:var(--muted)}
.tag{display:inline-block;padding:5px 10px;border-radius:20px;
background:#34202b;color:#ffb1bd;font-weight:800}
.notice{border-left:3px solid var(--blue);padding:10px 14px;background:#0b1223}
footer{text-align:center;color:var(--muted);padding:24px}
code{overflow-wrap:anywhere}
@media(max-width:600px){header{align-items:flex-start;flex-direction:column}
.panel{padding:17px}main{margin-top:25px}}
</style>
</head>
<body>
<header>
  <div class="brand">🛡️ Phish<span>Guard</span></div>
  <small>EMAIL THREAT INVESTIGATION</small>
</header>
<main>
  <div class="eyebrow">Security analysis workspace</div>
  <h1>Investigate suspicious emails.</h1>
  <p>Analyze email indicators, review available authentication evidence,
  calculate file integrity hashes, and generate an investigation report.</p>

  <section class="panel">
    <h2>Analyze an email</h2>
    <p>Upload an .eml file or paste the complete raw email, including its headers.
    Files are analyzed in memory and are not intentionally saved as uploaded files.</p>
    <form action="/analyze" method="post" enctype="multipart/form-data">
      <label for="email_file">Upload email (.eml, maximum 1 MB)</label>
      <input id="email_file" type="file" name="email_file" accept=".eml,message/rfc822">
      <label for="raw_email">Or paste raw email content</label>
      <textarea id="raw_email" name="raw_email"
      placeholder="From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Example&#10;&#10;Email body..."></textarea>
      <button type="submit">Analyze email →</button>
    </form>
  </section>

  {% if error %}
  <section class="panel"><h2>Unable to analyze</h2><p>{{ error }}</p></section>
  {% endif %}

  {% if result %}
  <section class="panel">
    <div class="eyebrow">Investigation result</div>
    <h2>{{ result.verdict }}</h2>
    <p>{{ result.summary }}</p>
    <div class="grid">
      <div class="metric"><span class="muted">Indicators found</span>
        <strong>{{ result.ioc_count }}</strong></div>
      <div class="metric"><span class="muted">SHA-256</span>
        <strong style="font-size:13px">{{ result.sha256 }}</strong></div>
      <div class="metric"><span class="muted">SPF</span>
        <strong>{{ result.auth.SPF }}</strong></div>
      <div class="metric"><span class="muted">DKIM</span>
        <strong>{{ result.auth.DKIM }}</strong></div>
      <div class="metric"><span class="muted">DMARC</span>
        <strong>{{ result.auth.DMARC }}</strong></div>
    </div>
    <p class="notice">Authentication values are taken from an existing
    Authentication-Results header when available. This tool does not independently
    verify DNS records or cryptographic DKIM signatures.</p>
  </section>

  <section class="panel">
    <h2>Indicators of compromise</h2>
    {% if result.iocs %}
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Type</th><th>Indicator</th></tr></thead>
      <tbody>{% for item in result.iocs %}
      <tr><td>{{ item.type }}</td><td><code>{{ item.value }}</code></td></tr>
      {% endfor %}</tbody>
    </table></div>
    {% else %}<p>No email addresses, domains, or URLs were extracted.</p>{% endif %}
    <a class="download" href="/download/iocs">Download IOCs (CSV)</a>
  </section>

  <section class="panel">
    <h2>Investigation evidence</h2>
    <p><b>Subject:</b> {{ result.subject or "(no subject)" }}</p>
    <p><b>From:</b> {{ result.sender or "(not provided)" }}</p>
    <p><b>Analysis time (UTC):</b> {{ result.timestamp }}</p>
    <h2>Investigation timeline</h2>
    <p>1. Email content received for analysis.</p>
    <p>2. Headers, URLs, email addresses and domains examined.</p>
    <p>3. Available authentication results reviewed.</p>
    <p>4. SHA-256 calculated and report generated.</p>
    <h2>MITRE ATT&CK reference</h2>
    <p><b>T1566 — Phishing:</b> relevant as an investigation reference when
    evidence supports a phishing attempt. This mapping alone does not prove
    that the technique occurred.</p>
    <a class="download" href="/download/report">Download investigation report</a>
  </section>
  {% endif %}
  <p class="notice">Use authorized sample emails only. This is a triage aid,
  not a guarantee of maliciousness. A URL or keyword alone does not prove phishing.</p>
</main>
<footer>PhishGuard · Educational cybersecurity investigation project</footer>
</body>
</html>
"""


# The latest analysis is kept in process memory for the demo's download links.
# Use a proper per-user storage design before supporting multiple users in production.
latest_result = None


def analyze_email(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    text_parts = []
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            try:
                content = part.get_content()
                if isinstance(content, str):
                    text_parts.append(content)
            except (LookupError, UnicodeError, ValueError):
                pass

    body = "\n".join(text_parts)
    content = raw.decode("utf-8", errors="replace")
    combined = content + "\n" + body

    # Remove common trailing punctuation from extracted URLs.
    urls = set(re.findall(r'https?://[^\s<>"\']+', combined, re.I))
    urls = {u.rstrip(".,;:!?)\\]}") for u in urls}
    emails = set(re.findall(
        r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', combined
    ))

    domains = set()
    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()
            if host:
                domains.add(host)
        except ValueError:
            pass
    for email in emails:
        domains.add(email.rsplit("@", 1)[1].lower())

    iocs = []
    iocs += [{"type": "URL", "value": value} for value in sorted(urls)]
    iocs += [{"type": "Email address", "value": value} for value in sorted(emails)]
    iocs += [{"type": "Domain", "value": value} for value in sorted(domains)]

    auth_header = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    auth = {}
    for name in ("SPF", "DKIM", "DMARC"):
        match = re.search(r'\b' + name.lower() + r'\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)', auth_header, re.I)
        auth[name] = match.group(1).upper() if match else "Not provided"

    # Transparent heuristic: findings are indicators, not a definitive verdict.
    suspicious_terms = (
        "verify your account", "password expires", "urgent action",
        "account suspended", "confirm your password", "click here"
    )
    lower = combined.lower()
    reasons = []
    if urls:
        reasons.append(f"{len(urls)} URL(s) found")
    if any(term in lower for term in suspicious_terms):
        reasons.append("urgency or account-verification language found")
    if any(auth[name] in ("FAIL", "SOFTFAIL", "PERMERROR") for name in auth):
        reasons.append("an authentication failure is recorded in the supplied header")

    if reasons:
        verdict = "REVIEW — potential phishing indicators"
        summary = "Signals requiring human review: " + "; ".join(reasons) + "."
    else:
        verdict = "NO OBVIOUS INDICATORS FOUND"
        summary = "The basic checks did not find the configured indicators. This does not prove the email is safe."

    return {
        "verdict": verdict,
        "summary": summary,
        "ioc_count": len(iocs),
        "iocs": iocs,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "subject": str(message.get("Subject", "")),
        "sender": str(message.get("From", "")),
        "auth": auth,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "raw_size": len(raw),
    }


@app.get("/")
def index():
    return render_template_string(PAGE, result=None, error=None)


@app.post("/analyze")
def analyze():
    global latest_result
    uploaded = request.files.get("email_file")
    pasted = request.form.get("raw_email", "").strip()

    if uploaded and uploaded.filename:
        if not uploaded.filename.lower().endswith(".eml"):
            return render_template_string(
                PAGE, result=None, error="Please upload a .eml file."
            ), 400
        raw = uploaded.read(1_048_577)
    else:
        raw = pasted.encode("utf-8")

    if not raw:
        return render_template_string(
            PAGE, result=None, error="Upload an .eml file or paste email content."
        ), 400
    if len(raw) > 1_048_576:
        return render_template_string(
            PAGE, result=None, error="The email exceeds the 1 MB size limit."
        ), 413

    try:
        latest_result = analyze_email(raw)
    except Exception:
        return render_template_string(
            PAGE, result=None,
            error="The email could not be parsed. Check the raw email format and try again."
        ), 400

    return render_template_string(PAGE, result=latest_result, error=None)


@app.get("/download/iocs")
def download_iocs():
    if latest_result is None:
        return "Analyze an email first.", 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "indicator"])
    for item in latest_result["iocs"]:
        writer.writerow([item["type"], item["value"]])
    data = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(data, mimetype="text/csv", as_attachment=True,
                     download_name="iocs.csv")


@app.get("/download/report")
def download_report():
    if latest_result is None:
        return "Analyze an email first.", 400
    r = latest_result
    lines = [
        "# PhishGuard Email Investigation Report",
        "",
        f"- Analysis time: {r['timestamp']}",
        f"- Subject: {r['subject'] or '(no subject)'}",
        f"- Sender: {r['sender'] or '(not provided)'}",
        f"- Verdict: {r['verdict']}",
        f"- Summary: {r['summary']}",
        f"- SHA-256: {r['sha256']}",
        "",
        "## Authentication evidence",
    ]
    lines += [f"- {k}: {v}" for k, v in r["auth"].items()]
    lines += ["", "## Indicators of compromise"]
    lines += [f"- {item['type']}: {item['value']}" for item in r["iocs"]]
    lines += [
        "", "## MITRE ATT&CK reference",
        "- T1566 — Phishing (reference only; applicability requires analyst review).",
        "", "## Limitations",
        "- This report uses basic pattern-based checks, not a trained detection model.",
        "- SPF, DKIM and DMARC are read from supplied Authentication-Results headers only.",
        "- No URL reputation, sandboxing or independent DNS verification is performed.",
        "- A verdict is a triage suggestion, not proof of maliciousness.",
    ]
    data = io.BytesIO("\n".join(lines).encode("utf-8"))
    return send_file(data, mimetype="text/markdown", as_attachment=True,
                     download_name="investigation_report.md")


@app.errorhandler(413)
def too_large(_error):
    return "Upload exceeds the 1 MB limit.", 413


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
