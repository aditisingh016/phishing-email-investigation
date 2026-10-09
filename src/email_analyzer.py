import re
import sys
from pathlib import Path
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

REPORT_DIR = Path("reports")


# ============================================================
# EMAIL LOADING
# ============================================================

def load_email(email_path):
    """Load an .eml file."""

    with open(email_path, "rb") as file:
        return BytesParser(
            policy=policy.default
        ).parse(file)


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """Extract URLs from email content."""

    pattern = r"https?://[^\s<>\"']+"

    return re.findall(pattern, text)


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url):
    """Extract domain from URL."""

    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return "Unknown"


# ============================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================

def extract_email_domain(address):
    """Extract domain from an email address."""

    match = re.search(
        r"@([A-Za-z0-9.-]+)",
        address
    )

    if match:
        return match.group(1).lower()

    return "Unknown"


# ============================================================
# SOCIAL ENGINEERING ANALYSIS
# ============================================================

def analyze_social_engineering(text):

    indicators = []

    text_lower = text.lower()

    urgency_keywords = [
        "urgent",
        "immediately",
        "within 30 minutes",
        "action required",
        "verify immediately",
        "suspended",
        "security alert",
        "unusual sign-in"
    ]

    credential_keywords = [
        "verify your account",
        "login",
        "password",
        "credentials",
        "sign in",
        "account verification"
    ]

    fear_keywords = [
        "account will be suspended",
        "unauthorized access",
        "security risk",
        "unusual activity",
        "did not initiate"
    ]

    for keyword in urgency_keywords:

        if keyword in text_lower:

            indicators.append(
                f"Urgency / time pressure: '{keyword}'"
            )

    for keyword in credential_keywords:

        if keyword in text_lower:

            indicators.append(
                f"Credential harvesting language: '{keyword}'"
            )

    for keyword in fear_keywords:

        if keyword in text_lower:

            indicators.append(
                f"Fear / threat language: '{keyword}'"
            )

    return indicators


# ============================================================
# HEADER ANALYSIS
# ============================================================

def analyze_headers(message):

    findings = []

    sender = message.get(
        "From",
        "Unknown"
    )

    reply_to = message.get(
        "Reply-To",
        "Not present"
    )

    return_path = message.get(
        "Return-Path",
        "Not present"
    )

    authentication = message.get(
        "Authentication-Results",
        "Not present"
    )

    sender_domain = extract_email_domain(
        sender
    )

    reply_domain = extract_email_domain(
        reply_to
    )

    authentication_lower = authentication.lower()

    if sender_domain != reply_domain:

        findings.append(
            "Sender and Reply-To domains differ."
        )

    if "spf=fail" in authentication_lower:

        findings.append(
            "SPF authentication failed."
        )

    if "dkim=fail" in authentication_lower:

        findings.append(
            "DKIM authentication failed."
        )

    if "dmarc=fail" in authentication_lower:

        findings.append(
            "DMARC authentication failed."
        )

    return {
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "sender_domain": sender_domain,
        "reply_domain": reply_domain,
        "authentication": authentication,
        "findings": findings
    }


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_urls(urls):

    findings = []

    for url in urls:

        domain = extract_domain(url)

        parsed = urlparse(url)

        path = parsed.path.lower()

        query = parsed.query.lower()

        suspicious_words = [
            "login",
            "verify",
            "verification",
            "account",
            "secure",
            "password",
            "session"
        ]

        matched_words = []

        for word in suspicious_words:

            if word in path or word in query:

                matched_words.append(word)

        if matched_words:

            findings.append(
                f"Suspicious URL behavior detected for "
                f"{domain}: {', '.join(matched_words)}"
            )

        # Detect unusual long query strings
        if len(query) > 40:

            findings.append(
                f"URL contains a long query string: {domain}"
            )

    return findings


# ============================================================
# SEVERITY ASSESSMENT
# ============================================================

def calculate_severity(
    header_findings,
    url_findings,
    social_findings
):

    score = 0

    score += len(header_findings) * 3
    score += len(url_findings) * 2
    score += len(social_findings)

    if score >= 12:

        severity = "CRITICAL"

    elif score >= 8:

        severity = "HIGH"

    elif score >= 4:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    return severity, score


# ============================================================
# IMPACT ASSESSMENT
# ============================================================

def assess_impact(
    header_findings,
    url_findings,
    social_findings
):

    impacts = []

    if header_findings:

        impacts.append(
            "Potential sender impersonation."
        )

    if url_findings:

        impacts.append(
            "Potential credential harvesting."
        )

    if social_findings:

        impacts.append(
            "Potential user manipulation through "
            "social-engineering techniques."
        )

    if header_findings and url_findings:

        impacts.append(
            "Potential Microsoft 365 account compromise."
        )

        impacts.append(
            "Potential unauthorized access to "
            "corporate resources."
        )

    if not impacts:

        impacts.append(
            "No significant impact identified."
        )

    return impacts


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(
    email_path,
    message,
    header_data,
    urls,
    url_findings,
    social_findings,
    severity,
    score,
    impacts
):

    REPORT_DIR.mkdir(
        exist_ok=True
    )

    report_path = REPORT_DIR / "automated_investigation_report.md"

    sender = header_data["sender"]
    reply_to = header_data["reply_to"]
    return_path = header_data["return_path"]

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "# Phishing Email Investigation Report\n\n"
        )

        report.write(
            "## 1. Evidence\n\n"
        )

        report.write(
            f"- Evidence file: `{email_path}`\n"
        )

        report.write(
            "- Investigation type: Simulated phishing email analysis\n\n"
        )

        report.write(
            "## 2. Sender Analysis\n\n"
        )

        report.write(
            f"- From: `{sender}`\n"
        )

        report.write(
            f"- Reply-To: `{reply_to}`\n"
        )

        report.write(
            f"- Return-Path: `{return_path}`\n"
        )

        report.write(
            f"- Sender domain: `{header_data['sender_domain']}`\n"
        )

        report.write(
            f"- Reply-To domain: `{header_data['reply_domain']}`\n\n"
        )

        report.write(
            "## 3. Authentication Analysis\n\n"
        )

        report.write(
            f"```\n{header_data['authentication']}\n```\n\n"
        )

        if header_data["findings"]:

            for finding in header_data["findings"]:

                report.write(
                    f"- {finding}\n"
                )

        else:

            report.write(
                "- No major authentication anomalies detected.\n"
            )

        report.write("\n")

        report.write(
            "## 4. URL Analysis\n\n"
        )

        if urls:

            for url in urls:

                report.write(
                    f"- `{url}`\n"
                )

        else:

            report.write(
                "- No URLs detected.\n"
            )

        report.write("\n")

        if url_findings:

            report.write(
                "### URL Indicators\n\n"
            )

            for finding in url_findings:

                report.write(
                    f"- {finding}\n"
                )

            report.write("\n")

        report.write(
            "## 5. Social Engineering Indicators\n\n"
        )

        if social_findings:

            for finding in social_findings:

                report.write(
                    f"- {finding}\n"
                )

        else:

            report.write(
                "- No obvious social-engineering indicators detected.\n"
            )

        report.write("\n")

        report.write(
            "## 6. Severity Assessment\n\n"
        )

        report.write(
            f"**Severity: {severity}**\n\n"
        )

        report.write(
            f"Risk score: **{score}**\n\n"
        )

        report.write(
            "## 7. Potential Impact\n\n"
        )

        for impact in impacts:

            report.write(
                f"- {impact}\n"
            )

        report.write("\n")

        report.write(
            "## 8. Investigation Verdict\n\n"
        )

        report.write(
            "The email exhibits multiple characteristics "
            "consistent with a phishing attempt. "
            "The identified indicators include authentication "
            "failures, suspicious URL characteristics, and "
            "social-engineering techniques.\n\n"
        )

        report.write(
            "**Recommended classification: PHISHING**\n"
        )

    return report_path


# ============================================================
# MAIN INVESTIGATION
# ============================================================

def investigate_email(email_path):

    print("\n" + "=" * 70)

    print(
        "              PHISHING EMAIL INVESTIGATION"
    )

    print("=" * 70)

    message = load_email(email_path)

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    print("\n[1] SENDER & HEADER ANALYSIS")
    print("-" * 70)

    header_data = analyze_headers(
        message
    )

    print(
        f"From       : {header_data['sender']}"
    )

    print(
        f"Reply-To   : {header_data['reply_to']}"
    )

    print(
        f"Return-Path: {header_data['return_path']}"
    )

    print(
        f"Sender domain: {header_data['sender_domain']}"
    )

    print(
        f"Reply-To domain: {header_data['reply_domain']}"
    )

    for finding in header_data["findings"]:

        print(
            f"WARNING: {finding}"
        )

    # --------------------------------------------------------
    # Email body
    # --------------------------------------------------------

    body = message.get_body(
        preferencelist=("plain", "html")
    )

    if body:

        body_text = body.get_content()

    else:

        body_text = ""

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    print("\n[2] URL & DOMAIN ANALYSIS")
    print("-" * 70)

    urls = extract_urls(
        body_text
    )

    if urls:

        for url in urls:

            print(
                f"URL: {url}"
            )

            print(
                f"Domain: {extract_domain(url)}"
            )

    else:

        print(
            "No URLs detected."
        )

    url_findings = analyze_urls(
        urls
    )

    for finding in url_findings:

        print(
            f"WARNING: {finding}"
        )

    # --------------------------------------------------------
    # Social engineering
    # --------------------------------------------------------

    print(
        "\n[3] SOCIAL ENGINEERING ANALYSIS"
    )

    print("-" * 70)

    social_findings = analyze_social_engineering(
        body_text
    )

    if social_findings:

        for finding in social_findings:

            print(
                f"- {finding}"
            )

    else:

        print(
            "No obvious social-engineering indicators detected."
        )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity, score = calculate_severity(
        header_data["findings"],
        url_findings,
        social_findings
    )

    print(
        "\n[4] SEVERITY ASSESSMENT"
    )

    print("-" * 70)

    print(
        f"Risk score: {score}"
    )

    print(
        f"Severity: {severity}"
    )

    # --------------------------------------------------------
    # Impact
    # --------------------------------------------------------

    impacts = assess_impact(
        header_data["findings"],
        url_findings,
        social_findings
    )

    print(
        "\n[5] POTENTIAL IMPACT"
    )

    print("-" * 70)

    for impact in impacts:

        print(
            f"- {impact}"
        )

    # --------------------------------------------------------
    # Verdict
    # --------------------------------------------------------

    print(
        "\n[6] INVESTIGATION VERDICT"
    )

    print("-" * 70)

    print(
        "The email exhibits multiple characteristics "
        "consistent with a phishing attempt."
    )

    print(
        "\nRecommended classification: PHISHING"
    )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    report_path = generate_report(
        email_path,
        message,
        header_data,
        urls,
        url_findings,
        social_findings,
        severity,
        score,
        impacts
    )

    print(
        f"\nAutomated report saved to: {report_path}"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "              INVESTIGATION COMPLETE"
    )

    print(
        "=" * 70
    )


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            "python src/email_analyzer.py "
            "sample_data/phishing_email.eml"
        )

        sys.exit(1)

    investigate_email(
        sys.argv[1]
    )