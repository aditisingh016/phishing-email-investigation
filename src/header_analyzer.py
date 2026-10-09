import re
from pathlib import Path
from email import policy
from email.parser import BytesParser


EMAIL_FILE = Path("sample_data/phishing_email.eml")


def load_email():
    with open(EMAIL_FILE, "rb") as file:
        return BytesParser(policy=policy.default).parse(file)


def extract_domain(email_address):
    match = re.search(r"@([A-Za-z0-9.-]+)", email_address)

    if match:
        return match.group(1).lower()

    return "Unknown"


def main():

    message = load_email()

    sender = message.get("From", "Unknown")
    reply_to = message.get("Reply-To", "Not present")
    return_path = message.get("Return-Path", "Not present")
    received = message.get("Received", "Not present")
    authentication = message.get(
        "Authentication-Results",
        "Not present"
    )

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)

    print("\n" + "=" * 70)
    print("              EMAIL HEADER ANALYSIS")
    print("=" * 70)

    print("\n[IDENTITY INFORMATION]")
    print("-" * 70)

    print(f"From       : {sender}")
    print(f"Reply-To   : {reply_to}")
    print(f"Return-Path: {return_path}")

    print("\n[DOMAIN COMPARISON]")
    print("-" * 70)

    print(f"Sender domain   : {sender_domain}")
    print(f"Reply-To domain : {reply_domain}")

    if sender_domain != reply_domain:
        print("WARNING: Sender and Reply-To domains differ.")
    else:
        print("Sender and Reply-To domains match.")

    print("\n[RECEIVED HEADER]")
    print("-" * 70)

    print(received)

    # Extract IP address
    ip_match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        received
    )

    if ip_match:
        print(f"\nObserved sending IP: {ip_match.group()}")
    else:
        print("\nNo IPv4 address found.")

    print("\n[EMAIL AUTHENTICATION]")
    print("-" * 70)

    print(authentication)

    authentication_lower = authentication.lower()

    checks = {
        "SPF": r"spf=(pass|fail|softfail|neutral|none)",
        "DKIM": r"dkim=(pass|fail|neutral|none)",
        "DMARC": r"dmarc=(pass|fail|bestguesspass|none)"
    }

    for mechanism, pattern in checks.items():

        match = re.search(
            pattern,
            authentication_lower
        )

        if match:

            result = match.group(1).upper()

            print(f"{mechanism}: {result}")

        else:

            print(f"{mechanism}: Not detected")

    print("\n[HEADER SECURITY ASSESSMENT]")
    print("-" * 70)

    findings = []

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

    if sender_domain != reply_domain:
        findings.append(
            "Reply-To domain differs from sender domain."
        )

    if findings:

        for finding in findings:
            print(f"- {finding}")

    else:

        print("No major header anomalies detected.")

    print("\n[VERDICT]")
    print("-" * 70)

    if findings:

        print(
            "Header analysis identified multiple indicators "
            "consistent with sender impersonation/phishing."
        )

    else:

        print(
            "Header analysis did not identify significant anomalies."
        )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()