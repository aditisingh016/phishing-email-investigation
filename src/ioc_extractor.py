import csv
import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


EMAIL_FILE = Path("sample_data/phishing_email.eml")
OUTPUT_FILE = Path("reports/iocs.csv")


def load_email():

    with open(EMAIL_FILE, "rb") as file:
        return BytesParser(policy=policy.default).parse(file)


def get_body(message):

    if message.is_multipart():

        body_parts = []

        for part in message.walk():

            if part.get_content_type() == "text/plain":

                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

        return "\n".join(body_parts)

    return message.get_content()


def extract_urls(text):

    pattern = r'https?://[^\s<>"\']+'

    return re.findall(pattern, text)


def extract_email_addresses(text):

    pattern = (
        r'\b[A-Za-z0-9._%+-]+'
        r'@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    )

    return sorted(set(re.findall(pattern, text)))


def extract_domains(urls):

    domains = []

    for url in urls:

        parsed = urlparse(url)

        if parsed.netloc:

            domain = parsed.netloc.lower()

            if domain not in domains:
                domains.append(domain)

    return domains


def main():

    message = load_email()

    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    body = get_body(message)

    combined_text = (
        sender
        + "\n"
        + reply_to
        + "\n"
        + body
    )

    urls = extract_urls(body)

    domains = extract_domains(urls)

    email_addresses = extract_email_addresses(
        combined_text
    )

    iocs = []

    # Sender email
    for email in email_addresses:

        if email.lower() in sender.lower():

            iocs.append({
                "type": "Email Address",
                "indicator": email,
                "source": "Sender",
                "description": "Email address associated with the sender"
            })

    # Reply-To
    for email in email_addresses:

        if email.lower() in reply_to.lower():

            iocs.append({
                "type": "Email Address",
                "indicator": email,
                "source": "Reply-To",
                "description": "Email address specified in Reply-To header"
            })

    # URLs
    for url in urls:

        iocs.append({
            "type": "URL",
            "indicator": url,
            "source": "Email Body",
            "description": "URL extracted from phishing email"
        })

    # Domains
    for domain in domains:

        iocs.append({
            "type": "Domain",
            "indicator": domain,
            "source": "URL",
            "description": "Domain associated with extracted URL"
        })

    # Make sure reports directory exists
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Write CSV
    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        fieldnames = [
            "type",
            "indicator",
            "source",
            "description"
        ]

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for ioc in iocs:
            writer.writerow(ioc)

    print("\nIOC extraction completed.")
    print(f"IOC report saved to: {OUTPUT_FILE}")
    print(f"Total IOCs identified: {len(iocs)}")


if __name__ == "__main__":
    main()