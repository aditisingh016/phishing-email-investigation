# Phishing Email Investigation Tool

A Python-based cybersecurity project that analyzes suspicious emails, identifies potential phishing indicators, examines email authentication headers, and documents evidence integrity.

## Project Overview

This project demonstrates a basic phishing email investigation workflow using a sample email in `.eml` format. It combines automated analysis with investigation reports to help explain why an email may be suspicious.

## Features

- **Email Analysis:** Examines a sample email and produces an automated investigation report.
- **IOC Extraction:** Extracts potential indicators of compromise (IOCs) and exports them to CSV.
- **Email Header Analysis:** Checks SPF, DKIM, and DMARC authentication results.
- **Evidence Integrity:** Uses SHA-256 hashing to record the sample email's file integrity.
- **Investigation Reports:** Documents findings, an investigation timeline, and MITRE ATT&CK mapping.
- **Screenshots:** Includes visual evidence of the investigation workflow.

## Project Structure

```text
phishing-email-investigation/
├── app.py
├── src/
│   ├── email_analyzer.py
│   ├── ioc_extractor.py
│   ├── header_analyzer.py
│   └── hash_evidence.py
├── sample_data/
│   └── phishing_email.eml
├── reports/
├── screenshots/
└── .gitignore
```

## Technologies Used

- Python
- Email parsing
- Regular expressions
- CSV reporting
- SHA-256 hashing
- Git and GitHub

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/aditisingh016/phishing-email-investigation.git
cd phishing-email-investigation
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

Install the dependencies required by the application and scripts. If a `requirements.txt` file is provided, run:

```bash
pip install -r requirements.txt
```

### 4. Run the analysis scripts

```bash
python src/email_analyzer.py sample_data/phishing_email.eml
python src/ioc_extractor.py
python src/header_analyzer.py
python src/hash_evidence.py
```

Run commands from the project root directory.

## Reports and Evidence

The `reports/` directory contains investigation findings, extracted IOCs, header analysis, evidence integrity information, and supporting documentation. The `screenshots/` directory contains screenshots of selected investigation steps.

## Important Disclaimer

This project uses sample data for educational and portfolio purposes. Findings from the sample should not be interpreted as proof of a real-world security incident. Authentication failures and other indicators must be evaluated in context.

## Author

Aditi Singh

GitHub: [@aditisingh016](https://github.com/aditisingh016)
