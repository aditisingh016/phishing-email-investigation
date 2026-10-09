# Phishing Email Investigation Report

## 1. Evidence

- Evidence file: `sample_data/phishing_email.eml`
- Investigation type: Simulated phishing email analysis

## 2. Sender Analysis

- From: `Microsoft 365 Security <security-alert@microsoft365-security.example>`
- Reply-To: `account-verification@microsoft365-security.example`
- Return-Path: `<security-alert@microsoft365-security.example>`
- Sender domain: `microsoft365-security.example`
- Reply-To domain: `microsoft365-security.example`

## 3. Authentication Analysis

```
mail.company.example;        spf=fail smtp.mailfrom=microsoft365-security.example;        dkim=fail header.d=microsoft365-security.example;        dmarc=fail header.from=microsoft365-security.example
```

- SPF authentication failed.
- DKIM authentication failed.
- DMARC authentication failed.

## 4. URL Analysis

- `https://login.microsoft365-security.example/verify?session=847291`

### URL Indicators

- Suspicious URL behavior detected for login.microsoft365-security.example: verify, session

## 5. Social Engineering Indicators

- Urgency / time pressure: 'immediately'
- Urgency / time pressure: 'within 30 minutes'
- Urgency / time pressure: 'suspended'
- Urgency / time pressure: 'unusual sign-in'
- Credential harvesting language: 'verify your account'
- Credential harvesting language: 'login'
- Fear / threat language: 'did not initiate'

## 6. Severity Assessment

**Severity: CRITICAL**

Risk score: **18**

## 7. Potential Impact

- Potential sender impersonation.
- Potential credential harvesting.
- Potential user manipulation through social-engineering techniques.
- Potential Microsoft 365 account compromise.
- Potential unauthorized access to corporate resources.

## 8. Investigation Verdict

The email exhibits multiple characteristics consistent with a phishing attempt. The identified indicators include authentication failures, suspicious URL characteristics, and social-engineering techniques.

**Recommended classification: PHISHING**
