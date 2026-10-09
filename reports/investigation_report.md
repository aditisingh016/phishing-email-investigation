# Phishing Email Investigation & Incident Analysis

## 1. Incident Overview

**Incident Type:** Phishing / Credential Theft Attempt  
**Investigation Type:** Email Security Investigation  
**Severity:** HIGH  
**Status:** Confirmed Phishing Attempt  
**Environment:** Simulated Corporate Environment  
**Investigator:** Security Analyst  

---

## 2. Executive Summary

A simulated phishing email was investigated after being delivered to a corporate employee.

The email impersonates a Microsoft 365 security notification and claims that an unusual sign-in was detected on the user's account.

The recipient is instructed to verify the account within 30 minutes or risk account suspension.

Analysis identified multiple phishing indicators, including:

- Sender impersonation
- Suspicious sender domain
- Suspicious Reply-To address
- Credential/account verification request
- Urgency and time pressure
- Threat of account suspension
- Suspicious verification URL
- Security-themed social engineering
- Potential credential theft objective

Based on the combined indicators, the email was assessed as a **HIGH severity phishing incident**.

---

# 3. Email Details

| Field | Value |
|---|---|
| Sender | Microsoft 365 Security <security-alert@microsoft365-security.example> |
| Recipient | employee@company.example |
| Reply-To | account-verification@microsoft365-security.example |
| Subject | URGENT: Unusual sign-in detected - Verify your account |
| Date | Wed, 07 Oct 2026 09:42:18 +0530 |
| Message-ID | 20261007094218.847291@microsoft365-security.example |

---

# 4. Sender Analysis

The sender claims to represent the Microsoft 365 Security Team.

However, the sender uses:

`microsoft365-security.example`

instead of an official Microsoft domain.

This creates a strong impersonation indicator.

### Finding

The displayed sender identity attempts to establish trust by using the Microsoft 365 brand while the actual sender domain is unrelated to Microsoft's legitimate infrastructure.

**Assessment:** Suspicious sender / brand impersonation.

---

# 5. Reply-To Analysis

The email contains the following Reply-To address:

`account-verification@microsoft365-security.example`

The Reply-To address is controlled by the same simulated suspicious domain rather than an official Microsoft domain.

A Reply-To address can be used by attackers to redirect responses away from the apparent sender.

**Assessment:** Suspicious Reply-To infrastructure.

---

# 6. URL Analysis

The email contains the following URL:

`https://login.microsoft365-security.example/verify?session=847291`

### Observed characteristics

- Contains `login`
- Contains `verify`
- Contains `session` query parameter
- Uses a domain unrelated to Microsoft's legitimate infrastructure
- Attempts to create the appearance of an account verification portal

### Potential Objective

The URL appears designed to direct the recipient toward a fake account verification process.

The likely objective is credential harvesting.

**Assessment:** Suspicious credential-verification URL.

---

# 7. Social Engineering Analysis

Multiple social-engineering techniques were identified.

## 7.1 Urgency

The email states that the recipient has only 30 minutes to verify the account.

This creates time pressure and discourages careful investigation.

## 7.2 Fear / Threat

The email warns that account access may be suspended.

This encourages the recipient to act quickly to avoid a perceived negative consequence.

## 7.3 Authority Impersonation

The attacker impersonates a Microsoft 365 security team.

Using a trusted technology provider increases the likelihood that the recipient will believe the message.

## 7.4 Account Security Pretext

The email claims that an unusual sign-in occurred.

Security-related notifications are commonly used as phishing lures because recipients may be concerned about unauthorized access.

## 7.5 Credential Verification

The recipient is instructed to verify their account using an external URL.

This is consistent with credential-phishing activity.

---

# 8. Indicators of Compromise

The following indicators were extracted during analysis.

| IOC Type | Indicator | Context |
|---|---|---|
| Email Address | security-alert@microsoft365-security.example | Sender |
| Email Address | account-verification@microsoft365-security.example | Reply-To |
| URL | https://login.microsoft365-security.example/verify?session=847291 | Email body |
| Domain | login.microsoft365-security.example | URL domain |

The IOC list is also available in:

`reports/iocs.csv`

---

# 9. Risk Assessment

The investigation identified multiple independent risk indicators.

### Risk Factors

| Risk Factor | Finding |
|---|---|
| Sender impersonation | Detected |
| Suspicious domain | Detected |
| Suspicious Reply-To | Detected |
| Credential request | Detected |
| Urgency | Detected |
| Threat of account suspension | Detected |
| Suspicious URL | Detected |
| Security-themed lure | Detected |

### Overall Severity

**HIGH**

The incident was classified as HIGH because the email attempts to manipulate the recipient into visiting a suspicious authentication URL and potentially submitting account credentials.

---

# 10. Potential Impact

If a recipient interacted with the phishing URL and submitted credentials, potential consequences could include:

1. Microsoft 365 account compromise
2. Unauthorized access to corporate resources
3. Email account takeover
4. Exposure of sensitive information
5. Abuse of the compromised account
6. Further phishing campaigns using the compromised mailbox
7. Potential lateral movement within the organization

No actual compromise is assumed in this simulation.

The assessment describes the potential impact if the phishing attempt were successful.

---

# 11. Recommended Incident Response

## Immediate Actions

1. Quarantine the phishing email.
2. Block the identified phishing domain.
3. Block the identified URL.
4. Search mailboxes for similar messages.
5. Identify all recipients of the phishing email.
6. Warn affected users not to interact with the message.

## If a User Clicked the URL

1. Reset the user's password.
2. Revoke active authentication sessions.
3. Review recent login activity.
4. Investigate suspicious authentication events.
5. Review mailbox rules for unauthorized forwarding.
6. Check for additional suspicious activity.

## Organization-Level Actions

1. Add identified indicators to security controls.
2. Improve email filtering rules.
3. Enable or strengthen multi-factor authentication.
4. Conduct phishing awareness training.
5. Monitor for additional messages using the same campaign indicators.

---

# 12. Investigation Conclusion

The analyzed email demonstrates characteristics consistent with a phishing campaign targeting corporate Microsoft 365 credentials.

The combination of:

- brand impersonation,
- suspicious sender infrastructure,
- suspicious Reply-To address,
- credential verification request,
- urgency,
- threat-based language,
- and a suspicious authentication URL

supports classification as a **HIGH severity phishing incident**.

The identified indicators should be added to appropriate security monitoring and blocking controls.

---

# 13. Investigation Limitations

This project uses a simulated phishing email and reserved `.example` domains.

No real malicious infrastructure was contacted during the investigation.

Therefore:

- No real domain reputation was assessed.
- No live malicious URL was accessed.
- No real user credentials were involved.
- No actual compromise occurred.

The project demonstrates the investigation methodology and automated analysis process in a controlled environment.