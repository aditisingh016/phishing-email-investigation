# MITRE ATT&CK Mapping

This investigation maps the observed phishing behavior to relevant
MITRE ATT&CK techniques.

| Technique ID | Technique | Observed Behavior | Evidence |
|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Email contains a link directing the recipient to an account verification page | `phishing_email.eml` |
| T1583.001 | Acquire Infrastructure: Domains | Simulated attacker infrastructure uses a domain designed to resemble a trusted security service | Suspicious sender/URL domain |
| T1036 | Masquerading | Sender impersonates a Microsoft 365 security team | Sender identity |
| T1056.002 | Input Capture: GUI Input Capture | Potential credential harvesting through a fake authentication page | Credential verification URL |

## Primary Technique

### T1566.002 — Phishing: Spearphishing Link

The strongest ATT&CK mapping is **T1566.002**.

The simulated phishing email contains a link that attempts to persuade
the recipient to access an account verification page.

The message uses urgency, security-related language, and account
suspension threats to increase the probability that the recipient
will click the link.

## Supporting Technique

### T1036 — Masquerading

The sender presents itself as a Microsoft 365 Security Team.

The apparent identity is designed to create trust and convince the
recipient that the email is a legitimate security notification.

## Potential Credential Collection

### T1056.002 — Input Capture: GUI Input Capture

The simulated URL represents a potential credential-harvesting page.

No real credentials are collected in this project.

This mapping represents the potential attacker objective rather than
a confirmed credential compromise.

## ATT&CK Assessment

The investigation primarily demonstrates:

- Phishing
- Link-based social engineering
- Brand impersonation
- Potential credential harvesting

The ATT&CK mapping is based on the simulated evidence available in
this controlled investigation.