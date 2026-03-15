# 📘 Lab 2 — Email Threat Analysis Lab

--- 

## 🎯 Objective
Perform a full SOC‑style investigation of a suspicious email, including header analysis, sender infrastructure, threat‑intel enrichment, and correlation with Microsoft Defender XDR/Sentinel. 
This lab builds on the SIEM foundation created in Lab 1 — Sentinel Workspace Setup & Ingestion Validation.

--- 

## 🧩 Step 1 — Extract & Analyse the Email Header

- Open the email → View Original / View Message Source
- Copy the full header into a header analysis tool

--- 

#### Review:

- S-PF / DKIM / DMARC
- Sending IP
- Return‑Path vs From
- Reply‑To anomalies
- Routing path
- X‑Mailer

---

## Evidence
screenshots/header-analysis.png

Analyst notes explaining anomalies

---

## 🌐 Step 2 — Investigate Sender Infrastructure

- WHOIS lookup on sending IP
- Domain age lookup
- Hosting provider identification
- Geolocation vs claimed sender

---

## Evidence
screenshots/whois.png

screenshots/domain-age.png

Analyst commentary

---

## 🧪 Step 3 — VirusTotal Analysis

#### URL Analysis
- Submit URL
- Review detections, behaviour, relations

#### Attachment Analysis
- Upload file (if safe)
- Review static + dynamic analysis
- Identify dropped files

#### Evidence
- screenshots/vt-url.png
- screenshots/vt-file.png
- Analyst interpretation

---

## 🛡️ Step 4 — Correlate With Defender XDR / Sentinel

### KQL Queries
Find all emails from the same sender

```kql
EmailEvents
| where SenderFromAddress == "<suspicious sender>"
| summarize count() by RecipientEmailAddress
```

```kql
UrlClickEvents
| where OriginalUrl contains "<domain>"
```

```kql
UrlClickEvents
| where OriginalUrl contains "<domain>"
```

```kql
EmailAttachmentInfo
| where FileName contains "<filename>"
```
#### Evidence
- screenshots/sentinel-query-results.png
- screenshots/defender-alerts.png

---

## 🧭 Step 5 — MITRE ATT&CK Mapping

### Observation	Technique	Why
- Malicious link	T1566.002	Delivered via email
- Malicious attachment	T1566.001	Requires user to open
- Macro execution	T1204	User execution
- PowerShell payload	T1059	Command execution


