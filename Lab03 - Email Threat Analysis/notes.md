## 🗒️ Lab 03 — Analyst Walkthrough \& Commentary

## 🔍 Header Analysis

* SPF result: Pass
* DKIM result: Pass
* DMARC result: Pass
* Routing anomalies: None
* Return‑Path mismatch: None
* X‑Mailer observations:
#### The header includes:
* x-google-dkim-signature, x-gm-message-state and x-gm-features

### Commentary:

This email is a benign test message sent from a legitimate Gmail account. All authentication mechanisms (SPF, DKIM, DMARC) passed, the routing path is clean, and the infrastructure metadata matches Google’s normal sending behaviour. No indicators of spoofing, manipulation, or malicious infrastructure.

### Screenshots

#### SPF Result
![spf](./screenshots/filename.png)




dkim=pass header.d=gmail.com



dmarc=pass action=none header.from=gmail.com



sender IP is 209.85.218.46



Received: from mail-ej1-f46.google.com (209.85.218.46)

Received: by CH1PEP0000DA7D.namprd04.prod.outlook.com

Received: by CH2PR03CA0022.outlook.office365.com



From: Jac <jacbethphill@gmail.com>

smtp.mailfrom=gmail.com



x-google-dkim-signature: ...

x-gm-message-state: ...

x-gm-features: ...





## 🌐 Infrastructure Findings

* Domain age:
* WHOIS registrant:
* Hosting provider:
* Geolocation:

#### Commentary:

?

## 🧪 VirusTotal Findings

### URL

* Detection ratio:
* Behaviour summary:
* Redirect chain:

### Attachment

* Static analysis:
* Sandbox behaviour:
* Dropped files:

#### Commentary:

?

## 🛡️ Sentinel/XDR Correlation

* Number of affected users:
* SafeLinks/SafeAttachments actions:
* Related alerts:

#### Commentary:

?

## 🧭 MITRE Mapping

* Put here

## 📝 Final Analyst Report

* here.

