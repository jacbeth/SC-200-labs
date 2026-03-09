Lab 3: Azure Storage Threat Detection — Detection Set

This lab focuses on identifying suspicious access patterns within Azure Storage accounts using KQL and Microsoft Sentinel. The goal is to simulate real SOC detection engineering work by analysing blob access logs, identifying anomalies, and building detections aligned with MITRE ATT\&CK.

Azure Storage is a common target for attackers due to its use for backups, logs, application data, and sensitive files. This lab demonstrates how to detect early‑stage reconnaissance, misuse of SAS tokens, and potential data exfiltration.

## Data Source

Table: StorageBlobLogs  

- Log Types:
- Blob downloads (GetBlob)
- Blob deletions (DeleteBlob)
- Authentication metadata
- Caller IP information
- SAS token usage

## Detection Goals

This lab implements four focused detections designed to surface suspicious or high‑risk behaviour:

- Repeated blob downloads from the same IP
- Blob access from unusual or non‑corporate IP ranges
- Blob access authenticated using SAS tokens
- Blob deletions that may indicate destructive or post‑exfiltration activity

Each detection includes KQL, explanation, MITRE mapping, and analyst commentary.


## 🔍 Detection 1: Repeated Blob Downloads from the Same IP

### Objective

Identify potentially suspicious or automated access to Azure Storage Blobs by detecting repeated downloads from the same IP within a one‑hour window.

StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where DownloadCount > 25

### Explanation

This detection highlights repeated blob downloads from a single IP address within a one‑hour window. While occasional downloads are normal, repeated access may indicate automated scripts, credential misuse, or early‑stage data exfiltration.

### MITRE ATT\&CK - Tactic: Exfiltration (TA0010)

Technique: Exfiltration Over Web Services (T1567)


This is a strong early‑warning signal. Attackers often test access or begin quietly pulling data before escalating. Grouping by IP and time window provides a simple but effective behavioural baseline.

## 🔍 Detection 2: Blob Access from Unusual or Non‑Corporate IP Ranges

### Objective

Detect blob access originating from IP addresses outside expected geographic or organisational ranges.

StorageBlobLogs

| where OperationName == "GetBlob"

| where CallerIpAddress !startswith "192.168."

&nbsp;   and CallerIpAddress !startswith "10."

&nbsp;   and CallerIpAddress !startswith "172.16."

| summarize AccessCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)

| where AccessCount > 0

(Adjust IP ranges to match your environment.)

### Explanation

This detection surfaces blob access from unfamiliar or external IPs. In many organisations, blob access should originate from:

- Corporate networks
- VPN ranges
- Azure services

Unexpected IPs may indicate:

Credential compromise
SAS token leakage
External attacker reconnaissance

### MITRE ATT\&CK - Tactic: Initial Access (TA0001)

Technique: Valid Accounts (T1078)
Analyst Commentary

This detection is especially valuable when combined with geo‑IP enrichment. Even a single access from an unexpected region can be a high‑fidelity signal of compromise.

## Detection 3: Blob Access Using SAS Tokens

### Objective

Identify blob access authenticated using Shared Access Signatures (SAS), which are high‑risk if leaked.

StorageBlobLogs

| where AuthenticationType == "SAS"

| summarize SASAccessCount = count(), Blobs = make\_set(Uri, 5)

&nbsp;   by CallerIpAddress, bin(TimeGenerated, 1h)

### Explanation

SAS tokens bypass normal authentication and authorisation controls. If leaked, they allow attackers to download or modify blobs without logging in.

This detection highlights:

- SAS token usage
- Which blobs were accessed
- From which IPs
- In what time window

### MITRE ATT\&CK - Tactic: Defense Evasion (TA0005)

Technique: Use of Credentials (T1550)

SAS tokens are powerful and dangerous. Any unexpected SAS usage should be treated as a potential security incident. This detection provides visibility into a commonly overlooked attack vector.


## Detection 4: Blob Deletions (DeleteBlob)

### Objective

Detect deletion of blobs, which may indicate destructive behaviour or cleanup after exfiltration.

StorageBlobLogs

| where OperationName == "DeleteBlob"

| summarize DeleteCount = count(), DeletedBlobs = make\_set(Uri, 10)

&nbsp;   by CallerIpAddress, CallerAccountName, bin(TimeGenerated, 1h)

### Explanation

Blob deletions are less common than reads and often indicate:

- Cleanup after data theft
- Malicious tampering
- Accidental or unauthorised deletion
- Compromised accounts attempting to hide activity

### MITRE ATT\&CK - Tactic: Impact (TA0040)

Technique: Data Destruction (T1485)

# Findings

Repeated downloads from a single IP
SAS token usage from unexpected locations
Blob deletions performed by a test account
Normal vs suspicious access patterns

## Learning Outcomes

I gained hands on experience with:

- Analysing Azure Storage access logs
- Building behavioural detections using KQL
- Mapping detections to MITRE ATT\&CK
- Understanding blob access patterns and risks
- Documenting detections in a SOC‑ready format

## Reflection

This lab strengthened my understanding of cloud storage attack surfaces and the importance of monitoring blob access patterns. I learned how small anomalies — such as repeated downloads or unexpected IPs — can be early indicators of compromise. 
