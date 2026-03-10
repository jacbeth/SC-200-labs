## Lab 3 — Azure Threat Detection

Azure Storage is a high‑value target for attackers due to its use for backups, logs, application data, and sensitive files. This lab focuses on identifying suspicious access patterns within Azure Storage accounts using Microsoft Sentinel and KQL.

The goal is to simulate detection work by analysing blob access logs, identifying anomalies, and building detections aligned with MITRE ATT\&CK.

## Data Sources

This lab primarily uses StorageBlobLogs, but also incorporates AzureActivity to provide visibility into control‑plane operations such as SAS token creation, key regeneration, and network rule changes.

### StorageBlobLogs

Contains operational logs for blob access, including:

* Blob downloads (GetBlob)
* Blob deletions (DeleteBlob)
* Authentication type (Key, OAuth, SAS)
* Caller IP address
* URI and container information

### Additional Log Source - AzureActivity

Captures control‑plane operations such as:

* SAS token creation
* Storage account key regeneration
* Network rule modifications
* Role assignments and permission changes

These events are critical for identifying attacker attempts to weaken storage security or establish persistence.

🔍 Detection 1 — Repeated Blob Downloads from the Same IP

Identify potentially suspicious or automated access to Azure Storage Blobs by detecting repeated downloads from the same IP within a short time window.

StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 15m)
| where DownloadCount > 25
| sort by DownloadCount desc

### Explanation

Repeated downloads from a single IP may indicate:

* Automated scripts
* Credential misuse
* Early‑stage data exfiltration

### MITRE ATT\&CK - Tactic: Exfiltration (TA0010)

Technique: Exfiltration Over Web Services (T1567)

### Commentary

This is a strong early‑warning signal. Attackers often begin by quietly pulling data before escalating.



🔍 Detection 2 — Blob Access from Unusual or Non‑Corporate IP Ranges

Detect blob access originating from IP addresses outside expected geographic or organisational ranges.

StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress !startswith "192.168."
and CallerIpAddress !startswith "10."
and CallerIpAddress !startswith "172.16."
| summarize AccessCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 0

### Explanation

Unexpected IPs may indicate:

* Credential compromise
* SAS token leakage
* External attacker reconnaissance

### MITRE ATT\&CK - Tactic: Initial Access (TA0001)

Technique: Valid Accounts (T1078)

Commentary
This detection becomes extremely powerful when combined with geo‑IP enrichment or threat intelligence lookups.



🔍 Detection 3 — Blob Access Using SAS Tokens

Identify blob access authenticated using Shared Access Signatures (SAS), which are high‑risk if leaked.

StorageBlobLogs
| where AuthenticationType == "SAS"
| summarize SASAccessCount = count(), Blobs = make\_set(Uri, 5)
by CallerIpAddress, bin(TimeGenerated, 1h)

### Explanation

SAS tokens bypass normal authentication controls. Unexpected SAS usage is a high‑fidelity indicator of compromise.

### MITRE ATT\&CK - Tactic: Defense Evasion (TA0005)

Technique: Use of Credentials (T1550)

Commentary
SAS tokens are powerful and dangerous. Any unexpected usage should be treated as a potential incident.



🔍 Detection 4 — Blob Deletions (DeleteBlob)

Detect deletion of blobs, which may indicate destructive behaviour or cleanup after exfiltration.

StorageBlobLogs
| where OperationName == "DeleteBlob"
| summarize DeleteCount = count(), DeletedBlobs = make\_set(Uri, 10)
by CallerIpAddress, CallerAccountName, bin(TimeGenerated, 1h)

### Explanation

Blob deletions may indicate:

* Cleanup after data theft
* Malicious tampering
* Compromised accounts attempting to hide activity

### MITRE ATT\&CK - Tactic: Impact (TA0040)

Technique: Data Destruction (T1485)

📌 Findings

* Repeated downloads from a single IP
* SAS token usage from unexpected locations
* Blob deletions performed by a test account
* Control‑plane activity (AzureActivity) that may indicate attacker preparation
* Clear distinction between normal vs suspicious access patterns



🎓 Learning Outcomes
I gained hands‑on experience with:

Analysing Azure Storage access logs
Building behavioural detections using KQL
Mapping detections to MITRE ATT\&CK
Understanding blob access patterns and risks
Documenting detections in a SOC‑ready format



🪞 Reflection
This lab strengthened my understanding of cloud storage attack surfaces and the importance of monitoring both data‑plane and control‑plane activity. Even small anomalies — such as repeated downloads or unexpected IPs — can be early indicators of compromise.

