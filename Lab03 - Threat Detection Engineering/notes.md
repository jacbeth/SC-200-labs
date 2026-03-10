# Lab 3 — Threat Detection Notes

These notes document the execution of Lab 3, including screenshots, observations, and commentary. T

## Environment Setup & Log Generation

### Actions Performed
- Uploaded several test blobs to the storage account
- Downloaded the same blob repeatedly (10–30 times) to generate GetBlob events
- Generated a SAS token and accessed blobs using SAS
- Deleted a few blobs to generate DeleteBlob events

### Why this matters
StorageBlobLogs only populate when real blob operations occur. AzureActivity logs provide context around SAS creation, key regeneration, RBAC changes, etc.

### 📦 Verification of Log Ingestion
Before running detections, I confirmed that both required log sources were flowing into my Sentinel workspace.

### Queries Run and Screenshots

#### Queries
StorageBlobLogs
| limit 10

AzureActivity
| limit 10

#### Screenshot
![StorageBlobLogs verification](./screenshots/1-storagebloblogs-query.png)

#### Screenshot
![Azure Activity verification](./screenshots/2-azureactivity-query.png)

### Tables List Verification

#### Location
Microsoft Sentinel → Logs, left side panel shows every table currently available in the Log Analytics workspace.

#### Screenshot
![Tables](./screenshots/3-tableslist.png)

Both tables appear in the workspace: StorageBlobLogs and AzureActivity. This validates that the environment is ready for detection engineering.

## 🔍 Detection 1 — Repeated Blob Downloads from the Same IP
### Summary
Detects repeated blob downloads from the same IP address within a 15‑minute window. High‑frequency access may indicate automation, credential misuse, or early‑stage data exfiltration.

KQL Query:

StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 15m)
| where DownloadCount > 25
| sort by DownloadCount desc

#### Explanation
- Filters for blob download operations (GetBlob)
- Groups events by IP in 15‑minute bins
- Flags any IP performing more than 25 downloads
- Sorts results to highlight the most active IPs

#### Execution Evidence

Query execution/results
![query_results](./screenshots/4-detection1-query-results.png)


#### Findings
IPs exceeded threshold 92.40.169.163. This was expected as the result of simulated attack.

#### Commentary
A sudden spike in blob downloads is a classic early indicator of data harvesting. Attackers often begin by quietly pulling data before escalating. 

MITRE Mapping
Tactic              	Technique
Exfiltration (TA0010)	Exfiltration Over Web Services (T1567)

## 🔍 Detection 2 — Blob Access from Unusual or Non‑Corporate IP Ranges
### Summary
Detects blob access originating from IP addresses outside expected private or corporate ranges.

KQL Query:

StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress !startswith "192.168."
    and CallerIpAddress !startswith "10."
    and CallerIpAddress !startswith "172.16."
| summarize AccessCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 0

#### Explanation
- Filters for blob downloads
- Excludes RFC1918 private IP ranges
- Groups access by IP per hour
- Surfaces any external IP performing blob access

#### Execution Evidence

![detection2](./screenshots/5-detection2-query-results)


#### Findings
External IPs accessed blobs - 92.40.169.164 and 195.149.13.240
Results were as expected and triggerd by blob access multiple times on my home network

#### Commentary
Unexpected IPs are a strong indicator of credential compromise, SAS token leakage, or external reconnaissance. This detection becomes extremely powerful when enriched with geo‑location or threat intelligence feeds.

MITRE Mapping
Tactic	                Technique
Initial Access (TA0001)	Valid Accounts (T1078)


## 🔍 Detection 3 — Blob Access Using SAS Tokens
### Summary
Identifies blob access authenticated using SAS tokens. SAS tokens are high‑risk if leaked because they grant scoped access without requiring credentials.

KQL Query:

StorageBlobLogs
| where AuthenticationType == "SAS"
| summarize SASAccessCount = count(), Blobs = make_set(Uri, 5)
    by CallerIpAddress, bin(TimeGenerated, 1h)

#### Explanation
Filters for operations authenticated via SAS
Counts SAS‑based access per IP per hour
Captures a sample of accessed blob URIs

#### Execution Evidence
Add screenshots:

SAS token generation (from earlier lab step)

Query execution

Results showing SAS‑based access

#### Findings
Record which IPs used SAS tokens and whether the usage aligns with expected behaviour.

#### Commentary
SAS tokens are powerful and dangerous. They bypass identity‑based controls and can be leaked through URLs, logs, or misconfigured applications. Any unexpected SAS usage should be treated as a potential incident.

MITRE Mapping
Tactic	Technique
Defense Evasion (TA0005)	Use of Credentials (T1550)

## 🔍 Detection 4 — Blob Deletions (DeleteBlob)
Summary
Detects blob deletions, which may indicate destructive behaviour or cleanup after exfiltration.

KQL Query:

StorageBlobLogs
| where OperationName == "DeleteBlob"
| summarize DeleteCount = count(), DeletedBlobs = make_set(Uri, 10)
    by CallerIpAddress, CallerAccountName, bin(TimeGenerated, 1h)

#### Explanation
- Filters for blob deletion operations
- Groups deletions by IP, account, and time window
- Captures a sample of deleted blob URIs

### Execution Evidence

![description](./screenshots/filename.png)
Query execution

Results showing deleted blobs

Any correlation with earlier detections

#### Findings
Document which blobs were deleted, who performed the deletion, and whether it was authorised.

#### Analyst Commentary
Blob deletion is a high‑impact action. It may indicate malicious cleanup after data theft, insider threat activity, or compromised credentials performing destructive operations. This detection is essential for both security and operational monitoring.

MITRE Mapping
Tactic	Technique
Impact (TA0040)	Data Destruction (T1485)
