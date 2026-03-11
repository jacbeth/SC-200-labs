# Lab 3 — Threat Detection Notes
These notes document the execution of Lab 3, including screenshots, observations, and commentary. 

## Environment Setup & Log Generation

### Actions Performed
- Uploaded several test blobs to the storage account
- Downloaded the same blob repeatedly (10–30 times) to generate GetBlob events
- Generated a SAS token and accessed blobs using SAS
- Deleted a few blobs to generate DeleteBlob events

### Important
StorageBlobLogs only populate when real blob operations occur. AzureActivity logs provide context around SAS creation, key regeneration, RBAC changes, etc.

### 📦 Verification of Log Ingestion
Before running detections, I confirmed that both required log sources were flowing into my Sentinel workspace.

### Queries Run
StorageBlobLogs
| limit 10

AzureActivity
| limit 10

#### Screenshot of Blob query
![StorageBlobLogs verification](./screenshots/1-storagebloblogs-query.png)

#### Screenshot of AzureActivity query
![Azure Activity verification](./screenshots/2-azureactivity-query.png)

### Tables List Verification
Located at Microsoft Sentinel → Logs, left side panel shows every table currently available in the Log Analytics workspace.

#### Screenshot of Tableslist
![Tables](./screenshots/3-tableslist.png)

Both tables appear in the workspace: StorageBlobLogs and AzureActivity. This validates that the environment is ready for detection engineering.

## 🔍 Detection 1 — Repeated Blob Downloads from the Same IP
Detects repeated blob downloads from the same IP address within a 15‑minute window. High‑frequency access may indicate automation, credential misuse, or early‑stage data exfiltration.

KQL Query:

StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 15m)
| where DownloadCount > 25
| sort by DownloadCount desc

### Explanation
- Filters for blob download operations (GetBlob)
- Groups events by IP in 15‑minute bins
- Flags any IP performing more than 25 downloads
- Sorts results to highlight the most active IPs

### Execution Evidence

#### Screenshot of query execution/results
![query_results](./screenshots/4-detection1-query-results.png)

### Findings
IPs exceeded threshold 92.40.169.163. This was expected as the result of simulated attack.

### Commentary
A sudden spike in blob downloads is a classic early indicator of data harvesting. Attackers often begin by quietly pulling data before escalating. 

### MITRE Mapping
Tactic: Exfiltration (TA0010) 	Technique: Exfiltration Over Web Services (T1567)
	
## 🔍 Detection 2 — Blob Access from Unusual or Non‑Corporate IP Ranges
Detects blob access originating from IP addresses outside expected private or corporate ranges.

KQL Query:

StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress !startswith "192.168."
    and CallerIpAddress !startswith "10."
    and CallerIpAddress !startswith "172.16."
| summarize AccessCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 0

### Explanation
- Filters for blob downloads
- Excludes RFC1918 private IP ranges
- Groups access by IP per hour
- Surfaces any external IP performing blob access

### Execution Evidence

#### Screenshot of query execution/results
![detection2](./screenshots/6-detection2-query-results.png)

### Findings
External IPs accessed blobs - 92.40.169.164 and 195.149.13.240
Results were as expected and triggered by accessing blob multiple times on my home network

### Commentary
Unexpected IPs are a strong indicator of credential compromise, SAS token leakage, or external reconnaissance. 

### MITRE Mapping
Tactic: Initial Access (TA0001)  Technique: Valid Accounts (T1078)


## 🔍 Detection 3 — Blob Access Using SAS Tokens
Identifies blob access authenticated using SAS tokens. SAS tokens are high risk if leaked because they grant scoped access without requiring credentials.

KQL Query:

StorageBlobLogs
| where AuthenticationType == "SAS"
| summarize SASAccessCount = count(), Blobs = make_set(Uri, 5)
    by CallerIpAddress, bin(TimeGenerated, 1h)

### Explanation
- Filters for operations authenticated via SAS
- Counts SAS‑based access per IP per hour
- Captures a sample of accessed blob URIs

### Execution Evidence

#### Screenshot of query execution/results
![detection3](./screenshots/7-detection3-query-results.png)


### 🧾 Findings
SAS authenticated access was successfully detected in StorageBlobLogs, confirming that diagnostic settings and log ingestion are functioning correctly. 
All SAS activity originated from the same public IP address (92.40.169.164), with different ephemeral ports. This indicates the access came from a single machine. Multiple blob operations were performed, with SASAccessCount values ranging from 1 to 65 per hour‑bucketed entry.

### Accessed blobs included:

- security2container?restype=container&comp=list (container listing)
- 1-Diagnostic-setting-configuration...
- 3-Storage-Activity?comp=tags...

The presence of container listing operations (comp=list) confirms that the SAS token allowed enumeration of container contents. No unexpected IP addresses or suspicious geographic anomalies were observed. All activity aligns with the expected behaviour of a controlled SAS token test.

### Commentary
The results show a clear pattern of SAS token usage from a single client machine. The repeated access counts (e.g., 39, 64, 65 operations) are consistent with intentional testing, such as repeatedly downloading blobs or refreshing SAS URLs. The fact that the same IP appears with different source ports is normal — each HTTP request uses a new ephemeral port. This confirms the activity is legitimate and not indicative of distributed or automated external scanning.

### MITRE Mapping 
Tactic: Defense Evasion (TA0005) Technique: Use of Credentials (T1550)	

## 🔍 Detection 4 — Blob Deletions (DeleteBlob)
Detects blob deletions, which may indicate destructive behaviour or cleanup after exfiltration.

KQL Query:

StorageBlobLogs
| where OperationName == "DeleteBlob"
| summarize 
    DeleteCount = count(),
    DeletedBlobs = make_set(Uri, 10)
    by CallerIpAddress, bin(TimeGenerated, 1h)

### Explanation
- Filters for blob deletion operations
- Groups deletions by IP, account, and time window
- Captures a sample of deleted blob URIs

### Execution Evidence

![deleteblob](./screenshots/8-detection4-query-results.png)

### ⭐ Findings

- Blob deletion activity was successfully captured in StorageBlobLogs using the KQL query.
- The deleted blob continued to generate log entries, confirming that deletion operations are fully logged even after the file no longer exists.
- Attempts to access the blob using the previous SAS URL resulted in HTTP 404 (Not Found), which is expected behaviour once the object has been deleted.
- All deletion activity originated from the same public IP address, with no evidence of unauthorised access or unexpected clients.

###  Commentary
The results show normal, controlled behaviour consistent with intentional testing. All deletions came from a single IP address and targeted specific blobs, with no signs of enumeration, mass deletion, or access from unknown sources. This confirms that the SAS token and blob deletion operations behaved as expected within the lab environment.

### MITRE Mapping
Tactic:	Impact (TA0040)	Technique: Data Destruction (T1485)

