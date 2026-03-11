## Lab 4: Anonymous Blob Access Detection & Misconfiguration Analysis

### Container Configuration

- Set Public Access Level Blob containerto intentionally allow anonymous read access.
- Uploaded a test file (test.txt) to generate activity.

Important: Public access is a common real‑world misconfiguration that exposes data without authentication.

### Anonymous Access Testing

- Copied the blob URL directly from the Azure portal.
- Opened a private/incognito browser window.
- Accessed the blob successfully without authentication, confirming the container was publicly accessible.
- Refreshed the blob multiple times to generate repeated anonymous read events.
- Observation: Anonymous access does not require SAS tokens, keys, or Azure AD credentials.

### Log Ingestion Verification

#### Confirmed that diagnostic settings were sending:

- StorageBlobLogs
- StorageRead
- StorageWrite

Waited 2–5 minutes for ingestion
Verified that anonymous access events appeared in StorageBlobLogs.

#### Fields of interest:

- AuthenticationType == "Anonymous"
- OperationName == "GetBlob"
- CallerIpAddress
- Uri

### KQL Queries Used

#### Anonymous Access Detection

StorageBlobLogs
| where AuthenticationType == "Anonymous"
| summarize AccessCount = count(), Blobs = make_set(Uri, 10)
    by CallerIpAddress, bin(TimeGenerated, 1h)

#### Screenshot of Anonymous access KQL query and results
![anonymousaccess](./screenshots/filename.png)

#### Container Enumeration Detection

StorageBlobLogs
| where Uri contains "comp=list"
| summarize ListOperations = count()
    by CallerIpAddress, bin(TimeGenerated, 1h)

#### Screenshot of Container listing KQL query and results
![containerlisting](./screenshots/filename.png)

#### High Volume Anonymous Reads

StorageBlobLogs
| where AuthenticationType == "Anonymous"
| summarize TotalReads = count()
    by bin(TimeGenerated, 1h)
| where TotalReads > 20

#### Screenshot of High‑volume access detection results
![highvolumeaccess](./screenshots/filename.png)

### Findings

- Anonymous blob access was successfully logged.
- All access originated from the expected test IP address.
- Container listing operations (comp=list) were captured, showing that public access allowed enumeration of blob contents.
- High volume reads were detected during testing, confirming that repeated anonymous access is fully logged.
- No unexpected IPs or suspicious access patterns were observed.

### Commentary
Azure logs anonymous access clearly, including the caller IP, timestamp, and blob URI. This is essential for forensic investigations, especially when dealing with misconfigurations that expose data publicly. The behaviour observed in this lab matches real‑world cloud incidents where public containers lead to data exposure. Anonymous reads, container listings, and repeated access attempts were all captured as expected. This demonstrates that Azure provides sufficient telemetry to detect misconfigurations, provided diagnostic settings are correctly configured. 

