## Lab 2 - Notes

### Purpose of Diagnostic Settings

Many Azure services do not automatically send logs to Microsoft Sentinel. Diagnostic settings act as the pipeline that forwards resource logs into the monitoring environment. Without diagnostic settings enabled, infrastructure activity may not be visible.

### Log Sources Enabled

The following Azure resource logs were configured and forwarded to the Log Analytics Workspace for analysis within Microsoft Sentinel: Azure Storage Blob service logs (StorageBlobLogs)

These logs capture operations such as:

- blob uploads
- blob downloads
- blob deletions
- client IP addresses
- operation timestamps

### Diagnostic Settings Configuration
The screenshot below shows the diagnostic setting applied to the Blob service of the storage account, confirming that logs are being forwarded to the LAW‑Security‑labs Log Analytics workspace.

![Blob Diagnostic Setting](./screenshots/2-Diagnostic-setting-configuratinon.png)


This telemetry allows monitoring for suspicious file access patterns such as abnormal download activity or potential data exfiltration. NB $logs is reserved for system log files.

The screenshot below shows the diagnostic settings applied to the storage account, confirming that Storage and Blob logging were successfully enabled while other services (Queue, Table, File) remain disabled for this lab.

![Diagnostic Settings](./screenshots/your-image-name.png)

Below is an example query confirming that StorageBlobLogs are being successfully ingested into the workspace:

StorageBlobLogs
| sort by TimeGenerated desc
| take 20

![Log Query Results](./screenshots/4-log-query-results.png)

This output shows recent blob‑related operations such as GetBlobProperties and GetContainerProperties, confirming that StorageBlobLogs are being successfully ingested.

### SOC Visibility Improvement

After enabling diagnostic settings, the SIEM environment now ingests:

* Identity logs
* Azure Activity logs
* Resource logs

This significantly improves the detection capabilities of the SOC environment.

## Example Threat Hunting Query

The following Kusto Query Language query was used to detect potential abnormal download activity from Azure Storage.
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize DownloadCount = count() by CallerIpAddress, bin(TimeGenerated, 15m)
| where DownloadCount > 2
| sort by DownloadCount desc

This query identifies possible data exfiltration attempts by detecting numbers of file downloads from a single IP address (DownloadCount would be higher in real world environment).

### Operational Considerations

Diagnostic logging increases data ingestion into the Log Analytics Workspace, which can affect cost and retention settings in production environments. For lab environments, log volume is usually minimal.

### Result

The SOC environment now provides monitoring  across both identity services and Azure infrastructure resources. This allows Microsoft Sentinel to detect potential threats affecting cloud resources as well as user identities.

