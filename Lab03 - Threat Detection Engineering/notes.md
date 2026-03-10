# Lab 3 — Threat Detection Notes

These notes document the full execution of Lab 3, including screenshots, observations, and commentary. They serve as evidence of hands on work and reinforce understanding of Azure Storage threat detection.

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

### 1.3 Tables List Verification

#### Location
Microsoft Sentinel → Logs, left side panel shows every table currently available in the Log Analytics workspace.

#### Screenshot
![Tables](./screenshots/3-tableslist.png)

Both tables appear in the workspace: StorageBlobLogs and AzureActivity. This validates that the environment is ready for detection engineering.