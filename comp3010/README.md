# BOTSv3 Incident Analysis Report: Frothly Brewing Company Security Investigation

**Author:** Pak Chun  
**Date:** February 2025  
**Repository:** [GitHub Repo]  
**Video Presentation:** [YouTube link]

## Introduction

The **Boss of the SOC version 3 (BOTSv3)** dataset, provided by Splunk, simulates a realistic cybersecurity incident in a fictitious brewing company, **Frothly**. It includes diverse logs from network, endpoint (Windows/Linux), email, AWS CloudTrail, S3 access logs, and more, enabling blue-team analysis following the cyber kill chain and incident response frameworks.

This investigation focuses on the **200-level question set** (primarily AWS misconfiguration and endpoint OS analysis), emphasizing cloud security incidents (public S3 bucket exposure) and endpoint visibility gaps. Objectives include identifying IAM activity, detecting MFA bypass risks, uncovering misconfigurations (e.g., public S3 via PutBucketAcl), tracing unauthorized uploads, and spotting anomalous Windows editions.

**Scope:** Limited to AWS-related (CloudTrail, S3 access logs) and winhostmon events in the BOTSv3 dataset ingested into a local Splunk Enterprise instance on Ubuntu VM. Assumptions: Dataset covers August 2018 events; time range set to `earliest=0`; no external threat intelligence used beyond dataset logs.

This exercise mirrors Tier 1–3 SOC analyst workflows: monitoring, triage, deep-dive investigation, and recommendations for improved detection/response.

## SOC Roles & Incident Handling Reflection

SOCs operate in tiers: **Tier 1** (alert triage/monitoring), **Tier 2** (deep analysis/escalation), **Tier 3** (hunting/forensics/advanced response). In BOTSv3, Tier 1 would detect high-volume alerts (e.g., public S3 via CloudTrail anomalies), Tier 2 performs SPL queries for root cause (e.g., user bstoll's PutBucketAcl), and Tier 3 recommends controls (e.g., S3 Block Public Access).

Incident handling follows **NIST SP 800-61r2** lifecycle:

- **Preparation** — SOC infrastructure (Splunk with data models, alerts on MFA=false, S3 ACL changes).
- **Detection & Analysis** — Identify indicators (e.g., PutBucketAcl with AllUsers grants, no-MFA API calls).
- **Containment, Eradication, Recovery** — Revoke public access, reset credentials, patch misconfigs.
- **Post-Incident** — Lessons: enforce MFA, least privilege, automated S3 scanning.

BOTSv3 highlights gaps: accidental insider misconfigs (human error) evade prevention; detection relies on log visibility; response delayed without proactive alerts. Reflection: Modern SOCs need SOAR for automation and threat hunting to shift left.

## Installation & Data Preparation

Splunk Enterprise was installed on an Ubuntu 22.04 VM (8GB RAM, 4 vCPU) for realistic SOC simulation (isolated, scalable).

**Steps:**

1. Download Splunk Enterprise (free trial) from splunk.com.
2. Install via `.deb` package: `sudo dpkg -i splunk-*.deb`.
3. Start Splunk: `sudo /opt/splunk/bin/splunk start --accept-license`.
4. Access UI: http://<VM-IP>:8000 (default admin/changeme).
5. Download BOTSv3 dataset: https://github.com/splunk/botsv3 → botsv3_data_set.tgz (~320MB pre-indexed).
6. Ingest: Extract tgz → copy `.spl` files to `/opt/splunk/etc/apps/` or use "Add Data" → monitor directory.
7. Validate: Search `index=botsv3 | stats count by sourcetype` → confirms 100+ sourcetypes (aws:cloudtrail, aws:s3:accesslogs, winhostmon, etc.).
8. Time range: Set to All Time or `earliest=0` for full coverage.

**Justification:** Ubuntu VM mimics lightweight SOC forwarder/standalone; pre-indexed format speeds analysis (no parsing overhead); local setup ensures data sovereignty/privacy. In production SOC, use distributed Splunk (indexers + search heads) with heavy forwarders for scalability.

**Evidence:**  
![Splunk Home Dashboard]  
![Sourcetype Count]  
![Index=botsv3 Stats]

## Guided Questions

Focus: AWS IAM/S3 misconfiguration + endpoint OS anomaly.

**1:** IAM users accessing AWS services?  
**Answer:** bstoll,btun,splunk_access,web_admin  
**Query:** `index=botsv3 sourcetype=aws:cloudtrail earliest=0 | stats count by userIdentity.userName | sort userIdentity.userName`  
**Evidence/SOC Relevance:** CloudTrail logs identity/actions → Tier 1 monitors for anomalous users; enables least-privilege auditing.

**Screenshot:** [IAM Users Table]

**2:** Field for alerting no-MFA API activity?  
**Answer:** userIdentity.sessionContext.attributes.mfaAuthenticated (or additionalEventData.MFAUsed in some extractions)  
**Query:** `index=botsv3 sourcetype=aws:cloudtrail "false" earliest=0 | table userIdentity.sessionContext.attributes.mfaAuthenticated`  
**Relevance:** Critical alert rule for privileged actions without MFA → prevents credential-stuffing escalation.

**3:** Processor number on web servers?  
**Answer:** E5-2676  
**Query:** `index=botsv3 sourcetype=hardware "web" OR gacrux | stats count by cpu_type`  
**Relevance:** Baseline hardware intel for anomaly detection (e.g., unexpected CPU usage in mining).

**4:** Event ID enabling public S3 access?  
**Answer:** ab45689d-69cd-41e7-8705-5350402cf7ac  
**Query:** `index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl "AllUsers" earliest=0 | table eventID requestParameters.AccessControlPolicy`  
**Relevance:** Detects misconfigs → alert on public-read grants.

**Screenshot:** [PutBucketAcl Event]

**5** Bud's username?  
**Answer:** bstoll  
**Query:** From above, `... | table userIdentity.userName`  
**Relevance:** Insider threat/insider error attribution.

**6** Public S3 bucket name?  
**Answer:** frothlywebcode  
**Query:** Same as Q203 → `requestParameters.bucketName`  
**Relevance:** Scope exposure impact.

**7** Text file uploaded while public?  
**Answer:** OPEN_BUCKET_PLEASE_FIX.txt  
**Query:** `index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode operation=RestObjectPUT httpstatus=200 "*.txt" earliest=0 | table key`  
**Relevance:** Exfiltration/data exposure vector → monitor S3 PUTs post-ACL change.

**Screenshot:** [S3 Access Log]

**8** FQDN of endpoint with different Windows edition?  
**Answer:** bstoll-l.froth.ly  
**Query:** `index=botsv3 sourcetype=winhostmon earliest=0 | stats values(caption) as editions by host | sort host` → outlier BSTOLL-L → cross-ref Sysmon/WinEventLog for FQDN.  
**Relevance:** Asset baseline deviation → potential compromise or misconfig indicator.

**Overall Reflection:** These reveal insider misconfig + visibility gaps. SOC improvement: Enable GuardDuty, S3 Block Public Access by default, MFA enforcement, OS inventory baselines.

## Conclusion, References & Professional Presentation

**Findings Summary:** Frothly suffered an accidental public S3 exposure (frothlywebcode) by bstoll, leading to sensitive file upload (OPEN_BUCKET_PLEASE_FIX.txt). No MFA on some API calls, endpoint OS outlier (bstoll-l.froth.ly).

**Key Lessons:** Human error drives many incidents; log visibility (CloudTrail + S3 logs) enables fast detection; baselines critical for anomalies.

**SOC Improvements:** 
- Proactive: Enforce MFA, S3 account-level blocks, automated ACL scanning.
- Detection: Alerts on PutBucketAcl with public grants, no-MFA privileged actions.
- Response: SOAR playbooks for revocation.
- Forward-looking: Adopt MITRE ATT&CK for Cloud, integrate with AWS Config rules.

**References** (IEEE style):  
[1] P. Cichonski et al., "Computer Security Incident Handling Guide," NIST Special Publication 800-61 Revision 2, 2012. [Online]. Available: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf  
[2] Splunk, "BOTSv3 Dataset," GitHub, 2018. [Online]. Available: https://github.com/splunk/botsv3  
[3] AWS, "Amazon S3 PutBucketAcl API," AWS Documentation. [Online]. Available: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html  

**Appendices:** Screenshots folder, full SPL queries export.

**Video:** Embedded/linked above – demonstrates live Splunk searches, dashboards (e.g., AWS Overview), and strategic discussion.
