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
