# 11. The Control Selection

## MedDefense Health Systems — Control Selection and Framework Mapping

This task maps the **10 risks marked "Mitigate" in Task 10** to specific security controls selected from the Task 7 cost-benefit analysis.

### Framework convention

- **CIS mappings:** CIS Critical Security Controls v8/v8.1 safeguard numbering.
- **NIST mappings:** NIST Cybersecurity Framework (CSF) **Version 1.1** category notation, because the task specifies mappings such as `PR.AC`.
- **Cost basis:** Year-1 annual planning estimates from Task 7.
- **Budget basis:** Task 8 funds Controls 1, 2, 3, 4, 5 and 8 for exactly **$120,000**. The Westside firewall remains **deferred** and the outsourced 24/7 SOC remains **rejected**.
- **Risk-reduction figures:** Task 7 control reductions are standalone estimates. Where several controls reduce the same risk, their ALE reductions overlap and must **not** be added together as if they were independent savings.

---

# RISK-001 — Ransomware Double Extortion Against the EHR

## Control 1 — Network Segmentation

```yaml
Risk: RISK-001
Selected Control: Network segmentation between user, server, EHR, Active Directory, backup, and other sensitive network zones
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  Task 7 modeled ransomware ALE falling from $1,050,000 to $612,500,
  a standalone reduction of $437,500. The model reduces Exposure Factor
  from 60% to 35% by limiting lateral movement and blast radius.
Dependencies: >
  Requires an accurate network architecture and approved communication paths.
  This control should be implemented before the dedicated medical-device
  isolation design is finalized.
```

## Control 2 — MFA for VPN and Administrative Access

```yaml
Risk: RISK-001
Selected Control: Multi-factor authentication for VPN, privileged and administrative accounts
CIS Control Mapping:
  - CIS Control 6 — Access Control Management
  - Safeguard 6.4 — Require MFA for Remote Network Access
  - Safeguard 6.5 — Require MFA for Administrative Access
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
Control Type: Preventive
Control Category: Technical
Implementation Cost: $4,000/year
Expected Risk Reduction: >
  Task 7 modeled ransomware ALE falling from $1,050,000 to $840,000,
  a standalone reduction of $210,000. The modeled ARO falls from
  0.35 to 0.28 because stolen remote or privileged credentials become
  less useful without the second authentication factor.
Dependencies: >
  Requires a current inventory of privileged, VPN and administrative accounts.
  No other funded Task 7 control must be deployed first.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-001
Selected Control: Centralized security logging, correlation and alerting using Wazuh SIEM
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.1 — Centralize Security Event Alerting
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 modeled ransomware ALE falling from $1,050,000 to $910,000,
  a standalone reduction of $140,000. Earlier detection is modeled as
  reducing Exposure Factor from 60% to 52%.
Dependencies: >
  Requires log-producing systems to have logging enabled and relevant sources
  to be identified. EDR, firewall and medical-device logs can be integrated
  after the Wazuh platform is operational.
```

## Control 4 — Offsite Immutable Backup

```yaml
Risk: RISK-001
Selected Control: Offsite immutable backup replication using AWS S3 Glacier / immutable storage
CIS Control Mapping:
  - CIS Control 11 — Data Recovery
  - Safeguard 11.2 — Perform Automated Backups
  - Safeguard 11.3 — Protect Recovery Data
  - Safeguard 11.4 — Establish and Maintain an Isolated Instance of Recovery Data
  - Safeguard 11.5 — Test Data Recovery
NIST CSF Mapping:
  - PR.IP — Information Protection Processes and Procedures
  - RC.RP — Recovery Planning
Control Type: Corrective
Control Category: Technical
Implementation Cost: $15,000/year
Expected Risk Reduction: >
  Task 7 modeled ransomware ALE falling from $1,050,000 to $787,500,
  a standalone reduction of $262,500. The model reduces Exposure Factor
  from 60% to 45% because clean recovery remains available even if
  production systems are encrypted.
Dependencies: >
  Requires identification of critical systems, backup scope, retention
  requirements and protected backup credentials. Restore testing follows
  successful replication and immutability configuration.
```

## Control 5 — Sophos Intercept X EDR

```yaml
Risk: RISK-001
Selected Control: Upgrade endpoint and server protection to Sophos Intercept X EDR
CIS Control Mapping:
  - CIS Control 10 — Malware Defenses
  - Safeguard 10.1 — Deploy and Maintain Anti-Malware Software
  - Safeguard 10.5 — Enable Anti-Exploitation Features
  - Safeguard 10.6 — Centrally Manage Anti-Malware Software
  - Safeguard 10.7 — Use Behavior-Based Anti-Malware Software
  - CIS Control 13, Safeguard 13.7 — Deploy a Host-Based Intrusion Prevention Solution
NIST CSF Mapping:
  - PR.PT — Protective Technology
  - DE.CM — Security Continuous Monitoring
Control Type: Preventive / Detective
Control Category: Technical
Implementation Cost: $36,000/year
Expected Risk Reduction: >
  Task 7 modeled ransomware ALE falling from $1,050,000 to $870,000,
  a standalone reduction of $180,000. The modeled ARO falls from
  0.35 to 0.29 through better detection and prevention of malicious
  execution, persistence and credential theft.
Dependencies: >
  Requires an accurate inventory of supported endpoints and servers.
  EDR can be deployed independently, but forwarding EDR events to Wazuh
  depends on the SIEM integration being configured.
```

---

# RISK-002 — Active Directory Privileged Compromise

## Control 2 — MFA for Administrative Access

```yaml
Risk: RISK-002
Selected Control: MFA for privileged Active Directory and other administrative accounts
CIS Control Mapping:
  - CIS Control 6 — Access Control Management
  - Safeguard 6.5 — Require MFA for Administrative Access
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
Control Type: Preventive
Control Category: Technical
Implementation Cost: $4,000/year
Expected Risk Reduction: >
  Task 7 modeled Active Directory compromise ALE falling from $210,000
  to $140,000, a standalone reduction of $70,000. The modeled ARO falls
  from 0.30 to 0.20.
Dependencies: >
  Requires a complete privileged-account inventory and confirmation of
  authentication paths that support MFA.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-002
Selected Control: Centralized monitoring of Active Directory authentication, privilege and security events through Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.1 — Centralize Security Event Alerting
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 modeled Active Directory compromise ALE falling from $210,000
  to $186,000, a standalone reduction of $24,000 through earlier
  detection and response.
Dependencies: >
  Active Directory audit logging must be enabled and forwarded to Wazuh.
  The SIEM platform itself does not depend on MFA or segmentation.
```

## Control 1 — Network Segmentation

```yaml
Risk: RISK-002
Selected Control: Restrict network paths to domain controllers and privileged management services
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  Task 7 did not calculate a separate Active Directory ALE reduction
  for segmentation. The control reduces attack paths and the ability
  to reach domain controllers from ordinary user or server networks.
  Task 10 projects overall RISK-002 residual risk falling from
  20 Critical to 10 High after the planned controls.
Dependencies: >
  Requires network architecture documentation and approved management paths.
```

---

# RISK-003 — Backup and Recovery Infrastructure Neutralized During Ransomware

## Control 4 — Offsite Immutable Backup

```yaml
Risk: RISK-003
Selected Control: Offsite immutable backup replication with protected recovery copies and restore testing
CIS Control Mapping:
  - CIS Control 11 — Data Recovery
  - Safeguard 11.2 — Perform Automated Backups
  - Safeguard 11.3 — Protect Recovery Data
  - Safeguard 11.4 — Establish and Maintain an Isolated Instance of Recovery Data
  - Safeguard 11.5 — Test Data Recovery
NIST CSF Mapping:
  - PR.IP — Information Protection Processes and Procedures
  - RC.RP — Recovery Planning
Control Type: Corrective
Control Category: Technical
Implementation Cost: $15,000/year
Expected Risk Reduction: >
  Task 6 did not calculate a separate ALE for backup neutralization because
  its financial impact is included in RISK-001. Task 10 projects overall
  RISK-003 residual risk falling from 20 Critical to 8 Moderate once
  immutable offsite copies and restricted recovery paths are in place.
Dependencies: >
  Backup scope and critical-system priorities must be defined first.
  Replication must be operational before restore tests can validate recovery.
```

## Control 1 — Network Segmentation

```yaml
Risk: RISK-003
Selected Control: Isolate backup servers, NAS storage and backup administration from ordinary workstation and server networks
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  No separate backup-infrastructure ALE reduction was calculated in Task 7.
  Segmentation reduces the chance that a production-system compromise can
  directly reach backup administration and recovery infrastructure.
Dependencies: >
  Network segmentation design should identify the backup zone and the
  minimum approved management and replication flows.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-003
Selected Control: Monitor backup authentication, deletion, configuration and failure events through Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  No separate Task 7 ALE reduction was assigned specifically to RISK-003.
  The control improves detection of abnormal backup deletion, access,
  configuration changes and failed jobs before recovery capability is lost.
Dependencies: >
  Backup platforms must produce usable security and operational logs and
  forward them to Wazuh.
```

---

# RISK-004 — Opportunistic Compromise of `billing-srv-01`

## Control 5 — Sophos Intercept X EDR

```yaml
Risk: RISK-004
Selected Control: Deploy Sophos Intercept X EDR on billing-srv-01 and other supported servers/endpoints
CIS Control Mapping:
  - CIS Control 10 — Malware Defenses
  - Safeguard 10.1 — Deploy and Maintain Anti-Malware Software
  - Safeguard 10.5 — Enable Anti-Exploitation Features
  - Safeguard 10.6 — Centrally Manage Anti-Malware Software
  - Safeguard 10.7 — Use Behavior-Based Anti-Malware Software
  - CIS Control 13, Safeguard 13.7 — Deploy a Host-Based Intrusion Prevention Solution
NIST CSF Mapping:
  - PR.PT — Protective Technology
  - DE.CM — Security Continuous Monitoring
Control Type: Preventive / Detective
Control Category: Technical
Implementation Cost: $36,000/year
Expected Risk Reduction: >
  Task 7 modeled billing-srv-01 ALE falling from $234,000 to $136,500,
  a standalone reduction of $97,500. The modeled ARO falls from
  0.60 to 0.35.
Dependencies: >
  The server must support the EDR agent. Central management should be
  established before relying on EDR coverage as an operational control.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-004
Selected Control: Centralized logging and alerting for billing-srv-01 through Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 modeled billing-srv-01 ALE falling from $234,000 to $195,000,
  a standalone reduction of $39,000 through improved detection.
Dependencies: >
  Logging must be enabled on billing-srv-01 and forwarded to Wazuh.
  EDR events can be added as an additional source after EDR deployment.
```

## Control 1 — Network Segmentation

```yaml
Risk: RISK-004
Selected Control: Restrict billing-srv-01 communication to required business and administrative paths
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  Task 7 recognized additional billing-server risk reduction from segmentation
  but did not add a separate ALE value to the financial case. The control
  limits lateral movement if the vulnerable server is compromised.
Dependencies: >
  Requires an approved list of services and systems that legitimately
  communicate with billing-srv-01.
```

---

# RISK-005 — Negligent Insider or Unmanaged Endpoint Creates a Foothold

## Control 5 — Sophos Intercept X EDR

```yaml
Risk: RISK-005
Selected Control: Centrally managed EDR coverage for supported MedDefense workstations and servers
CIS Control Mapping:
  - CIS Control 10 — Malware Defenses
  - Safeguard 10.1 — Deploy and Maintain Anti-Malware Software
  - Safeguard 10.6 — Centrally Manage Anti-Malware Software
  - Safeguard 10.7 — Use Behavior-Based Anti-Malware Software
  - CIS Control 13, Safeguard 13.7 — Deploy a Host-Based Intrusion Prevention Solution
NIST CSF Mapping:
  - PR.PT — Protective Technology
  - DE.CM — Security Continuous Monitoring
Control Type: Preventive / Detective
Control Category: Technical
Implementation Cost: $36,000/year
Expected Risk Reduction: >
  No separate ALE was calculated for RISK-005. EDR reduces the chance that
  malware or unauthorized activity on a managed endpoint becomes a persistent
  foothold. Task 10 projects overall residual risk falling from
  16 Critical to 8 Moderate after the planned controls.
Dependencies: >
  Requires reconciliation of the enterprise asset inventory so unsupported,
  unknown or unmanaged devices can be identified instead of assumed protected.
```

## Control 1 — Network Segmentation

```yaml
Risk: RISK-005
Selected Control: Limit network access available to unmanaged, unknown and user endpoint networks
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive / Compensating
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  No separate ALE reduction was calculated for this risk. Segmentation
  limits the damage an unmanaged endpoint can cause by restricting access
  to EHR, Active Directory, backup and other sensitive zones.
Dependencies: >
  Requires identification of endpoint, guest, unmanaged-device and
  sensitive-server network zones.
```

---

# RISK-006 — Unsupported Windows XP MRI Workstation Exploited

## Control 1 — Network Segmentation

```yaml
Risk: RISK-006
Selected Control: Strictly isolate WS-RAD-01 from general-purpose networks and allow only required clinical communication
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Compensating / Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  Task 7 did not calculate a standalone ALE reduction for MRI segmentation.
  The control is compensating because Windows XP cannot be brought back into
  normal vendor support. Task 10 projects RISK-006 falling from
  15 High to 10 High after isolation and monitoring.
Dependencies: >
  Requires confirmation of the MRI workstation's legitimate clinical
  communication paths before deny-by-default filtering is applied.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-006
Selected Control: Monitor network/security events associated with the MRI workstation and its permitted gateways through Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.6 — Collect Network Traffic Flow Logs
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective / Compensating
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  No standalone Task 7 ALE reduction was calculated for this control against
  the MRI risk. Monitoring provides a compensating detection layer around an
  end-of-life host that may not support modern endpoint security tooling.
Dependencies: >
  Because the Windows XP workstation may not support a modern agent,
  monitoring depends on usable network, firewall or gateway telemetry being
  sent to Wazuh.
```

---

# RISK-007 — Alaris Pump Environment Compromise or Disruption

## Control 8 — Medical-Device Isolation and Monitoring

```yaml
Risk: RISK-007
Selected Control: Dedicated medical-device network isolation with tightly controlled traffic and security monitoring
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - CIS Control 13, Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
  - CIS Control 13, Safeguard 13.3 — Deploy a Network Intrusion Detection Solution
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - DE.CM — Security Continuous Monitoring
Control Type: Preventive / Detective / Compensating
Control Category: Technical / Operational
Implementation Cost: $18,000/year
Expected Risk Reduction: >
  Task 7 modeled Alaris ALE falling from $108,000 to $24,000,
  a standalone reduction of $84,000. The model reduces EF from 45% to 25%
  and ARO from 0.20 to 0.08.
Dependencies: >
  The enterprise segmentation architecture should be defined first so the
  medical-device zone, approved clinical services and blocked paths can be
  implemented consistently. Clinical Engineering must validate required flows.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-007
Selected Control: Centralize available Alaris-zone, network and security telemetry in Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.1 — Centralize Security Event Alerting
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical / Operational
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 modeled Alaris ALE falling from $108,000 to $96,000 under the
  SIEM control alone, a standalone reduction of $12,000.
Dependencies: >
  Requires medical-device zone telemetry, network logs or supported device
  events to be available. The isolation project defines the boundaries that
  monitoring should observe.
```

---

# RISK-008 — Trusted Vendor / Supply-Chain Compromise Reaches the EHR

## Control 2 — MFA for Vendor and Administrative Access

```yaml
Risk: RISK-008
Selected Control: MFA for vendor remote access and privileged maintenance accounts
CIS Control Mapping:
  - CIS Control 6 — Access Control Management
  - Safeguard 6.4 — Require MFA for Remote Network Access
  - Safeguard 6.5 — Require MFA for Administrative Access
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - ID.SC — Supply Chain Risk Management
Control Type: Preventive
Control Category: Technical / Administrative
Implementation Cost: $4,000/year
Expected Risk Reduction: >
  Task 7 did not calculate a separate vendor-compromise ALE. MFA reduces
  the usefulness of stolen or reused vendor credentials. Task 10 projects
  overall RISK-008 residual risk falling from 15 High to 10 High after
  the planned controls.
Dependencies: >
  Vendor accounts must be individually identified, owned and tied to
  approved access paths before MFA coverage can be verified.
```

## Control 1 — Network Segmentation

```yaml
Risk: RISK-008
Selected Control: Constrain vendor maintenance access to the specific systems and services required
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - ID.SC — Supply Chain Risk Management
Control Type: Preventive
Control Category: Technical
Implementation Cost: $25,000/year
Expected Risk Reduction: >
  No standalone ALE reduction was calculated for the vendor risk.
  Segmentation reduces the scope of a compromised trusted vendor account
  by preventing unrestricted movement from maintenance access into EHR,
  Active Directory or other Critical systems.
Dependencies: >
  Requires documented vendor access requirements and an approved network
  architecture.
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-008
Selected Control: Monitor vendor authentication and maintenance activity through Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - Safeguard 8.12 — Collect Service Provider Logs, where supported
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
  - ID.SC — Supply Chain Risk Management
Control Type: Detective
Control Category: Technical / Administrative
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  No separate ALE reduction was calculated. Centralized logging gives
  MedDefense visibility into unusual vendor logins, privilege use and
  maintenance activity that could otherwise resemble legitimate access.
Dependencies: >
  Vendor access systems and supported provider services must generate
  authentication and activity logs that can be collected.
```

---

# RISK-009 — Malicious Insider Misuses Legitimate EHR Access

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-009
Selected Control: Centralize and review EHR authentication and access logs for anomalous or high-risk activity
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.1 — Centralize Security Event Alerting
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical / Operational
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 did not calculate a separate malicious-insider ALE. The control
  addresses the visibility weakness documented in Task 10 by making
  inappropriate access patterns easier to detect and review. Task 10 projects
  overall RISK-009 residual risk falling from 15 High to 8 Moderate after
  the planned controls.
Dependencies: >
  EHR authentication and access auditing must be enabled and available
  for ingestion into Wazuh.
```

## Control 2 — MFA

```yaml
Risk: RISK-009
Selected Control: MFA for privileged and remote accounts capable of accessing or administering the EHR environment
CIS Control Mapping:
  - CIS Control 6 — Access Control Management
  - Safeguard 6.4 — Require MFA for Remote Network Access
  - Safeguard 6.5 — Require MFA for Administrative Access
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
Control Type: Preventive
Control Category: Technical
Implementation Cost: $4,000/year
Expected Risk Reduction: >
  No separate ALE reduction was calculated for RISK-009. MFA does not stop
  an authorized insider from abusing access they legitimately possess, but
  it reduces account takeover, credential sharing and misuse of privileged
  or remote access paths.
Dependencies: >
  Requires identification of privileged and remote EHR-related accounts.
  It complements, rather than replaces, audit monitoring.
```

---

# RISK-010 — Westside Clinic Perimeter Compromise

## Control 6 — Dedicated Westside Enterprise Firewall

```yaml
Risk: RISK-010
Selected Control: Replace the consumer-grade Westside edge router with a dedicated enterprise firewall and controlled VPN boundary
CIS Control Mapping:
  - CIS Control 12 — Network Infrastructure Management
  - Safeguard 12.1 — Ensure Network Infrastructure is Up-to-Date
  - Safeguard 12.2 — Establish and Maintain a Secure Network Architecture
  - CIS Control 13, Safeguard 13.4 — Perform Traffic Filtering Between Network Segments
NIST CSF Mapping:
  - PR.AC — Identity Management and Access Control
  - PR.PT — Protective Technology
Control Type: Preventive
Control Category: Technical
Implementation Cost: $15,000/year
Expected Risk Reduction: >
  Task 7 estimated approximately $30,000/year of modeled risk reduction
  from replacing the Westside boundary device. In Task 8 this control was
  deferred because the funded portfolio already consumes the full $120,000
  budget. RISK-010 therefore remains 12 High until the firewall is funded;
  after deployment, Task 10 projects residual risk of 8 Moderate.
Dependencies: >
  The firewall should align with the enterprise segmentation architecture,
  approved Westside-to-Central VPN flows and centralized logging design.
Funding Status: Deferred to a later funding cycle
```

## Control 3 — Wazuh SIEM

```yaml
Risk: RISK-010
Selected Control: Centralize available Westside router, VPN, server and security logs in Wazuh
CIS Control Mapping:
  - CIS Control 8 — Audit Log Management
  - Safeguard 8.9 — Centralize Audit Logs
  - Safeguard 8.11 — Conduct Audit Log Reviews
  - CIS Control 13, Safeguard 13.1 — Centralize Security Event Alerting
NIST CSF Mapping:
  - DE.CM — Security Continuous Monitoring
  - DE.AE — Anomalies and Events
Control Type: Detective
Control Category: Technical
Implementation Cost: $22,000/year
Expected Risk Reduction: >
  Task 7 did not assign a separate Westside-specific ALE reduction to Wazuh.
  The funded SIEM still improves visibility into suspicious VPN, server and
  boundary activity while the dedicated firewall remains deferred.
Dependencies: >
  Existing Westside devices must export usable logs. When the new firewall
  is eventually funded, its security and VPN logs should also be onboarded.
```

---

# Control Dependency Map

The map below shows **implementation dependencies and logical sequencing**, not a requirement that every control wait for the previous one. Several controls can be implemented in parallel.

```text
Existing prerequisites
|
+-- Asset inventory / account inventory / network architecture / log-source inventory
|      |
|      +--> Network Segmentation — T7 Control 1
|      |      |
|      |      +--> Medical-Device Isolation — T7 Control 8
|      |      |      |
|      |      |      +--> Medical-device network telemetry to Wazuh
|      |      |
|      |      +--> Westside Firewall — T7 Control 6 [DEFERRED]
|      |             |
|      |             +--> Westside firewall/VPN logs to Wazuh
|      |
|      +--> MFA — T7 Control 2
|      |      |
|      |      +--> Administrative / VPN / vendor accounts protected
|      |
|      +--> Wazuh SIEM Core — T7 Control 3
|      |      |
|      |      +--> Active Directory logs
|      |      +--> EHR logs
|      |      +--> Billing server logs
|      |      +--> Backup logs
|      |      +--> EDR alerts
|      |      +--> Medical-device / network telemetry
|      |      +--> Westside logs
|      |
|      +--> Sophos Intercept X EDR — T7 Control 5
|      |      |
|      |      +--> EDR events integrated into Wazuh
|      |
|      +--> Offsite Immutable Backup — T7 Control 4
|             |
|             +--> Replication and immutability configured
|                    |
|                    +--> Restore testing
|
+-- Clinical Engineering validation
       |
       +--> Approved medical-device communication paths
              |
              +--> Final medical-device isolation rules
```

## Dependency Interpretation

### 1. Network segmentation is the architectural foundation

The general segmentation design should be established before MedDefense finalizes the medical-device isolation rules. The Alaris environment needs a clearly defined zone, known dependencies and approved clinical communication paths so isolation does not interfere with patient care.

### 2. Wazuh must exist before centralized monitoring can work

Individual systems can generate logs before the SIEM is deployed, but Wazuh must be operational before MedDefense can correlate those sources centrally. EDR, Active Directory, EHR, backup, medical-device-network and future Westside firewall telemetry should then be onboarded in stages.

### 3. EDR and SIEM complement each other but can be deployed in parallel

Sophos Intercept X does not technically require Wazuh to protect endpoints. However, integrating EDR alerts with the SIEM improves central visibility and incident investigation.

### 4. Immutable backup requires validation after implementation

The backup platform must first replicate protected recovery copies to an isolated or immutable location. Only then can MedDefense perform meaningful recovery testing and confirm that the control actually works.

### 5. The Westside firewall remains deferred

The enterprise firewall is still a selected treatment for RISK-010, but it is **not included in the current $120,000 funded programme**. Current-year monitoring through Wazuh can improve detection at Westside, but the full projected reduction to **8 Moderate** depends on the firewall being funded and deployed in a later cycle.

---

# Control Selection Summary

| Risk ID | Selected Controls | Current Funding Position |
|---|---|---|
| **RISK-001** | Segmentation, MFA, Wazuh SIEM, immutable backup, EDR | Funded |
| **RISK-002** | MFA, Wazuh SIEM, segmentation | Funded |
| **RISK-003** | Immutable backup, segmentation, Wazuh SIEM | Funded |
| **RISK-004** | EDR, Wazuh SIEM, segmentation | Funded |
| **RISK-005** | EDR, segmentation | Funded |
| **RISK-006** | Segmentation, Wazuh SIEM | Funded compensating controls |
| **RISK-007** | Medical-device isolation and monitoring, Wazuh SIEM | Funded |
| **RISK-008** | MFA, segmentation, Wazuh SIEM | Funded |
| **RISK-009** | Wazuh SIEM, MFA | Funded |
| **RISK-010** | Westside enterprise firewall, Wazuh SIEM | SIEM funded; firewall deferred |

---

# Budget Consistency Check

```text
Network segmentation:                 $25,000
MFA:                                   $4,000
Wazuh SIEM:                           $22,000
Offsite immutable backup:             $15,000
Sophos Intercept X EDR:               $36,000
Medical-device isolation:             $18,000
------------------------------------------------
Current funded programme:            $120,000
Available budget:                    $120,000
Remaining:                                 $0
```

```text
Deferred:
Westside enterprise firewall:         $15,000

Rejected for current programme:
Outsourced 24/7 SOC:                 $240,000
```

The control-selection plan therefore remains consistent with Task 8. Selecting the Westside firewall as the intended treatment for RISK-010 does **not** mean it is currently funded.

---

# Framework Mapping Notes

The selected safeguards were chosen because they directly match the intended implementation:

- **CIS 12.2** explicitly requires a secure network architecture addressing segmentation and least privilege.
- **CIS 13.4** requires traffic filtering between network segments.
- **CIS 6.4 and 6.5** require MFA for remote network and administrative access.
- **CIS 8.9** specifically identifies SIEM-style centralization of audit logs, while **8.11** requires regular review.
- **CIS 13.1** covers centralized security-event alerting and correlation.
- **CIS 11.2–11.5** cover automated backups, protection of recovery data, isolated recovery copies and recovery testing.
- **CIS 10.1, 10.5, 10.6 and 10.7** cover managed anti-malware, exploit protection, central management and behavior-based malware defenses.
- **CIS 13.7** explicitly recognizes EDR as an example of a host-based intrusion-prevention solution.
- NIST CSF 1.1 mappings use the task's requested category notation, including **PR.AC**, **PR.PT**, **DE.CM**, **DE.AE**, **PR.IP**, **RC.RP** and **ID.SC**.

---

# Conclusion

The control selections preserve traceability from the MedDefense Risk Register to the funded security programme.

The same six controls funded in Task 8 are used to mitigate the risks they were designed to address:

1. Network segmentation
2. MFA
3. Wazuh SIEM
4. Offsite immutable backup
5. Sophos Intercept X EDR
6. Medical-device isolation and monitoring

The Westside enterprise firewall remains the planned treatment for **RISK-010**, but its **$15,000** cost is deferred because the current programme already uses the full **$120,000** budget.

This keeps Task 11 consistent with the risk decisions, cost-benefit analysis and budget allocation established in the previous tasks.
