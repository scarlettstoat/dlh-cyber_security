# MedDefense Health Systems — Complete Control Matrix

This document consolidates the security controls identified across the MedDefense assessment to date. It updates the original control inventory with controls evidenced through the incident analysis, physical walk-through, environment documentation and asset reconciliation.

## Effectiveness Rating

- **Strong** — properly configured, covering the intended scope and actively maintained.
- **Adequate** — implemented and useful, but limited by scope, coverage, age or other documented weaknesses.
- **Weak** — present but poorly implemented, easily bypassed, ad hoc or insufficiently maintained.

---

# Part 1: Updated Control Registry

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence / Source |
|---|---|---|---|---|---|---|
| **C-001** | Inbound Web Firewall Restriction | Technical | Preventive | `web-srv-01`, patient portal, public website and DMZ | **Adequate** | Task 4 firewall extract permits inbound HTTP/HTTPS only. Effectiveness is limited because later asset reconciliation shows uncertainty over whether `web-srv-01` is actually isolated in a DMZ. |
| **C-002** | Default Deny Firewall Rule | Technical | Preventive | Systems and network zones behind the FortiGate | **Strong** | Task 4 firewall extract shows an enabled `Deny-All` rule blocking traffic not explicitly permitted by earlier policies. |
| **C-003** | Firewall Traffic Logging | Technical | Detective | Traffic traversing the FortiGate | **Adequate** | Task 4 firewall rules log web, VPN, outbound and denied traffic. Logs exist, but MedDefense has no centralized SIEM or continuous monitoring capability documented. |
| **C-004** | SSH Root Login Disabled | Technical | Preventive | `ehr-srv-01` | **Strong** | Task 4 SSH configuration explicitly sets `PermitRootLogin no`. |
| **C-005** | SSH Key-Only Authentication | Technical | Preventive | `ehr-srv-01` | **Strong** | Task 4 SSH configuration enables public-key authentication and disables password authentication. |
| **C-006** | SSH Authentication Attempt Limit | Technical | Preventive | `ehr-srv-01` | **Strong** | Task 4 SSH configuration limits authentication attempts with `MaxAuthTries 3`. |
| **C-007** | SSH Forwarding Restrictions | Technical | Preventive | `ehr-srv-01` and resources reachable from it | **Strong** | Task 4 SSH configuration disables X11 and TCP forwarding. |
| **C-008** | SSH Authentication Logging | Technical | Detective | `ehr-srv-01` | **Adequate** | Task 4 config sends SSH authentication activity to the `AUTH` facility with `VERBOSE` logging, but logs are not centrally monitored. |
| **C-009** | Password Requirements Policy | Administrative | Preventive | MedDefense user accounts and information systems within policy scope | **Weak** | Task 4 password policy requires eight-character passwords, complexity, 90-day rotation and five-password history. Enforcement beyond documented Windows systems is unclear and the minimum requirement is limited. |
| **C-010** | Active Directory Password Policy Enforcement | Technical | Preventive | Windows systems and AD accounts | **Adequate** | Task 4 confirms enforcement through Active Directory Group Policy. Coverage is limited to systems governed by AD policy. |
| **C-011** | Account Lockout | Technical | Preventive | Accounts subject to the password policy | **Strong** | Task 4 documents a 30-minute lockout after five failed authentication attempts. |
| **C-012** | Password History Enforcement | Technical | Preventive | Accounts subject to the password policy | **Adequate** | Task 4 documents retention of the previous five passwords to restrict immediate reuse. |
| **C-013** | Shared Account Password Change on Departure | Administrative | Preventive | Systems using shared accounts | **Weak** | Task 4 policy requires shared passwords to change when someone with access leaves, but shared accounts remain in use and weaken individual accountability. |
| **C-014** | Sophos Endpoint Malware Protection | Technical | Preventive | 372 managed Windows 10/11 workstations | **Adequate** | Task 4 Sophos report confirms active malware protection. Task 7 identified a Windows endpoint population materially larger than 372, leaving a coverage gap. |
| **C-015** | Sophos Automated Threat Containment | Technical | Corrective | Windows endpoints covered by Sophos | **Adequate** | Task 4 shows detected threats being blocked or quarantined automatically; effectiveness is constrained by endpoint coverage. |
| **C-016** | Nightly Virtual Machine Backups | Technical | Corrective | `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01`, `web-srv-01` | **Adequate** | Task 4 documents nightly Veeam backups with 14-day retention. The backup server and NAS are in the same rack/network and several documented servers are outside the listed backup scope. |
| **C-017** | Backup Restore Testing | Administrative | Detective | Backup and recovery capability | **Weak** | Task 4 documents only a partial restore test of `file-srv-01`, performed eight months earlier. |
| **C-018** | Main Entrance Security Guard | Physical | Deterrent | MedDefense Central main entrance and facility occupants | **Adequate** | Task 4 physical-security contract provides one guard Monday-Friday, 07:00-19:00. There is no night or weekend guard coverage. |
| **C-019** | Visitor Registration and Badge Verification | Administrative | Preventive | Central facility access through the main entrance | **Adequate** | Task 4 documents visitor registration and badge checks at the security desk. Task 3 found an alternative restricted-area door propped open, reducing overall effectiveness. |
| **C-020** | Security Guard Incident Reporting | Administrative | Detective | Incidents observable at the Central main entrance | **Adequate** | Task 4 assigns incident reporting to the contracted guard, but coverage is limited to staffed hours and the main-entrance area. |
| **C-021** | Central CCTV Monitoring and Recording | Physical | Detective | Main entrance, ER entrance and parking-garage entrance | **Weak** | Task 4 documents four analog cameras and 30-day DVR retention. Task 3 confirms that no camera covers the server-room entrance. |
| **C-022** | Westside Entrance Camera | Physical | Detective | Westside Clinic front entrance | **Weak** | Task 4 documents one locally recorded camera with approximately 48 hours of SD-card retention. |
| **C-023** | Annual Security Awareness Training | Administrative | Preventive | MedDefense personnel, systems and information | **Adequate** | Task 4 records annual `CyberSafe Basics` training covering passwords, phishing, physical security and reporting. No ongoing testing or effectiveness metrics are documented. |
| **C-024** | FortiGate Local Log Retention | Technical | Detective | FortiGate and network traffic handled by it | **Adequate** | Task 4 documents 30 days of local firewall logs. Lack of centralized collection and continuous monitoring limits detection capability. |
| **C-025** | Windows Server Event Logging | Technical | Detective | Windows servers | **Weak** | Task 4 confirms Windows Event Viewer logging, but review is manual and there is no centralized log-management platform. |
| **C-026** | Linux Server Syslog | Technical | Detective | Linux servers | **Weak** | Task 4 confirms standard local syslog records under `/var/log`; no central aggregation or continuous monitoring is documented. |
| **C-027** | Apache Log Retention | Technical | Detective | `web-srv-01` and `billing-srv-01` | **Weak** | Task 4 documents weekly rotation and four-week retention, but the logs remain locally managed and are not continuously monitored. |
| **C-028** | EHR Application Audit Logging | Technical | Detective | EHR application and patient-record access | **Adequate** | Task 4 confirms vendor-managed EHR audit logging. MedDefense must request exports rather than having documented continuous internal monitoring. |
| **C-029** | Active Directory Critical Event Logging | Technical | Detective | Active Directory | **Weak** | Task 4 confirms AD critical-event logging, but records are reviewed manually and there is no centralized SIEM. |
| **C-030** | Secondary Active Directory Domain Controller | Technical | Corrective | Active Directory authentication and directory services | **Adequate** | Task 0 and Task 7 identify both `ad-dc-01` and `ad-dc-02`. The second controller provides service redundancy, although both remain dependent on the broader Central environment. |
| **C-031** | Site-to-Site VPN Protection | Technical | Preventive | Traffic between Central, Westside and Corporate HQ | **Adequate** | Task 0 documents IPSec/site-to-site VPN connectivity to Central. HQ configuration appeared functional, but ACLs were not audited; Westside relies on a consumer Netgear router with no separate firewall. |
| **C-032** | Central UPS Power Protection | Physical | Preventive | Central systems connected to the UPS | **Weak** | Task 0 documents approximately 20 minutes of UPS support. Exact protected systems, tested runtime and shutdown procedures are unknown. |
| **C-033** | HID Badge Access Control | Physical | Preventive | Controlled doors and restricted areas at Central | **Weak** | Task 0 and Task 7 confirm an AD-connected HID badge system. Task 3 found that the server room accepts the same generic badge issued broadly to employees and that another restricted-area door was physically propped open. |
| **C-034** | Separate Guest Wi-Fi SSID | Technical | Preventive | Corporate/internal wireless environment | **Weak** | Task 0 documents a separate guest SSID, but actual isolation from the internal network has never been verified. |
| **C-035** | Paper-Record EHR Outage Fallback | Administrative | Compensating | Clinical operations dependent on the EHR | **Weak** | Incident E documents that physicians reverted to paper records during the nine-hour EHR outage. This provided a temporary alternative, but no formal business-continuity or tested downtime procedure is documented. |
| **C-036** | Printed Medication Reference Cross-Check | Administrative | Detective | Pharmacy management and medication dosage information | **Weak** | Incident C was detected when a pharmacist noticed that electronic dosage values did not match a printed reference. The control proved useful, but no evidence shows that this comparison is a formal or systematic validation process. |

---

# Part 2: Updated Control Summary Matrix

For averaging effectiveness, the following numeric values are used:

- **Strong = 3**
- **Adequate = 2**
- **Weak = 1**

Average scores are interpreted as:

- **2.50-3.00: Strong**
- **1.50-2.49: Adequate**
- **1.00-1.49: Weak**

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | **12 controls** — Avg. **2.42/3 (Adequate)** | **8 controls** — Avg. **1.50/3 (Adequate)** | **3 controls** — Avg. **2.00/3 (Adequate)** | **0 controls** | **0 controls** |
| **Administrative** | **4 controls** — Avg. **1.50/3 (Adequate)** | **3 controls** — Avg. **1.33/3 (Weak)** | **0 controls** | **1 control** — Avg. **1.00/3 (Weak)** | **0 controls** |
| **Physical** | **2 controls** — Avg. **1.00/3 (Weak)** | **2 controls** — Avg. **1.00/3 (Weak)** | **0 controls** | **0 controls** | **1 control** — Avg. **2.00/3 (Adequate)** |

### Matrix Observation

The control landscape is weighted heavily toward **technical preventive and detective controls**. The most visible gaps are the absence of technical compensating controls, administrative corrective controls, physical corrective controls and stronger physical preventive coverage. Detective controls also exist largely as local logs or manual processes rather than centralized, continuously monitored capabilities.

---

# Part 3: Control Coverage Map — Top 5 Critical Assets

| Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|---|---|---|---|---|---|
| **1. EHR System — `ehr-srv-01`, `ehr-db-01`, EHR application** | C-002, C-004, C-005, C-006, C-007, C-009, C-023, C-031, C-033 | C-008, C-026, C-028 | C-016 | C-035 | **Partially Protected** — the EHR has strong SSH hardening, audit logging and backups, but `ehr-db-01` remains reachable from the wider internal network, monitoring is not centralized, backup infrastructure is locally concentrated and the paper fallback is informal. |
| **2. Pharmacy Management System — `A-038`** | C-009, C-023, C-031 | C-036 | — | — | **Under-Protected** — only broad organizational controls and an observed manual dosage cross-check are evidenced. No application-specific preventive controls, centralized monitoring, documented backup/recovery control or formal compensating control has been identified despite the previous six-hour dosage-integrity incident. |
| **3. BD Alaris Infusion-Pump Estate — `A-032`** | C-002, C-023 | C-003 | — | — | **Under-Protected** — the pumps benefit from perimeter protection and staff awareness, but there is no documented device-specific access control, network isolation, corrective recovery capability or compensating control. The scan specifically notes known vulnerabilities and lack of recommended network isolation. |
| **4. Network Core and Connectivity — FortiGate and Central Core Switching** | C-002, C-019, C-023, C-031, C-032, C-033 | C-003, C-020, C-024 | — | — | **Partially Protected** — the FortiGate, VPNs, logging and physical controls provide several layers of protection, but Central remains effectively flat, the second-floor network closet was unlocked with credentials displayed, and no documented network-device configuration backup, redundant core or formal compensating control exists. |
| **5. Active Directory — `ad-dc-01`, `ad-dc-02`** | C-002, C-009, C-010, C-011, C-012, C-013, C-023, C-033 | C-025, C-029 | C-016, C-030 | — | **Partially Protected** — AD has password enforcement, account lockout, logging, one documented backup and a secondary domain controller, but monitoring is manual, no broad MFA or privileged-access management is documented and both controllers remain dependent on the wider Central environment. |

## Coverage Gaps by Critical Asset

### 1. EHR System
All four listed control functions are represented, but coverage remains incomplete. The largest gaps are **internal network restriction around `ehr-db-01`, centralized detection, tested recovery and stronger physical access control**. No strong technical control is documented that restricts database access specifically to the EHR application server.

### 2. Pharmacy Management System
The pharmacy system lacks documented **corrective and compensating controls**, and its detective coverage relies on a manual observation that happened to catch the previous dosage error. The project has not identified application-specific access controls, change validation, audit monitoring or a documented recovery mechanism for this system.

### 3. BD Alaris Infusion Pumps
The infusion-pump estate lacks documented **corrective and compensating controls** and has very limited device-specific preventive or detective protection. The absence of actual network segmentation is especially significant because the devices provide direct patient treatment.

### 4. Network Core and Connectivity
The network core has preventive and detective controls, but no documented **corrective or compensating function** for a core-network failure or compromise. There is also no confirmed redundant core-switch architecture or documented configuration-recovery control.

### 5. Active Directory
AD has preventive, detective and corrective controls, but no documented **compensating control**. More importantly, the preventive layer lacks broadly deployed MFA, privileged-access management and confirmed administrative-account separation, while detective controls rely on manual log review.
