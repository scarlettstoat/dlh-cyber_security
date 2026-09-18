# 3. The Gap-to-Framework Bridge

## Purpose

This document connects MedDefense's highest-priority security gaps to the vulnerability evidence and threat paths identified in Projects 1x00, 1x01, and 1x02.

The objective is to create a clear traceability chain:

**Gap → Vulnerability → Threat → Framework Control → Recommended Action**

The eight gaps below were selected by combining:

- the threat-informed reprioritization from Project 1x01 Task 15;
- the frequency with which a gap appears across the five MedDefense kill chains;
- the final contextualized findings from Project 1x02; and
- the potential impact on Critical clinical, identity, recovery, and business systems.

The three strongest cross-cutting priorities remain **GAP-011 (monitoring), GAP-001 (segmentation), and GAP-007 (MFA/PAM)**. The remaining gaps were selected because Project 1x02 provided strong technical evidence that they expose Critical assets or materially increase the impact of realistic MedDefense attack paths.

---

## 1. GAP-011 — Security Logging Fragmented and Not Continuously Monitored

**Gap Reference:** GAP-011

**Description:** Firewall, SSH, Windows, Linux, Apache, EHR, and Active Directory logs exist, but they are mainly local or manually reviewed and are not continuously correlated.

**Vulnerability Evidence:**  
- **Finding 021** — security events from `ad-dc-02` are not centrally forwarded.
- Project 1x02 also repeatedly showed that useful logs exist on individual systems without a centralized detection process.

**Threat Context:**  
This is the most cross-cutting gap in the threat model. It benefits **Ransomware Groups / Organized Crime, Nation-State APTs, malicious insiders, hacktivists, and opportunistic attackers**.

It appears in:

- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 2** — VPN Entry to Backup Neutralisation
- **Kill Chain 3** — Compromised MedTech Access to the EHR
- **Kill Chain 4** — Retained Insider Access to Active Directory
- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

**NIST CSF Function:** Detect

**CIS Control:** **CIS Control 13 — Network Monitoring and Defense**

**Recommended Action:** Centralize priority security events from AD, EHR, firewalls, Windows/Linux servers, endpoints, and critical clinical systems into a monitored alerting platform with defined review and escalation ownership.

---

## 2. GAP-001 — No Effective Internal Segmentation

**Gap Reference:** GAP-001

**Description:** Central workstations, servers, medical devices, and other systems use different addressing ranges but are not separated by consistently enforced security boundaries.

**Vulnerability Evidence:**  
- **Finding 003** — PostgreSQL on `ehr-db-01` is reachable from the wider internal network.
- **Finding 004** — the unsupported `WS-RAD-01` exposes legacy RDP/SMB services that are dangerous if an attacker gains an internal foothold.
- **Finding 010** — the Alaris environment has a security weakness whose impact increases when medical devices are broadly reachable.
- **Findings 015/030** — NAS management interfaces are broadly reachable internally.

**Threat Context:**  
The gap is a major blast-radius multiplier for **Ransomware Groups / Organized Crime, Nation-State APTs, malicious insiders, and opportunistic attackers**.

It appears in all five modeled kill chains:

- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 2** — VPN Entry to Backup Neutralisation
- **Kill Chain 3** — Compromised MedTech Access to the EHR
- **Kill Chain 4** — Retained Insider Access to Active Directory
- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

**NIST CSF Function:** Protect

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Introduce enforced segmentation between user networks, Critical servers, Active Directory, backups, medical IoT, and clinical legacy systems using least-privilege firewall/ACL rules and default-deny east-west access where practical.

---

## 3. GAP-007 — MFA and Privileged-Access Controls Not Broadly Implemented

**Gap Reference:** GAP-007

**Description:** MFA is not broadly deployed and MedDefense lacks a formal privileged-access-management process and consistently separated administrative identities.

**Vulnerability Evidence:**  
- **Finding 007** — LDAP signing is not enforced on `ad-dc-01`, weakening the integrity of an important identity-management pathway.
- **Finding 009** — password-based SSH authentication remains enabled on `billing-srv-01`, allowing stolen or reused credentials to provide remote shell access.

**Threat Context:**  
This gap is directly relevant to **Ransomware Groups / Organized Crime, Nation-State APTs, and malicious insiders**, because stolen, retained, or vendor credentials become more useful when additional authentication and privileged-access controls are absent.

It appears in:

- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 2** — VPN Entry to Backup Neutralisation
- **Kill Chain 3** — Compromised MedTech Access to the EHR
- **Kill Chain 4** — Retained Insider Access to Active Directory

**NIST CSF Function:** Protect

**CIS Control:** **CIS Control 6 — Access Control Management**

**Recommended Action:** Require MFA for remote, administrative, and vendor access, separate privileged identities from normal user accounts, and introduce controlled privileged-access workflows for Critical systems.

---

## 4. GAP-016 — No Formal Vulnerability and Patch-Management Programme

**Gap Reference:** GAP-016

**Description:** MedDefense lacks a documented end-to-end process for identifying, prioritizing, remediating, and verifying vulnerabilities across exposed and Critical systems.

**Vulnerability Evidence:**  
- **Finding 001** — CVE-2021-44790 affecting Apache `mod_lua` on `billing-srv-01`.
- **Finding 002** — CVE-2019-0211 local privilege escalation on the same Apache host.
- **Finding 011** — `billing-srv-01` remains on Ubuntu 18.04 without an acceptable supported security-maintenance path.
- **Finding 026** — the same host uses an outdated Linux 4.15 kernel.

Together, these findings show both individual exploitable weaknesses and the wider lifecycle problem caused by unsupported software.

**Threat Context:**  
This gap is relevant to **Unskilled / Opportunistic Attackers, Ransomware Groups / Organized Crime, Nation-State APTs, and hacktivists** because known vulnerabilities can provide an initial foothold without requiring sophisticated techniques.

The clearest modeled path is:

- **Kill Chain 2** — VPN Entry to Backup Neutralisation

Project 1x01 specifically showed how exploitation of an exposed remote-access vulnerability could bypass the perimeter and lead to internal compromise and recovery-system attack.

**NIST CSF Function:** Identify  
*Remediation is implemented through Protect, but the programme-level gap begins with the failure to continuously identify, assess, prioritize, and track vulnerabilities.*

**CIS Control:** **CIS Control 7 — Continuous Vulnerability Management**

**Recommended Action:** Establish a formal vulnerability-management cycle covering asset scope, recurring scans, vendor advisories, risk-based remediation SLAs, ownership, exception handling, verification, and rescanning.

---

## 5. GAP-008 — Backup Infrastructure Concentrated with Production

**Gap Reference:** GAP-008

**Description:** `backup-srv-01`, `NAS-01`, and Veeam are locally concentrated with production systems, while restore testing and recovery isolation are incomplete.

**Vulnerability Evidence:**  
- **Finding 015** — Synology NAS management services are reachable broadly from the internal network.
- **Finding 030** — the NAS administrative login surface is also broadly reachable internally.

These findings provide a direct route from an internal foothold toward systems that support MedDefense's recovery capability.

**Threat Context:**  
This gap is primarily relevant to **Ransomware Groups / Organized Crime**, with additional relevance to malicious insiders or destructive APT activity.

It appears in:

- **Kill Chain 1** — Phishing to EHR Double Extortion *(potential/conditional dependency)*
- **Kill Chain 2** — VPN Entry to Backup Neutralisation *(direct dependency)*

The ransomware model specifically depends on weakening or destroying recovery capability before encryption.

**NIST CSF Function:** Recover

**CIS Control:** **CIS Control 11 — Data Recovery**

**Recommended Action:** Isolate backup administration from normal production access, use separate privileged credentials, maintain an isolated recovery copy, and regularly test restoration of Critical systems.

---

## 6. GAP-003 — Medical IoT Lacks Device-Specific Isolation and Monitoring

**Gap Reference:** GAP-003

**Description:** BD Alaris pumps, Philips IntelliVue monitors, and other clinical devices lack dedicated network isolation and device-specific monitoring.

**Vulnerability Evidence:**  
- **Finding 010** — BD Alaris network-session vulnerability; applicability requires version/component validation before treating the CVE as confirmed.
- **Finding 016** — Philips IntelliVue web-management access is insufficiently restricted.
- **Finding 024** — Philips monitor-to-EHR / HL7 traffic is insufficiently protected on the flat network.

**Threat Context:**  
The gap is relevant to **malicious insiders, Ransomware Groups / Organized Crime, opportunistic attackers, and Nation-State APTs**.

It is explicitly used in:

- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

The high priority is driven not only by attack frequency but by the patient-safety consequences of unauthorized access to medication-delivery and monitoring systems.

**NIST CSF Function:** Protect

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Place medical IoT in dedicated security zones, restrict device-management and clinical communication flows to approved systems, and monitor traffic crossing those boundaries.

---

## 7. GAP-006 — Unsupported Windows XP MRI Control Environment

**Gap Reference:** GAP-006

**Description:** `WS-RAD-01`, the MRI control workstation, runs unsupported Windows XP SP3 and lacks a documented MRI-specific isolation and monitoring control.

**Vulnerability Evidence:**  
- **Finding 004** — unsupported Windows XP MRI workstation with mature legacy vulnerabilities including MS08-067, BlueKeep, and MS17-010/EternalBlue exposure.
- **Finding 012** — SMBv1 remains enabled on the MRI workstation as part of the legacy environment.

Project 1x02 classified Finding 004 as an immediate Critical priority because ordinary patching cannot provide a durable fix for the unsupported platform.

**Threat Context:**  
The system is relevant to **Unskilled / Opportunistic Attackers, Ransomware Groups / Organized Crime, Nation-State APTs, and malicious insiders**.

No single one of the five selected Project 1x01 kill chains explicitly depends on GAP-006. Instead, the MRI workstation was identified as a **high-impact post-foothold lateral-movement target**, particularly for ransomware or opportunistic exploitation using mature public exploits.

**NIST CSF Function:** Protect

**CIS Control:** **CIS Control 4 — Secure Configuration of Enterprise Assets and Software**

**Recommended Action:** Immediately isolate `WS-RAD-01`, block unnecessary RDP/SMB access from the general network, permit only validated clinical/vendor flows, monitor the segment, and move toward a supported replacement.

---

## 8. GAP-002 — EHR Database Reachable from the Wider Internal Network

**Gap Reference:** GAP-002

**Description:** PostgreSQL TCP/5432 on `ehr-db-01` is reachable from the wider internal network rather than being limited to approved EHR application and administration systems.

**Vulnerability Evidence:**  
- **Finding 003** — unrestricted PostgreSQL exposure on `ehr-db-01`, including `listen_addresses='*'` and a `pg_hba.conf` rule covering the wider internal environment.

Finding 003 was treated as a Critical vulnerability in Project 1x02 even though it has no CVE, because the weakness is the deployment configuration itself and the affected EHR database is a Critical asset.

**Threat Context:**  
The gap is relevant to **Ransomware Groups / Organized Crime, Nation-State APTs, malicious insiders, and opportunistic attackers**.

It appears in:

- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 3** — Compromised MedTech Access to the EHR

Both paths can converge on the EHR database after the attacker establishes an earlier foothold.

**NIST CSF Function:** Protect

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Restrict PostgreSQL TCP/5432 to the approved EHR application and administration hosts, narrow `pg_hba.conf`, and enforce the restriction with network ACL/firewall policy.

---

# Traceability Summary

| Priority Gap | Vulnerability Evidence from 1x02 | Threat / Kill Chain Context | NIST CSF Function | CIS Control | Recommended Action |
|---|---|---|---|---|---|
| **GAP-011 — Fragmented monitoring** | Finding 021 | Multiple actor types; Kill Chains **1–5** | Detect | **13 — Network Monitoring and Defense** | Centralize priority security events and establish owned alert review/escalation |
| **GAP-001 — No effective segmentation** | Findings 003, 004, 010, 015, 030 | Ransomware, APT, insider, opportunistic; Kill Chains **1–5** | Protect | **12 — Network Infrastructure Management** | Segment users, servers, AD, backups, medical IoT, and legacy clinical systems |
| **GAP-007 — MFA/PAM weakness** | Findings 007, 009 | Ransomware, APT, malicious insider; Kill Chains **1–4** | Protect | **6 — Access Control Management** | Deploy MFA and controlled privileged access with separate admin identities |
| **GAP-016 — Vulnerability/patch-management gap** | Findings 001, 002, 011, 026 | Opportunistic, ransomware, APT, hacktivist; Kill Chain **2** | Identify | **7 — Continuous Vulnerability Management** | Establish recurring discovery, prioritization, remediation, verification, and rescanning |
| **GAP-008 — Backup concentration** | Findings 015, 030 | Primarily ransomware; Kill Chain **1** (conditional), **2** (direct) | Recover | **11 — Data Recovery** | Isolate recovery infrastructure and credentials and test restores regularly |
| **GAP-003 — Medical IoT isolation/monitoring** | Findings 010, 016, 024 | Insider, ransomware, opportunistic, APT; Kill Chain **5** | Protect | **12 — Network Infrastructure Management** | Create medical-IoT zones with restricted and monitored clinical/management flows |
| **GAP-006 — Unsupported MRI workstation** | Findings 004, 012 | Opportunistic/ransomware/APT/insider; post-foothold target rather than explicit selected chain | Protect | **4 — Secure Configuration of Enterprise Assets and Software** | Isolate the legacy MRI workstation and move toward supported replacement |
| **GAP-002 — Broad EHR database exposure** | Finding 003 | Ransomware, APT, insider, opportunistic; Kill Chains **1 and 3** | Protect | **12 — Network Infrastructure Management** | Restrict PostgreSQL access to approved EHR/application administration paths |

---

## Strategic Interpretation

The bridge shows that MedDefense does not have eight unrelated security problems. Several vulnerability findings repeatedly connect back to the same small number of structural weaknesses.

**GAP-011, GAP-001, and GAP-007 have the highest strategic leverage** because they affect multiple actor types and multiple attack paths. Improving monitoring, segmentation, and identity controls therefore reduces risk across several scenarios at once.

At the same time, the framework mapping cannot ignore asset-specific Critical exposures. **GAP-006** requires special treatment because the MRI workstation is unsupported and cannot be fixed through normal patching, while **GAP-002** provides an unnecessarily broad route to the EHR database. **GAP-003** brings direct patient-safety concerns into the network architecture problem, and **GAP-008** determines whether MedDefense can recover when preventive controls fail.

The recommended actions therefore combine broad controls with targeted remediation. This provides the traceability required for later cost-benefit analysis: each investment can be linked back to a documented gap, technical evidence, realistic threat path, and recognized framework control.

---

## Source Cross-References

This bridge is based on:

- Project 1x00 — Security Posture Assessment and Gap Analysis
- Project 1x01 Task 10 — Kill Chains
- Project 1x01 Task 15 — Gap-Threat Correlation and Re-prioritization
- Project 1x02 — Final Vulnerability Assessment and Contextualized Findings
- NIST Cybersecurity Framework 2.0
- CIS Controls v8

