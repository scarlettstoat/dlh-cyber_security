# MedDefense Health Systems — Gap-Threat Correlation

## Purpose

Project 1x00 identified MedDefense's weaknesses by looking inward at asset criticality, data sensitivity and control coverage. Project 1x01 adds the external half of the risk picture: **which actors would exploit each weakness, which kill chains depend on it and which Board-level scenarios become possible because it remains open**.

This assessment uses the **Project 1x00 Task 12 Gap Analysis as reassessed in Task 13**. The baseline therefore contains **GAP-001 through GAP-018**:

- GAP-001 to GAP-015 from the original Task 12 Gap Analysis
- GAP-007 reassessed from Medium to High in Task 13
- GAP-008, GAP-011 and GAP-015 reassessed from High to Critical in Task 13
- GAP-016, GAP-017 and GAP-018 added as Critical gaps in Task 13

> **Scope note:** GAP-019 through GAP-022 were identified later in the Project 1x00 predecessor review, not in Task 12 as updated by Task 13. They are therefore outside the explicit baseline requested for this task. Task 14 references GAP-020 as an additional supporting issue in the ransomware scenario, but it is not included in the ranking counts below.

## Threat-Path Counting Method

For prioritisation, a gap receives one occurrence each time it is explicitly listed as exploited in:

- one of the **five kill chains** in `10-kill_chains.md`; or
- one of the **three integrated scenarios** in `14-threat_scenarios.md`.

GAP-008 is listed as **potential** in Kill Chain 1 and definite in Kill Chain 2. The matrix records both, but marks the first as conditional.

---

# Full Gap-Threat Correlation

## GAP-001 — No Effective Internal Segmentation

**Gap ID:** GAP-001

**Gap Description:** Central workstations, servers and medical devices use different addressing ranges but are not separated by enforced VLAN or firewall security boundaries.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious
- Unskilled / Opportunistic Attacker

**Kill Chains:**  
- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 2** — VPN Entry to Backup Neutralisation
- **Kill Chain 3** — Compromised MedTech Access to the EHR
- **Kill Chain 4** — Retained Insider Access to Active Directory
- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign
- **Scenario 3** — MedTech supply-chain espionage

**Updated Risk Level:** **Critical — Same**

**Justification:**  
This is the most consistently exploited preventive weakness in the project. It appears in **all five kill chains** and in two of the three integrated scenarios. Ransomware, privileged insiders, opportunistic attackers and sophisticated external actors all benefit from the same condition: once one system is compromised, MedDefense does not strongly restrict east-west movement toward EHR, Active Directory, backups or medical IoT. The threat analysis therefore confirms that GAP-001 is not simply a network-design problem; it is a **cross-actor attack-path multiplier**.

---

## GAP-002 — EHR Database Reachable from the Wider Internal Network

**Gap ID:** GAP-002

**Gap Description:** PostgreSQL TCP 5432 on `ehr-db-01` is reachable from the wider internal network rather than being restricted to approved EHR application and administration hosts.

**Original Risk Level:** **Medium**

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious
- Unskilled / Opportunistic Attacker

**Kill Chains:**  
- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 3** — Compromised MedTech Access to the EHR

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign
- **Scenario 3** — MedTech supply-chain espionage

**Updated Risk Level:** **High — Upgraded**

**Justification:**  
The original Medium rating reflected the existence of local Linux logging, EHR audit logging and backups. Project 1x01 shows that those controls do not reduce the database's importance as an **attack-path intersection**. Both the top ransomware path and the vendor-compromise path explicitly converge on `ehr-db-01`, and Task 11 STRIDE shows that direct database reachability supports both Information Disclosure and Tampering of Critical patient data. The controls still justify stopping short of Critical, but the repeated use of this path raises the threat-informed urgency to **High**.

---

## GAP-003 — Medical IoT Lacks Device-Specific Isolation and Monitoring

**Gap ID:** GAP-003

**Gap Description:** BD Alaris pumps, Philips IntelliVue monitors and other clinical devices lack dedicated network isolation and device-specific monitoring.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Insider — Malicious
- Unskilled / Opportunistic Attacker
- Nation-State APT

**Kill Chains:**  
- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

**Scenarios:**  
- None of the three selected Task 14 scenarios depends directly on GAP-003.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Although GAP-003 appears in only one of the five selected kill chains, the affected systems directly support medication delivery and patient monitoring. Task 8 confirms that medical IoT is broadly reachable internally, and Task 9 found Medical IoT to be the most connected asset class across the vector matrix. The relatively narrow appearance in the final three scenarios reflects scenario selection, not low exposure. The direct patient-safety consequence keeps this gap Critical.

---

## GAP-004 — Server-Room Access Not Restricted to Authorized Personnel

**Gap ID:** GAP-004

**Gap Description:** Generic employee badge access can reach the server room, with no dedicated door camera or visitor logging.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Insider — Malicious
- Unskilled / Opportunistic Attacker with physical access
- Organized Crime where an attacker uses impersonation or an on-site accomplice

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-004.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-004.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Threat-path frequency is low because the project's highest-priority scenarios are primarily remote and credential-driven. However, successful physical access to the server room bypasses several logical controls at once and exposes EHR, backup and other Critical infrastructure. The potential for immediate Availability, Integrity and Confidentiality impact remains severe enough that threat analysis does not justify a downgrade; it should simply rank below the more frequently traversed Critical gaps.

---

## GAP-005 — Unlocked Network Closet and Exposed Switch Credentials

**Gap ID:** GAP-005

**Gap Description:** A Central network closet was found unlocked with switch-management credentials posted beside the equipment.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Insider — Malicious
- Unskilled / Opportunistic Attacker with physical access
- Organized Crime using impersonation or physical intrusion

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-005.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-005.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
The gap is not a recurring remote kill-chain dependency, but it exposes both Critical network infrastructure and administrative credentials. A person who reaches the closet could connect rogue equipment, change switch configuration or disrupt clinical connectivity without first defeating the Internet perimeter. Its threat-informed sequencing is below GAP-001/GAP-011/GAP-007, but the direct physical path to a shared Critical dependency still supports a Critical rating.

---

## GAP-006 — Unsupported Windows XP MRI Control Environment

**Gap ID:** GAP-006

**Gap Description:** `WS-RAD-01`, the MRI control workstation, runs unsupported Windows XP SP3 and lacks a documented MRI-specific isolation/monitoring control.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Unskilled / Opportunistic Attacker
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-006.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-006.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Task 8 confirms that unsupported systems are a realistic technical vector, and the supply-chain assessment shows that Siemens maintenance introduces an additional trusted path to the MRI environment. The legacy platform cannot be treated like an ordinary workstation because it supports a Critical clinical imaging service and cannot receive normal security support. Its absence from the selected top five kill chains reduces sequencing priority, not the underlying Critical patient-safety risk.

---

## GAP-007 — MFA and Privileged-Access Controls Not Broadly Implemented

**Gap ID:** GAP-007

**Gap Description:** MFA is not broadly deployed and MedDefense lacks formal PAM and consistently separated administrative identities.

**Original Risk Level:** **High** *(reassessed from Medium in Project 1x00 Task 13)*

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious

**Kill Chains:**  
- **Kill Chain 1** — Phishing to EHR Double Extortion
- **Kill Chain 2** — VPN Entry to Backup Neutralisation
- **Kill Chain 3** — Compromised MedTech Access to the EHR
- **Kill Chain 4** — Retained Insider Access to Active Directory

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign
- **Scenario 3** — MedTech supply-chain espionage

**Updated Risk Level:** **Critical — Upgraded**

**Justification:**  
Project 1x00 Task 13 already upgraded GAP-007 after real-world evidence showed how valid credentials enable prolonged healthcare compromise. Project 1x01 strengthens the case further: GAP-007 appears in **four of five kill chains** and two of three scenarios, second only to segmentation and monitoring as a recurring enabler. Stolen, retained or vendor credentials become much more dangerous when there is no broad MFA/PAM layer to stop their reuse. Because the gap repeatedly enables both initial access and privilege escalation toward Critical assets, it now warrants **Critical** threat-informed priority.

---

## GAP-008 — Backup Infrastructure Concentrated with Production

**Gap ID:** GAP-008

**Gap Description:** `backup-srv-01`, `NAS-01` and Veeam are locally concentrated with production systems, with limited restore testing and incomplete coverage.

**Original Risk Level:** **Critical** *(reassessed from High in Project 1x00 Task 13)*

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Insider — Malicious
- Nation-State APT where destructive impact is intended

**Kill Chains:**  
- **Kill Chain 1** — Phishing to EHR Double Extortion *(conditional/potential dependency)*
- **Kill Chain 2** — VPN Entry to Backup Neutralisation *(direct dependency)*

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign

**Updated Risk Level:** **Critical — Same**

**Justification:**  
RaaS operators specifically target backups to increase extortion pressure. Task 10 makes backup neutralisation the objective of Kill Chain 2, while Scenario 1 explicitly destroys recovery capability before encryption. The gap does not create initial access, but once an attacker reaches the environment it determines whether MedDefense can recover without prolonged clinical disruption. The ransomware threat evidence strongly validates the Critical rating.

---

## GAP-009 — Pharmacy Change Validation and Recovery Weakness

**Gap ID:** GAP-009

**Gap Description:** The pharmacy management system lacks formal change validation, automated integrity checks and a documented rollback/recovery process.

**Original Risk Level:** **Medium**

**Threat Actors:**  
- Insider — Malicious
- Ransomware Groups / Organized Crime after application compromise
- Nation-State APT where manipulation is the objective

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-009.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-009.

**Updated Risk Level:** **Medium — Same**

**Justification:**  
The pharmacy system remains highly safety-sensitive, but Project 1x01 does not show this gap as a recurring preferred path for the prioritized actors. The main evidence remains the previous faulty change rather than a strong external exploitation pattern. The existing printed cross-check also provides some detective coverage. Threat analysis therefore does not justify an upgrade at this stage.

---

## GAP-010 — Patient Portal Authorization Failure Not Verified as Remediated

**Gap ID:** GAP-010

**Gap Description:** The patient portal previously allowed authenticated users to access other patients' laboratory results by changing a URL parameter, with no documented remediation verification.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Hacktivist
- Unskilled / Opportunistic Attacker
- Ransomware Groups / Organized Crime
- Nation-State APT

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-010.

**Scenarios:**  
- None of the three selected Task 14 scenarios explicitly depends on GAP-010.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
The portal is Internet-facing and has already demonstrated a real patient-data authorization failure. Task 6 specifically identifies the public website/patient portal as the most plausible hacktivist target, while opportunistic and organized-crime actors can also exploit exposed application weaknesses. The absence from the selected top-five kill chains reflects the project decision to prioritize other paths, not a lack of viable attackers. Critical Restricted data remains directly exposed if the flaw persists.

---

## GAP-011 — Security Logging Fragmented and Not Continuously Monitored

**Gap ID:** GAP-011

**Gap Description:** Firewall, SSH, Windows, Linux, Apache, EHR and AD logs exist, but are mostly local/manual with no centralized SIEM-style correlation and alerting.

**Original Risk Level:** **Critical** *(reassessed from High in Project 1x00 Task 13)*

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious
- Hacktivist
- Unskilled / Opportunistic Attacker

**Kill Chains:**  
- **Kill Chain 1**
- **Kill Chain 2**
- **Kill Chain 3**
- **Kill Chain 4**
- **Kill Chain 5**

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign
- **Scenario 2** — Malicious insider patient-data disclosure
- **Scenario 3** — MedTech supply-chain espionage

**Updated Risk Level:** **Critical — Same**

**Justification:**  
GAP-011 is the **single most frequently recurring gap in Project 1x01**: it appears in all five kill chains and all three integrated scenarios. It is actor-agnostic—ransomware relies on undetected reconnaissance, insiders rely on legitimate activity not being reviewed, supply-chain attackers rely on trusted sessions blending into normal administration, and opportunistic actors benefit when low-sophistication activity persists. Closing GAP-011 would not prevent every initial foothold, but it would create detection opportunities across more attack stages than any other single gap.

---

## GAP-012 — Shadow IT on Production Networks

**Gap ID:** GAP-012

**Gap Description:** Undocumented systems and personal technology operate on production networks without assured ownership, patching, endpoint protection or monitoring.

**Original Risk Level:** **High**

**Threat Actors:**  
- Unskilled / Opportunistic Attacker
- Ransomware Groups / Organized Crime
- Insider — Malicious

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-012.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-012.

**Updated Risk Level:** **High — Same**

**Justification:**  
Shadow IT remains an important foothold creator, especially for opportunistic actors and ransomware. However, the five most critical kill chains do not require it because MedDefense already has multiple more direct entry and movement paths. The threat analysis therefore confirms the gap as significant but not as urgent as segmentation, monitoring, identity or recovery weaknesses.

---

## GAP-013 — Incomplete Endpoint and Device-Management Coverage

**Gap ID:** GAP-013

**Gap Description:** Sophos protects only part of the documented Windows estate, physician-iPad MDM status is unclear and unmanaged personal devices have previously reached the internal network.

**Original Risk Level:** **High**

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Unskilled / Opportunistic Attacker
- Nation-State APT

**Kill Chains:**  
- **Kill Chain 1** — Phishing to EHR Double Extortion

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign

**Updated Risk Level:** **High — Same**

**Justification:**  
Endpoint gaps create a realistic initial foothold for phishing, malware and opportunistic compromise, and Task 14 uses that condition in the primary ransomware scenario. However, MedDefense already has substantial Sophos coverage and automated containment on 372 managed Windows endpoints. The threat evidence reinforces High urgency but does not demonstrate enough absence of control to justify Critical.

---

## GAP-014 — Westside Consumer Router / No Dedicated Firewall

**Gap ID:** GAP-014

**Gap Description:** Westside relies on a Netgear Nighthawk consumer router, an unmanaged switch and a site-to-site VPN to Central without a dedicated enterprise firewall or local network-security monitoring.

**Original Risk Level:** **Critical**

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Unskilled / Opportunistic Attacker
- Nation-State APT

**Kill Chains:**  
- None of the five selected kill chains explicitly depends on GAP-014.

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-014.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
The site remains a viable alternate route into MedDefense because it handles clinical information and maintains a trusted VPN path toward Central. Its absence from the selected kill chains means it is not currently the *most frequent* route, but the combination of weak perimeter controls and inter-site trust still gives a successful compromise potential organization-wide consequences.

---

## GAP-015 — No Formal IR / BCP / DR Programme

**Gap ID:** GAP-015

**Gap Description:** Incident response, business continuity and disaster recovery remain informal, with limited restore testing and weak paper fallback.

**Original Risk Level:** **Critical** *(reassessed from High in Project 1x00 Task 13)*

**Threat Actors:**  
- Ransomware Groups / Organized Crime
- Nation-State APT
- Insider — Malicious
- Hacktivist
- Unskilled / Opportunistic Attacker

**Kill Chains:**  
- None of the five Task 10 kill-chain gap lists explicitly names GAP-015, although it affects containment and recovery after any of them.

**Scenarios:**  
- **Scenario 1** — BlackReef ransomware campaign

**Updated Risk Level:** **Critical — Same**

**Justification:**  
GAP-015 is primarily an **impact amplifier rather than an exploitation mechanism**. That explains its lower path count. Ransomware is MedDefense's highest-priority external threat, and the organization has already handled a ransomware event through improvised response. A lack of tested containment, continuity and recovery procedures can convert a containable technical compromise into prolonged clinical and financial disruption. The Critical rating remains appropriate even though attackers do not "use" the gap in the same way they use a password or network weakness.

---

## GAP-016 — No Formal Vulnerability and Patch-Management Programme

**Gap ID:** GAP-016

**Gap Description:** MedDefense lacks a documented end-to-end process for identifying, prioritizing, remediating and verifying vulnerabilities across exposed and Critical systems.

**Original Risk Level:** **Critical — Added in Project 1x00 Task 13**

**Threat Actors:**  
- Unskilled / Opportunistic Attacker
- Ransomware Groups / Organized Crime
- Nation-State APT
- Hacktivist

**Kill Chains:**  
- **Kill Chain 2** — VPN Entry to Backup Neutralisation

**Scenarios:**  
- None of the three selected scenarios explicitly depends on GAP-016 because Scenario 1 uses phishing rather than a VPN exploit as its primary vector.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Task 8 identifies vulnerable software as a specific MedDefense technical vector, and Kill Chain 2 shows how exploitation of an exposed remote-access service could bypass the perimeter and lead directly to recovery-system attack. Opportunistic actors particularly benefit because they can automate exploitation of known vulnerabilities, while ransomware affiliates and APT actors can use the same exposed weaknesses more deliberately. The programme-level absence remains Critical.

---

## GAP-017 — Weak Identity Lifecycle and Offboarding

**Gap ID:** GAP-017

**Gap Description:** Employment and contract termination are not formally integrated with immediate, verified account deactivation across VPN, AD and applications.

**Original Risk Level:** **Critical — Added in Project 1x00 Task 13**

**Threat Actors:**  
- Insider — Malicious
- Ransomware Groups / Organized Crime using retained or transferred credentials
- Nation-State APT using compromised valid accounts

**Kill Chains:**  
- **Kill Chain 4** — Retained Insider Access to Active Directory

**Scenarios:**  
- None of the three selected Task 14 scenarios explicitly depends on GAP-017.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Valid accounts are especially dangerous because they can bypass perimeter and application controls while initially appearing legitimate. Kill Chain 4 demonstrates how one retained account can become the first step toward Active Directory compromise. The threat actor matrix also identifies malicious insiders as having disproportionately high effective access despite modest technical capability. The Critical rating remains justified.

---

## GAP-018 — No Verified Medical-Device Credential-Hardening Standard

**Gap ID:** GAP-018

**Gap Description:** MedDefense has not verified that vendor-default administrative credentials are changed or that a consistent credential baseline exists across medical IoT and embedded clinical devices.

**Original Risk Level:** **Critical — Added in Project 1x00 Task 13**

**Threat Actors:**  
- Unskilled / Opportunistic Attacker
- Insider — Malicious
- Ransomware Groups / Organized Crime
- Nation-State APT

**Kill Chains:**  
- **Kill Chain 5** — Insider Abuse of the Alaris Pump Environment

**Scenarios:**  
- None of the three selected Task 14 scenarios explicitly depends on GAP-018.

**Updated Risk Level:** **Critical — Same**

**Justification:**  
Task 8 shows that weak/default device credentials require little sophistication once an attacker can reach the management interface. In MedDefense's flat environment, credential weakness therefore combines directly with GAP-003 and GAP-001. Because the affected devices support medication delivery and patient monitoring, even a narrow compromise can produce direct patient-safety consequences. The threat analysis confirms rather than reduces the Critical rating.

---

# Re-Prioritized Gap List

The threat-informed ranking below orders gaps first by **updated risk level**, then by **frequency across the five kill chains and three scenarios**, then by the breadth of affected Critical assets.

| Rank | Gap | Updated Risk | Kill Chains | Scenarios | Total Path Appearances | Movement |
|---:|---|---|---:|---:|---:|---|
| **1** | **GAP-011 — Fragmented / non-continuous monitoring** | **Critical** | **5** | **3** | **8** | Same |
| **2** | **GAP-001 — No effective internal segmentation** | **Critical** | **5** | **2** | **7** | Same |
| **3** | **GAP-007 — MFA / PAM weakness** | **Critical** | **4** | **2** | **6** | **↑ Upgraded from High** |
| **4** | **GAP-008 — Backup concentration** | **Critical** | **2*** | **1** | **3*** | Same |
| **5** | **GAP-003 — Medical IoT isolation / monitoring** | **Critical** | **1** | **0** | **1** | Same |
| **6** | **GAP-015 — No formal IR / BCP / DR** | **Critical** | **0** | **1** | **1** | Same |
| **7** | **GAP-016 — Vulnerability / patch management** | **Critical** | **1** | **0** | **1** | Same |
| **8** | **GAP-017 — Identity lifecycle / offboarding** | **Critical** | **1** | **0** | **1** | Same |
| **9** | **GAP-018 — Medical-device credential hardening** | **Critical** | **1** | **0** | **1** | Same |
| **10** | **GAP-010 — Patient portal authorization** | **Critical** | **0** | **0** | **0** | Same |
| **11** | **GAP-014 — Westside weak perimeter** | **Critical** | **0** | **0** | **0** | Same |
| **12** | **GAP-006 — Unsupported MRI environment** | **Critical** | **0** | **0** | **0** | Same |
| **13** | **GAP-004 — Weak server-room access** | **Critical** | **0** | **0** | **0** | Same |
| **14** | **GAP-005 — Unlocked network closet / credentials** | **Critical** | **0** | **0** | **0** | Same |
| **15** | **GAP-002 — EHR database network exposure** | **High** | **2** | **2** | **4** | **↑ Upgraded from Medium** |
| **16** | **GAP-013 — Incomplete endpoint / device management** | **High** | **1** | **1** | **2** | Same |
| **17** | **GAP-012 — Shadow IT on production networks** | **High** | **0** | **0** | **0** | Same |
| **18** | **GAP-009 — Pharmacy validation / recovery weakness** | **Medium** | **0** | **0** | **0** | Same |

\* GAP-008 appears directly in Kill Chain 2 and conditionally in Kill Chain 1. The table counts both for visibility but preserves the distinction.

## Ranking Interpretation

The list should **not** be read as saying GAP-010 or GAP-014 are unimportant because they have zero appearances. They remain Critical because they directly expose Critical systems or Restricted data. The path-count method instead answers a different question: **which control improvements would break the largest number of the specific high-priority attacks modeled in Project 1x01?**

---

# The Critical Three

## 1. GAP-011 — Fragmented / Non-Continuous Monitoring

**Frequency:** **8 of 8 modeled attack paths** — all five kill chains and all three integrated scenarios.

GAP-011 is the strongest cross-cutting priority because almost every actor benefits when malicious behavior is logged but not actively correlated: ransomware can perform reconnaissance, insiders can browse records, vendor attackers can masquerade as maintenance activity and opportunistic compromises can persist. Closing it would create detection opportunities across Initial Access, Persistence, Credential Access, Discovery, Lateral Movement, Collection and Exfiltration rather than addressing only one technique.

## 2. GAP-001 — No Effective Internal Segmentation

**Frequency:** **7 of 8 modeled attack paths** — all five kill chains and Scenarios 1 and 3.

GAP-001 is the main **blast-radius multiplier**. It does not normally create the first foothold, but it converts a phished workstation, VPN compromise, malicious insider session, vendor foothold or medical-device access into a route toward other Critical assets. Effective segmentation would force attackers through additional controlled boundaries and break multiple paths at the Lateral Movement stage.

## 3. GAP-007 — Broad MFA / PAM Weakness

**Frequency:** **6 of 8 modeled attack paths** — four kill chains and Scenarios 1 and 3.

GAP-007 turns stolen, retained and vendor credentials into durable attack tools. It appears in phishing-driven ransomware, VPN-to-backup compromise, supply-chain intrusion and malicious-insider escalation. Broad MFA, separated administrative identities and PAM would therefore reduce both Initial Access success and Privilege Escalation across several actor types.

---

# The Surprise

## GAP-002 — EHR Database Exposure: Medium → High

The clearest threat-informed surprise is **GAP-002**. In the original Task 12 Gap Analysis it was rated **Medium** because Linux logging, EHR audit logging and backups provided partial detective/corrective coverage. Project 1x01 changes the urgency because `ehr-db-01` is no longer just an internally overexposed database in theory: it appears in **two of the five critical kill chains and two of the three Board-level scenarios**, including both the highest-priority ransomware path and the MedTech supply-chain path. Task 11 STRIDE also shows that the same network exposure supports both **Information Disclosure** and **Tampering**, and EHR Integrity is directly tied to patient safety. The technical controls still prevent an automatic jump to Critical, but the threat evidence makes **High** the more defensible priority.

## Secondary Surprise — GAP-007: Medium in Task 12 → High in Task 13 → Critical Here

GAP-007 shows an even larger cumulative change in understanding. The original internal assessment rated broad MFA/PAM weakness **Medium** because password policies, lockout, AD logging and a secondary domain controller provided partial controls. The Project 1x00 reality check upgraded it to **High** after a real healthcare breach demonstrated the danger of valid credentials. Project 1x01 then shows the same weakness in **six of eight modeled paths**. The issue is therefore not simply "MFA would be nice"; credential trust is one of the main mechanisms connecting phishing, vendor compromise and malicious insider activity to Critical MedDefense systems. Threat-informed prioritisation raises it to **Critical**.

---

# Threat-Informed Conclusion

Project 1x01 changes the order in which MedDefense should think about remediation. The internal posture assessment correctly identified many severe weaknesses, but the threat analysis shows that a small subset of gaps repeatedly connects otherwise different attacks. **GAP-011, GAP-001 and GAP-007** are the highest-leverage controls because they respectively improve detection, restrict lateral movement and reduce the value of compromised identities across ransomware, insider and supply-chain scenarios.

The key lesson is that remediation should not focus only on the system where an attack starts. MedDefense gains more resilience by closing gaps that **break attack chains at multiple stages**: centralized detection and alerting, enforced internal segmentation, strong MFA/PAM, protected recovery infrastructure, vulnerability management and tightly controlled vendor/identity access.
