# MedDefense Health Systems — STRIDE Threat Model for the EHR

## Scope

This threat model applies STRIDE to MedDefense's most critical system:

- `ehr-srv-01` (**A-001**) — Ubuntu 20.04 EHR application server at `10.10.2.10`
- `ehr-db-01` (**A-002**) — PostgreSQL EHR database at `10.10.2.11`
- EHR application (**A-036**)
- Central clinical workstations and thin clients used by physicians, nurses and other clinical staff
- The internal network paths connecting users, the application server, the database and shared identity infrastructure

Project 1x00 rates EHR Confidentiality, Integrity and Availability as **Critical**. The database contains Restricted patient/clinical information, PostgreSQL TCP 5432 is reachable from the wider internal network, Central lacks effective internal segmentation, EHR audit records are vendor-managed rather than continuously monitored by MedDefense, and an unattended nurse-station workstation has already demonstrated a data-in-use exposure.

---

# S — Spoofing

## EHR-S1 — Stolen Clinician Identity

**Category:** **S — Spoofing**

**Threat ID:** `EHR-S1`

**Description:**  
An attacker obtains a clinician's MedDefense credentials and authenticates to systems as that clinician. Because clinical users have legitimate access to patient information, the attacker can make malicious access appear to originate from an authorized care provider.

**Attack Vector:**  
**Removable Devices / Unmanaged Endpoints** or **Vulnerable Software** from Task 8 could place credential-stealing malware on a clinical workstation; phishing or vishing from Task 4 could also capture the password directly.

**Impact:**  
The attacker could view patient records, use the compromised identity to support further internal reconnaissance, or perform actions that appear to be legitimate clinical activity. This creates a patient-privacy breach and makes attribution more difficult.

**Existing Control:**  
- **C-009 — Password Requirements Policy**
- **C-010 — Active Directory Password Policy Enforcement**
- **C-011 — Account Lockout**
- **C-028 — EHR Application Audit Logging**

**Gap:**  
- **GAP-007 — MFA and privileged-access controls are not broadly implemented**
- **GAP-011 — Security logging is fragmented and not continuously monitored**

---

## EHR-S2 — Session Hijacking at an Unattended Clinical Workstation

**Category:** **S — Spoofing**

**Threat ID:** `EHR-S2`

**Description:**  
A person uses an already authenticated EHR session left open on a clinical workstation and performs actions under the legitimate employee's identity. Project 1x00 already observed an unattended nurse-station workstation displaying an active patient record for approximately 15 minutes.

**Attack Vector:**  
**Unmanaged Endpoint / Internal Access** combined with physical proximity to a logged-in workstation. The attacker does not need to defeat EHR authentication if a legitimate session is already active.

**Impact:**  
Unauthorized viewing or action can be recorded as though it came from the logged-in nurse or clinician, exposing Restricted patient information and undermining accountability.

**Existing Control:**  
- **C-028 — EHR Application Audit Logging** records patient-record activity
- **C-023 — Annual Security Awareness Training** provides general guidance on safe system use

**Gap:**  
- **GAP-011 — Fragmented monitoring** limits rapid detection of anomalous EHR access
- No dedicated 1x00 control is documented for enforced EHR session locking or care-context validation

---

# T — Tampering

## EHR-T1 — Direct Modification of Patient Records Through `ehr-db-01`

**Category:** **T — Tampering**

**Threat ID:** `EHR-T1`

**Description:**  
A compromised internal host attempts direct access to PostgreSQL on `ehr-db-01` and modifies patient data outside the intended EHR application path. The database is reachable on **TCP 5432 from the wider internal network**, not only from `ehr-srv-01`.

**Attack Vector:**  
**Open Service Ports** + **Unsecure Networks** from Task 8: an attacker with any internal foothold can reach the database service because Central has no enforced east-west segmentation.

**Impact:**  
Altered allergies, medication history, diagnoses, laboratory values or other clinical information could cause clinicians to make treatment decisions using false data, creating direct patient-safety risk.

**Existing Control:**  
- **C-016 — Nightly Virtual Machine Backups**
- **C-026 — Linux Server Syslog**
- **C-028 — EHR Application Audit Logging** for application-level activity

**Gap:**  
- **GAP-002 — EHR database is reachable from the wider internal network**
- **GAP-001 — No effective internal segmentation**
- **GAP-011 — Database/security monitoring is not centrally correlated**

---

## EHR-T2 — Unauthorized Modification of EHR Application Components

**Category:** **T — Tampering**

**Threat ID:** `EHR-T2`

**Description:**  
An attacker who obtains privileged access to `ehr-srv-01` modifies EHR application files, configuration or supporting code so that the system behaves differently from the approved clinical application.

**Attack Vector:**  
**Open Service Ports / Unsecure Networks** combined with compromised privileged access. The scan confirms SSH, HTTPS and TCP 8080 on `ehr-srv-01`; SSH itself is strongly hardened, so the attacker would still need a valid authorized key or another privileged foothold rather than simply guessing an SSH password.

**Impact:**  
Malicious application changes could alter how records are displayed, processed or transmitted, potentially causing incorrect clinical information to reach users or creating covert access to patient data.

**Existing Control:**  
- **C-004 — SSH Root Login Disabled**
- **C-005 — SSH Key-Only Authentication**
- **C-006 — SSH Authentication Attempt Limit**
- **C-007 — SSH Forwarding Restrictions**
- **C-008 — SSH Authentication Logging**
- **C-016 — Nightly Virtual Machine Backups**

**Gap:**  
- **GAP-007 — Privileged-access management is not formally implemented**
- **GAP-011 — Server and authentication logs are not continuously monitored**

---

# R — Repudiation

## EHR-R1 — Unauthorized Use of an Existing Clinical Session

**Category:** **R — Repudiation**

**Threat ID:** `EHR-R1`

**Description:**  
An unauthorized person accesses records through an unattended workstation and the EHR audit trail records the actions against the legitimate employee's account. The real actor can therefore deny involvement while the legitimate user may also truthfully deny performing the actions.

**Attack Vector:**  
**Internal / Unmanaged Endpoint access** to an already authenticated clinical workstation.

**Impact:**  
MedDefense may know that a patient record was accessed but be unable to prove who physically performed the action, weakening incident investigation, privacy-breach reconstruction and disciplinary or legal response.

**Existing Control:**  
- **C-028 — EHR Application Audit Logging**

**Gap:**  
- **GAP-011 — EHR audit information is not continuously monitored by MedDefense**
- No documented technical control ties every EHR action to fresh user verification or care-context confirmation

---

## EHR-R2 — Compromised Account Activity Cannot Be Reliably Attributed to the Real Person

**Category:** **R — Repudiation**

**Threat ID:** `EHR-R2`

**Description:**  
An attacker using stolen clinician credentials accesses or exports EHR information, while logs attribute the activity only to the compromised identity. Without strong second-factor authentication and centralized correlation of endpoint, identity, network and EHR events, MedDefense may struggle to distinguish the account owner from the attacker.

**Attack Vector:**  
**Removable Devices / Unmanaged Endpoints** or **Vulnerable Software** used to steal credentials, followed by legitimate-looking authenticated EHR access.

**Impact:**  
Attribution delays can make it harder to determine which records were exposed, whether the real employee was involved and what regulatory notifications are required.

**Existing Control:**  
- **C-028 — EHR Application Audit Logging**
- **C-029 — Active Directory Critical Event Logging**
- **C-003/C-024 — FortiGate traffic/log retention** where relevant traffic crosses the firewall

**Gap:**  
- **GAP-007 — MFA is not broadly implemented**
- **GAP-011 — Logs remain fragmented and manually reviewed**

---

# I — Information Disclosure

## EHR-I1 — Direct Exposure of the EHR Database from a Compromised Internal Host

**Category:** **I — Information Disclosure**

**Threat ID:** `EHR-I1`

**Description:**  
An attacker who compromises any reachable internal system discovers PostgreSQL TCP 5432 on `ehr-db-01` and attempts to query or extract patient data directly rather than through the normal EHR application.

**Attack Vector:**  
**Open Service Ports** + **Unsecure Networks** from Task 8.

**Impact:**  
Electronic health records, laboratory results and other Restricted clinical information could be disclosed at scale, creating privacy, regulatory, legal and reputational consequences.

**Existing Control:**  
- **C-016 — Nightly Virtual Machine Backups** provides recovery but does not prevent disclosure
- **C-026 — Linux Server Syslog**
- **C-028 — EHR Application Audit Logging** provides application audit coverage but does not by itself restrict direct network access to PostgreSQL

**Gap:**  
- **GAP-002 — EHR database reachable from the wider internal network**
- **GAP-001 — No effective internal segmentation**
- **GAP-011 — Incomplete centralized detection**

---

## EHR-I2 — Patient Data Copied from an EHR Workstation to Removable or Unmanaged Storage

**Category:** **I — Information Disclosure**

**Threat ID:** `EHR-I2`

**Description:**  
A user or attacker operating an EHR-access workstation copies patient information to USB storage, a personal storage device or another unmanaged destination. Project 1x00 later confirmed that USB storage is unrestricted and no organization-wide DLP capability is documented.

**Attack Vector:**  
**Removable Devices / Unmanaged Endpoints** from Task 8.

**Impact:**  
Large quantities of Restricted patient information could leave MedDefense without timely detection, resulting in a reportable privacy breach and loss of control over copies of clinical data.

**Existing Control:**  
- **C-014 — Sophos Endpoint Malware Protection** on covered Windows endpoints
- **C-023 — Annual Security Awareness Training**
- **C-028 — EHR Application Audit Logging** may show source-record access

**Gap:**  
- **GAP-020 — No organisation-wide DLP or removable-media control**
- **GAP-013 — Endpoint/device-management coverage is incomplete**
- **GAP-011 — No centralized monitoring of abnormal export behavior**

---

# D — Denial of Service

## EHR-D1 — Ransomware Encryption of EHR Systems

**Category:** **D — Denial of Service**

**Threat ID:** `EHR-D1`

**Description:**  
A ransomware affiliate gains an internal foothold, escalates privileges and encrypts `ehr-srv-01`, `ehr-db-01` or the wider environment on which the EHR depends. The same attacker may target local backups before deployment to extend the outage.

**Attack Vector:**  
**Vulnerable Software**, **Unsecure Networks** or an initial compromised endpoint, followed by lateral movement across Central's flat network.

**Impact:**  
Clinicians lose immediate electronic access to patient information. MedDefense has already shown the consequence of EHR unavailability: a previous planned migration overrun caused a **nine-hour outage** and forced physicians to revert to paper records.

**Existing Control:**  
- **C-016 — Nightly Virtual Machine Backups**
- **C-017 — Backup Restore Testing** (Weak)
- **C-035 — Paper-Record EHR Outage Fallback** (Weak)

**Gap:**  
- **GAP-001 — No effective internal segmentation**
- **GAP-008 — Backup infrastructure is concentrated with production**
- **GAP-015 — Formal IR/BCP/DR is not established**
- **GAP-011 — Delayed detection can increase attacker dwell time**

---

## EHR-D2 — Internal Resource Exhaustion Against EHR Services

**Category:** **D — Denial of Service**

**Threat ID:** `EHR-D2`

**Description:**  
A compromised internal host generates excessive connections or requests against `ehr-srv-01` or PostgreSQL on `ehr-db-01`, exhausting application, database or network resources and degrading legitimate clinical access.

**Attack Vector:**  
**Open Service Ports** + **Unsecure Networks** from Task 8. The attacker benefits from broad internal reachability to EHR services without crossing an enforced internal firewall boundary.

**Impact:**  
Slow or unavailable EHR access can delay clinical decisions, medication review, laboratory-result retrieval and documentation, forcing staff toward manual fallback procedures.

**Existing Control:**  
- **C-026 — Linux Server Syslog**
- **C-028 — EHR Application Audit Logging**
- **C-035 — Paper-Record EHR Outage Fallback**

**Gap:**  
- **GAP-001 — No effective internal segmentation/east-west restriction**
- **GAP-011 — No centralized detection of abnormal internal traffic**
- **GAP-015 — Continuity procedures remain informal and untested**

---

# E — Elevation of Privilege

## EHR-E1 — Compromised User Account Escalates Through Active Directory

**Category:** **E — Elevation of Privilege**

**Threat ID:** `EHR-E1`

**Description:**  
An attacker begins with a normal MedDefense user account or compromised workstation, enumerates Active Directory and obtains higher-privilege credentials. Those privileges are then used to expand access toward EHR servers and other Critical systems.

**Attack Vector:**  
**Unsecure Networks** plus a compromised endpoint or stolen credential. Central's flat network gives the attacker broad access to AD services and other internal systems after the initial foothold.

**Impact:**  
A low-privilege compromise can become a domain-level incident, allowing the attacker to access more patient data, change permissions, disable accounts or support ransomware deployment against the EHR.

**Existing Control:**  
- **C-010 — Active Directory Password Policy Enforcement**
- **C-011 — Account Lockout**
- **C-012 — Password History Enforcement**
- **C-029 — Active Directory Critical Event Logging**
- **C-030 — Secondary Active Directory Domain Controller**

**Gap:**  
- **GAP-007 — MFA/PAM and separated administrative identities are incomplete**
- **GAP-001 — Flat internal network**
- **GAP-011 — AD monitoring is manual rather than continuously correlated**

---

## EHR-E2 — Trusted Maintenance Access Expands Beyond Its Intended Scope

**Category:** **E — Elevation of Privilege**

**Threat ID:** `EHR-E2`

**Description:**  
A compromised or malicious privileged maintenance user reaches `ehr-srv-01` through authorized administrative access and then attempts to use that position to reach `ehr-db-01` or other internal systems beyond the intended maintenance scope. Project 1x01 Task 5 established that MedTech has direct maintenance access to `ehr-srv-01`, but direct authorized access to `ehr-db-01` is **not** documented.

**Attack Vector:**  
**Open Service Ports / Unsecure Networks** combined with compromised privileged or trusted third-party access.

**Impact:**  
A compromise that should be limited to one application server can expand into database access, broader patient-data exposure or control over additional internal systems.

**Existing Control:**  
- **C-004 — SSH Root Login Disabled**
- **C-005 — SSH Key-Only Authentication**
- **C-006 — SSH Authentication Attempt Limit**
- **C-007 — SSH Forwarding Restrictions**
- **C-008 — SSH Authentication Logging**

**Gap:**  
- **GAP-007 — No formal PAM / stronger privileged-access governance**
- **GAP-001 — No effective internal segmentation**
- **GAP-002 — `ehr-db-01` is reachable beyond the application server**
- **GAP-011 — Privileged activity is not centrally monitored**

---

# STRIDE Summary for EHR

**Tampering represents the greatest STRIDE risk to the MedDefense EHR.** Information Disclosure and Denial of Service are also severe, but EHR Integrity has an unusually direct connection to patient safety: clinicians use the information in the EHR to make decisions about diagnoses, allergies, medications, laboratory results and treatment. A confidentiality breach exposes patients and creates regulatory harm, while an outage forces difficult but recognizable fallback procedures; corrupted clinical data can be more dangerous because the system may remain available and appear trustworthy while presenting incorrect information. MedDefense's environment makes this especially concerning because `ehr-db-01` is reachable from the wider internal network, Central lacks effective segmentation and monitoring is fragmented. An attacker who successfully tampers with patient records could therefore cause harm before staff realize that the information they are relying on is no longer trustworthy.

---

## Project Cross-References

- Project 1x00 — `7-asset_registry.md`
- Project 1x00 — `8-criticality_assessment.md`
- Project 1x00 — `9-data_map.md`
- Project 1x00 — `10-complete_control_matrix.md`
- Project 1x00 — `12-gap_analysis.md`
- Project 1x00 — `15-predecessor_review.md` (`GAP-020`)
- Project 1x01 — `5-supply_chain_assessment.md`
- Project 1x01 — `8-technical_vectors.md`
- Project 1x01 — `10-kill_chains.md`
