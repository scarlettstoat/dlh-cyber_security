# MedDefense Health Systems — Prioritized Gap Analysis

This assessment cross-references the MedDefense Asset Criticality Assessment, established data classifications and protection gaps, the Complete Control Matrix, and Shadow IT findings from the Asset Registry and network reconciliation.

Risk levels are assigned using the prioritization rules provided for this task. The rules are applied in order: a gap is rated **Critical** only where a Critical-rated asset or Restricted data is affected **and** there is no relevant detective or corrective control. Where controls exist but remain incomplete, the rating is reduced according to the remaining asset/data exposure.

---

## GAP-001

**Gap ID:** GAP-001  
**Title:** No effective internal segmentation between servers, workstations and medical devices  
**Affected Asset(s):** Central core switch (A-017), access-switch estate (A-018), EHR assets (A-001, A-002, A-036), medical IoT (A-031, A-032, A-033, A-034) — associated asset categories rated **Critical**  
**Data at Risk:** EHR/clinical data, medication data and patient-monitoring information — **Restricted**  
**Current Control Status:** C-002 provides a default-deny perimeter firewall rule, C-003/C-024 provide FortiGate logging, and C-031 protects site-to-site VPN traffic. These controls do not enforce separation between Central's internal workstation, server and medical-device ranges.  
**What is Missing:** Effective **Technical / Preventive** VLAN or firewall segmentation and **Technical / Detective** monitoring of east-west traffic between internal security zones.  
**Risk Level:** **Critical**  
**Risk Justification:** Multiple Critical clinical assets and Restricted data are reachable across the same internal environment, with no relevant detective or corrective control for unauthorized lateral movement inside Central.  
**Potential Impact:** Compromise of one workstation or vulnerable medical device could provide a route to EHR, Active Directory, medical IoT or other clinical systems, turning a single-system compromise into a wider clinical outage or data breach.

---

## GAP-002

**Gap ID:** GAP-002  
**Title:** EHR database is reachable from the wider internal network  
**Affected Asset(s):** `ehr-db-01` (A-002), EHR application environment (A-001, A-036) — **Critical**  
**Data at Risk:** Electronic health records and patient clinical information — **Restricted**  
**Current Control Status:** C-004 through C-008 harden and log SSH access to `ehr-srv-01`; C-026 provides local Linux logging; C-028 provides EHR audit logging; and C-016 backs up `ehr-db-01`. None restrict PostgreSQL access specifically to authorized application or administration hosts.  
**What is Missing:** **Technical / Preventive** database network access restrictions and stronger database-specific **Detective** monitoring.  
**Risk Level:** **Medium**  
**Risk Justification:** The asset and data are Critical/Restricted, but detective logging and a corrective backup control already provide partial protection. Under the supplied rules, these controls reduce the gap below Critical even though the remaining exposure is significant.  
**Potential Impact:** A compromised internal host could attempt direct database access, potentially exposing or altering patient records used by clinicians.

---

## GAP-003

**Gap ID:** GAP-003  
**Title:** Medical IoT devices lack device-specific isolation and monitoring  
**Affected Asset(s):** BD Alaris infusion-pump estate (A-032), Philips IntelliVue monitor estate (A-031), vital-sign monitor (A-033) — **Critical** clinical asset categories  
**Data at Risk:** Medication dosage information and patient-monitoring data — **Restricted**  
**Current Control Status:** C-002 provides perimeter firewall protection and C-023 provides general staff awareness. The Complete Control Matrix identifies the infusion-pump estate as Under-Protected. The scan records known vulnerabilities on the pumps and Task 3 observed a monitor with firmware last updated in 2019.  
**What is Missing:** Device-specific **Technical / Preventive** isolation and restricted management access, plus effective device-specific **Detective** monitoring and documented **Corrective** recovery capability.  
**Risk Level:** **Critical**  
**Risk Justification:** Critical patient-care devices handle Restricted clinical information, and there is no relevant device-level detective or corrective control for compromise of the medical IoT estate.  
**Potential Impact:** An attacker could manipulate dosage or monitoring information, disrupt devices during treatment or use a vulnerable medical device as a foothold into other clinical systems.

---

## GAP-004

**Gap ID:** GAP-004  
**Title:** Server-room access is not restricted to authorized personnel  
**Affected Asset(s):** Central server room (A-043) and hosted critical systems, including EHR and backup infrastructure — **Critical**  
**Data at Risk:** Clinical/EHR and backup data — **Restricted**; employee and financial information — **Confidential**  
**Current Control Status:** C-033 provides HID badge access but is rated Weak because the same generic employee badge can access the room. C-021 provides CCTV elsewhere at Central, but no camera covers the server-room door, and no visitor log is maintained.  
**What is Missing:** Strong **Physical / Preventive** role-restricted badge access and **Physical / Detective** access logging/camera coverage at the server room.  
**Risk Level:** **Critical**  
**Risk Justification:** Critical infrastructure and Restricted data are physically accessible through a weak preventive control with no effective detective or corrective control specific to unauthorized server-room access.  
**Potential Impact:** An unauthorized person could disconnect, remove or tamper with servers and storage, causing EHR interruption, data exposure, backup loss or wider clinical-service disruption.

---

## GAP-005

**Gap ID:** GAP-005  
**Title:** Network closet is unlocked and switch-management credentials are exposed  
**Affected Asset(s):** Second-floor network closet (A-044), Central access-switch estate (A-018) — Network Core and Site Connectivity **Critical**  
**Data at Risk:** Switch-management credentials — **Restricted**; clinical traffic — **Restricted**; business traffic — **Confidential**  
**Current Control Status:** C-018 through C-021 provide general facility controls, but none specifically protects or monitors the network closet. The closet was observed unlocked and the management credentials were posted beside the switches.  
**What is Missing:** **Physical / Preventive** locking, secure credential storage and **Physical/Technical / Detective** access monitoring for the network infrastructure.  
**Risk Level:** **Critical**  
**Risk Justification:** Restricted administrative credentials and Critical network infrastructure are directly exposed, with no relevant detective or corrective control protecting the closet or credentials.  
**Potential Impact:** An unauthorized person could alter switch configuration, connect rogue equipment, intercept traffic or disrupt connectivity supporting clinical systems.

---

## GAP-006

**Gap ID:** GAP-006  
**Title:** MRI control environment relies on an unsupported Windows XP platform  
**Affected Asset(s):** `WS-RAD-01` MRI control workstation (A-022), Siemens MAGNETOM MRI (A-029) — PACS/Medical Imaging **Critical**  
**Data at Risk:** Diagnostic imaging and associated patient clinical information — **Restricted**  
**Current Control Status:** The Windows XP MRI control workstation remains connected to Central's broadly reachable internal environment. No MRI-specific detective or corrective control is documented in the Complete Control Matrix.  
**What is Missing:** A supported platform or a formal **Technical / Compensating-Preventive** control such as network isolation with tightly restricted communications, together with dedicated **Detective** monitoring and documented recovery procedures.  
**Risk Level:** **Critical**  
**Risk Justification:** The imaging environment is Critical, processes Restricted clinical information and uses an end-of-life operating system without a documented relevant detective or corrective control.  
**Potential Impact:** Exploitation could disrupt MRI services, expose diagnostic information, affect imaging integrity or provide an attacker with a route toward other systems.

---

## GAP-007

**Gap ID:** GAP-007  
**Title:** MFA and privileged-access controls are not broadly implemented  
**Affected Asset(s):** `ad-dc-01` (A-005), `ad-dc-02` (A-006) — Identity and Access Management **Critical**  
**Data at Risk:** Authentication credentials and privileged account information — **Restricted**  
**Current Control Status:** C-009 through C-013 provide password requirements, AD enforcement, account lockout and password history. C-029 provides AD event logging, and C-030 provides a secondary domain controller. MFA is documented only for James Chen's personal account.  
**What is Missing:** Strong **Technical / Preventive** MFA for privileged/sensitive access, separated administrative identities and formal privileged-access management.  
**Risk Level:** **Medium**  
**Risk Justification:** Critical identity infrastructure and Restricted credentials are involved, but existing preventive, detective and corrective controls partially reduce the exposure. The supplied prioritization rules therefore place this incomplete-control gap at Medium rather than Critical.  
**Potential Impact:** Theft of a privileged password could enable unauthorized account or permission changes and provide access across multiple clinical and administrative systems.

---

## GAP-008

**Gap ID:** GAP-008  
**Title:** Backup infrastructure is concentrated in the same physical and network location  
**Affected Asset(s):** `backup-srv-01` (A-009), `NAS-01` (A-010), Veeam (A-041) — Backup/Recovery Infrastructure **Critical**  
**Data at Risk:** Backup copies containing clinical information — **Restricted** and business/financial information — **Confidential**  
**Current Control Status:** C-016 performs nightly backups with 14-day retention, and C-017 provides limited restore testing. The NAS and backup server remain in the same rack, room and network, and the documented backup job does not include all servers.  
**What is Missing:** Independent/offsite or isolated **Technical / Corrective** backup protection, broader backup coverage and regular **Administrative / Detective** restore testing.  
**Risk Level:** **High**  
**Risk Justification:** Confidential information is at risk and control coverage is incomplete. Existing backup and restore-testing controls reduce the risk but do not protect against an event affecting both production and local recovery infrastructure.  
**Potential Impact:** Ransomware or physical damage could affect production systems and their available recovery copies at the same time, extending outages and increasing the possibility of unrecoverable recent data.

---

## GAP-009

**Gap ID:** GAP-009  
**Title:** Pharmacy system lacks formal change validation and recovery procedures  
**Affected Asset(s):** Pharmacy management system (A-038) — Medication Management **Critical**  
**Data at Risk:** Medication and dosage information used in patient care — **Restricted**  
**Current Control Status:** C-036 provides a Weak detective control: a pharmacist identified the previous dosage error by comparing the application with a printed reference. No pharmacy-specific backup, automated integrity validation or documented rollback control is evidenced.  
**What is Missing:** Formal **Administrative/Technical / Preventive** change testing and approval, automated **Detective** integrity validation, and **Corrective** rollback/recovery procedures.  
**Risk Level:** **Medium**  
**Risk Justification:** The system and data are Critical/Restricted, but the existing manual cross-check provides partial detective coverage. Under the supplied rules, partial controls reduce the rating below Critical.  
**Potential Impact:** A faulty or unauthorized database change could again distribute incorrect dosage information across all three sites and influence medication decisions before staff identify the error.

---

## GAP-010

**Gap ID:** GAP-010  
**Title:** Patient portal authorization failure has no documented remediation verification  
**Affected Asset(s):** Patient portal (A-037), `web-srv-01` (A-011) — patient-record access environment **Critical** due to the data handled  
**Data at Risk:** Patient laboratory results and portal-accessible health information — **Restricted**  
**Current Control Status:** C-001/C-002 restrict network access to `web-srv-01`, and C-027 retains Apache logs. The February incident demonstrated that authenticated patients could view other patients' laboratory results by changing a URL parameter. No application-level detective or corrective control addressing the authorization defect is documented.  
**What is Missing:** Strong **Technical / Preventive** object-level authorization, application-security testing and relevant **Detective/Corrective** controls for unauthorized patient-record access.  
**Risk Level:** **Critical**  
**Risk Justification:** Restricted patient information was demonstrably exposed and there is no documented application-level detective or corrective control addressing the access-control failure itself.  
**Potential Impact:** Patients could gain unauthorized access to other patients' laboratory information, causing a patient privacy breach and associated legal, regulatory and reputational consequences.

---

## GAP-011

**Gap ID:** GAP-011  
**Title:** Security logging is fragmented and not continuously monitored  
**Affected Asset(s):** EHR (A-001, A-002, A-036), Active Directory (A-005, A-006), network infrastructure (A-016 to A-019) and other Critical systems  
**Data at Risk:** Clinical information and credentials — **Restricted**; business information — **Confidential**  
**Current Control Status:** C-003, C-008 and C-024 through C-029 generate firewall, SSH, Windows, Linux, Apache, EHR and AD logs. Most remain local or manually reviewed and no centralized SIEM/continuous monitoring capability is documented.  
**What is Missing:** Centralized **Technical / Detective** aggregation, correlation, alerting and defined monitoring ownership.  
**Risk Level:** **High**  
**Risk Justification:** Confidential and Restricted information is handled by affected systems and detective coverage exists but is incomplete. The gap therefore meets the High condition for incomplete control coverage.  
**Potential Impact:** Malicious access, lateral movement or privilege changes could remain undetected, increasing attacker dwell time and making incident containment and investigation more difficult.

---

## GAP-012

**Gap ID:** GAP-012  
**Title:** Undocumented Shadow IT systems operate on production networks  
**Affected Asset(s):** `UNKNOWN-01` (A-012), Westside Linux system `10.10.10.200` (A-014) — individual criticality **Unknown**; connected to environments supporting Critical systems  
**Data at Risk:** Exact data holdings **Unknown**; access to Internal network information and potential paths toward **Confidential** and **Restricted** systems  
**Current Control Status:** The systems were found through the network scan rather than through an established asset-management control. No documented owner, purpose, patching process, endpoint protection or system-specific monitoring exists.  
**What is Missing:** **Administrative / Preventive** ownership and authorization, **Technical / Preventive** hardening/access restrictions, and system-specific **Detective/Corrective** coverage.  
**Risk Level:** **High**  
**Risk Justification:** The systems' own criticality and data are unknown, so the finding is not automatically rated Critical. However, they are unmanaged systems on production networks with incomplete control coverage and access paths toward sensitive environments, supporting a High risk rating.  
**Potential Impact:** An undocumented system could contain vulnerable or unauthorized software and provide a persistent foothold for movement toward clinical or administrative assets.

---

## GAP-013

**Gap ID:** GAP-013  
**Title:** Endpoint protection and device-management coverage is incomplete  
**Affected Asset(s):** Central workstation estate (A-020), ER thin clients (A-021), Westside workstations (A-024), physician iPads (A-028) — Clinical Endpoints **Critical**; administrative endpoints (A-026, A-027) **High**  
**Data at Risk:** Patient information — **Restricted**; employee and business information — **Confidential**  
**Current Control Status:** C-014/C-015 provide Sophos malware protection and automated containment on 372 Windows 10/11 endpoints, while C-023 provides awareness training. The full documented endpoint population is larger, iPad management is unclear, and an unmanaged personal laptop previously remained on the internal network for three weeks.  
**What is Missing:** Complete **Technical / Preventive/Corrective** endpoint-security coverage, MDM for mobile devices, and network admission controls preventing unmanaged personal devices from accessing internal networks.  
**Risk Level:** **High**  
**Risk Justification:** High administrative assets and Confidential data are directly affected, while existing endpoint controls cover only part of the environment. This meets the High rule for incomplete control coverage.  
**Potential Impact:** An unmanaged or unprotected endpoint could expose sensitive information, introduce malware or provide an internal foothold for attacks on clinical systems.

---

## GAP-014

**Gap ID:** GAP-014  
**Title:** Westside Clinic relies on a consumer router with no dedicated firewall  
**Affected Asset(s):** Westside Netgear router (A-015), `ws-srv-01` (A-013), Westside workstations (A-024) and imaging workstation (A-025) — Site Connectivity **Critical**  
**Data at Risk:** Patient/scheduling/imaging information — **Restricted**; business/file-share information — **Confidential**  
**Current Control Status:** C-031 provides an IPSec VPN to Central, but Westside has no dedicated enterprise firewall. C-022 is limited to physical entrance-camera detection and does not monitor network threats.  
**What is Missing:** Enterprise **Technical / Preventive** perimeter firewalling, restrictive inbound/outbound policy and relevant **Technical / Detective** network-security monitoring at Westside.  
**Risk Level:** **Critical**  
**Risk Justification:** Critical connectivity and Restricted clinical information are exposed at the site perimeter without a relevant local detective or corrective network-security control.  
**Potential Impact:** Compromise of the Westside router or a locally exposed system could disrupt clinic operations or provide an attack path through the site-to-site VPN toward Central.

---

## GAP-015

**Gap ID:** GAP-015  
**Title:** Incident response, business continuity and disaster recovery are not formally established  
**Affected Asset(s):** All Critical clinical/infrastructure categories, including EHR, network core, medical IoT, Active Directory and backup infrastructure  
**Data at Risk:** Restricted patient/clinical information and **Confidential** operational/business information  
**Current Control Status:** C-016 provides backups, C-017 provides limited restore testing, and C-035 provides a Weak paper-record fallback for EHR outages. The January ransomware response was improvised over four days and no formal IR, BCP or DR process is documented.  
**What is Missing:** Formal **Administrative / Corrective** incident-response and recovery procedures, tested continuity plans, defined responsibilities and recurring exercises.  
**Risk Level:** **High**  
**Risk Justification:** Confidential information and Critical systems are affected and existing backup/compensating measures provide incomplete coverage. The gap therefore meets the High rule rather than Critical.  
**Potential Impact:** During ransomware or a major outage, MedDefense may lose time deciding how to contain the event, preserve evidence and restore services, prolonging clinical and business disruption.

---

# Gap Distribution Summary

## Risk-Level Distribution

| Risk Level | Number of Gaps | Gap IDs |
|---|---:|---|
| **Critical** | **7** | GAP-001, GAP-003, GAP-004, GAP-005, GAP-006, GAP-010, GAP-014 |
| **High** | **5** | GAP-008, GAP-011, GAP-012, GAP-013, GAP-015 |
| **Medium** | **3** | GAP-002, GAP-007, GAP-009 |
| **Low** | **0** | — |
| **Total** | **15** | — |

No Low gaps are included because the prioritized findings identified during this stage do not concern Low-rated assets with compensating measures. Medium findings are retained where meaningful existing controls reduce—but do not eliminate—exposure affecting otherwise critical systems.

## Gaps by Primary Asset Category

| Primary Asset Category | Number of Gaps | Gap IDs |
|---|---:|---|
| **Network Core and Site Connectivity** | **4** | GAP-001, GAP-005, GAP-012, GAP-014 |
| **EHR and Patient Record Systems** | **2** | GAP-002, GAP-010 |
| **Medication Management and Infusion Systems** | **2** | GAP-003, GAP-009 |
| **Cross-cutting Security Operations / Continuity** | **2** | GAP-011, GAP-015 |
| **Physical Security and Facility Infrastructure** | **1** | GAP-004 |
| **PACS and Medical Imaging** | **1** | GAP-006 |
| **Identity and Access Management** | **1** | GAP-007 |
| **Backup, Recovery and Virtualization** | **1** | GAP-008 |
| **Clinical Endpoints** | **1** | GAP-013 |

**Network Core and Site Connectivity** has the highest number of gaps. This is especially significant because the network is a shared dependency for EHR, Active Directory, medical devices, imaging systems and endpoints; weakness in this category increases the possible impact of weaknesses elsewhere.

## Control Gap Concentration

The identified gaps are concentrated most heavily in:

1. **Technical / Preventive controls** — internal segmentation, medical-device isolation, database restrictions, application authorization, MFA, endpoint admission controls and stronger Westside perimeter security are absent or inadequate.
2. **Technical / Detective controls** — existing logs are fragmented and predominantly local/manual; medical IoT, Shadow IT and internal east-west traffic have especially limited detection coverage.
3. **Corrective controls** — recovery capability is thin outside the limited Veeam scope, with weak restore testing and little documented recovery coverage for pharmacy, network infrastructure and medical IoT.
4. **Physical / Preventive and Detective controls** — generic server-room badge access, an unlocked network closet and incomplete CCTV coverage leave critical infrastructure physically exposed.
5. **Compensating controls** — very few formal alternatives exist where primary controls cannot currently be implemented, particularly around legacy clinical technology.

Overall, MedDefense's largest problem is not that it has no security controls. The gap is that existing controls are **unevenly applied and do not consistently match the criticality of the assets and sensitivity of the data they protect**.
