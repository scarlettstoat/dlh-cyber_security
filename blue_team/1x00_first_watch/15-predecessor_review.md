# MedDefense Health Systems — Predecessor Review

## Purpose

This review evaluates Marcus Webb's unfinished **Security Assessment — Draft v0.3** against the completed MedDefense assessment. Marcus's work is useful evidence, but it is not treated as authoritative simply because it predates the current review. Each conclusion is compared with the later asset reconciliation, control analysis, Gap Analysis, incident evidence and advanced-task findings.

---

# Part 1 — Comparative Analysis

## 1. Marcus's Documented Findings

| Finding | Marcus's Assessment | Your Assessment | Agree / Disagree | Resolution |
|---|---|---|---|---|
| **M-01 — Network Segmentation** | **Critical.** Entire Central environment described as flat, with workstations, servers and medical IoT mutually reachable. | **GAP-001 — Critical.** Later scan evidence confirms that the `/24` ranges are addressing conventions only and are not separated by VLAN/firewall enforcement. | **Agree** | Retain **Critical**. Later evidence strengthens Marcus's conclusion. Internal segmentation remains one of MedDefense's highest-priority controls because it reduces lateral movement and the blast radius of a compromise. |
| **M-02 — Backup Isolation** | **Critical.** NAS and production systems share the same room/network. Marcus also records a monthly offsite tape rotation, leaving up to 30 days of possible data loss. | **GAP-008 — Critical after reality-check reassessment.** Veeam/NAS protection is locally concentrated and restore testing is weak. Earlier project evidence had not established a usable offsite copy. | **Agree, with evidence update** | Marcus's draft adds evidence of a **monthly offsite tape rotation**, so the issue should no longer be described as a total absence of offsite backup. The gap remains Critical because a monthly copy provides an unacceptable recovery point for Critical clinical systems and local production/backup copies remain exposed together. |
| **M-03 — Medical IoT Exposure** | **High, potentially Critical.** Approximately 200 medical/connected devices are broadly reachable; some expose management interfaces/default credentials and Alaris isolation is not implemented. | **GAP-003 — Critical** and **GAP-018 — Critical.** Later asset work confirms Alaris and monitor exposure, known vulnerabilities and lack of isolation; the reality check also elevated device credential hardening as a separate issue. | **Agree on finding; disagree on final rating** | Retain **Critical**. Marcus correctly recognised the patient-safety dimension, but later evidence justifies resolving the ambiguity in favour of Critical because the devices directly support monitoring and medication delivery. |
| **M-04 — Absence of Monitoring and Detection** | **High.** States MedDefense has "zero detective capability": no SIEM, IDS/IPS, centralised logs or automated alerting. | **GAP-011 — Critical after reassessment.** MedDefense does have detective controls, including firewall, Windows, Linux, Apache, EHR and AD logging, but most are local/manual and not centrally correlated. | **Partially disagree** | Marcus is correct about the absence of **centralised active detection and alerting**, but "zero detective capability" is too broad. Controls C-003, C-008 and C-024 through C-029 demonstrate that logs/audit capability exists. The more accurate conclusion is that detective coverage is **fragmented, passive and operationally weak**. The risk remains **Critical** after the reality-check task and the billing crypto-miner evidence. |
| **M-05 — No MFA on Any System** | **High.** States MFA is not deployed anywhere and recommends VPN first, then admin and EHR. | **GAP-007 — High after reassessment.** Broad MFA and PAM are absent, but onboarding evidence records MFA on James Chen's personal account. | **Agree on systemic weakness; disagree with absolute wording** | Retain the gap as **High**, but state that MFA is **not broadly deployed**, rather than nonexistent. The isolated exception does not materially reduce organisation-wide credential risk. Prioritise remote/VPN and privileged access first, followed by Critical clinical applications where supported. |
| **M-06 — Westside Clinic Security** | **High.** Consumer router, no dedicated firewall, unmanaged switching, unlocked server closet and VPN connection to Central. | **GAP-014 — Critical.** Later scan confirms the consumer router and VPN-connected site; the wider assessment also confirms weak local physical and network controls. | **Agree on weakness; disagree on rating** | Retain **Critical** because Westside is not an isolated low-value office: it handles clinical operations and maintains a trusted path toward Central. A site compromise could therefore affect both local care and the wider MedDefense environment. |
| **M-07 — Shared Credentials in Radiology** | **Medium.** Shared `raduser` PACS credential removes individual accountability; Marcus lowers the rating because access is on-site. | Shared PACS credentials are documented in the Asset Registry/Data Map and fall within **GAP-007 identity/access weakness**. | **Agree on weakness; partially disagree on rationale** | Incorporate the shared PACS account explicitly into **GAP-007**. On-site restriction reduces Internet exposure but does not remove insider misuse, compromised-workstation or audit-accountability risk. The broader identity gap remains **High**. |
| **M-08 — End-of-Life Print Server** | **Low.** Windows Server 2012 R2 is unsupported; Marcus views it mainly as a compliance issue because the server is low-value and internal-only. | Asset **A-008** is confirmed active and deprecated. The broader issue is now covered by **GAP-016 — vulnerability and patch-management programme**, rated Critical at programme level. | **Disagree with "low-value therefore low-risk" reasoning** | Do not make print services a top remediation priority, but do not treat the host as merely a compliance concern. In a flat network, an unsupported internal server can still become an attacker foothold or persistence point. Handle it through GAP-016, prioritised below exposed/Critical systems but scheduled for migration to a supported platform. |

---

## 2. Marcus Findings We Had Not Fully Captured

Marcus's unfinished section contains several observations that were either absent from the original Task 12 Gap Analysis or only partially covered later. Each is evaluated below.

### A. Patient Portal Still Allows TLS 1.0 — **Valid**

Marcus records that `web-srv-01` supports TLS 1.0 alongside TLS 1.2. This is a distinct transport-security configuration issue affecting an Internet-facing service that handles Restricted patient information. **GAP-010** addresses object-level authorisation and **GAP-016** addresses vulnerability/patch management, but neither explicitly requires removal of obsolete cryptographic protocols.

#### New Gap — GAP-019

**Gap ID:** GAP-019  
**Title:** Patient portal permits obsolete TLS protocol support  
**Affected Asset(s):** Patient portal (A-037), `web-srv-01` (A-011)  
**Data at Risk:** Patient portal credentials, laboratory results and other portal-accessible health information — **Restricted**  
**Current Control Status:** C-001/C-002 restrict inbound network access and HTTPS is available, while C-027 retains Apache logs. Marcus's draft reports that TLS 1.0 remains enabled alongside TLS 1.2.  
**What is Missing:** Strong **Technical / Preventive** transport-security configuration that disables obsolete protocols and enforces an approved modern TLS baseline, supported by periodic configuration verification.  
**Risk Level:** **High**  
**Risk Justification:** The affected service is Internet-facing and processes Restricted information, but existing HTTPS/perimeter/logging controls provide partial protection. The weakness therefore represents incomplete rather than absent control coverage.  
**Potential Impact:** Weak protocol support could reduce the confidentiality and integrity assurance of patient-portal sessions and create avoidable exposure on a high-value Internet-facing service.

---

### B. No DLP and Unrestricted USB Storage — **Valid**

Marcus identifies two connected weaknesses: MedDefense has no documented DLP capability, and workstation USB storage is unrestricted. Earlier work recognised fragmented monitoring and later noted the value of high-volume export alerting, but Marcus's evidence is broader: patient and financial information can leave through email, removable media or cloud upload without a dedicated prevention/detection layer.

#### New Gap — GAP-020

**Gap ID:** GAP-020  
**Title:** No organisation-wide data-loss prevention or removable-media control  
**Affected Asset(s):** User workstations, Microsoft 365/email, HR and Finance workflows, EHR-access endpoints and other systems handling Restricted or Confidential information  
**Data at Risk:** Patient/clinical information — **Restricted**; HR, billing and financial information — **Confidential**  
**Current Control Status:** Endpoint protection and general awareness controls exist, but no DLP control is documented for email, cloud upload or removable media, and Marcus records unrestricted USB storage on workstations.  
**What is Missing:** **Technical / Preventive and Detective** DLP controls for sensitive-data transfer, removable-media restrictions appropriate to business need, alerting for abnormal exports and **Administrative / Preventive** rules for approved data-transfer methods/exceptions.  
**Risk Level:** **High**  
**Risk Justification:** Restricted and Confidential information is exposed to multiple exfiltration channels, while general endpoint/security controls do not specifically detect or block sensitive-data removal.  
**Potential Impact:** A malicious insider, compromised account or infected workstation could copy large volumes of patient, employee or financial data to USB, personal cloud storage or email without timely detection.

---

### C. HQ Landlord-Managed Infrastructure Has No Security Assurance — **Valid**

The existing assessment knew that HQ networking was landlord-managed and that MedDefense operated on a dedicated VLAN, but Marcus adds a specific governance concern: MedDefense has no visibility into the security of the shared building infrastructure on which its site connectivity depends. This is not equivalent to proving that the landlord network is insecure, but it is a legitimate third-party assurance gap.

#### New Gap — GAP-021

**Gap ID:** GAP-021  
**Title:** Third-party HQ network dependency lacks documented security assurance  
**Affected Asset(s):** Corporate HQ network, HQ workstations/laptops, site-to-site connectivity to Central  
**Data at Risk:** Confidential administrative, HR, financial and legal information; potential connectivity path toward systems at Central  
**Current Control Status:** C-031 provides site-to-site VPN protection and the HQ environment is documented as using a MedDefense VLAN. However, VPN ACLs have not been audited and no documented security assurance, configuration visibility or contractual control requirements for the landlord-managed infrastructure have been identified.  
**What is Missing:** **Administrative / Preventive** third-party security requirements and assurance, periodic review of shared-network controls, and **Technical / Detective** validation of VPN/ACL behavior and unexpected cross-tenant or infrastructure exposure.  
**Risk Level:** **High**  
**Risk Justification:** Existing VPN and VLAN controls reduce direct exposure, but MedDefense relies on infrastructure it does not administer and has not demonstrated that the surrounding control environment meets its security requirements.  
**Potential Impact:** Misconfiguration or compromise of shared building infrastructure could expose HQ connectivity, disrupt business operations or create an unexpected route toward MedDefense systems.

---

### D. No Formal Change-Management Process — **Valid**

Marcus's observation is supported by MedDefense's incident history. Configuration changes are reportedly made without consistent documentation, testing or approval, and the untested cron modification contributed to the three-week backup gap discovered during the January ransomware recovery. **GAP-009** addresses pharmacy-specific change validation, but it does not cover organisation-wide infrastructure and server changes.

#### New Gap — GAP-022

**Gap ID:** GAP-022  
**Title:** No formal change-management process for production systems and infrastructure  
**Affected Asset(s):** Servers, network infrastructure, backup systems, clinical applications and other production technology  
**Data at Risk:** Restricted clinical data, credentials and Confidential business information depending on the affected system  
**Current Control Status:** Some systems have technical controls and backups, but there is no documented organisation-wide process requiring change ownership, approval, testing, rollback planning and post-change verification.  
**What is Missing:** **Administrative / Preventive** change-control procedures, **Administrative / Detective** post-change verification/audit trail and defined **Corrective** rollback requirements for failed changes.  
**Risk Level:** **High**  
**Risk Justification:** The gap spans Critical systems and has already contributed to a failed backup configuration. Existing technical controls reduce some consequences but do not prevent untested or undocumented configuration changes from introducing new exposure.  
**Potential Impact:** A configuration error could disable backups, weaken firewall or authentication controls, corrupt clinical data, expose services or create prolonged outages without a reliable rollback path.

---

## 3. Findings We Identified That Marcus Missed

Marcus's draft was valuable but incomplete. The following significant findings were identified in the later assessment and are not fully addressed in his documented findings.

| Our Finding | Evidence / Identifier | Why Marcus May Have Missed It |
|---|---|---|
| **Critical physical access weaknesses at Central** | **GAP-004**, **GAP-005** — generic server-room badge access; unlocked network closet; exposed switch credentials; incomplete CCTV coverage | His draft appears primarily network/system focused. The later physical walk-through provided direct evidence he may not have collected or formally incorporated before leaving. |
| **Patient portal broken object-level authorization** | **GAP-010**, A-037 — patients could alter a URL parameter and view other patients' laboratory results | Marcus noted TLS configuration but not the demonstrated application-authorisation incident. His assessment may have lacked application testing depth or he may not have reconciled the incident log into the draft. |
| **Legacy Windows XP MRI control environment** | **GAP-006**, A-022 | Marcus said he had not completed the medical-device review. Certification and operational constraints also required follow-up with Radiology/Clinical Engineering that may not have been completed before he left. |
| **EHR database reachable from the wider internal environment** | **GAP-002**, A-002 | M-01 recognises the flat network generally, but the later asset/scan reconciliation exposed the more specific database-access problem: PostgreSQL should be reachable only from the EHR application tier. |
| **Pharmacy change-integrity and recovery weakness** | **GAP-009**, A-038 | His draft does not translate the six-hour dosage incident into a formal application-integrity/change-control finding. Time pressure and an unfinished application-control review are plausible explanations. |
| **Shadow IT and unknown production systems** | **GAP-012**, A-012, A-014 and later A-054 to A-056 | The network scan reconciliation and later staff disclosures occurred during the newer assessment. Marcus's own notes show documentation was incomplete, so he may simply not have known these systems/services existed. |
| **Incomplete endpoint/mobile security coverage** | **GAP-013** | Later asset reconciliation compared Sophos coverage against the broader endpoint estate and highlighted unclear physician-iPad management. Marcus did not complete endpoint-security evaluation. |
| **No formal IR/BCP/DR programme** | **GAP-015** | Marcus recognised symptoms of weak response and recovery, but did not consolidate them into a formal cross-cutting governance gap before his draft ended. |
| **Systematic vulnerability/patch-management weakness** | **GAP-016** | Marcus identified individual legacy/unpatched systems, but the later real-world breach validation showed the need to treat this as an organisation-wide programme gap rather than a collection of isolated technical findings. |
| **Identity lifecycle/offboarding weakness** | **GAP-017** | This was identified through the later external breach comparison. No evidence in Marcus's draft shows that joiner/mover/leaver processes were assessed. |
| **Root cause of recurring billing-server compromise** | Advanced Task 2 — `billing-srv-01` crypto-miner under `www-data`, suspected Apache/web-layer entry path | Marcus correctly noticed the miner and suspected something was wrong, but his draft stopped at detection. The later root-cause analysis connected the process, network behavior and repeated compromise after rebuild and asked whether the original entry point had ever been removed. |

Marcus's omissions do not make his assessment poor; they are consistent with an **unfinished assessment conducted under limited time, incomplete documentation and incomplete technical review**. The later work benefited from additional packet evidence, a broader network scan, physical observations, asset reconciliation and explicit cross-referencing of incidents, controls and data flows.

---

# 4. Overall Resolution of Marcus's Assessment

Marcus's central diagnosis was largely correct: MedDefense's most serious weaknesses are architectural and systemic rather than isolated configuration errors. His strongest findings—flat networking, weak monitoring, exposed medical IoT, inadequate backup isolation, weak MFA and Westside exposure—align closely with the later assessment.

The main corrections are about **precision and completeness**. He occasionally overstates absence ("zero detective capability", "no MFA on any system"), underestimates risk where later evidence increases business impact (medical IoT, Westside and the unsupported print server in a flat network), and leaves several application, physical-security, governance and Shadow IT issues undocumented. His draft should therefore be treated as valuable supporting evidence, not as a replacement for the completed assessment.

---

# Part 2 — The Last Page

Marcus's unfinished threat-landscape work is the logical continuation of the completed internal posture assessment because the two analyses answer different but connected questions: the internal assessment identifies **which MedDefense assets are critical, where the control gaps are and what the impact of exploitation would be**, while the external analysis identifies **which threat actors and attack techniques are most likely to target those weaknesses**. Our assessment already shows that an initial compromise could become much more serious because of weaknesses such as internal network reachability, limited MFA, medical-device exposure and fragmented monitoring; the next step is to determine how closely those weaknesses match current ransomware, valid-account, public-facing application and insider attack patterns. That external context would allow MedDefense to refine likelihood and sequencing—for example, deciding which Critical and High gaps face the most immediate real-world exploitation pressure rather than treating every internal weakness as equally urgent. Marcus was therefore correct that internal posture is only half of the risk picture: once MedDefense understands **where it is vulnerable**, a formal Threat Landscape Report can show **who is most likely to exploit it, how they would do so and which remediation should come first**.
