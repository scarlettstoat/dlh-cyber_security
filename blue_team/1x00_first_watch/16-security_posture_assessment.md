# MedDefense Health Systems
# Security Posture Assessment

**Assessment Date:** 1 September 2026  
**Prepared for:** MedDefense Health Systems Board and Executive Leadership  
**Assessment Scope:** MedDefense Central, Westside Clinic and Corporate HQ

---

# 1. Executive Summary

MedDefense Health Systems' current security posture is **high risk and fragmented**. The organization has several useful security controls, but they are unevenly applied and do not consistently match the criticality of the clinical systems and sensitive data they protect. The assessment identified **15 prioritized security gaps: 7 Critical, 5 High and 3 Medium**.

The **single most critical finding** is the lack of effective internal network segmentation at MedDefense Central. Workstations, servers and network-connected medical devices use separate addressing ranges but remain reachable across the same internal environment. A compromise of one endpoint or vulnerable medical device could therefore provide a path toward the EHR, Active Directory, patient monitoring, medication systems or other critical services.

The top three actions are:

1. **Separate critical systems and clinical devices from general user networks.** Implement enforced internal segmentation, isolate medical IoT and the legacy MRI workstation, and replace Westside Clinic's consumer router with an enterprise firewall.
2. **Close known access-control weaknesses immediately.** Restrict server-room and network-closet access, remove exposed administrative credentials and verify remediation of the patient portal authorization failure.
3. **Use the remaining annual budget to strengthen resilience and detection once Critical treatments are underway.** Priority follow-on areas are isolated backups, centralized monitoring, Shadow IT management, endpoint/mobile coverage and formal incident-response and continuity planning.

MedDefense has already experienced the type of consequences these weaknesses can produce: ransomware interrupted billing for four days, an EHR migration caused a nine-hour clinical outage, a patient portal flaw exposed other patients' laboratory results, and a pharmacy update displayed incorrect medication dosages across all three sites.

**Budget implication:** The seven Critical treatments require an estimated **$91,000** of the available **$120,000** annual security budget, leaving **$29,000** for implementation contingency and the next highest High-risk priorities.

---

# 2. Scope and Methodology

## 2.1 Assessment Scope

The assessment covered all three MedDefense operating locations:

- **MedDefense Central** — 350-bed acute-care hospital and primary location for clinical and core IT infrastructure.
- **Westside Clinic** — suburban outpatient facility providing primary care, diagnostic imaging, blood work, minor procedures and physical therapy.
- **Corporate HQ** — administrative location supporting Finance, HR, Legal, Marketing, Executive Leadership and IT.

The assessment considered:

- Servers and data stores
- Network infrastructure and site connectivity
- Clinical and administrative endpoints
- EHR, patient portal, pharmacy and business applications
- PACS, MRI, CT and medical imaging
- Network-connected medical devices
- Identity and access management
- Backup and recovery infrastructure
- Physical security infrastructure
- Patient, clinical, credential, employee, financial and operational data

## 2.2 Sources of Information

The assessment consolidates evidence gathered throughout the MedDefense project, including:

- Onboarding documentation and partial asset lists
- Network topology and service information
- Marcus Webb's notes and incident history
- Physical walk-through observations
- Firewall, SSH, password, antivirus, backup, physical-security, training and logging artifacts
- Network scan summary across the three MedDefense sites
- Asset Registry and reconciliation findings
- Asset Criticality Assessment
- Data classification and protection analysis
- Complete Control Matrix and effectiveness ratings
- Shadow IT findings
- Revised Prioritized Gap Analysis
- Risk Treatment Decisions and budget analysis

Findings remain traceable through the project's identifiers:

- **Assets:** `A-xxx`
- **Controls:** `C-xxx`
- **Gaps:** `GAP-xxx`

## 2.3 Limitations and Assumptions

This assessment is based on the evidence available during the project and is not a substitute for a full penetration test or comprehensive technical audit.

Important limitations include:

- The original asset documentation was incomplete and sometimes contradictory.
- Historical endpoint and medical-device counts differ from current scan results.
- A full vulnerability assessment has not been completed for every server, endpoint or medical device.
- The complete cloud/SaaS estate has not been verified beyond known services such as Microsoft O365.
- The exact location of the Central server room is contradictory across source documents.
- The actual security-zone placement of `web-srv-01` requires confirmation.
- Physician iPad management and MDM coverage remain unclear.
- Several detective controls rely on local or manually reviewed logs.
- Two undocumented Linux systems were discovered whose owners, purpose and data holdings remain unknown.
- The External Threat Landscape Assessment has not yet been completed.

Where evidence is incomplete, this assessment records the uncertainty rather than assuming that a control or asset state is stronger than the available evidence supports.

---

# 3. Asset Landscape

## 3.1 Asset Inventory Summary

The consolidated Asset Registry contains **53 registry records**. Some records represent grouped estates—such as hundreds of workstations or approximately 120 infusion pumps—so this number is not the total number of individual physical devices.

### Registry Records by Asset Type

| Asset Type | Registry Records |
|---|---:|
| Server | 13 |
| Endpoint | 10 |
| Application | 8 |
| Physical Infrastructure | 7 |
| Network Device | 6 |
| IoT Medical | 6 |
| Data Store | 3 |
| **Total** | **53** |

### Registry Records by Site Association

| Site / Association | Registry Records |
|---|---:|
| MedDefense Central | 36 |
| Westside Clinic | 8 |
| Corporate HQ | 2 |
| Multi-site / organization-wide | 2 |
| Cloud / organization-wide | 1 |
| Location not sufficiently documented | 4 |
| **Total** | **53** |

The concentration of assets at Central increases the significance of shared infrastructure weaknesses. A single failure affecting Central's core network, server room or authentication environment can influence multiple clinical services at once.

## 3.2 Top 5 Critical Assets

### 1. EHR System — `ehr-srv-01`, `ehr-db-01` and EHR Application

The EHR is MedDefense's most critical information system because clinicians depend on it for current patient information. Confidentiality, integrity and availability are all Critical. The previous nine-hour outage forced physicians to use paper records, demonstrating the operational impact of losing the service.

### 2. Pharmacy Management System — A-038

The pharmacy system is Critical because the integrity of medication information directly affects patient safety across all three sites. MedDefense has already experienced a six-hour incident in which a database update caused incorrect dosage values to be displayed.

### 3. BD Alaris Infusion-Pump Estate — A-032

Approximately 120 network-connected infusion pumps support medication delivery and dosage updates. Their integrity and availability are Critical because compromise can affect treatment being delivered directly to patients. The devices also lack effective network isolation.

### 4. Network Core and Connectivity

The FortiGate, switching infrastructure, wireless network and site VPNs are shared dependencies for EHR, medical devices, imaging, Active Directory and user endpoints. A major network compromise can therefore affect several critical services simultaneously.

### 5. Active Directory — `ad-dc-01` and `ad-dc-02`

Active Directory provides centralized identity and authentication services. Unauthorized changes could give an attacker broad access across MedDefense, while a directory-wide outage could prevent staff from authenticating to systems required for clinical and business operations.

## 3.3 Data Classification Summary

| Classification | MedDefense Examples | Security Significance |
|---|---|---|
| **Restricted** | EHR/PHI, laboratory results, diagnostic imaging, medication/dosage information, patient-monitoring information, authentication credentials, backups containing clinical information | Exposure or alteration may create direct patient-safety, privacy, legal and regulatory consequences. |
| **Confidential** | HR/employee information, billing and financial records, contracts and sensitive business information | Unauthorized disclosure or alteration can create financial, privacy and legal harm. |
| **Internal** | Network/system documentation, internal procedures and non-public operational information | Disclosure can assist an attacker and create operational risk. |
| **Public** | Approved public website and marketing information | Confidentiality is low, but integrity remains important; MedDefense's public website has previously been defaced. |

The principal data-protection concern is that **Restricted information is processed by Critical systems that are not consistently isolated, monitored or recovered at a level appropriate to their sensitivity**.

---

# 4. Current Security Controls

## 4.1 Control Matrix Summary

The Complete Control Matrix documents **36 existing controls**.

### Controls by Category

| Category | Count |
|---|---:|
| Technical | 23 |
| Administrative | 8 |
| Physical | 5 |
| **Total** | **36** |

### Controls by Function

| Function | Count |
|---|---:|
| Preventive | 18 |
| Detective | 13 |
| Corrective | 3 |
| Compensating | 1 |
| Deterrent | 1 |
| **Total** | **36** |

### Controls by Effectiveness

| Effectiveness | Count |
|---|---:|
| Strong | 6 |
| Adequate | 16 |
| Weak | 14 |
| **Total** | **36** |

## 4.2 Overall Maturity Assessment

MedDefense's security-control maturity is **developing but fragmented**. The organization has useful technical controls, but they have accumulated unevenly and are not yet organized into a consistently enforced security architecture.

### Relative Strengths

- FortiGate default-deny perimeter rule
- Strong SSH configuration on `ehr-srv-01`
- Active Directory password enforcement and account lockout
- Sophos malware protection and automated containment on covered systems
- Nightly Veeam backups for documented in-scope virtual machines
- Secondary Active Directory domain controller
- Existing EHR audit logging
- Annual security-awareness training

### Principal Weaknesses

- No effective internal network segmentation
- Limited medical-IoT-specific protection
- Legacy Windows XP MRI control environment
- Fragmented security monitoring
- Incomplete endpoint/mobile-device coverage
- Weak physical protection of critical infrastructure
- Locally concentrated backup architecture
- Limited tested recovery capability
- No formal IR/BCP/DR programme
- Shadow IT and incomplete asset ownership
- Application-specific access and integrity weaknesses

## 4.3 Key Control Effectiveness Findings

The central weakness is **incomplete coverage rather than complete absence of controls**.

Strong controls often apply only to a narrow part of the environment. For example, SSH hardening is strong on `ehr-srv-01`, but equivalent hardening is not documented across every Linux system. Sophos protects 372 Windows systems, but the documented Windows estate is larger. Multiple systems generate security logs, but the logs remain fragmented and are not continuously correlated.

The functional distribution is also unbalanced. MedDefense has **18 Preventive and 13 Detective controls**, but only **3 Corrective controls and 1 Compensating control**. This leaves recovery and alternative-control capability thin when prevention cannot be fully implemented.

---

# 5. Gap Analysis

The revised Gap Analysis identifies **15 prioritized gaps**:

- **7 Critical**
- **5 High**
- **3 Medium**
- **0 Low**

## 5.1 Critical Findings

| Gap | Description | Affected Assets | Potential Impact | Recommended Treatment |
|---|---|---|---|---|
| **GAP-001** | No effective internal segmentation between servers, workstations and medical devices | Network core, EHR, medical IoT and other Critical systems | A single endpoint compromise could spread into multiple clinical systems and cause a wider outage or breach | **Mitigate:** enforced VLAN/security zones, inter-zone firewalling and east-west monitoring |
| **GAP-003** | Medical IoT lacks device-specific isolation and monitoring | Infusion pumps and patient-monitoring devices | Manipulation or disruption could affect medication delivery, monitoring and patient safety | **Mitigate:** dedicated device zones, restricted communications and monitoring |
| **GAP-004** | Server-room access is not restricted to authorized personnel | Server room and hosted Critical infrastructure | Unauthorized physical access could cause data exposure, equipment tampering or clinical outages | **Mitigate:** restricted badges, access logging, CCTV and visitor controls |
| **GAP-005** | Network closet is unlocked and switch credentials are exposed | Network closet and access switches | Unauthorized users could change network configuration, intercept traffic or disrupt clinical connectivity | **Mitigate:** lock closet, rotate credentials and log administrative access |
| **GAP-006** | MRI control environment relies on unsupported Windows XP | `WS-RAD-01` and Siemens MRI | Exploitation could disrupt imaging, expose clinical data or provide a route into the wider network | **Mitigate:** compensating VLAN isolation with firewall allow-list to PACS and monitored exception management |
| **GAP-010** | Patient portal authorization failure has no documented remediation verification | Patient portal and `web-srv-01` | Patients could access other patients' laboratory information, creating privacy and regulatory exposure | **Mitigate:** server-side authorization enforcement and security regression testing |
| **GAP-014** | Westside uses a consumer router with no dedicated firewall | Westside connectivity, server, endpoints and imaging | Local compromise could disrupt the clinic or provide an attack path through the VPN toward Central | **Mitigate:** enterprise firewall, restrictive policies and local security logging |

## 5.2 High Findings

| Gap | Description | Affected Assets | Potential Impact | Recommended Treatment |
|---|---|---|---|---|
| **GAP-008** | Backup infrastructure is concentrated in one physical/network location | `backup-srv-01`, `NAS-01`, Veeam | Ransomware or physical damage could affect production and recovery copies together | **Mitigate:** isolated/offsite copies, broader backup scope and regular restore testing |
| **GAP-011** | Security logging is fragmented and manually reviewed | EHR, AD, servers and network infrastructure | Malicious activity may remain undetected, increasing attacker dwell time and incident impact | **Mitigate:** centralized log collection, correlation and alerting |
| **GAP-012** | Undocumented Shadow IT operates on production networks | `UNKNOWN-01`, Westside `10.10.10.200` | Unmanaged systems could provide vulnerable or persistent footholds toward sensitive assets | **Mitigate:** identify, isolate, authorize/remove and continuously discover assets |
| **GAP-013** | Endpoint and device-management coverage is incomplete | Clinical/admin endpoints and physician iPads | Malware or unmanaged devices could expose sensitive data or provide an internal attack path | **Mitigate:** close Sophos gaps, deploy MDM and strengthen admission controls |
| **GAP-015** | Formal incident response, business continuity and disaster recovery are absent | All Critical systems | Response delays and weak recovery coordination could prolong clinical and business outages | **Mitigate:** documented and tested IR/BCP/DR procedures |

## 5.3 Medium Findings

| Gap | Description | Why Medium |
|---|---|---|
| **GAP-002** | `ehr-db-01` is reachable from the wider internal network | Critical/Restricted exposure exists, but EHR/database logging and backup controls partially reduce the gap |
| **GAP-007** | MFA and privileged-access controls are incomplete | Critical identity exposure exists, but password controls, AD logging and redundancy provide partial protection |
| **GAP-009** | Pharmacy system lacks formal change validation and recovery | Critical clinical integrity risk remains, but the existing manual printed-reference cross-check provides some detective coverage |

## 5.4 Gap Distribution Analysis

| Risk Level | Number of Gaps |
|---|---:|
| Critical | 7 |
| High | 5 |
| Medium | 3 |
| Low | 0 |
| **Total** | **15** |

**Network Core and Site Connectivity** has the greatest concentration of findings, with four gaps. This is particularly important because network connectivity is a common dependency across EHR, Active Directory, medical devices, imaging and user endpoints.

Control deficiencies are concentrated in:

- **Technical / Preventive:** segmentation, medical-device isolation, application authorization, MFA and secure site perimeter controls.
- **Technical / Detective:** centralized monitoring and east-west/device visibility.
- **Corrective:** tested recovery remains limited.
- **Physical / Preventive and Detective:** critical infrastructure access is weaker than its criticality warrants.
- **Compensating:** few formal alternative controls exist where primary remediation is not immediately feasible.

---

# 6. Risk Treatment Recommendations

The seven Critical gaps are the current fiscal year's first treatment priority. Each is assigned **Mitigate** because acceptance or transfer would not adequately address patient-safety, clinical-availability or privacy consequences, while outright avoidance would require MedDefense to stop necessary clinical activities.

Cost figures are **planning estimates**, not vendor quotations.

## 6.1 Seven Priority Recommendations

| Priority | Gap | Recommendation | Strategy | Cost Estimate | Planning Allocation | Timeline |
|---|---|---|---|---|---:|---|
| **1** | GAP-001 | Enforce internal network segmentation between users, servers, medical devices and management zones | Mitigate | $10-50K | **$25,000** | Long-term > 1 month |
| **2** | GAP-003 | Isolate and monitor medical IoT, allowing only approved clinical communications | Mitigate | $10-50K | **$18,000** | Long-term > 1 month |
| **3** | GAP-004 | Restrict and monitor server-room physical access | Mitigate | $1-10K | **$8,000** | Short-term < 1 month |
| **4** | GAP-005 | Lock the network closet, rotate exposed credentials and log switch administration | Mitigate | $1-10K | **$3,000** | Quick Win < 1 week |
| **5** | GAP-006 | Apply compensating isolation to the Windows XP MRI workstation, permitting only required PACS communications | Mitigate | $1-10K | **$7,000** | Short-term < 1 month |
| **6** | GAP-010 | Remediate and independently verify patient-portal object-level authorization | Mitigate | $10-50K | **$15,000** | Short-term < 1 month |
| **7** | GAP-014 | Replace Westside's consumer router with an enterprise firewall/security gateway | Mitigate | $10-50K | **$15,000** | Short-term < 1 month |
|  |  | **Critical-treatment total** |  |  | **$91,000** |  |

### MRI Treatment Position

The MRI cannot currently be patched or replaced within the budget cycle and must remain connected to PACS. Its immediate treatment is therefore a **compensating control**: place `WS-RAD-01` on an isolated VLAN and configure firewall rules permitting only the traffic required to communicate with PACS and explicitly approved management services. The underlying Windows XP risk remains, so this treatment reduces rather than eliminates risk.

## 6.2 Budget Allocation

| Budget Use | Amount |
|---|---:|
| Seven Critical risk treatments | **$91,000** |
| Implementation contingency / next High-risk treatments | **$29,000** |
| **Annual Security Budget** | **$120,000** |

The remaining **$29,000** should first protect delivery of the Critical programme against implementation uncertainty. Once Critical milestones are funded and underway, unused funds should be directed toward the highest-value High risks:

1. GAP-008 — isolated/offsite backup and restore testing
2. GAP-011 — centralized security monitoring
3. GAP-015 — formal incident response and continuity planning
4. GAP-013 — endpoint/mobile management coverage
5. GAP-012 — Shadow IT discovery and governance

## 6.3 Quick Wins — Within 1 Week

- Lock the second-floor network closet.
- Remove the posted switch-management credentials and rotate the password.
- Restrict server-room badge permissions to personnel with a legitimate operational need.
- Begin documenting the MRI legacy-system exception, owner and review date.
- Confirm that the public/restricted-area emergency exit is no longer routinely propped open.
- Identify and isolate the two undocumented Linux systems pending ownership verification.
- Begin verification that the patient portal can no longer return another patient's records.

## 6.4 Short-Term Priorities — Within 1 Month

- Complete server-room access logging and camera coverage.
- Isolate `WS-RAD-01` and enforce PACS-only/required-service firewall rules.
- Correct and security-test the patient portal authorization model.
- Deploy the Westside enterprise firewall and restrict VPN reachability.
- Begin centralized collection of the most security-relevant existing logs using available remaining budget.
- Perform a current Critical-system restore test and document the result.

## 6.5 Long-Term Roadmap — More Than 1 Month

- Complete staged internal segmentation at Central.
- Complete medical-IoT isolation and traffic monitoring.
- Develop a supported replacement/upgrade plan for the Windows XP MRI control environment.
- Expand isolated/offsite backup and whole-service restore testing.
- Mature centralized monitoring and security alerting.
- Expand endpoint protection and MDM coverage.
- Introduce recurring asset discovery and Shadow IT governance.
- Formalize and exercise incident-response, business-continuity and disaster-recovery plans.
- Reassess the Critical and High gaps after implementation and report residual risk to executive leadership.

---

# 7. Conclusion and Next Steps

MedDefense has a workable security foundation, but the current environment exposes **Critical clinical services and Restricted information to risks that exceed an acceptable level for a healthcare organization**. The central issue is not the absence of all security controls; it is that controls are fragmented, incomplete and often weakest at the points where compromise could have the greatest patient-care or operational impact.

The risk is demonstrated by MedDefense's own incident history. Billing has already been unavailable for four days following ransomware, the EHR has already experienced a nine-hour outage, patient laboratory information has already been exposed through broken portal authorization, and incorrect dosage information has already been displayed across the organization.

If the recommended treatments are not implemented, a compromised endpoint, vulnerable medical device, legacy MRI workstation, stolen physical access, application authorization failure or weak site perimeter can continue to create consequences beyond the initially affected system. Fragmented monitoring and limited recovery maturity also increase the likelihood that future incidents will be detected late and restored slowly.

The Board should therefore approve the **$91,000 Critical-risk treatment programme**, retain the remaining **$29,000** for implementation contingency and follow-on High-risk remediation, and require accountable owners and milestone reporting for each `GAP-xxx` treatment.

Once the internal posture remediation programme is underway, the next analytical phase should complete **Marcus Webb's unfinished External Threat Landscape Assessment**. That assessment should identify the external threat actors, ransomware activity, healthcare-focused intrusion patterns and exploitation trends most relevant to MedDefense, then compare those threats against the residual risks that remain after this programme.
