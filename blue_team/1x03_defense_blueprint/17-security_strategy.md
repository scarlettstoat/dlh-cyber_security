# 17. The Security Strategy Document

# MedDefense Health Systems
## Security Strategy Document

**Prepared for:** Board and Executive Leadership  
**Prepared by:** Security Department  
**Programme:** Project 1x03 — Defense Blueprint  
**Companion Documents:** Security Posture Assessment (1x00), Threat Landscape Report (1x01), Vulnerability Assessment Summary (1x02)  
**Planning Horizon:** Six months, with Year 2 priorities identified  
**Annual Security Budget:** **$120,000**

---

# 1. Executive Summary

MedDefense Health Systems currently operates with a **high and fragmented cybersecurity risk posture**. The organization has useful security controls, but the highest-risk attack paths repeatedly exploit the same weaknesses: limited internal segmentation, incomplete identity protection, fragmented monitoring, vulnerable or unsupported systems, weak recovery isolation, and insufficiently controlled medical-device and third-party access.

The strategic approach is to adopt **NIST Cybersecurity Framework (CSF) 2.0** as the governance and Board-reporting backbone, supported by **CIS Controls v8** for tactical implementation. Risk treatment is based on asset criticality, threat-informed kill chains, vulnerability evidence, quantitative Annual Loss Expectancy (ALE), control cost-benefit analysis, and residual-risk review.

MedDefense should approve the full **$120,000 first-year security programme**. The funded portfolio consists of network segmentation, MFA, Wazuh SIEM, offsite immutable backup, Sophos Intercept X EDR, and medical-device isolation and monitoring. Task 8 estimates a **gross standalone modeled risk reduction of $1.636 million** across the funded controls; because several controls reduce the same risks, those standalone figures overlap and must not be treated as fully additive realized savings. The independent Task 6 top-five risk model shows annualized loss exposure falling from **$1,765,625 to $874,100**, a modeled reduction of **$891,525 per year** for the five quantified risks.

### Top 3 Priority Actions

1. **Implement enforced network segmentation.** Separate clinical workstations, servers, medical devices, management systems, guest/IoT devices, and backup infrastructure using least-privilege inter-zone firewall rules.
2. **Reduce credential and detection risk.** Require MFA for administrative, remote, and vendor access, and centralize priority telemetry in Wazuh with owned alert review and escalation.
3. **Protect recovery and patient-safety-critical systems.** Deploy immutable offsite backup, complete EDR coverage for supported systems, and isolate/monitor medical IoT and the unsupported MRI environment.

The strategy does not attempt to eliminate all cyber risk in six months. Its objective is to move MedDefense from a reactive and broadly trusted environment toward a **documented, owned, monitored, segmented, and repeatable security operating model**.

---

# 2. Governance Framework

## 2.1 Framework Selection Rationale

MedDefense should use:

- **NIST CSF 2.0** as the strategic security and risk-management framework;
- **CIS Controls v8** as the prioritized implementation framework; and
- **ISO/IEC 27001** as a future assurance option rather than a current certification target.

### Why NIST CSF 2.0

NIST CSF is appropriate because MedDefense needs a framework that can connect technical security problems to governance, risk, executive oversight, response, and recovery.

Its six Functions give the Board a simple structure:

```text
GOVERN
  ↓
IDENTIFY
  ↓
PROTECT
  ↓
DETECT
  ↓
RESPOND
  ↓
RECOVER
```

This is a strong fit for MedDefense because the project has already shown that its weaknesses are not only technical. Ownership, monitoring, recovery, vendor access, policy, and risk acceptance are also part of the problem.

### Why CIS Controls v8

CIS Controls provide the operational layer underneath NIST CSF.

The MedDefense programme repeatedly depends on safeguards from:

- CIS 6 — Access Control Management
- CIS 7 — Continuous Vulnerability Management
- CIS 8 — Audit Log Management
- CIS 10 — Malware Defenses
- CIS 11 — Data Recovery
- CIS 12 — Network Infrastructure Management
- CIS 13 — Network Monitoring and Defense

This gives IT and Security specific, auditable actions rather than leaving the framework at a high level.

### Why ISO 27001 Is Deferred

ISO 27001 certification would add formal assurance and an auditable Information Security Management System, but it is not the best first-year use of MedDefense's limited security budget.

The immediate need is to reduce live operational risk. A certification programme should be reconsidered in **12–24 months** if a major payer, customer, partner, regulator, or business-development requirement creates a clear need for third-party certification.

---

## 2.2 NIST CSF Current vs. Target Profile

| NIST CSF Function | Current Level | 6-Month Target | Strategic Focus |
|---|---|---|---|
| **Govern** | Partial | **Managed** | Formal ownership, policy, risk review, Board reporting |
| **Identify** | Partial | **Managed** | Maintained asset inventory, recurring risk and vulnerability review |
| **Protect** | Partial | **Managed** | MFA, segmentation, EDR, secure configuration, medical-device controls |
| **Detect** | Not Implemented | **Managed** | Centralized logging, alert correlation, owned investigation process |
| **Respond** | Partial | **Managed** | Formal IR plan, playbooks, escalation, tabletop exercise |
| **Recover** | Partial | **Managed** | Immutable backup, recovery objectives, restore testing |

The most significant maturity gap is **Detect**. MedDefense has logs and local security capabilities, but no dependable organization-wide monitoring process. Protect is the second major concern because several Critical assets remain exposed by segmentation, credential, lifecycle, and configuration weaknesses.

The six-month goal is deliberately **Managed**, not Optimized. MedDefense first needs repeatable security operations before it can claim continuous improvement and advanced maturity.

---

## 2.3 CIS Controls Maturity Scorecard

The CIS scorecard below summarizes the current state and the intended six-month direction using the evidence established throughout Projects 1x00–1x03.

| CIS Control | Current Position | 6-Month Target | Priority |
|---|---|---|---|
| **1 — Enterprise Assets** | Partial asset inventory; unmanaged/unknown systems identified | Maintained inventory with owner, criticality and lifecycle status | High |
| **2 — Software Assets** | Incomplete visibility; legacy/EOL software present | Approved software inventory and lifecycle tracking | High |
| **3 — Data Protection** | Sensitive data identified, but controls vary by system | Documented handling and protection requirements | High |
| **4 — Secure Configuration** | Inconsistent; legacy and weak configurations remain | Repeatable baseline and exception process | High |
| **5 — Account Management** | Existing AD controls, but lifecycle weaknesses remain | Controlled joiner-mover-leaver process | High |
| **6 — Access Control Management** | MFA/PAM incomplete | MFA for remote/admin/vendor access and stronger privileged control | Critical |
| **7 — Continuous Vulnerability Management** | Assessment exists but process is not fully operationalized | Recurring scan, SLA, remediation and verification cycle | Critical |
| **8 — Audit Log Management** | Logs fragmented/local | Centralized priority logs and review process | Critical |
| **9 — Email/Web Protections** | Existing controls but phishing remains major path | Threat-focused tuning and awareness support | High |
| **10 — Malware Defenses** | Sophos present but coverage/capability incomplete | Intercept X EDR across supported estate | Critical |
| **11 — Data Recovery** | Recovery exists but resilience/testing is incomplete | Immutable offsite backup plus tested restores | Critical |
| **12 — Network Infrastructure Management** | Separate ranges but flat trust model | Enforced VLAN/security-zone architecture | Critical |
| **13 — Network Monitoring and Defense** | Weak east-west visibility | Wazuh plus network/security telemetry and defined alerting | Critical |
| **14 — Security Awareness** | Training exists but threat-focused maturity is limited | Role-aware, phishing/credential/vendor-focused programme | High |
| **15 — Service Provider Management** | Trusted vendor pathways exist | Named, time-bounded, MFA-protected vendor access | High |
| **16 — Application Security** | Authorization and exposed-service findings exist | Risk-based remediation and secure-change validation | High |
| **17 — Incident Response** | Reactive capability, limited formalization | Documented plan, playbooks and exercise | Critical |
| **18 — Penetration Testing** | Vulnerability work exists; attack-path validation limited | Targeted validation of segmentation and critical attack paths | Medium/High |

The maturity strategy is to establish **IG1-level discipline quickly**, then extend controls toward the risk profile expected of a regional healthcare provider rather than treating IG1 as the final destination.

---

## 2.4 Governance Structure and Roles

MedDefense should separate executive accountability, security oversight, technical execution, and business ownership.

### Governance Model

```text
Board / CEO — Dr. Morales
        |
        | Budget approval, policy approval, major risk acceptance
        |
   vCISO / Executive Security Adviser
        |
        | Strategy, independent governance, Board reporting
        |
Deputy CISO — James Chen
        |
        | Security programme ownership and coordination
        |
        +-------------------------------+
        |                               |
Security Analyst                 IT Director — Sarah Park
        |                               |
Risk analysis                     Technical remediation
Monitoring                        Patching/configuration
Vendor assessment                 Infrastructure changes
Control verification              System administration
        |
Department Heads / Data Owners
        |
Business and clinical risk ownership
```

### Core RACI Summary

| Activity | Accountable | Responsible / Lead |
|---|---|---|
| Security budget approval | CEO | Deputy CISO |
| Vulnerability remediation | IT Director | IT + Security Analyst |
| Incident response execution | Deputy CISO | IT + Security Analyst |
| Security policy approval | CEO | Deputy CISO |
| Significant risk acceptance | CEO | Business risk owner with Security input |
| Awareness programme | Deputy CISO | Security Analyst + Department Heads |
| Vendor risk assessment | Deputy CISO | Security Analyst |
| Audit coordination | Deputy CISO | Security Analyst |

### Senior Security Leadership

MedDefense should use a **vCISO for the next 6–12 months** rather than immediately consume a large share of the technical security budget with a full-time executive hire. The vCISO should provide Board reporting, programme governance, policy oversight, and independent risk challenge while James remains the internal security lead.

---

# 3. Quantitative Risk Analysis

## 3.1 Top 5 Risks by Annual Loss Expectancy

| Rank | Risk | ALE Before Control | Modeled ALE After Control | Reduction |
|---:|---|---:|---:|---:|
| **1** | EHR ransomware double extortion | **$1,050,000** | **$612,500** | **$437,500** |
| **2** | `billing-srv-01` compromise | **$234,000** | **$39,000** | **$195,000** |
| **3** | Active Directory privileged compromise | **$210,000** | **$168,000** | **$42,000** |
| **4** | Windows XP MRI exploitation/disruption | **$163,625** | **$30,600** | **$133,025** |
| **5** | Alaris environment compromise/disruption | **$108,000** | **$24,000** | **$84,000** |

### Combined Top-5 Model

```text
Total ALE before controls:  $1,765,625
Total ALE after controls:     $874,100
Modeled ALE reduction:        $891,525
```

These figures are planning estimates based on AV, EF, SLE, and ARO. They are designed for investment comparison and prioritization, not as predictions of exact future losses.

---

## 3.2 Risk Register Summary

| Risk ID | Risk | Inherent Risk | Treatment | Planned Residual Risk |
|---|---|---|---|---|
| **RISK-001** | EHR ransomware double extortion | **25 Critical** | Mitigate | **15 High** |
| **RISK-002** | Active Directory privileged compromise | **20 Critical** | Mitigate | **10 High** |
| **RISK-003** | Backup/recovery neutralization | **20 Critical** | Mitigate | **8 Moderate** |
| **RISK-004** | `billing-srv-01` compromise | **16 Critical** | Mitigate | **8 Moderate** |
| **RISK-005** | Negligent insider / unmanaged endpoint | **16 Critical** | Mitigate | **8 Moderate** |
| **RISK-006** | Windows XP MRI exploitation | **15 High** | Mitigate | **10 High** |
| **RISK-007** | Alaris environment compromise | **15 High** | Mitigate | **10 High** |
| **RISK-008** | Vendor / supply-chain compromise | **15 High** | Mitigate | **10 High** |
| **RISK-009** | Malicious insider EHR misuse | **15 High** | Mitigate | **8 Moderate** |
| **RISK-010** | Westside perimeter compromise | **12 High** | Mitigate | **12 High until firewall funded; 8 Moderate after deployment** |

The risk register is owned by **Deputy CISO James Chen**, maintained operationally by the Security Analyst, and reviewed monthly with out-of-cycle review after major incidents, new Critical vulnerabilities, control failures, major environment changes, or KRI breaches.

---

## 3.3 Risk Appetite Statement

MedDefense's risk appetite should reflect its role as a healthcare provider.

### Very Low / Near-Zero Appetite

MedDefense should have **very low appetite** for risks that could:

- directly affect patient safety;
- compromise Restricted patient information at scale;
- create organization-wide identity compromise;
- disable the EHR or other Critical clinical services;
- destroy recovery capability;
- leave known Critical attack paths open without compensating controls; or
- permit uncontrolled privileged/vendor access to Critical systems.

### Limited Appetite

MedDefense may temporarily tolerate **High residual risk** only when:

- the primary remediation is not immediately technically possible;
- there is a documented business or clinical reason;
- compensating controls materially reduce likelihood or blast radius;
- a named owner is assigned;
- the exception has a review/expiry date; and
- the CEO or delegated executive authority formally accepts the residual risk where required.

### Moderate Appetite

MedDefense may accept **Moderate residual risk** when the cost or operational impact of further reduction is disproportionate, provided monitoring, ownership, and review remain in place.

### Risk-Acceptance Principle

```text
Critical patient-safety / Restricted-data risk:
    Mitigate first.

High residual risk:
    Time-bound exception + compensating controls + executive visibility.

Moderate residual risk:
    May be tolerated with owner, monitoring and review.

Undocumented acceptance:
    Not permitted.
```

---

# 4. Control Strategy

## 4.1 Cost-Benefit Analysis

| Control | Cost | Standalone ALE Reduction | Net Value | Decision |
|---|---:|---:|---:|---|
| **Network segmentation** | $25,000 | $437,500 | **$412,500** | Fund |
| **Offsite immutable backup** | $15,000 | $321,000 | **$306,000** | Fund |
| **MFA for VPN/admin** | $4,000 | $280,000 | **$276,000** | Fund |
| **Sophos Intercept X EDR** | $36,000 | $298,500 | **$262,500** | Fund |
| **Wazuh SIEM** | $22,000 | $215,000 | **$193,000** | Fund |
| **Medical-device isolation/monitoring** | $18,000 | $84,000 | **$66,000** | Fund |
| **Westside enterprise firewall** | $15,000 | $30,000 | **$15,000** | Defer |
| **Outsourced 24/7 SOC** | $240,000 | $161,575 | **-$78,425** | Reject for current cycle |

The outsourced SOC is not rejected because monitoring lacks value. It is rejected because MedDefense should first build the SIEM and telemetry foundation at a much lower cost.

---

## 4.2 Budget Allocation

### Fund Now — $120,000

```text
Network segmentation:                 $25,000
MFA:                                   $4,000
Wazuh SIEM:                           $22,000
Offsite immutable backup:             $15,000
Sophos Intercept X EDR:               $36,000
Medical-device isolation:             $18,000
------------------------------------------------
TOTAL:                                $120,000
REMAINING:                                  $0
```

### Defer

**Westside enterprise firewall — $15,000**

Deferral accepts approximately **$30,000/year of modeled opportunity cost**. RISK-010 therefore remains **12 High** until the firewall is funded.

### Reject for This Budget Cycle

**Outsourced 24/7 SOC — $240,000**

The control costs more than the entire annual security budget and exceeds its modeled ALE reduction.

---

## 4.3 Control Selection and Framework Mapping

| Control | Main Risks | CIS Mapping | NIST CSF Mapping | Type |
|---|---|---|---|---|
| **Network segmentation** | R001–R008, especially ransomware/lateral movement | CIS 12.2, 13.4 | PR.AC, PR.PT | Preventive |
| **MFA** | R001, R002, R008, R009 | CIS 6.4, 6.5 | PR.AC | Preventive |
| **Wazuh SIEM** | R001–R004, R006–R010 | CIS 8.9, 8.11, 13.1 | DE.CM, DE.AE | Detective |
| **Immutable backup** | R001, R003 | CIS 11.2–11.5 | PR.IP, RC.RP | Corrective |
| **Sophos Intercept X EDR** | R001, R002, R004, R005 | CIS 10.1, 10.5–10.7, 13.7 | PR.PT, DE.CM | Preventive / Detective |
| **Medical-device isolation** | R006, R007 | CIS 12.2, 13.3, 13.4 | PR.AC, DE.CM | Preventive / Detective / Compensating |
| **Westside firewall** | R010 | CIS 12.1, 12.2, 13.4 | PR.AC, PR.PT | Preventive |

The important strategic point is traceability:

```text
Risk
  ↓
Control
  ↓
Cost
  ↓
Framework safeguard
  ↓
Implementation evidence
  ↓
Residual risk
```

---

## 4.4 Immediate Quick Wins

The first security improvements should begin before the larger architecture projects are complete.

### Within the First 1–2 Weeks

- Require MFA for privileged and remote-access accounts that can be migrated immediately.
- Lock the second-floor network closet.
- Remove exposed switch-management credentials and rotate them.
- Restrict server-room access to personnel with a legitimate operational need.
- Identify and isolate undocumented systems pending ownership verification.
- Document the Windows XP MRI exception, business owner, compensating controls, and review date.
- Confirm central logging sources that can be onboarded to Wazuh first.
- Perform a Critical-system backup restore test and record the result.
- Freeze creation of new shared/vendor privileged accounts without named ownership.
- Begin validating the patient-portal authorization remediation and other open Critical findings.

### Why These Are Quick Wins

They require limited new infrastructure but reduce:

- stolen-credential value;
- unmanaged access;
- physical compromise risk;
- unowned legacy risk;
- recovery uncertainty; and
- the time required to detect abnormal activity.

---

# 5. Architecture Recommendations

## 5.1 Target Segmentation Design

MedDefense should move from broad internal reachability to six enforced security zones.

| VLAN | Zone | Proposed Range | Main Systems |
|---:|---|---|---|
| **10** | Clinical Workstations | `10.10.1.0/24` | Nurse/physician workstations |
| **20** | Server Zone | `10.10.2.0/24` | EHR, billing, AD, file/application servers |
| **30** | Medical Device Zone | `10.10.3.0/24` | Alaris, Philips, PACS, MRI |
| **40** | Management Zone | `10.10.4.0/24` | Admin workstations, Wazuh, security tools |
| **50** | Guest / Non-Clinical IoT | `10.10.5.0/24` | Visitor Wi-Fi, low-trust IoT |
| **60** | Backup / Recovery Zone | `10.10.6.0/24` | Veeam, NAS, backup services |

### Architectural Principle

```text
INTER-ZONE TRAFFIC = DENY BY DEFAULT
ALLOW ONLY DOCUMENTED BUSINESS / CLINICAL / SECURITY FLOWS
```

Examples:

- Clinical workstations may reach the EHR application over HTTPS.
- `ehr-srv-01` may reach `ehr-db-01` on PostgreSQL.
- General clinical endpoints may **not** directly reach PostgreSQL.
- Admin protocols originate from the Management Zone.
- Medical devices may communicate only with required clinical integration services.
- Guest/IoT has no access to production networks.
- Backup management is not reachable from ordinary workstation networks.

---

## 5.2 Kill Chain Disruption

### Kill Chain #1 — Ransomware

Original path:

```text
Phishing
  ↓
Compromised endpoint / credentials
  ↓
Persistence
  ↓
AD discovery / credential theft
  ↓
Lateral movement
  ↓
EHR data theft
  ↓
Ransomware
```

Segmentation does not stop the phishing email itself.

It breaks or constrains the chain after foothold establishment by:

- preventing unrestricted workstation-to-server access;
- restricting direct database connectivity;
- removing general access to backup administration;
- blocking medical-device management from ordinary user networks;
- separating privileged administration into the Management Zone; and
- reducing the number of systems reachable from a compromised endpoint.

### Impact on the Five Modeled Kill Chains

| Kill Chain | Segmentation Effect |
|---|---|
| **1 — Phishing → AD → EHR** | Blocks broad lateral movement and direct EHR database reachability |
| **2 — VPN → Backup → Ransomware** | Restricts VPN reach and isolates backup management |
| **3 — Vendor → EHR** | Limits trusted vendor session scope |
| **4 — Retained Insider → AD** | Separates ordinary access from privileged management paths |
| **5 — Insider → Alaris** | Restricts medical-device management to approved systems |

**Estimated result: all five top kill chains are disrupted at one or more stages.**

That does not mean segmentation prevents every attack. It means a single successful foothold is much less likely to become organization-wide compromise.

---

# 6. Policy Foundation

## 6.1 Acceptable Use Policy Summary

The Acceptable Use Policy should establish minimum behavior requirements for all employees, contractors, temporary staff, and approved third parties using MedDefense systems or networks.

### Core Requirements

Users must:

- use MedDefense systems primarily for authorized business and clinical purposes;
- protect passwords, authentication factors, and access tokens;
- never share user or administrator credentials;
- use only approved software, cloud services, and storage locations;
- follow data-classification and handling requirements;
- connect only approved devices to MedDefense networks;
- follow removable-media restrictions;
- not disable or bypass security controls, logging, EDR, MFA, or network restrictions;
- report suspected phishing, malware, credential compromise, lost devices, and policy violations promptly;
- use remote access only through approved channels;
- comply with monitoring and security-investigation requirements; and
- obtain formal approval for exceptions.

### Prohibited Examples

- installing unapproved software;
- storing patient information in personal cloud accounts;
- connecting unknown devices to internal networks;
- sharing accounts;
- using another person's credentials;
- bypassing endpoint security;
- using unauthorized remote-access tools;
- moving Restricted data to personal media; and
- deliberately circumventing segmentation or access controls.

### Enforcement

Policy exceptions should be:

```text
Documented
  + Risk assessed
  + Approved
  + Assigned an owner
  + Given an expiry/review date
  + Supported by compensating controls
```

---

## 6.2 Policy Roadmap

| Timing | Policy / Standard | Why It Is Needed |
|---|---|---|
| **Month 1** | Information Security Policy | Establish overall security authority and governance |
| **Month 1** | Acceptable Use Policy | Set user behavior and technology-use expectations |
| **Month 1–2** | Access Control / MFA / Privileged Access Policy | Govern admin, vendor and remote access |
| **Month 1–2** | Vulnerability and Patch Management Policy | Define scanning, SLAs, ownership and exceptions |
| **Month 2** | Incident Response Policy | Create formal containment, escalation and evidence process |
| **Month 2–3** | Data Classification and Handling Policy | Standardize protection of Restricted/Confidential data |
| **Month 2–3** | Backup and Recovery Policy | Define immutable backup, restore testing and recovery ownership |
| **Month 3** | Vendor / Third-Party Security Policy | Control trusted maintenance and service-provider risk |
| **Month 3–4** | Network Security / Segmentation Standard | Make zone and firewall requirements mandatory |
| **Month 3–4** | Medical Device Security Standard | Define device isolation, credentials, monitoring and exceptions |
| **Month 4–5** | Logging and Monitoring Standard | Define required sources, retention, alerting and review |
| **Month 5–6** | Cryptographic Standard | Transition into Project 1x04 |

Policies should be reviewed **at least annually** and after material incidents, major technology changes, regulatory changes, or significant audit findings.

---

# 7. Residual Risk Assessment

## 7.1 Adversarial / Red-Team Challenge Findings

Even after the Year 1 programme, several realistic attack paths remain.

### Finding 1 — Segmentation Reduces, but Does Not Eliminate, Privileged Compromise

If an attacker obtains a genuinely privileged identity, the attacker may traverse approved management paths.

**Residual requirement:** MFA, separated admin identities, vendor restrictions, alerting, and future PAM maturity remain essential.

### Finding 2 — Phishing Still Exists Before Segmentation Takes Effect

Segmentation mainly constrains post-compromise movement. Users can still be phished.

**Residual requirement:** EDR, MFA, email controls, awareness training, and rapid alert investigation remain necessary.

### Finding 3 — The Windows XP MRI Workstation Remains Permanently Vulnerable

Isolation reduces exposure but does not restore vendor support.

**Residual requirement:** treat segmentation as compensating control only. Replace the clinical platform in Year 2.

### Finding 4 — Monitoring Without 24/7 Staffing Can Still Produce Detection Delays

Wazuh creates visibility, but alerts only reduce risk when somebody owns review and escalation.

**Residual requirement:** establish documented daily/high-priority review and reconsider managed monitoring once telemetry quality is mature.

### Finding 5 — Medical Devices Remain Constrained by Vendor and Clinical Requirements

Some systems may not support modern agents, patch cycles, or authentication controls.

**Residual requirement:** use network-based monitoring, isolation, vendor-approved updates, and Clinical Engineering validation.

### Finding 6 — Recovery Controls Must Be Tested, Not Merely Purchased

An immutable backup design can fail through configuration, credential, replication, or restore problems.

**Residual requirement:** scheduled restore testing and evidence.

### Finding 7 — Vendor Trust Remains a Path to Critical Systems

MFA and segmentation reduce exposure, but a legitimate approved vendor session may still reach sensitive systems.

**Residual requirement:** named identities, time-limited access, source restriction, logging, and Year 2 privileged-access improvements.

---

## 7.2 Accepted / Temporarily Tolerated Risks

No Critical risk should be treated as permanently acceptable simply because remediation is difficult.

The strategy does, however, contain **time-bound residual-risk decisions**.

### Windows XP MRI

**Position:** Temporarily tolerate residual High risk after isolation because the clinical platform cannot be patched into supported status immediately.

**Conditions:**

- dedicated medical/MRI zone;
- no general RDP/SMB reachability;
- only validated PACS/vendor/management flows;
- monitoring;
- documented exception;
- named clinical/IT owner; and
- Year 2 replacement project.

### Westside Firewall Deferral

**Position:** The dedicated firewall remains required but is deferred because the Year 1 portfolio uses the full $120,000 budget.

**Residual state:** RISK-010 remains **12 High** until funded.

**Conditions:**

- retain Wazuh visibility where possible;
- audit VPN rules;
- minimize trusted inter-site paths;
- monitor the edge device;
- place the firewall at the top of the next available funding cycle.

### Residual High Risk on EHR / AD / Medical IoT

The planned controls reduce likelihood and blast radius, but a successful event can still have Critical impact.

**Position:** Residual High risk is tolerated only while controls are being implemented and validated, with monthly risk review and KRI monitoring.

---

## 7.3 Year 2 Priorities

1. **Replace the Windows XP MRI control environment.**
2. **Fund the Westside enterprise firewall.**
3. **Move from basic privileged access controls toward PAM / just-in-time administration.**
4. **Evaluate managed 24/7 monitoring after Wazuh telemetry and triage processes mature.**
5. **Expand endpoint/mobile-device management and admission controls.**
6. **Mature continuous vulnerability management with SLA metrics and executive escalation.**
7. **Improve vendor-access governance and session monitoring.**
8. **Perform targeted penetration testing of segmentation and recovery controls.**
9. **Progress from CIS IG1 toward the safeguards appropriate to IG2-level healthcare risk.**
10. **Reassess ISO 27001 certification if a business requirement appears.**

---

# 8. Implementation Roadmap

## Six-Month Programme

```text
MONTH 1–2
Quick wins + procurement + design
        ↓
MONTH 3–4
Core control deployment
        ↓
MONTH 5–6
Validation + optimization + residual-risk review
```

---

## Phase 1 — Months 1–2
### Quick Wins + Procurement

### Objectives

Establish governance, reduce obvious access risks, prepare the architecture, and purchase/configure the funded controls.

### Milestones

- Board approves the $120,000 programme.
- Governance/RACI model formally adopted.
- MFA rollout begins with privileged, remote, and vendor accounts.
- Wazuh architecture built and priority log-source list approved.
- Sophos Intercept X procurement/deployment plan confirmed.
- Immutable backup design and retention requirements approved.
- Segmentation discovery completed:
  - switch-port mapping;
  - asset-to-zone mapping;
  - allowed communication flows;
  - PACS/MRI dependencies;
  - medical-device dependencies.
- Medical Device Zone design validated with Clinical Engineering.
- Physical quick wins completed.
- Initial restore test performed.
- Legacy MRI exception documented.
- Policy foundation published or assigned owners.

### Dependencies

```text
Asset inventory
      ↓
Zone mapping
      ↓
Firewall rule design

Account inventory
      ↓
MFA rollout

Log-source inventory
      ↓
Wazuh onboarding
```

### Success Metrics

| Metric | Phase 1 Target |
|---|---:|
| Privileged/admin accounts inventoried | **100%** |
| Privileged/VPN accounts without MFA | **0% where technically supported** |
| Critical assets assigned to proposed VLAN/security zones | **100%** |
| Priority Wazuh log sources identified | **100%** |
| Critical backup restore test completed | **≥1 documented test** |
| Unknown/unowned production devices | **0 unresolved at phase exit** |
| Core security policies with named owner | **100%** |

---

## Phase 2 — Months 3–4
### Core Controls Deployment

### Objectives

Deploy the funded technical controls and begin enforcing new trust boundaries.

### Milestones

- VLANs/security zones created.
- Inter-zone routing moved through firewall/policy enforcement.
- Clinical-to-EHR access restricted to approved application flows.
- Direct workstation-to-EHR-database access removed.
- Management Zone established.
- Backup / Recovery Zone established.
- Medical Device Zone isolation implemented.
- MRI access restricted to required clinical/vendor flows.
- Wazuh receives:
  - Active Directory logs;
  - EHR/server logs;
  - firewall/segmentation logs;
  - EDR alerts;
  - backup logs;
  - available medical-device/network telemetry.
- Sophos Intercept X deployed to supported endpoints and servers.
- Offsite immutable backup replication operational.
- Initial alert rules established for:
  - privileged authentication;
  - suspicious lateral movement;
  - backup changes;
  - EDR detections;
  - high-risk EHR activity.

### Success Metrics

| Metric | Phase 2 Target |
|---|---:|
| Critical zones behind enforced inter-zone policy | **100%** |
| Unapproved direct workstation → PostgreSQL access | **0** |
| Unapproved workstation → backup-management access | **0** |
| Managed supported endpoints with target EDR | **≥95%, with remaining exceptions documented** |
| Critical AD/EHR/backup/security log sources in Wazuh | **100% of defined priority sources** |
| Medical-device management reachable from general workstation zone | **0 approved exceptions unless documented** |
| Immutable offsite backup jobs succeeding | **≥98% over review period** |

---

## Phase 3 — Months 5–6
### Validation + Optimization

### Objectives

Prove that controls operate as intended, close temporary exceptions, and move security processes from "implemented" to "managed."

### Milestones

- Segmentation rule review and cleanup.
- Controlled validation of kill-chain break points.
- Restore test from immutable/offsite backup.
- Wazuh alert tuning and documented triage process.
- Incident-response playbooks completed for:
  - ransomware;
  - compromised privileged account;
  - vendor compromise;
  - medical-device security event;
  - EHR misuse.
- At least one tabletop exercise conducted.
- Risk Register re-scored using implemented evidence.
- KRI thresholds reviewed.
- Policy acknowledgments/training completed.
- Year 2 investment request prepared.
- NIST CSF Current Profile reassessed against Managed target.

### Success Metrics

| Metric | Phase 3 Target |
|---|---:|
| High-priority Wazuh alerts with named owner/SLA | **100%** |
| Critical restore test success | **100% of scheduled tests** |
| Segmentation exceptions without owner/expiry | **0** |
| Critical/High vulnerabilities beyond SLA | **0 unapproved overdue findings** |
| Tabletop exercises completed | **≥1** |
| Top-10 risks with updated residual score and owner | **100%** |
| NIST CSF functions at documented/repeatable process level | **6/6 progressing toward Managed** |
| Security-policy acknowledgement / required training | **Target ≥98%** |

---

# 9. Next Steps

## 9.1 Connection to Project 1x04 — Cryptographic Foundation

Project 1x03 establishes **where trust boundaries should exist, who may cross them, how risk is governed, and how events are monitored**.

Project 1x04 should build the cryptographic layer that protects information and identity across those boundaries.

The transition should focus on:

- inventorying encryption and protocol use;
- identifying TLS 1.0, weak cipher, SMBv1, cleartext HL7, and other legacy protocol exposure;
- defining an approved TLS baseline;
- certificate lifecycle management;
- encryption of Restricted data at rest and in transit;
- key and secrets management;
- secure service-to-service authentication;
- backup encryption;
- cryptographic requirements for vendor access;
- medical-device cryptographic limitations and compensating controls; and
- migration planning for legacy systems that cannot meet the target cryptographic baseline.

The segmentation architecture from Task 14 provides the ideal foundation because cryptographic controls can be applied according to zone, data sensitivity, and trust boundary.

---

## 9.2 Path from Strategy to Implementation

The MedDefense security programme now has a complete chain from evidence to execution:

```text
1x00 — Security Posture Assessment
What do we have and where are the gaps?
        ↓
1x01 — Threat Landscape
Who would attack us and how?
        ↓
1x02 — Vulnerability Assessment
Which weaknesses are technically exploitable and how urgent are they?
        ↓
1x03 — Defense Blueprint
Which controls should we fund, how should we govern them, and how should the architecture change?
        ↓
1x04 — Cryptographic Foundation
How should trust, encryption, keys, certificates and secure protocols protect the redesigned environment?
        ↓
Implementation + validation + continuous improvement
```

---

# Board Decision Requested

The Board is asked to approve:

1. **The $120,000 Year 1 security programme.**
2. **NIST CSF 2.0 as the strategic governance framework**, supported by CIS Controls v8.
3. **The six-month implementation roadmap.**
4. **The governance model**, including clear risk ownership and use of vCISO support.
5. **Time-bound residual-risk treatment** for the Windows XP MRI environment.
6. **Deferral of the Westside firewall to the next funding cycle unless funds become available earlier.**
7. **Progression into Project 1x04** to establish the cryptographic foundation for the segmented target architecture.

---

# Conclusion

MedDefense's security problem is not a lack of individual products. It is the way multiple weaknesses currently connect.

A phished endpoint can become an identity problem.  
An identity problem can become a lateral-movement problem.  
A lateral-movement problem can become an EHR, medical-device, or backup problem.  
Weak monitoring allows the chain to continue.  
Weak recovery makes the final impact worse.

The strategy therefore invests in controls that break **multiple links in the same attack chains**.

The first-year programme:

- constrains lateral movement through segmentation;
- reduces credential abuse through MFA;
- creates centralized detection through Wazuh;
- preserves recovery through immutable backup;
- improves endpoint prevention and detection through EDR; and
- protects patient-safety-critical medical devices through dedicated isolation and monitoring.

This does not remove all cyber risk. It changes MedDefense from an environment where one compromise can spread broadly into one where trust is limited, activity is visible, recovery is protected, and major risks have clear owners.

That is the foundation required to move from security assessment to a sustainable security programme.

---

# Internal Traceability

This strategy synthesizes the Project 1x03 workstreams covering:

- T0 — Framework Landscape
- T1 — NIST CSF Current/Target Profile
- T2 — CIS Controls maturity assessment
- T4 — Governance Architecture
- T6 — ALE Workshop
- T7 — Cost-Benefit Analysis
- T8 — Budget Allocation
- T10 — Risk Register
- T11 — Control Selection
- T12 — Policy Foundation / Acceptable Use
- T13 — Immediate Quick Wins
- T14 — Segmentation Architecture
- T15 — Adversarial / Red-Team challenge
- T16 — Risk Appetite and residual-risk decisions

It also carries forward evidence from Projects 1x00, 1x01 and 1x02 where required for traceability.
