# MedDefense Health Systems
# Threat Landscape Report

**Assessment Date:** 4 September 2026  
**Prepared for:** MedDefense Health Systems Board and Executive Leadership  
**Assessment Scope:** MedDefense Central, Westside Clinic and Corporate HQ  
**Companion Document:** Project `1x00_first_watch` — Security Posture Assessment

---

# 1. Executive Summary

MedDefense operates in a healthcare threat environment where financially motivated ransomware, misuse of legitimate access and opportunistic exploitation are more relevant than highly targeted espionage. The organisation is not unusually attractive because of its brand; it is attractive because it is a **350-bed regional hospital with valuable patient data, Critical clinical services, legacy technology and several internal weaknesses that allow one foothold to become a wider incident**.

The **single most dangerous threat is ransomware double extortion against the EHR environment**. Healthcare is the most-targeted critical-infrastructure sector for ransomware in the supplied intelligence, and the same evidence reports that data theft precedes encryption in a large majority of healthcare ransomware incidents. MedDefense's own architecture makes this threat unusually credible: phishing or stolen credentials can lead into a flat Central network, Active Directory can become an access multiplier, `ehr-db-01` is reachable from the wider internal network and backup infrastructure remains locally concentrated.

The Board should prioritise three actions:

1. **Create central security monitoring and alerting.** MedDefense already produces firewall, Windows, Linux, SSH, EHR and Active Directory logs; the immediate need is to bring them together so suspicious activity is detected while an attack is still developing.
2. **Segment Critical systems from general user access.** Separate user endpoints, EHR/database systems, Active Directory, backup infrastructure and medical IoT with enforced network controls so one compromised device cannot freely reach multiple clinical systems.
3. **Strengthen identity and privileged access.** Expand MFA, separate administrative identities, implement privileged-access controls and convert vendor maintenance to named, least-privilege, time-limited access.

The central conclusion is straightforward: **MedDefense's largest threat is not one attacker or one vulnerability; it is the ability of different attackers to reuse the same internal weaknesses.** Closing the gaps that repeatedly appear across ransomware, insider and vendor scenarios will reduce more risk than treating threats one by one.

---

# 2. Scope and Methodology

## 2.1 Scope

This Threat Landscape Report evaluates the threat environment relevant to:

- **MedDefense Central** — 350-bed acute-care hospital and primary clinical/IT site
- **Westside Clinic** — outpatient clinical site connected to Central
- **Corporate HQ** — administrative site connected to Central

The analysis focuses on adversaries, vectors, attack surfaces, attack sequences and business consequences affecting MedDefense's Critical assets, especially:

- EHR and patient-record systems
- PACS and medical imaging
- Pharmacy and medication systems
- Medical IoT and infusion pumps
- Active Directory
- Network core and site connectivity
- Backup and recovery infrastructure
- Clinical endpoints
- Internet-facing patient and public services
- Trusted third-party pathways

## 2.2 Intelligence Sources Used

The threat analysis uses the six-source intelligence dossier supplied for Project `1x01_know_your_enemy`:

1. **CISA Healthcare Advisory Extract** — ransomware prevalence, initial-access patterns, double extortion, downtime and recovery cost
2. **HC3 healthcare threat briefing** — actor types, motivations, sophistication and healthcare victim profiles
3. **HHS breach statistics** — healthcare breach volume, breach type and affected information locations
4. **Regional Hospital ransomware case** — VPN exploitation, lateral movement, Domain Controller compromise, exfiltration, backup impact and ransomware deployment
5. **Healthcare ransomware economics briefing** — ransom/payment behaviour, recovery cost, patient-data value and RaaS operating model
6. **Marcus Webb's unfinished threat analysis** — preliminary MedDefense-specific actor prioritisation and local observations

The project also uses the supplied BlackReef RaaS profile, anonymised threat-actor reports and the two ATT&CK attack narratives.

## 2.3 Internal Evidence from Project 1x00

This report is the external-threat companion to the Security Posture Assessment. The principal 1x00 inputs are:

- `7-asset_registry.md`
- `8-criticality_assessment.md`
- `9-data_map.md`
- `10-complete_control_matrix.md`
- `12-gap_analysis.md`
- `13-reality_check.md`
- `15-predecessor_review.md`
- `16-security_posture_assessment.md`

Project 1x00 established **where MedDefense is weak**. Project 1x01 establishes **who can exploit those weaknesses, how the exploitation would unfold and which gaps now deserve the greatest urgency**.

## 2.4 Analytical Frameworks

The following frameworks were applied:

- **Threat-actor profiling** — actor type, resources, sophistication, motivation and likelihood
- **Attack-surface analysis** — external, internal and human attack surfaces
- **Vector-to-asset mapping** — which attack methods can reach which Critical systems
- **Kill-chain analysis** — initial access through objective and business impact, with defensive break points
- **STRIDE** — systematic EHR threat identification across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service and Elevation of Privilege
- **MITRE ATT&CK Enterprise** — mapping attack behaviours to shared industry tactics and techniques
- **Threat-informed gap correlation** — recalibrating 1x00 gap priorities using Project 1x01 attack paths and scenarios

## 2.5 Analytical Limitations

This is an intelligence and architecture assessment, not a penetration test. Important limitations are preserved rather than inferred away:

- The FortiGate is an important exposed technology, but current evidence does **not** prove it is presently vulnerable or unpatched.
- `billing-srv-01` has a credible Apache/web-layer compromise pattern, but its original entry route and direct Internet exposure are not proven.
- MedTech has confirmed direct maintenance access to `ehr-srv-01`; direct authorised access to `ehr-db-01` is **not** documented.
- Entra ID use is unverified; Microsoft 365 is confirmed, but cloud identity authority is not assumed.
- Medical-device credential hardening is unverified; the report does not claim that every Alaris pump or monitor currently uses a vendor-default password.
- `web-srv-01` is documented inconsistently as both DMZ and Central server subnet; actual enforcement requires validation.
- Physician-iPad MDM status is unclear.
- The next phase, Project `1x02`, should technically validate the vulnerabilities and exposure assumptions that this threat analysis has prioritised.

---

# 3. Healthcare Sector Threat Overview

## 3.1 Why Healthcare Is Targeted

### Clinical urgency creates extortion leverage

Hospitals cannot tolerate prolonged loss of EHR, imaging, medication or monitoring services. This makes Availability uniquely valuable to attackers. The supplied intelligence reports an **average hospital downtime of 18 days after ransomware** and a healthcare ransom-payment rate of **60% versus 46% across industries**.

### Patient information has durable criminal value

Healthcare records combine identity, insurance and medical information. The dossier cites approximately **$250-$1,000 per patient record**, compared with **$5-$50 for payment-card information**. Unlike a payment card, medical identity data cannot simply be cancelled and reissued.

### Legacy and difficult-to-patch systems remain in service

Medical devices and operational technology can remain in use because replacement depends on vendor support, clinical availability, certification and budget. MedDefense contains the same pattern: Windows XP on the MRI control workstation, Windows Server 2012 R2 on `print-srv-01`, Ubuntu 18.04 on `billing-srv-01`, aging medical-device firmware and known Alaris vulnerabilities.

### Mid-size hospitals provide an attractive economic balance

The healthcare intelligence identifies hospitals in approximately the **100-500-bed range** as attractive ransomware victims: large enough to hold valuable data and support meaningful extortion demands, but often without the security resources of national systems. MedDefense's 350-bed Central Hospital fits this profile closely.

## 3.2 Sector Statistics Relevant to MedDefense

| Sector Indicator | Intelligence Evidence | Relevance to MedDefense |
|---|---:|---|
| Ransomware share of reported critical-infrastructure incidents | **25%** in the cited 2023-2024 healthcare data | Confirms ransomware as the primary external threat |
| Healthcare ransomware incidents with data exfiltration before encryption | **73%** | Backups alone do not remove confidentiality/extortion risk |
| Initial access via public-facing applications | **38%** | Patient portal, web services and remote-access infrastructure require continuous vulnerability management |
| Initial access via phishing | **31%** | Staff and privileged IT personnel remain high-value entry points |
| Initial access via valid credentials | **22%** | MFA, PAM and offboarding have direct threat relevance |
| External remote services | **9%** | VPN and remote-access paths remain material |
| Average hospital ransomware downtime | **18 days** | EHR and clinical continuity risk is business-critical |
| Average recovery cost | **$2.7 million** | Material financial exposure even apart from ransom |
| Average ransom demand | **$1.2m in 2022 → $2.5m in 2024** | Criminal incentive is increasing |
| Healthcare ransom-payment rate | **60% vs 46% cross-industry** | Reinforces continued targeting incentive |
| HHS breach records in cited 24-month period | **1,247 breaches affecting 168m+ individuals** | Healthcare data exposure is high-volume and persistent |

## 3.3 Current Trends and Emerging Threats

### Double extortion is now the normal ransomware problem

Encryption is only one pressure mechanism. Attackers increasingly steal patient and business information first, then threaten publication even if the victim restores systems. For MedDefense, this makes database monitoring, DLP and egress detection as important as backup resilience.

### Ransomware has become industrialised

RaaS separates developers, affiliates, Initial Access Brokers and negotiators. Initial access can be bought for hundreds or thousands of dollars, meaning attackers no longer need to discover and exploit every victim themselves. MedDefense can therefore be targeted because a foothold is **available**, not because an elite attacker has chosen the organisation personally.

### Automation is lowering the skill floor

Automated scanning, commodity exploits, credential stuffing and AI-assisted social engineering increase the ability of lower-sophistication actors to identify weak services at scale. MedDefense's recurring `billing-srv-01` crypto-miner makes this more than a theoretical concern.

### Ideological disruption remains a secondary but growing concern

Hacktivism remains a lower-priority MedDefense threat today because the organisation has no documented political or controversial profile, but public healthcare services can become collateral targets during geopolitical or ideological campaigns.

---

# 4. MedDefense Threat Actor Profiles

## 4.1 Six-Actor Priority Matrix

| Priority | Actor Type | Likelihood | Capability | Primary Motivation | Most Likely MedDefense Path |
|---:|---|---|---|---|---|
| **1** | **Ransomware Groups / Organized Crime** | **Critical / Very High** | Medium-High | Financial gain / blackmail | Phishing, valid credentials, public-facing exploitation, trusted third parties |
| **2** | **Insider — Negligent** | **High** | Low technical skill; High opportunity | No malicious motive; convenience/error | Unsafe credential use, Shadow IT, unmanaged devices, data copying |
| **3** | **Unskilled / Opportunistic Attacker** | **High exposure** | Low | Financial gain, resource abuse, experimentation | Automated scanning, known exploits, credential stuffing |
| **4** | **Insider — Malicious** | **Medium** | Low-Medium technically; potentially High effective access | Financial gain, curiosity, grievance, sabotage | Legitimate access abuse, retained accounts, privileged misuse |
| **5** | **Nation-State APT** | **Low under current profile** | Very High | Espionage / strategic intelligence | Spear phishing, zero-days, supply-chain compromise |
| **6** | **Hacktivist** | **Low** | Low-Medium | Political / philosophical beliefs, publicity, disruption | DDoS, website/portal exploitation, defacement |

## 4.2 Priority Actor 1 — Ransomware Groups / Organized Crime

**Why MedDefense fits:** MedDefense closely matches the mid-size hospital victim profile and holds Restricted patient data with high extortion value. The intelligence identifies healthcare as heavily targeted and shows that attackers increasingly steal data before encryption.

**Operational model:** RaaS allows developers to provide ransomware and infrastructure while affiliates conduct intrusion and extortion. Initial Access Brokers can sell compromised VPN, remote-service or web access. This lowers the skill required for a coordinated multi-stage attack.

**Preferred MedDefense targets:** EHR, Active Directory and backup/recovery. EHR provides patient data and clinical leverage; AD provides broad control; backups determine recovery.

**Most relevant gaps:** GAP-001, GAP-007, GAP-008, GAP-011, GAP-013 and GAP-016.

**Priority judgement:** **Highest overall threat** because both likelihood and potential business impact are Critical.

## 4.3 Priority Actor 2 — Negligent Insider

**Why MedDefense fits:** The organisation already has real examples of unsafe trusted-user behaviour: shared PACS credentials, an unattended EHR session, an unmanaged personal laptop and a personal NAS containing patient-file copies.

**Operational model:** No adversary tooling is required. Ordinary access and workflow convenience can create disclosure directly or place an uncontrolled device inside the environment.

**Preferred MedDefense targets/exposure:** EHR data, clinical endpoints, shared storage and internal network access.

**Most relevant gaps:** GAP-012, GAP-013, GAP-007 and GAP-011; GAP-001 increases consequences after an unmanaged endpoint is compromised.

**Priority judgement:** **Second overall** because exposure is continuous and highly likely, even though malicious intent is absent.

## 4.4 Priority Actor 3 — Unskilled / Opportunistic Attacker

**Why MedDefense fits:** Opportunistic attackers do not need to know MedDefense exists in advance. They search for exposed services and old vulnerabilities. The environment contains legacy systems and a prior crypto-miner pattern consistent with commodity exploitation.

**Operational model:** Automated scanning, public exploits, weak credentials and cryptomining or other commodity malware.

**Preferred MedDefense targets:** Initially the easiest exposed or outdated system; later EHR, AD or medical IoT if the foothold reaches the flat network.

**Most relevant gaps:** GAP-016, GAP-001, GAP-011 and GAP-013.

**Priority judgement:** **Third overall** because deliberate targeting may be Medium, but exposure to indiscriminate exploitation is High.

## 4.5 Other Actors

**Malicious insiders** remain a High-impact threat because legitimate access can bypass perimeter defences and because offboarding, privileged-access governance and behavioural monitoring are incomplete.

**Nation-state APTs** have the highest technical capability but Low direct likelihood because MedDefense has no research programme. Supply-chain compromise is the most realistic way MedDefense could become a downstream APT victim.

**Hacktivists** remain Low priority under the current profile, but the patient portal and public website provide plausible disruption targets if MedDefense becomes associated with a political or geopolitical issue.

---

# 5. Attack Surface Analysis

## 5.1 External Surface

MedDefense's principal external surfaces are:

- **Patient portal / `web-srv-01` (A-037/A-011):** Internet-facing, handles Restricted health information and has a previous broken-authorization incident. `web-srv-01` security-zone placement remains unresolved.
- **Public website (A-053):** previously defaced; lower data sensitivity but reputational and foothold risk.
- **FortiGate 100F / Central edge (A-016):** critical Internet-edge and VPN technology; current vulnerability state is unknown, making systematic patch governance essential.
- **Westside Netgear edge (A-015):** consumer router with no dedicated enterprise firewall.
- **Microsoft 365 (A-039):** organisation-wide email/collaboration surface and a major social-engineering channel.
- **Public DNS:** provider, DNSSEC state and administrative model are not documented.
- **Third-party maintenance/software channels:** MedTech EHR maintenance, Sophos endpoint-management/update path and Siemens service activity.

**Key external gaps:** GAP-010, GAP-014, GAP-016, GAP-007, GAP-011 and GAP-017.

## 5.2 Internal Surface

The **internal surface represents the greatest technical risk** because Central is effectively flat. The `/24` address ranges are not enforced security boundaries.

Key evidence includes:

| Internal Exposure | Evidence | Threat Significance |
|---|---|---|
| `ehr-db-01` | PostgreSQL **5432** reachable from wider internal network | Direct route toward Restricted patient data; supports disclosure and tampering |
| `billing-srv-01` | MySQL **3306**, Ubuntu 18.04, prior ransomware and crypto-miner | Lower-value foothold can become a pivot |
| `pacs-srv-01` | SMB + DICOM **4242/11112**, shared `raduser` | Imaging data exposure and weak accountability |
| `NAS-01` | Management **5000/5001** network-wide | Recovery system reachable by ransomware |
| Active Directory | DNS, Kerberos, LDAP, SMB, LDAPS | Shared identity trust; privilege escalation multiplier |
| `WS-RAD-01` | Windows XP SP3 | Unsupported clinical foothold |
| Alaris / patient monitors | Known vulnerabilities, reachable management interfaces | Direct patient-safety consequence |
| `MON-VITALS-3F-01` | HTTP **80**, firmware last updated 2019 | Aging medical-device management surface |
| `UNKNOWN-01` | SSH + **8888/9090** | Unmanaged production foothold |
| Westside unknown Linux | SSH, HTTP, **3000** | Unmanaged host at weakly protected site |
| `ws-srv-01` | SMB + RDP | Remote administration/lateral movement at Westside |

**Key internal gaps:** GAP-001 is the primary multiplier; GAP-002, GAP-003, GAP-006, GAP-007, GAP-008, GAP-011, GAP-012, GAP-016 and GAP-018 deepen specific paths.

## 5.3 Human Surface

The principal human targets are:

- **Clinical staff:** EHR and clinical access; vulnerable to urgency, helpfulness and workload pressure
- **Reception/front desk:** patient data plus frequent interaction with unfamiliar people
- **IT/help desk/admins:** highly valuable privileged access; attractive for vendor-themed phishing and support pretexts
- **Executives:** BEC, authority and payment-approval exposure
- **Administrative staff:** O365, HR, Finance, Legal and Marketing data
- **External vendors/contractors:** trusted access partly outside MedDefense's direct control
- **Former staff/contractors:** residual-access risk where offboarding is delayed

The human surface is especially important because many attacks begin with **legitimate-looking access**. The strongest defensive requirements are MFA/PAM, endpoint coverage, active behavioural monitoring and reliable joiner-mover-leaver controls.

---

# 6. Critical Attack Paths

## 6.1 Kill Chain 1 — Phishing → Active Directory → EHR Double Extortion

**Sequence:** Spear phishing → compromised endpoint/credentials → persistence → AD discovery/credential theft → lateral movement → EHR data theft → ransomware.

**Primary assets:** A-001, A-002, A-005/A-006, A-036.

**Gaps:** GAP-007, GAP-013, GAP-011, GAP-001, GAP-002; GAP-008 can increase final impact.

**Break points:**
- Phishing-resistant MFA and complete endpoint coverage at Initial Access
- Centralised endpoint/identity monitoring at Persistence and Credential Access
- Segmentation and PostgreSQL restrictions at Lateral Movement
- Isolated recovery copies before Impact

## 6.2 Kill Chain 2 — VPN Exploit → Backup Neutralisation → Ransomware

**Sequence:** Exposed VPN vulnerability → internal foothold → network discovery → privileged access → backup/NAS attack → ransomware.

**Primary assets:** A-009, A-010, A-041 plus production systems.

**Gaps:** GAP-016, GAP-011, GAP-001, GAP-007, GAP-008.

**Break points:**
- Vulnerability scanning, patch ownership and emergency remediation on exposed systems
- VPN/authentication alerting
- Segmented backup management
- Protected/offsite recovery copies with regular restore testing

## 6.3 Kill Chain 3 — Compromised MedTech → EHR

**Sequence:** Vendor compromise → trusted maintenance session → persistence disguised as maintenance → internal discovery → movement toward EHR database/AD → data theft or ransomware.

**Primary assets:** A-001, A-002, A-036.

**Gaps:** GAP-007, GAP-011, GAP-001, GAP-002.

**Break points:**
- Named vendor accounts, MFA, source restrictions and just-in-time access
- Privileged-session monitoring
- Least-privilege network policy around the EHR
- Database restrictions and audit correlation

## 6.4 Kill Chain 4 — Retained Insider Access → Active Directory

**Sequence:** Account remains active after departure → off-hours VPN use → discovery/credential reuse → privileged AD changes → wider access or disruption.

**Primary assets:** A-005/A-006.

**Gaps:** GAP-017, GAP-011, GAP-007, GAP-001.

**Break points:**
- HR-linked automatic account disablement
- Post-termination authentication alerts
- PAM and separate administrative identities
- Central alerts on privileged-group/account changes

## 6.5 Kill Chain 5 — Insider → Alaris Pump Environment

**Sequence:** Legitimate internal access abused → device discovery → management access attempt → unauthorised configuration/disruption.

**Primary asset:** A-032.

**Gaps:** GAP-018, GAP-003, GAP-001, GAP-011.

**Break points:**
- Named role-based device-management access
- Verified removal of vendor-default credentials where supported
- Dedicated medical-IoT security zones
- Device-management traffic monitoring

## 6.6 Three Most Connected Assets

1. **Medical IoT — 8 assessed vectors.** Every vector category can plausibly reach or affect this estate; patient-safety impact makes this more than an IT concern.
2. **EHR System — 7 vectors.** It combines Restricted data, Critical Integrity and Critical Availability.
3. **Active Directory — 7 vectors.** It is an access multiplier: compromise can expand privileges across many systems.

BD Alaris, Network Core and Backup/Recovery also each have seven viable vector paths, but EHR and AD rank higher as shared system-wide dependencies.

## 6.7 Three Most Versatile Vectors

1. **Phishing / Spear Phishing — 7 asset groups**
2. **Malicious Insider — 7 asset groups**
3. **Negligent Insider — 7 asset groups**

VPN exploitation, vulnerable-software exploitation and physical access each reach six of the seven assessed asset groups.

---

# 7. STRIDE Analysis Summary

## 7.1 EHR Deep Analysis

The EHR STRIDE analysis identified **12 concrete threats, two per category**.

| STRIDE Category | Key EHR Threats | Main Evidence / Gaps |
|---|---|---|
| **Spoofing** | Stolen clinician identity; use of unattended authenticated session | GAP-007, GAP-011; unattended nurse-station evidence |
| **Tampering** | Direct patient-record modification via `ehr-db-01`; malicious EHR application modification | GAP-002, GAP-001, GAP-007, GAP-011 |
| **Repudiation** | Actions attributed to a hijacked session; compromised identity obscures real actor | C-028 exists, but GAP-011 limits active correlation |
| **Information Disclosure** | Direct database extraction; patient data copied to USB/unmanaged storage | GAP-002, GAP-001, GAP-011, GAP-013, GAP-020 |
| **Denial of Service** | EHR ransomware; internal resource exhaustion | GAP-001, GAP-008, GAP-011, GAP-015 |
| **Elevation of Privilege** | User account escalates through AD; trusted maintenance access expands beyond scope | GAP-007, GAP-001, GAP-002, GAP-011 |

### Greatest STRIDE Risk: Tampering

**Tampering is the most dangerous EHR category for MedDefense.** An obvious outage forces staff into fallback procedures; corrupted clinical information can remain available and appear trustworthy. Altered allergies, medications, diagnoses or laboratory values could therefore influence treatment before staff realise the system's integrity has been lost.

This risk is amplified by three facts:

- `ehr-db-01` is reachable from the wider internal network on PostgreSQL 5432.
- Central lacks enforced internal segmentation.
- Database, server and EHR audit evidence is not continuously correlated.

## 7.2 PACS / Medical Imaging — Top Threats

PACS and Medical Imaging are Critical because Confidentiality and Integrity are Critical and Availability is High.

**Top threats:**

1. **Spoofing / Repudiation — shared `raduser` account:** multiple Radiology users share one identity, reducing attribution and allowing misuse to appear legitimate.
2. **Information Disclosure — broad internal service reachability:** SMB and DICOM ports 4242/11112 expose imaging services to compromised internal hosts.
3. **Tampering — image or metadata alteration:** unauthorized modification could cause clinicians to rely on incorrect diagnostic information.
4. **Denial of Service — legacy MRI control environment:** unsupported Windows XP on `WS-RAD-01` creates a difficult-to-patch availability risk.

**Primary gaps:** GAP-001, GAP-006, GAP-007, GAP-011.

## 7.3 Active Directory — Top Threats

Active Directory is a Critical identity dependency because both Integrity and Availability are Critical.

**Top threats:**

1. **Elevation of Privilege:** stolen credentials or hashes can turn a user foothold into domain-level control.
2. **Tampering:** attackers or malicious insiders can alter accounts, privileged groups, authentication policy or Group Policy.
3. **Spoofing:** valid/stolen accounts can make malicious access appear legitimate.
4. **Denial of Service:** disabling accounts or damaging directory services can prevent staff from authenticating to clinical/business resources.

**Existing strengths:** password enforcement, lockout, AD logging and a secondary Domain Controller.

**Primary gaps:** GAP-007, GAP-011, GAP-001 and GAP-017.

## 7.4 Network Surface — Top Threats

Network Core and Site Connectivity are Critical shared dependencies.

**Top threats:**

1. **Tampering:** exposed switch-management credentials or privileged network access could alter routing, VLANs, ACLs or connectivity.
2. **Information Disclosure / interception:** weak physical/network boundaries can create opportunities to observe or redirect traffic.
3. **Denial of Service:** disruption of the core, Westside edge or site VPN can simultaneously affect multiple clinical services.
4. **Elevation of attack reach:** the flat Central network converts an endpoint compromise into access toward servers, AD and medical IoT.

**Primary gaps:** GAP-001, GAP-005, GAP-014, GAP-016 and GAP-011.

---

# 8. Threat Scenarios

## 8.1 Scenario 1 — BlackReef Hospital-Wide Ransomware

**Actor:** Organized Crime / BlackReef-style RaaS  
**Primary vector:** Spear phishing  
**Main sequence:** Phished IT user → persistent endpoint access → AD discovery/credential theft → EHR/database access → exfiltration → backup attack → ransomware  
**Primary assets:** EHR, AD, backups and endpoint estate  
**Business impact:** Clinical outage, patient-data breach, recovery costs, revenue loss, regulatory exposure and reputational damage  
**Key gaps:** GAP-013, GAP-011, GAP-007, GAP-001, GAP-002, GAP-008, GAP-015

**Board judgement:** **Highest-consequence and highest-likelihood integrated scenario.**

## 8.2 Scenario 2 — Malicious Insider Patient-Privacy Breach

**Actor:** Malicious Insider / registration employee  
**Primary vector:** Legitimate EHR access abused  
**Main sequence:** Normal login → high-profile patient search → sensitive information collected → disclosure to friend → public posting  
**Primary assets:** EHR application and patient records  
**Business impact:** Privacy breach, investigation/legal cost, regulatory exposure and immediate reputational harm  
**Key gap:** GAP-011 — EHR access is logged but not continuously monitored for inappropriate use

**Board judgement:** **Lower technical complexity but highly realistic because perimeter controls are irrelevant once legitimate access is abused.**

## 8.3 Scenario 3 — MedTech Supply-Chain Espionage

**Actor:** Nation-State APT using MedTech as a downstream stepping stone  
**Primary vector:** Vendor maintenance pathway  
**Main sequence:** Vendor compromise → trusted MedTech session → persistence disguised as maintenance → EHR/internal discovery → movement beyond intended scope → collection → exfiltration  
**Primary assets:** EHR application/server/database, potentially AD  
**Business impact:** Patient-data exposure, loss of confidence in EHR integrity, forensic/legal cost and third-party governance failure  
**Key gaps:** GAP-011, GAP-001, GAP-002, GAP-007

**Board judgement:** **Lower likelihood than ransomware, but Critical impact because trusted vendor access can bypass ordinary perimeter assumptions.**

Full scenario sequences and detection opportunities are provided in **Appendix A**.

---

# 9. Gap-Threat Correlation

## 9.1 How Threat Intelligence Changed the 1x00 Priorities

Project 1x00 initially ranked gaps based on asset criticality, data sensitivity and control coverage. Project 1x01 shows that some gaps occur repeatedly across otherwise different attacks.

The threat-informed model uses **GAP-001 through GAP-018**, reflecting Task 12 plus the Project 1x00 Task 13 reassessment. Later predecessor-review gaps (GAP-019 through GAP-022) remain valid supporting findings but are outside the formal counting baseline used for the correlation.

Two gaps moved further upward after threat analysis:

- **GAP-007 — MFA/PAM weakness:** High → **Critical**
- **GAP-002 — EHR database exposure:** Medium → **High**

## 9.2 Threat-Informed Top Gap Ranking

| Rank | Gap | Updated Risk | Kill Chains | Scenarios | Path Appearances |
|---:|---|---|---:|---:|---:|
| **1** | **GAP-011 — Fragmented/non-continuous monitoring** | Critical | **5** | **3** | **8** |
| **2** | **GAP-001 — No effective internal segmentation** | Critical | **5** | **2** | **7** |
| **3** | **GAP-007 — MFA/PAM weakness** | **Critical — upgraded** | **4** | **2** | **6** |
| **4** | GAP-008 — Backup concentration | Critical | 2* | 1 | 3* |
| **5** | GAP-003 — Medical IoT isolation/monitoring | Critical | 1 | 0 | 1 |
| **6** | GAP-015 — No formal IR/BCP/DR | Critical | 0 | 1 | 1 |
| **7** | GAP-016 — Vulnerability/patch management | Critical | 1 | 0 | 1 |
| **8** | GAP-017 — Identity lifecycle/offboarding | Critical | 1 | 0 | 1 |
| **9** | GAP-018 — Medical-device credential hardening | Critical | 1 | 0 | 1 |
| **10** | GAP-010 — Patient portal authorization | Critical | 0 | 0 | 0 |
| **11** | GAP-014 — Westside weak perimeter | Critical | 0 | 0 | 0 |
| **12** | GAP-006 — Unsupported MRI | Critical | 0 | 0 | 0 |
| **13** | GAP-004 — Weak server-room access | Critical | 0 | 0 | 0 |
| **14** | GAP-005 — Network closet / exposed credentials | Critical | 0 | 0 | 0 |
| **15** | **GAP-002 — EHR DB network exposure** | **High — upgraded** | **2** | **2** | **4** |
| **16** | GAP-013 — Incomplete endpoint/device management | High | 1 | 1 | 2 |
| **17** | GAP-012 — Shadow IT | High | 0 | 0 | 0 |
| **18** | GAP-009 — Pharmacy validation/recovery | Medium | 0 | 0 | 0 |

\* GAP-008 is a definite dependency in Kill Chain 2 and a conditional/potential dependency in Kill Chain 1.

Zero appearances do **not** mean a Critical gap is safe. They mean it was not required by the eight selected high-priority paths.

## 9.3 The Critical Three

### 1. GAP-011 — Fragmented / Non-Continuous Monitoring

Appears in **all five kill chains and all three scenarios**. It is the most actor-agnostic weakness: ransomware, insiders, vendors and opportunistic attackers all benefit when useful logs are not actively correlated.

### 2. GAP-001 — No Effective Internal Segmentation

Appears in **all five kill chains and two scenarios**. It is MedDefense's primary blast-radius multiplier: the initial foothold may differ, but weak east-west controls allow the compromise to reach other Critical assets.

### 3. GAP-007 — Broad MFA / PAM Weakness

Appears in **four kill chains and two scenarios**. It increases the value of stolen, retained and vendor credentials and enables both Initial Access and Privilege Escalation.

## 9.4 The Surprise

**GAP-002 — EHR database network exposure** moved from **Medium to High**. The original rating recognised existing logging and backup controls; the threat analysis shows that `ehr-db-01` is an actual convergence point in both the primary ransomware chain and the vendor-compromise chain. The same exposure supports EHR Information Disclosure and Tampering, making it more urgent than the inward-looking control assessment alone suggested.

A second major change is **GAP-007**, which moved from Medium in the original Task 12 analysis, to High after the Project 1x00 reality check, and to **Critical** after it appeared in six of eight Project 1x01 attack paths.

---

# 10. Prioritized Recommendations

## 10.1 Top 5 Threats and Actions

| Rank | Threat | Likelihood | Impact | Key Gap | Recommended Action | Effort |
|---:|---|---|---|---|---|---|
| **1** | **Ransomware double extortion against EHR** | Critical | Critical | **GAP-001** | Build enforced Critical-system segmentation; begin with EHR DB and backup-management restrictions | **Long-term** |
| **2** | **Negligent insider / unmanaged endpoint exposure** | High | Critical | **GAP-013** | Reconcile endpoint inventory, complete Sophos coverage, enrol iPads in MDM and block unregistered devices from production networks | **Short-term** |
| **3** | **Opportunistic exploitation of vulnerable/unsupported systems** | High | Critical | **GAP-016** | Establish vulnerability-management ownership, scanning, remediation SLAs and closure verification | **Short-term** |
| **4** | **Trusted-vendor / supply-chain compromise** | Medium | Critical | **GAP-007** | Convert vendor access to named, MFA-protected, least-privilege, time-limited sessions; begin with MedTech | **Short-term** |
| **5** | **Malicious insider abuse of legitimate access** | Medium | Critical | **GAP-011** | Centralise EHR, AD and VPN monitoring and alert on high-risk identity/patient-access patterns | **Quick Win** |

## 10.2 Recommendation-to-Threat Traceability

| Defensive Initiative | Threats Reduced | Principal Gaps |
|---|---|---|
| **Centralised monitoring and alerting** | Ransomware, malicious insider, vendor compromise, opportunistic attack, hacktivism | GAP-011 |
| **Critical-system segmentation** | Ransomware, opportunistic exploitation, vendor compromise, malicious insider, medical-IoT abuse | GAP-001, GAP-002, GAP-003 |
| **MFA/PAM and vendor-access governance** | Ransomware, malicious insider, supply chain, APT | GAP-007, GAP-017 |
| **Endpoint/MDM/NAC coverage** | Negligent insider, ransomware, opportunistic exploitation | GAP-013, GAP-012 |
| **Vulnerability-management programme** | Opportunistic exploitation, ransomware, APT, hacktivist web attack | GAP-016 |
| **Protected backups and tested recovery** | Ransomware and destructive insider/actor scenarios | GAP-008, GAP-015 |
| **Medical-IoT isolation/credential hardening** | Opportunistic, insider and ransomware device paths | GAP-003, GAP-018 |

## 10.3 Strategic Two-Initiative Recommendation

If MedDefense can fund only **two defensive initiatives next quarter**, it should choose:

1. **Centralised security monitoring and alerting**
2. **The first phase of Critical-system network segmentation**

These provide the greatest cross-threat reduction. GAP-011 appears in **8 of 8 modelled attack paths**, while GAP-001 appears in **7 of 8**. Monitoring gives MedDefense the ability to detect phishing follow-on activity, persistence, credential abuse, lateral movement, abnormal EHR access, vendor-session anomalies and exfiltration. Segmentation reduces the consequence of the initial control failure by preventing unrestricted movement from user endpoints or trusted vendor footholds toward EHR, AD, backups and medical IoT.

Together they solve the two problems that recur most often across this report: **attackers can move too far, and MedDefense sees them too late**.

## 10.4 Connection to Project 1x02 — Vulnerability Assessment

Project `1x02` should use this threat report to prioritise technical validation rather than scanning every system with equal urgency.

The vulnerability assessment should begin with:

1. **Internet-facing and remote-access systems** — FortiGate/VPN, `web-srv-01`, patient portal and other confirmed exposed services
2. **EHR and identity paths** — `ehr-srv-01`, `ehr-db-01`, AD and the network controls between them
3. **Backup management** — `backup-srv-01`, `NAS-01` and administrative reachability
4. **Legacy and unsupported systems** — `billing-srv-01`, `WS-RAD-01`, `print-srv-01`
5. **Medical IoT** — Alaris pumps, IntelliVue monitors and exposed device-management interfaces
6. **Westside edge and trusted site paths** — consumer router, RDP/SMB exposure and VPN policy
7. **Vendor-access boundaries** — MedTech maintenance scope and other privileged third-party channels

Project 1x02 should specifically validate whether the **assumed attack paths are technically exploitable**, identify exact vulnerabilities and configurations, and provide remediation evidence. This converts the current threat-informed priorities into verified technical findings.

---

# Conclusion

MedDefense's threat environment is serious but understandable. The organisation is not facing six unrelated adversaries requiring six separate defence programmes. The same weaknesses recur regardless of who attacks: limited visibility, broad internal reachability, weak privileged-access boundaries, legacy technology and incomplete device governance.

Ransomware remains the most dangerous external threat because it combines the highest likelihood with the ability to disrupt clinical operations and expose Restricted patient data simultaneously. Negligent insiders and opportunistic attackers follow because they need little sophistication to take advantage of MedDefense's normal workflows and technical exposure. Supply-chain and malicious-insider scenarios are less frequent but retain Critical impact because they begin with trusted access.

The strongest defensive strategy is therefore **path disruption**: detect malicious behaviour early, restrict how far any foothold can move, reduce the usefulness of stolen or trusted credentials, protect recovery systems and verify vulnerabilities before attackers do. That approach links the external threat landscape directly to the internal posture assessment and provides the evidence-based foundation for the Project 1x02 vulnerability assessment.

---

# Appendix A — Full Threat Scenarios

## A.1 Scenario 1 — BlackReef: From a Phished IT Director to Hospital-Wide Ransomware

**Threat Actor:** Organized Crime / BlackReef-style RaaS affiliate  
**Motivation:** Financial gain / blackmail  
**Initial Vector:** Spear phishing  
**Primary Surfaces:** Human → Internal  
**Primary Assets:** A-020, A-005/A-006, A-001, A-002, A-036, A-009, A-010, A-041

### Attack Sequence

1. **Initial Access:** A Fortinet-themed spear-phishing message targets the IT Director. The victim follows the malicious link/file path and attacker code executes on the workstation.
2. **Persistence:** A scheduled task or equivalent recurring mechanism maintains access.
3. **Discovery:** The attacker enumerates AD, privileged groups, EHR, backups and reachable systems.
4. **Credential Access / Privilege Escalation:** Credentials or hashes are obtained from the endpoint; privileged identity material is targeted.
5. **Lateral Movement:** The attacker reaches AD and then EHR systems. PostgreSQL 5432 on `ehr-db-01` is reachable internally.
6. **Collection / Exfiltration:** Patient and business data are gathered and transferred outside MedDefense.
7. **Impact Preparation:** Backup services and local recovery are targeted.
8. **Impact:** Ransomware encrypts reachable systems and disrupts EHR, authentication and business services.

### STRIDE

Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service and Elevation of Privilege are all activated.

### Gaps

GAP-013, GAP-011, GAP-007, GAP-001, GAP-002, GAP-008 and GAP-015. GAP-020 provides additional DLP context.

### Detection / Break Points

- Secure-email controls + user awareness before execution
- EDR and central Windows monitoring for persistence
- AD/identity analytics for enumeration and credential abuse
- Segmentation before EHR/database lateral movement
- DLP/database/egress analytics before exfiltration
- Backup administration alerts before recovery destruction
- GPO/remote-execution alerts before mass encryption

## A.2 Scenario 2 — The Curious Employee

**Threat Actor:** Malicious Insider — registration employee  
**Motivation:** Unauthorized disclosure / curiosity  
**Initial Vector:** Legitimate access abused  
**Primary Surface:** Human / Internal  
**Primary Assets:** A-036, A-002, A-020

### Attack Sequence

1. **Initial Access:** The employee signs into the EHR using a legitimate account.
2. **Collection:** She searches for a local politician without a care, registration or billing need.
3. **Collection:** She reads and retains sensitive treatment details.
4. **Exfiltration:** She communicates the information to a friend.
5. **Impact:** The information is posted publicly.

### STRIDE

Primary categories are Information Disclosure and Repudiation.

### Gap

**GAP-011** is the central weakness: access is audited, but the audit trail is not continuously monitored for role mismatch, no-care-relationship access or high-risk records.

### Detection / Break Points

- VIP-record alerting
- Care-relationship analytics
- Role-based anomaly detection
- Rapid supervisor/security review before the information leaves MedDefense

## A.3 Scenario 3 — Trusted Update, Untrusted Code

**Threat Actor:** Nation-State APT using MedTech as a downstream access path  
**Motivation:** Espionage  
**Initial Vector:** Supply-chain / vendor maintenance pathway  
**Primary Surfaces:** External third party → Internal  
**Primary Assets:** A-001, A-002, A-036; potentially A-005/A-006

### Attack Sequence

1. **Resource Development / Initial Access:** The attacker compromises a MedTech engineer, credential or maintenance platform outside MedDefense.
2. **Initial Access:** Compromised vendor access is used against `ehr-srv-01`.
3. **Persistence / Defence Evasion:** Malicious activity is made to resemble authorised maintenance.
4. **Discovery:** The attacker maps EHR, database, AD and reachable internal services.
5. **Lateral Movement / Elevation:** The attacker attempts to expand beyond MedTech's intended scope toward `ehr-db-01` and potentially AD.
6. **Collection:** EHR-accessible patient and operational information is gathered.
7. **Exfiltration:** Data leaves through encrypted or trusted-looking traffic.

### STRIDE

Spoofing, Repudiation, Information Disclosure and Elevation of Privilege are primary; Tampering is possible if application components are modified for persistence.

### Gaps

GAP-011, GAP-001, GAP-002 and GAP-007.

### Detection / Break Points

- Named vendor identities + MFA + source restrictions
- Just-in-time maintenance windows
- Privileged session recording
- Alerts on out-of-scope discovery
- Network segmentation around the EHR
- PostgreSQL allow-listing
- Database and egress analytics

---

# Appendix B — Evidence and Framework Traceability

| Report Finding | Primary Evidence |
|---|---|
| Ransomware is the primary external threat | Task 0 healthcare intelligence; Task 2 RaaS assessment; Task 6 actor matrix; Task 16 priority assessment |
| Internal surface is the greatest technical multiplier | Project 1x00 Asset Registry / Gap Analysis; Task 7 attack surface |
| Medical IoT is the most connected asset group | Task 9 vector-to-asset matrix |
| Phishing and insiders are the most versatile vectors | Task 9 vector-to-asset matrix |
| EHR Tampering is the most dangerous STRIDE category | Task 11 STRIDE analysis |
| Five critical operational attack paths | Task 10 kill chains |
| MITRE ATT&CK behaviour mapping | Task 13 ATT&CK assessment |
| Three Board scenarios | Task 14 integrated scenarios |
| GAP-011 / GAP-001 / GAP-007 are the Critical Three | Task 15 gap-threat correlation |
| GAP-002 requires threat-informed upgrade | Task 15 gap-threat correlation |
| Top 5 threats and recommended actions | Task 16 threat priority assessment |
| Asset criticality / control posture | Project 1x00 Tasks 8, 10, 12 and Security Posture Assessment |

## Principal Project Files

### Project 1x00 — Internal Security Posture

- `7-asset_registry.md`
- `8-criticality_assessment.md`
- `9-data_map.md`
- `10-complete_control_matrix.md`
- `12-gap_analysis.md`
- `13-reality_check.md`
- `15-predecessor_review.md`
- `16-security_posture_assessment.md`

### Project 1x01 — External Threat Landscape

- `0-threat_landscape_summary.md`
- `1-threat_actor_taxonomy.md`
- `2-ransomware_assessment.md`
- `3-insider_assessment.md`
- `4-social_engineering_analysis.md`
- `5-supply_chain_assessment.md`
- `6-threat_actor_matrix.md`
- `7-attack_surface_map.md`
- `8-technical_vectors.md`
- `9-vector_asset_matrix.md`
- `10-kill_chains.md`
- `11-stride_ehr.md`
- `13-attck_mapping.md`
- `14-threat_scenarios.md`
- `15-gap_threat_correlation.md`
- `16-threat_priority_assessment.md`
