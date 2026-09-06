# MedDefense Health Systems — Prioritized Threat Assessment

## Assessment Basis

This assessment ranks the five threats most likely to cause material harm to MedDefense by combining:

- threat-actor likelihood and capability from Project 1x01 Task 6;
- healthcare-sector evidence from Task 0;
- MedDefense-specific vectors and attack surfaces from Tasks 7–9;
- the five kill chains from Task 10;
- STRIDE consequences from Task 11;
- the integrated scenarios from Task 14; and
- the threat-informed gap correlation from Task 15.

The ranking considers **both likelihood and impact**. A technically sophisticated actor is not automatically a top priority if MedDefense is unlikely to attract it, while a lower-sophistication threat can rank highly when it repeatedly aligns with MedDefense's existing weaknesses.

---

# 1. Ransomware Double Extortion Against the EHR Environment

**Rank:** **1**

**Threat:** A RaaS affiliate gains access through phishing or stolen credentials, reaches Active Directory and the EHR through the flat network, steals patient data, weakens recovery and deploys ransomware.

**Actor Type:** **Ransomware Groups / Organized Crime — BlackReef-style RaaS affiliate**

**Primary Vector:** **Phishing / Spear Phishing leading to credential or endpoint compromise**

**Primary Target:** **EHR System — `ehr-srv-01` (A-001), `ehr-db-01` (A-002), EHR application (A-036)**

**Likelihood:** **Critical.** Task 0 identifies healthcare as the most-targeted critical-infrastructure sector for ransomware in 2023–2024, accounting for **25% of reported ransomware incidents across the cited critical-infrastructure sectors**. The dossier also reports that **73% of healthcare ransomware incidents involved data exfiltration before encryption**. MedDefense is a 350-bed regional hospital that closely matches the mid-size victim profile described in the intelligence, and its environment contains the same weaknesses repeatedly exploited by ransomware: limited MFA/PAM, fragmented monitoring, flat internal reachability and locally concentrated backups.

**Impact:** **Critical.** Project 1x00 rates EHR Confidentiality, Integrity and Availability as Critical. A successful double-extortion event could simultaneously expose Restricted patient records, encrypt clinical systems and interfere with authentication and recovery. MedDefense has already demonstrated dependence on EHR availability: a previous planned migration overrun produced a nine-hour outage and required paper fallback.

**Overall Priority:** **Critical — Immediate**

**Key Gap:** **GAP-001 — No effective internal segmentation.** Closing GAP-001 would not stop every phishing attempt, but it would prevent a single compromised endpoint from becoming an unrestricted route toward EHR, Active Directory, medical devices and backup infrastructure. It appears in all five Task 10 kill chains.

**Recommended Action:** **Long-term — implement phased internal segmentation beginning with Critical zones.** Create enforced security zones for user workstations, EHR/database systems, Active Directory, backup infrastructure and medical IoT; permit only documented required flows between them. As the first phase, restrict `ehr-db-01` TCP 5432 to approved EHR/application and administration hosts and isolate backup-management interfaces from ordinary user/server traffic.

---

# 2. Negligent Insider Creates Patient-Data Exposure or an Internal Foothold

**Rank:** **2**

**Threat:** A legitimate employee exposes patient information or creates an attacker foothold through unsafe credential handling, Shadow IT, unmanaged devices, unattended sessions or insecure data copying.

**Actor Type:** **Insider — Negligent**

**Primary Vector:** **Removable Devices / Unmanaged Endpoints / legitimate access used unsafely**

**Primary Target:** **EHR patient information and Clinical Endpoints — A-001/A-002/A-036 and the endpoint estate including A-020/A-028**

**Likelihood:** **High.** The Task 0 dossier reports that insiders account for a substantial portion of healthcare breaches and that **negligent behavior is more common than malicious insider behavior**. MedDefense has already observed multiple examples rather than merely theoretical exposure: an unattended authenticated EHR workstation, a personal laptop on the internal network, shared PACS credentials and a personal NAS containing patient-file copies.

**Impact:** **Critical.** The EHR and patient-record environment is Critical and contains Restricted information. A negligent action can directly disclose patient data, but it can also introduce malware or an unmanaged host into Central's flat internal network, allowing an external attacker to escalate from a user mistake into a wider clinical compromise.

**Overall Priority:** **Critical — Immediate**

**Key Gap:** **GAP-013 — Endpoint protection and device-management coverage is incomplete.** MedDefense cannot reliably reduce negligent-device risk while some endpoints, mobile devices and personal systems remain outside verified central management.

**Recommended Action:** **Short-term — enforce managed-device admission for clinical and corporate access.** Reconcile the full endpoint inventory against Sophos coverage, enroll physician iPads in a centrally managed MDM platform and block unregistered personal devices from internal production networks through NAC or equivalent access-control enforcement.

---

# 3. Opportunistic Exploitation of Vulnerable or Unsupported Systems

**Rank:** **3**

**Threat:** An automated or low-sophistication attacker exploits a known vulnerability or unsupported system, gains a foothold and benefits from MedDefense's flat internal network to reach higher-value assets.

**Actor Type:** **Unskilled / Opportunistic Attacker**

**Primary Vector:** **Vulnerable Software Exploit**

**Primary Target:** **Initially exposed/legacy systems; ultimately Active Directory, EHR or Medical IoT if the foothold expands**

**Likelihood:** **High.** Task 6 distinguishes deliberate targeting from exposure: opportunistic attackers may not select MedDefense by name, but MedDefense has **high exposure to indiscriminate scanning and exploitation**. The environment includes Ubuntu 18.04 on `billing-srv-01`, Apache 2.4.29, Windows XP on `WS-RAD-01`, Windows Server 2012 R2 on `print-srv-01`, aging medical-device firmware and known Alaris CVEs. The recurring crypto-miner on `billing-srv-01` demonstrates that commodity exploitation is a credible MedDefense pattern.

**Impact:** **Critical.** The initial victim may be a lower-value legacy server, but GAP-001 allows that foothold to become a route toward Critical EHR, identity and clinical-device assets. A low-skill attacker therefore does not need Critical-system exploit capability at the first step; MedDefense's architecture can supply the escalation path after entry.

**Overall Priority:** **High**

**Key Gap:** **GAP-016 — No formal vulnerability and patch-management programme for exposed and Critical systems.** This is the gap most directly aligned with automated exploitation of known weaknesses.

**Recommended Action:** **Short-term — establish a vulnerability-management programme with defined remediation SLAs.** Maintain an authoritative scan scope, monitor vendor advisories, scan exposed and Critical assets regularly, assign remediation owners and require emergency treatment of Internet-facing Critical vulnerabilities with documented verification of closure.

---

# 4. Supply-Chain Compromise Through a Trusted Technology Vendor

**Rank:** **4**

**Threat:** An external attacker compromises a trusted vendor and uses MedDefense's legitimate maintenance or software-management relationship as the entry path to Critical systems.

**Actor Type:** **Organized Crime / Ransomware Group using a compromised third party**  
*A highly capable Nation-State APT could use the same pathway for espionage, but Task 6 rates direct nation-state targeting of MedDefense as Low under its current non-research profile.*

**Primary Vector:** **Supply Chain Compromise / Vendor Access Pathway**

**Primary Target:** **EHR through MedTech Solutions, or Active Directory/endpoints through a compromised trusted software channel**

**Likelihood:** **Medium.** Supply-chain compromise is less frequent than ordinary phishing or opportunistic exploitation, but MedDefense has significant trusted dependencies. MedTech Solutions has direct maintenance access to `ehr-srv-01`, while Sophos has a trusted agent/update/configuration channel to **372 managed Windows endpoints**. The exact MedTech remote-access mechanism is undocumented, and the current Control Matrix does not establish a vendor-specific allowlist, session recording or just-in-time access model.

**Impact:** **Critical.** MedTech has direct access to MedDefense's highest-criticality clinical application, while a compromised Sophos management/update channel could create many internal footholds simultaneously. Either path can bypass assumptions made about the Internet perimeter and place the attacker inside trusted administration or software channels.

**Overall Priority:** **High**

**Key Gap:** **GAP-007 — MFA and privileged-access controls are not broadly implemented.** Stronger privileged-access governance would reduce the ability of compromised vendor identities or administrative credentials to operate as standing trusted access.

**Recommended Action:** **Short-term — convert vendor access to named, MFA-protected, time-limited privileged sessions.** Require each vendor maintenance account to have an individual identity, approved source/path, least-privilege scope, MFA where technically supported, explicit maintenance windows and automatic expiration; begin with MedTech because it reaches the EHR directly.

---

# 5. Malicious Insider Theft or Abuse of Legitimate Access

**Rank:** **5**

**Threat:** A current or former trusted user deliberately abuses legitimate access to obtain patient information, retain unauthorized access or manipulate Critical systems.

**Actor Type:** **Insider — Malicious**

**Primary Vector:** **Legitimate Access Abused / Valid Accounts**

**Primary Target:** **EHR patient records or Active Directory, depending on the insider's role**

**Likelihood:** **Medium.** Task 0 identifies malicious insiders as a meaningful healthcare threat but less common than negligent insiders. MedDefense's own analysis demonstrates credible conditions: staff have broad legitimate access to patient information, EHR activity is not continuously reviewed, privileged-access governance is incomplete and offboarding is not formally integrated with HR events.

**Impact:** **Critical.** An ordinary clinical or registration insider can cause a serious patient-privacy breach through inappropriate EHR access, while an IT insider with elevated access can alter accounts, disable services or interfere with authentication across the organization. Both EHR and Active Directory are Critical Project 1x00 assets.

**Overall Priority:** **High**

**Key Gap:** **GAP-011 — Security logging is fragmented and not continuously monitored.** Legitimate-account misuse is difficult to prevent solely at authentication time because the account itself may be valid. MedDefense therefore needs the ability to identify when valid access becomes abnormal or inappropriate.

**Recommended Action:** **Quick Win — begin centralized high-risk identity and EHR-access alerting using existing logs.** Feed `C-028` EHR audit activity, `C-029` AD events and VPN authentication logs into a centralized monitoring workflow and alert first on post-termination logins, privileged-group changes, high-profile patient access, no-care-relationship access and unusually high record-view/export volumes.

---

# Top 5 Summary

| Rank | Threat | Likelihood | Impact | Overall Priority | Key Gap |
|---:|---|---|---|---|---|
| **1** | Ransomware double extortion against EHR | **Critical** | **Critical** | **Critical — Immediate** | **GAP-001** |
| **2** | Negligent insider / unmanaged endpoint exposure | **High** | **Critical** | **Critical — Immediate** | **GAP-013** |
| **3** | Opportunistic exploitation of vulnerable/unsupported systems | **High** | **Critical** | **High** | **GAP-016** |
| **4** | Trusted-vendor / supply-chain compromise | **Medium** | **Critical** | **High** | **GAP-007** |
| **5** | Malicious insider abuse of legitimate access | **Medium** | **Critical** | **High** | **GAP-011** |

---

# Strategic Recommendation

If MedDefense can fund only **two defensive initiatives next quarter**, it should fund **(1) centralized security monitoring and alerting** and **(2) the first phase of Critical-system network segmentation**. Centralized monitoring directly addresses **GAP-011**, the most connected weakness in Task 15: it appeared in **all five kill chains and all three integrated scenarios**, and MedDefense already generates firewall, Windows, Linux, SSH, EHR and AD logs that can be brought together to detect credential abuse, persistence, unusual EHR access, lateral movement and data exfiltration. In parallel, segmentation addresses **GAP-001**, which appeared in **all five kill chains and two of the three scenarios**; separating user endpoints from EHR/database, Active Directory, backup and medical-IoT zones would prevent a single successful phishing, vendor or endpoint compromise from automatically becoming an organization-wide incident. Together, these initiatives provide the best combination of **containment and detection across multiple actor types**, rather than solving only one attack vector.
