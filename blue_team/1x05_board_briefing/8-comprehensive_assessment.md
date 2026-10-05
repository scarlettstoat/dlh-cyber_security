# 8. The Comprehensive Security Assessment

# MedDefense Health Systems
## Comprehensive Security Assessment

**Prepared for:** Dr. Patricia Morales and the MedDefense Board  
**Project:** `1x05_board_briefing`  
**Repository path:** `blue_team/1x05_board_briefing/8-comprehensive_assessment.md`  
**Assessment date:** October 2026  
**Classification:** Internal / Confidential

---

# 1. Executive Summary

MedDefense has made real progress in understanding its security environment, but its current posture is still **high risk and fragmented**.

Across the five previous projects, the same pattern keeps appearing: MedDefense has useful controls, but Critical systems are still too easy to reach from one another, identity protection is incomplete, monitoring is fragmented, several important systems are unsupported or weakly configured, backup recovery is too connected to production, and cryptographic protection is inconsistent.

This matters more now because the threat is no longer general.

The **Crimson Tide** ransomware campaign is actively targeting hospitals using an attack chain that closely matches MedDefense's current environment:

```text
Vulnerable FortiGate
        ↓
Credential and network discovery
        ↓
Flat-network lateral movement
        ↓
Active Directory / Kerberoasting
        ↓
Patient and billing data theft
        ↓
Backup destruction
        ↓
Ransomware and double extortion
```

MedDefense is therefore **inside the blast radius**.

Its FortiGate 100F is running FortiOS `7.0.9`, which is affected by **CVE-2023-27997**. The firewall is also the main perimeter and VPN dependency for the organization, and the support contract required to obtain the available firmware update has expired.

The updated ransomware Annual Loss Expectancy has increased from:

```text
$1,050,000/year
```

to:

```text
$2,700,000/year
```

because the updated Annual Rate of Occurrence is now `0.90`.

The existing decision to **mitigate** ransomware risk is still correct. What has changed is the timeline. Controls originally planned over six months now need to be accelerated into hours, days and weeks.

The immediate priorities are:

1. **Close the FortiGate entry path.** Restrict or disable SSL-VPN until the firewall is patched, renew the support contract for **$2,400**, verify the firmware and upgrade to FortiOS `7.0.14`.
2. **Protect recovery before the attacker can reach it.** Keep `NAS-01` isolated from production while an offsite immutable recovery copy is established and tested.
3. **Reduce the value of stolen credentials.** Rotate exposed VPN/administrative credentials and enforce MFA on privileged, remote and vendor access.
4. **Break lateral movement.** Restrict unnecessary RDP, SMB, SSH and WMI traffic and accelerate the planned network segmentation.
5. **Improve detection.** Review current FortiGate, Active Directory and endpoint evidence immediately and accelerate Wazuh onboarding for the systems most relevant to the Crimson Tide attack path.

The Board-approved Year 1 security programme remains **$120,000**, which is fully allocated. This assessment requests an additional **$2,400 emergency spend** for the FortiGate support renewal, bringing immediate approved security spending to **$122,400**.

The central conclusion is simple:

> **MedDefense is not adequately prepared for Crimson Tide today, but the risk can be materially reduced if the 72-hour response is executed immediately and the existing security strategy is accelerated rather than restarted.**

---

# 2. Emergency Status

## What Is Crimson Tide?

Crimson Tide is a ransomware campaign targeting hospitals.

The group is not relying on one technique. It first exploits vulnerable FortiGate SSL-VPN appliances, then uses the access to learn the network, steal credentials, move through poorly segmented systems, reach Active Directory, steal sensitive data, damage backups and finally deploy ransomware.

The goal is **double extortion**:

- disrupt hospital operations by encrypting systems; and
- threaten to publish stolen patient or business information.

## Is MedDefense in the Blast Radius?

**Yes.**

MedDefense currently has several of the same conditions used in the campaign:

| Crimson Tide Need | MedDefense Condition |
|---|---|
| Vulnerable FortiGate | **Yes - FortiOS 7.0.9** |
| Broad internal movement | **Yes - GAP-001 flat trust model** |
| Credential weaknesses | **Yes - incomplete MFA/PAM and legacy AD crypto** |
| Reachable patient databases | **Yes - broad EHR database reachability** |
| Readable sensitive data | **Yes - EHR and billing databases unencrypted at rest** |
| Reachable backups | **Yes - NAS/backup environment accessible from production** |
| Weak detection | **Yes - fragmented monitoring / GAP-011** |

MedDefense should therefore treat the advisory as an active exposure, not as general threat intelligence.

## 72-Hour Response Summary

### Tonight - 0 to 12 Hours

- Restrict or disable SSL-VPN.
- Preserve and review FortiGate evidence.
- Physically isolate `NAS-01`.
- Review and lock down FortiGate administrator access.
- Hunt AD and endpoint logs for credential abuse and lateral movement.

### Tomorrow - 12 to 36 Hours

- Approve the **$2,400** support renewal.
- Patch the FortiGate to `7.0.14`.
- Invalidate old VPN sessions and rotate high-risk credentials.
- Enforce MFA first for VPN/admin/vendor accounts.
- Restrict direct EHR and billing database access.
- Apply temporary lateral-movement restrictions.

### This Week - 36 to 72 Hours

- Implement the first segmentation boundaries.
- Stage AES-only Kerberos and LDAP signing after compatibility testing.
- Establish an offsite immutable recovery copy.
- Start EDR deployment on the highest-value supported systems.

The FortiGate patch comes first. MedDefense should not make several unrelated high-risk infrastructure changes at the same time and then be unable to identify which change caused an outage.

---

# 3. Security Posture Overview

## 3.1 Asset Landscape

The consolidated Asset Registry contains **53 registry records** across all three MedDefense locations.

Some records represent entire estates rather than one physical device, so the real device count is much higher.

| Asset Type | Registry Records |
|---|---:|
| Servers | 13 |
| Endpoints | 10 |
| Applications | 8 |
| Physical infrastructure | 7 |
| Network devices | 6 |
| Medical IoT | 6 |
| Data stores | 3 |
| **Total** | **53** |

The environment includes:

- MedDefense Central, a **350-bed acute-care hospital**;
- Westside Clinic;
- Corporate HQ;
- the EHR and patient portal;
- Active Directory;
- billing and finance systems;
- PACS and medical imaging;
- approximately 120 Alaris infusion pumps;
- approximately 80 Philips patient monitors;
- Windows workstation estates;
- Microsoft 365;
- FortiGate and site VPN infrastructure;
- Veeam and NAS backup systems; and
- several legacy or unmanaged systems.

The concentration of Critical services at Central means that weaknesses in shared infrastructure such as Active Directory, networking or backups can affect several clinical functions at once.

## 3.2 Control Maturity - NIST CSF

The strategy adopted **NIST CSF 2.0** as the governance framework and CIS Controls v8 as the implementation layer.

| NIST CSF Function | Current State | 6-Month Target |
|---|---|---|
| Govern | Partial | Managed |
| Identify | Partial | Managed |
| Protect | Partial | Managed |
| **Detect** | **Not Implemented** | **Managed** |
| Respond | Partial | Managed |
| Recover | Partial | Managed |

The biggest maturity weakness is **Detect**.

MedDefense already generates logs, but it does not yet have reliable organization-wide monitoring, correlation and owned alert review. This is why Wazuh remains one of the most important funded controls.

## 3.3 Top Security Gaps

Project `1x00` identified **15 prioritized gaps: 7 Critical, 5 High and 3 Medium**.

The gaps that matter most now are:

| Gap | Why It Matters |
|---|---|
| **GAP-001 - No effective internal segmentation** | Turns one foothold into a route toward EHR, AD, backups and clinical systems |
| **GAP-007 - Incomplete MFA/PAM** | Makes stolen credentials much more useful |
| **GAP-008 - Backup infrastructure concentrated with production** | Allows ransomware to attack recovery before encryption |
| **GAP-011 - Fragmented monitoring** | Makes it harder to detect the attack while it is developing |
| **GAP-016 - Weak vulnerability/patch management** | Allowed an Internet-facing Critical device to remain on vulnerable firmware |
| **GAP-002 - Broad EHR database reachability** | Gives an internal attacker a direct route toward patient data |
| **GAP-013 - Incomplete endpoint/device management** | Reduces visibility and containment across the endpoint estate |

The recurring lesson from all five projects is that the gaps **connect**. MedDefense's risk is higher because several weaknesses can be used in sequence.

---

# 4. Threat Landscape

## 4.1 Top Three Threat Actors

### 1. Ransomware Groups / Organized Crime

**Status: CRITICAL / ACTIVE**

This was already MedDefense's highest-priority external threat in `1x01`.

Crimson Tide now confirms that the original model was accurate. MedDefense has the same combination of perimeter exposure, flat internal reachability, credential weaknesses, sensitive healthcare data and reachable backups that ransomware operators prefer.

### 2. Negligent Insider

**Status: HIGH / CONTINUOUS**

This threat remains highly relevant because it does not require a sophisticated attacker.

Previous MedDefense evidence already included:

- unmanaged/personal devices;
- unattended authenticated sessions;
- shared credentials; and
- inappropriate storage of patient information.

A negligent user can expose data directly or create the foothold an external attacker needs.

### 3. Opportunistic Attacker

**Status: HIGH**

MedDefense contains enough unsupported or weakly configured systems that automated exploitation remains realistic.

The recurring compromise history on `billing-srv-01`, unsupported operating systems and public exploit availability mean an attacker does not need to target MedDefense personally. A scanner can find the weakness first.

## 4.2 How Crimson Tide Maps to the Original Threat Model

Crimson Tide does not introduce a completely new threat model.

It validates the one already built in `1x01`.

| Original Threat Model | Crimson Tide |
|---|---|
| Public-facing exploitation | FortiGate CVE-2023-27997 |
| Credential theft / valid account use | VPN credentials and Kerberoasting |
| Flat-network movement | RDP, SSH and WMI lateral movement |
| AD compromise | Privileged access and ransomware distribution |
| Sensitive-data theft | EHR / billing exfiltration |
| Backup targeting | Backup destruction before ransomware |
| Double extortion | Encryption + threat to publish stolen data |

The difference is urgency.

What was previously a credible attack path is now an active campaign against hospitals.

---

# 5. Vulnerability Status

## 5.1 Assessment Summary

Project `1x02` identified:

```text
31 total findings
26 requiring remediation
3 informational
2 false positives / applicability failures
```

The scanner initially reported:

- 4 Critical
- 7 High
- 11 Medium
- 5 Low
- 4 Informational

Manual validation showed that **83.9% of findings require remediation**.

The main weakness was not simply old software. More than half of the findings were primarily **misconfiguration** issues.

## 5.2 Five Findings That Matter Most

### 1. `WS-RAD-01` - Unsupported Windows XP MRI Workstation

The MRI control workstation is permanently exposed to legacy Windows vulnerabilities with mature public exploitation.

**Status:** **OPEN**

Immediate containment through segmentation is required. Long-term replacement remains a capital/clinical-technology project.

---

### 2. `ehr-db-01` - PostgreSQL Reachable Too Broadly

PostgreSQL is reachable from much more of the internal network than necessary.

The database also stores patient information on an unencrypted filesystem.

**Status:** **OPEN**

Access should be restricted to `ehr-srv-01` and explicitly approved administration/monitoring sources.

---

### 3. Active Directory - LDAP / Kerberos Weaknesses

LDAP signing is not enforced and the wider authentication environment still permits legacy RC4/DES Kerberos encryption.

Crimson Tide specifically uses credential abuse and Kerberoasting.

**Status:** **OPEN - CONTROLLED CHANGE REQUIRED**

This cannot safely be changed without compatibility testing because legacy clinical or vendor systems could lose authentication.

---

### 4. `billing-srv-01` - Compound Legacy Exposure

The billing server combines:

- Apache vulnerabilities;
- password-based SSH;
- Ubuntu 18.04 without normal security maintenance;
- an outdated kernel; and
- previous ransomware / crypto-miner history.

**Status:** **OPEN**

Short-term hardening should be followed by migration to a supported Ubuntu LTS platform.

---

### 5. `NAS-01` / Backup Infrastructure

NAS management and administrative interfaces are too broadly reachable, and the backup environment is not sufficiently separated from production.

Backups are also stored without adequate encryption.

**Status:** **OPEN - EMERGENCY CONTAINMENT AVAILABLE**

Physical isolation can be done immediately while an immutable offsite copy is established.

## 5.3 Remediation Progress

MedDefense has completed the **analysis, prioritization, implementation design and validation planning** for the main findings.

That is useful progress, but it is not the same as closing the vulnerabilities.

No Critical finding should be marked fixed until the production change is completed and verified.

Current position:

```text
Analysis:                 COMPLETE
Prioritization:           COMPLETE
Remediation design:       COMPLETE
Implementation playbooks: COMPLETE
Production closure:       NOT YET CONFIRMED
Post-change validation:   REQUIRED
```

Crimson Tide adds one new emergency exposure:

```text
CVE-2023-27997 on FortiOS 7.0.9
Status: CONFIRMED VULNERABLE / OPEN
```

---

# 6. Risk Quantification

## 6.1 Updated Top Five ALE

The original `1x03` model used an ARO of `0.35` for EHR ransomware.

The updated Crimson Tide analysis raises this to:

```text
ARO = 0.90
```

The ransomware SLE remains:

```text
$3,000,000
```

Therefore:

```text
Updated ransomware ALE:
$3,000,000 × 0.90 = $2,700,000/year
```

### Updated Top Five

| Rank | Risk | Current ALE |
|---:|---|---:|
| **1** | EHR ransomware / Crimson Tide double extortion | **$2,700,000** |
| **2** | `billing-srv-01` compromise | **$234,000** |
| **3** | Active Directory privileged compromise | **$210,000** |
| **4** | Windows XP MRI exploitation/disruption | **$163,625** |
| **5** | Alaris environment compromise/disruption | **$108,000** |
|  | **Total** | **$3,415,625/year** |

The updated ransomware calculation alone adds:

```text
$1,650,000/year
```

to the original top-five model.

These numbers are planning estimates, not predictions of exact future losses.

## 6.2 Budget Allocation Status

The approved Year 1 security programme is:

| Control | Allocation |
|---|---:|
| Network segmentation | $25,000 |
| MFA | $4,000 |
| Wazuh SIEM | $22,000 |
| Offsite immutable backup | $15,000 |
| Sophos Intercept X EDR | $36,000 |
| Medical-device isolation / monitoring | $18,000 |
| **Total** | **$120,000** |
| **Remaining** | **$0** |

The Westside enterprise firewall remains deferred at **$15,000**.

The outsourced 24/7 SOC remains rejected for the current budget cycle because its **$240,000** cost exceeds the full annual security budget.

## 6.3 Emergency Spend Request

The FortiGate support contract must be renewed before MedDefense can obtain the required firmware.

```text
Emergency FortiGate support renewal: $2,400
Existing Year 1 programme:          $120,000
------------------------------------------------
Immediate approved/requested spend: $122,400
```

The $2,400 should be treated as **additional emergency spend**, not taken from a fully allocated control programme that already addresses the same ransomware chain.

## 6.4 ROI - Implemented vs Planned Controls

MedDefense already has useful controls such as:

- FortiGate perimeter filtering;
- Sophos endpoint protection on part of the Windows estate;
- Veeam backups;
- Active Directory security policies;
- local Windows/Linux/application logging;
- O365 encryption; and
- site-to-site IPsec.

However, their coverage and effectiveness are uneven. A reliable financial ROI has **not** been calculated for those existing controls and should not be invented.

For the planned programme, `1x03` modeled:

```text
Top-five ALE before controls: $1,765,625
Top-five ALE after controls:    $874,100
Modeled annual reduction:       $891,525
```

Against the $120,000 programme:

```text
$891,525 / $120,000 ≈ 7.4
```

That was approximately **$7.40 of modeled annual risk reduction for every $1 of programme cost** before the Crimson Tide update.

The new threat intelligence strengthens that business case.

For example, using the existing segmentation model:

```text
Current Crimson Tide ransomware ALE:      $2,700,000
ALE after segmentation assumption:        $1,575,000
Modeled reduction from segmentation:      $1,125,000
Segmentation cost:                            $25,000
```

That does **not** mean MedDefense will literally save $1.125 million. It means the relative risk-reduction value of the control is now even stronger.

Realized ROI should only be reported after controls are deployed and effectiveness is measured.

---

# 7. Cryptographic Posture

## 7.1 Current Data Protection Coverage

Project `1x04` assessed **21 data-state combinations** across seven categories of information.

| Status | Cells | Percentage |
|---|---:|---:|
| Adequate | 3 | **14.3%** |
| Weak | 4 | **19.0%** |
| Absent | 14 | **66.7%** |
| **Total** | **21** | **100%** |

If any cryptographic protection is counted, including weak protection:

```text
7 / 21 = 33.3% coverage
```

But only:

```text
3 / 21 = 14.3%
```

currently have protection rated **Adequate**.

The three adequate areas are:

- O365 email at rest;
- O365 email in transit; and
- site-to-site VPN traffic in transit.

## 7.2 Critical Crypto Gaps Crimson Tide Can Exploit

### EHR Data at Rest - CRYPTO-001

Patient records on `ehr-db-01` are stored on an unencrypted filesystem.

If an attacker reaches the host or database files, the data does not have a separate encryption layer protecting it.

### Billing Data at Rest - CRYPTO-004

Billing/MySQL data is also stored without adequate encryption at rest.

This increases the value of successful data exfiltration.

### Credential Protection - CRYPTO-011

Active Directory still permits RC4/DES Kerberos mechanisms and LDAP protection is incomplete.

This directly overlaps with Crimson Tide's credential-theft and Kerberoasting phase.

### Backup Data - CRYPTO-013 / 014 / 015

`NAS-01` does not currently provide the cryptographic and isolation posture required for a ransomware-resistant recovery environment.

RAID provides availability. It does **not** provide confidentiality or ransomware isolation.

## 7.3 HIPAA Position

Under the current HIPAA Security Rule, regulated entities must protect the confidentiality, integrity and availability of ePHI using appropriate administrative, physical and technical safeguards.

HHS currently describes encryption as an **addressable** implementation specification. That does not mean optional in the ordinary sense: the organization must determine through risk analysis whether encryption is reasonable and appropriate, implement it where it is, or document an appropriate alternative.

For MedDefense, the present evidence makes weak or absent encryption difficult to justify for high-risk ePHI systems such as:

- the EHR database;
- backup copies;
- sensitive database traffic; and
- systems where compromise would expose large volumes of patient information.

MedDefense should therefore treat its current crypto posture as **not sufficiently mature for the level of risk identified**, rather than claiming HIPAA compliance simply because encryption is currently described as addressable.

HHS has also proposed a stronger HIPAA Security Rule that would require encryption of ePHI at rest and in transit with limited exceptions. At the time of this assessment, HHS continues to present this as a **proposed rule**, so it should be treated as a regulatory direction of travel rather than a final requirement.

> This assessment is a cybersecurity risk assessment, not a legal opinion on HIPAA compliance.

### Current HHS References

- HIPAA Security Rule:  
  `https://www.hhs.gov/hipaa/for-professionals/security/index.html`
- HHS encryption FAQ:  
  `https://www.hhs.gov/hipaa/for-professionals/faq/is-the-use-of-encryption-mandatory-in-the-security-rule/index.html`
- Proposed HIPAA Security Rule cybersecurity update:  
  `https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html`

---

# 8. Recommendations

## 8.1 First 72 Hours

### 0-12 Hours

1. Restrict/disable vulnerable SSL-VPN access.
2. Preserve and review FortiGate evidence.
3. Disconnect `NAS-01` from production.
4. Review FortiGate admin accounts and rotate where needed.
5. Hunt AD/endpoints for signs of credential abuse or lateral movement.

### 12-36 Hours

1. Approve the **$2,400** FortiGate renewal.
2. Verify and install FortiOS `7.0.14`.
3. Rotate high-risk VPN/admin credentials and invalidate old sessions.
4. Enforce MFA on privileged/VPN/vendor access.
5. Restrict EHR and billing database access.
6. Apply temporary east-west restrictions.

### 36-72 Hours

1. Start priority VLAN/ACL segmentation.
2. Stage AES-only Kerberos and LDAP signing after testing.
3. Establish an immutable offsite backup copy.
4. Start EDR deployment on Critical supported systems.

---

## 8.2 30-Day Accelerated Roadmap

### Days 4-7

- Complete first segmentation boundaries for Management, AD/EHR/Servers and Backup.
- Complete high-risk MFA rollout.
- Onboard FortiGate, AD, EHR, billing and backup logs to Wazuh first.
- Restrict PostgreSQL and MySQL source access.
- Complete Kerberos/LDAP compatibility review and staged enforcement.
- Confirm immutable backup creation and complete a restore test.

### Days 8-14

- Patch the Apache findings on `billing-srv-01`.
- Disable password-based SSH after validating key access.
- Expand EDR to the supported Critical server and admin workstation estate.
- Isolate the Windows XP MRI environment.
- Restrict medical-IoT management paths.
- Convert vendor administrative access to named, MFA-protected and time-bounded accounts.

### Days 15-30

- Migrate `billing-srv-01` away from unsupported Ubuntu 18.04.
- Expand segmentation to Clinical, Medical Device and Guest/IoT zones.
- Implement the first `1x04` encryption priorities:
  - EHR database transport protection;
  - billing database transport protection;
  - backup encryption;
  - central key-management process.
- Complete a ransomware-focused incident-response tabletop.
- Re-scan the Critical systems and verify closure rather than relying on change tickets alone.

---

## 8.3 Year 1 Strategic Priorities

### 1. Finish the $120,000 Control Programme

Deploy and verify:

- network segmentation;
- MFA;
- Wazuh SIEM;
- immutable offsite backup;
- Sophos Intercept X EDR; and
- medical-device isolation/monitoring.

### 2. Establish Continuous Vulnerability Management

MedDefense should have:

- recurring scans;
- named remediation owners;
- Critical/High remediation SLAs;
- external attack-surface monitoring;
- emergency vendor-advisory handling; and
- verification scans after remediation.

The FortiGate situation should not repeat.

### 3. Remove Unsupported Technology

Priority lifecycle work includes:

- Windows XP MRI control environment;
- Windows Server 2012 R2 print infrastructure;
- Ubuntu 18.04 billing environment without ESM.

Where immediate replacement is impossible, enforce segmentation and documented time-limited exceptions.

### 4. Raise Cryptographic Coverage

Move the 18 Weak/Absent data-state cells through the `1x04` remediation plan, prioritizing:

- patient records;
- credentials;
- backup data;
- billing data; and
- medical imaging.

### 5. Make Detection an Operating Process

Buying Wazuh is not the objective.

The objective is:

```text
log source
    ↓
central collection
    ↓
detection rule
    ↓
named analyst
    ↓
investigation
    ↓
escalation
    ↓
documented outcome
```

### 6. Test Recovery and Incident Response

Perform recurring:

- immutable-backup restore tests;
- EHR recovery exercises;
- ransomware tabletop exercises;
- privileged-account reviews; and
- segmentation rule validation.

---

## 8.4 Budget Recommendation

### Current Approved Programme

```text
$120,000
```

### Emergency Request

```text
FortiGate support renewal: $2,400
```

### Immediate Total

```text
$122,400
```

The Board should approve the additional $2,400 immediately.

It is not reasonable to preserve a fully allocated $120,000 programme while leaving the exact active ransomware entry point open over a relatively small support renewal.

Future capital requests should separately address:

- MRI platform replacement;
- Westside enterprise firewall;
- other legacy-system replacement; and
- larger cryptographic / key-management modernization where implementation cost exceeds the current programme.

---

# 9. Residual Risk Disclosure

Even after full implementation, MedDefense will not have zero cybersecurity risk.

The objective is to reduce the likelihood and blast radius to a level the organization can manage.

## 9.1 Risks That Will Remain

### Ransomware

Residual risk remains **High** because hospitals remain attractive targets and the consequence of a successful EHR outage remains Critical.

The organization can reduce likelihood and recovery time, but it cannot remove the threat actor.

### Windows XP MRI

Segmentation reduces reachability but does not make Windows XP secure.

Residual risk must remain High until the clinical platform is replaced.

### Medical Devices

Many medical devices depend on vendor-supported software and lifecycle constraints.

Network isolation and monitoring reduce exposure, but patient-safety impact means successful compromise can still be Critical.

### Third-Party / Vendor Access

MFA, named accounts and time limits reduce risk but cannot completely remove dependency on trusted vendors.

### Westside Perimeter

The dedicated Westside enterprise firewall remains deferred under the current $120,000 programme.

Until it is funded, **RISK-010 remains High**.

## 9.2 Risks MedDefense Is Accepting

MedDefense should **not** accept:

- the current vulnerable FortiGate;
- unrestricted Critical-system reachability;
- continuously network-accessible backups;
- unowned Critical vulnerabilities; or
- unrestricted privileged/vendor access.

The acceptable residual risks are narrower and time-bound:

| Residual Risk | Why It Is Temporarily Accepted | Required Condition |
|---|---|---|
| Windows XP MRI remains vulnerable | Clinical/vendor replacement cannot happen overnight | Strong segmentation, monitored access, replacement plan and review date |
| Westside firewall remains deferred | Higher-value controls consumed current budget | Existing restrictions, monitoring and a funded future replacement decision |
| Ransomware impact remains Critical | Hospital operations cannot make EHR impact insignificant | Reduce likelihood, isolate backups, test recovery and maintain executive visibility |
| Medical-device residual risk | Vendor/clinical constraints limit normal endpoint controls | Isolation, allow-listed management and Clinical Engineering/vendor involvement |

Risk acceptance must be documented, owned and reviewed. It cannot mean “we know about it and have not had time.”

---

# Next Module - Endpoint Hardening and Infrastructure Defense

The next phase should build directly on this assessment.

The priority moves from identifying the attack paths to **hardening the systems inside them**.

Key areas should include:

- secure endpoint baselines;
- Windows and Linux hardening;
- endpoint detection and response;
- privileged workstation security;
- firewall and switch hardening;
- infrastructure logging;
- network segmentation enforcement;
- service reduction;
- vulnerability remediation verification; and
- recovery testing.

The question for the next module is no longer:

> **Where could the attacker go?**

It is:

> **How difficult can MedDefense make every step of that path?**

---

# Final Assessment

MedDefense now understands its assets, threats, vulnerabilities, risks and security priorities much better than it did at the start of the programme.

That is important, but understanding the problem is no longer enough.

Crimson Tide shows that the weaknesses identified across the five projects are not theoretical. The active campaign connects them in almost the same order MedDefense's own assessments predicted.

The strategy does not need to be replaced.

It needs to be **accelerated and executed**.

The Board's immediate decision is therefore straightforward:

```text
Approve the $2,400 FortiGate emergency renewal.
Execute the 72-hour plan.
Protect backups and credentials.
Break lateral movement.
Accelerate the existing $120,000 security programme.
Verify every change.
```

If MedDefense does that, it will not become invulnerable.

It will become much harder to turn one vulnerability into a hospital-wide incident.

---

# Internal Source Documents

This assessment synthesizes:

- Project `1x00` - Security Posture Assessment
- Project `1x00` - Asset Registry / Criticality / Gap Analysis
- Project `1x01` - Threat Landscape Report
- Project `1x01` - Prioritized Threat Assessment / Kill Chains
- Project `1x02` - Vulnerability Assessment Summary
- Project `1x02` - Remediation Map / Validation Plan
- Project `1x03` - ALE Workshop
- Project `1x03` - Risk Register
- Project `1x03` - Budget Allocation
- Project `1x03` - Security Strategy Document
- Project `1x04` - Crypto Inventory
- Project `1x04` - Crypto Posture Audit
- Project `1x04` - Implementation Playbook
- Project `1x05` - Advisory Analysis
- Project `1x05` - CVE Deep Dive
- Project `1x05` - 72-Hour Emergency Plan
- Project `1x05` - Technical Proof
- Project `1x05` - Risk Register Update
