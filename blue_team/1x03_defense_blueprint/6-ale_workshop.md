# 6. The ALE Workshop

## Purpose

This task converts MedDefense's previously identified risks into quantitative annual loss estimates using:

- **Asset Value (AV)**
- **Exposure Factor (EF)**
- **Single Loss Expectancy (SLE)**
- **Annual Rate of Occurrence (ARO)**
- **Annual Loss Expectancy (ALE)**

The five risks below were selected from the combined evidence in Projects 1x00, 1x01 and 1x02. They prioritize the most serious combinations of Critical assets, recurring threat paths, validated vulnerability findings and patient/business impact.

> **Important valuation note:** Project 1x00 rated assets using CIA criticality rather than full accounting valuations. Where an exact MedDefense dollar figure was not available, this workshop uses clearly identified **planning estimates** derived from the documented outage history, healthcare-sector intelligence and the scale/criticality of the affected asset. These figures are decision-support estimates, not vendor quotations, insurance valuations or predictions of exact regulatory fines.

> **ARO note:** Project 1x01 primarily used qualitative likelihood ratings such as Critical, High and Medium. The numerical ARO values below are therefore conservative planning estimates informed by those ratings and the threat evidence. Sector percentages such as the 25% ransomware statistic are **not** treated as direct probabilities that MedDefense will be breached.

---

# Risk 1 — Ransomware Double Extortion Against the EHR

```yaml
Risk: Ransomware encrypts the EHR environment and exfiltrates patient data

Source:
  Gap IDs: GAP-001, GAP-002, GAP-007, GAP-008, GAP-011
  Vulnerability Findings: Finding 003, Finding 007, Finding 015, Finding 021, Finding 030
  Threat Actor: Ransomware Groups / Organized Crime

Asset: EHR System — ehr-srv-01 (A-001), ehr-db-01 (A-002), EHR application (A-036)

Asset Value (AV): $5,000,000
  Replacement/recovery cost: $2,700,000
  Revenue loss during downtime: $150,000 per day × 10 days = $1,500,000
  Regulatory penalties: $400,000
  Reputation/patient trust impact: $400,000

Exposure Factor (EF): 60%
  Reasoning: >
    A successful hospital-wide ransomware event can affect Confidentiality,
    Integrity and Availability at the same time. Project 1x01 models EHR data
    theft, backup targeting and encryption in the same attack chain. The EHR is
    MedDefense's most critical information system, but paper fallback and some
    backup capability prevent treating every successful event as a total 100%
    loss.

SLE: $5,000,000 × 0.60 = $3,000,000

ARO: 0.35 per year
  Reasoning: >
    Project 1x01 rated ransomware likelihood Critical. MedDefense is a 350-bed
    regional hospital matching the supplied mid-size hospital victim profile,
    has already suffered ransomware on billing-srv-01, and three regional
    hospitals in the supplied intelligence were attacked within approximately
    eight months. The 25% sector statistic describes ransomware's share of
    reported critical-infrastructure incidents, not MedDefense's direct annual
    probability, so 0.35 is used as a conservative planning estimate.

ALE: $3,000,000 × 0.35 = $1,050,000

Proposed Control: >
  Implement phased Critical-system network segmentation, beginning with EHR,
  Active Directory, backups and user networks, using least-privilege firewall
  and ACL rules.

Control Annual Cost: $25,000
  Note: >
    This is the existing Project 1x00 first-year planning allocation for
    GAP-001. Recurring operating cost was not separately quantified.

Estimated ALE After Control: $612,500
  New EF: 35%
  New ARO: 0.35
  Calculation: $5,000,000 × 0.35 × 0.35 = $612,500
  Reasoning: >
    Segmentation does not stop phishing or ransomware attempts, so the ARO is
    left unchanged. It primarily reduces the Exposure Factor by limiting
    lateral movement and preventing one compromised endpoint from freely
    reaching EHR, AD, backups and other Critical systems.

Net Benefit: $1,050,000 - $612,500 - $25,000 = $412,500
```

### Assessment

This is the largest quantified risk because it combines MedDefense's highest-priority threat with its most critical clinical system. The healthcare intelligence used in Project 1x01 reported an average ransomware recovery cost of **$2.7 million** and an average hospital downtime of **18 days**. The ten-day downtime assumption used here is therefore below the sector average and close to the **11-day EHR outage** in the comparable hospital case.

The control does not claim to make ransomware unlikely. Its value comes from reducing how much of MedDefense can be affected after the first control fails.

---

# Risk 2 — Active Directory Compromise Through Identity Weaknesses

```yaml
Risk: An attacker compromises Active Directory and gains organization-wide privileged access

Source:
  Gap IDs: GAP-007, GAP-011, GAP-001
  Vulnerability Findings: Finding 007, Finding 021
  Threat Actor: Ransomware Groups / Organized Crime; Insider — Malicious

Asset: Active Directory — ad-dc-01 (A-005) and ad-dc-02 (A-006)

Asset Value (AV): $1,000,000
  Replacement/recovery cost: $250,000
  Revenue loss during downtime: $125,000 per day × 4 days = $500,000
  Regulatory penalties: $100,000
  Reputation/patient trust impact: $150,000

Exposure Factor (EF): 70%
  Reasoning: >
    Active Directory is a shared dependency for authentication across
    MedDefense. Project 1x02 concluded that Finding 007 could create the
    broadest enterprise-wide damage if identity compromise led to privileged AD
    control. A successful compromise could affect accounts, Group Policy,
    access to Critical systems and ransomware deployment. Redundancy through
    ad-dc-02 prevents treating the exposure as a complete 100% asset loss.

SLE: $1,000,000 × 0.70 = $700,000

ARO: 0.30 per year
  Reasoning: >
    AD appears directly in the ransomware and retained-insider attack paths.
    Project 1x01 identifies valid credentials and privilege escalation as
    recurring mechanisms, while Project 1x02 confirms LDAP-signing weakness on
    ad-dc-01 and incomplete central event forwarding on ad-dc-02. The event is
    less frequent than general phishing attempts, so the ARO is below the
    ransomware scenario's 0.35.

ALE: $700,000 × 0.30 = $210,000

Proposed Control: >
  Discover unsigned LDAP clients and enforce LDAP signing on the domain
  controllers, with controlled compatibility testing and verification.

Control Annual Cost: $1,000
  Note: >
    This is the Project 1x02 planning cost for Finding 007 remediation. It does
    not represent the cost of a future full PAM platform.

Estimated ALE After Control: $168,000
  New EF: 70%
  New ARO: 0.24
  Calculation: $1,000,000 × 0.70 × 0.24 = $168,000
  Reasoning: >
    LDAP signing removes an important relay/manipulation path but does not
    eliminate phishing, stolen credentials or all privileged-access risk.
    The Exposure Factor is therefore unchanged and the ARO receives only a
    modest reduction.

Net Benefit: $210,000 - $168,000 - $1,000 = $41,000
```

### Assessment

Finding 007 is important because the affected asset is not simply another server. Active Directory is an **access multiplier**. Project 1x02 explicitly concluded that privileged compromise of AD could have a broader blast radius than compromise of a single application host.

The cost-benefit result also shows why this control is attractive: even a modest reduction in the likelihood of AD compromise produces a positive annual net benefit because the remediation cost is low.

---

# Risk 3 — Opportunistic Compromise of `billing-srv-01`

```yaml
Risk: An opportunistic attacker compromises billing-srv-01 and uses it as an internal foothold

Source:
  Gap IDs: GAP-016, GAP-001, GAP-011, GAP-007
  Vulnerability Findings: Finding 001, Finding 002, Finding 009, Finding 011, Finding 026
  Threat Actor: Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime

Asset: billing-srv-01 (A-004)

Asset Value (AV): $650,000
  Replacement/recovery cost: $200,000
  Revenue loss during downtime: $80,000 per day × 4 days = $320,000
  Regulatory penalties: $50,000
  Reputation/patient trust impact: $80,000

Exposure Factor (EF): 60%
  Reasoning: >
    The billing server is a High rather than Critical clinical asset, but it has
    multiple compounding weaknesses. Finding 001 can provide an Apache foothold,
    Finding 002 can support local privilege escalation, password-based SSH is
    enabled, and the host remains on an unsupported Ubuntu platform. Because
    GAP-001 allows a compromised server to become a wider internal foothold, a
    successful event can exceed the direct value of the billing workload.

SLE: $650,000 × 0.60 = $390,000

ARO: 0.60 per year
  Reasoning: >
    Project 1x01 rated MedDefense's exposure to opportunistic exploitation High.
    billing-srv-01 has already suffered ransomware and later showed a recurring
    crypto-miner pattern, demonstrating that compromise of this host is not
    theoretical. Public exploit material also exists for the Apache findings.

ALE: $390,000 × 0.60 = $234,000

Proposed Control: >
  Upgrade Apache, disable SSH password authentication in favor of approved
  keys, migrate the billing workload to a supported Ubuntu LTS platform and
  verify the replacement through rescanning.

Control Annual Cost: $19,500
  Cost components:
    Apache remediation: $1,000
    SSH hardening: $500
    Supported Ubuntu migration: $18,000
  Note: >
    These are first-year Project 1x02 planning costs. Normal future patching
    and operating cost were not separately quantified.

Estimated ALE After Control: $39,000
  New EF: 40%
  New ARO: 0.15
  Calculation: $650,000 × 0.40 × 0.15 = $39,000
  Reasoning: >
    Removing the known Apache weaknesses, eliminating password-based SSH and
    moving off unsupported Ubuntu substantially reduces repeat compromise
    likelihood. Residual risk remains because no server can be assumed
    invulnerable and the broader network architecture still matters.

Net Benefit: $234,000 - $39,000 - $19,500 = $175,500
```

### Assessment

This risk produces the **second-highest ALE** in the workshop even though billing is not MedDefense's most critical asset. The reason is frequency: this server has already experienced serious compromise and still contains several weaknesses that commodity attackers can exploit.

This is a good example of why quantitative risk is not the same thing as ranking systems only by clinical criticality.

---

# Risk 4 — Exploitation of the Unsupported MRI Workstation

```yaml
Risk: An attacker exploits the Windows XP MRI control workstation and disrupts Radiology operations

Source:
  Gap IDs: GAP-006, GAP-001, GAP-011, GAP-016
  Vulnerability Findings: Finding 004, Finding 012
  Threat Actor: Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime

Asset: WS-RAD-01 — MRI control workstation (A-022)

Asset Value (AV): $850,000
  Replacement/recovery cost: $350,000
  Revenue loss during downtime: $90,000 per day × 3 days = $270,000
  Regulatory penalties: $80,000
  Reputation/patient trust impact: $150,000

Exposure Factor (EF): 55%
  Reasoning: >
    The workstation supports a Critical imaging workflow and contains mature
    legacy RDP/SMB exploitation paths, including BlueKeep and MS17-010-class
    exposure. A compromise could stop MRI operations and provide an internal
    foothold. The impact is below 100% because the workstation is one component
    of the wider imaging environment and alternative/manual clinical processes
    may reduce the total loss.

SLE: $850,000 × 0.55 = $467,500

ARO: 0.35 per year
  Reasoning: >
    Finding 004 has very high exploit maturity and Project 1x02 treats it as an
    Immediate Critical priority. However, the host is internal rather than
    confirmed Internet-facing, so an attacker normally needs an existing
    internal foothold or trusted path before exploiting it. This keeps the ARO
    below the billing server's repeated-compromise estimate.

ALE: $467,500 × 0.35 = $163,625

Proposed Control: >
  Isolate WS-RAD-01 in a dedicated MRI/Radiology security zone, block
  general-network RDP/SMB and allow only vendor-validated PACS and management
  traffic while planning eventual supported replacement.

Control Annual Cost: $7,000
  Note: >
    This is the existing Project 1x00 / 1x02 first-year planning allocation for
    the MRI compensating-control programme.

Estimated ALE After Control: $30,600
  New EF: 30%
  New ARO: 0.12
  Calculation: $850,000 × 0.30 × 0.12 = $30,600
  Reasoning: >
    Isolation reduces both reachability and blast radius. It does not remove
    the Windows XP vulnerabilities, so residual risk remains until the platform
    is replaced.

Net Benefit: $163,625 - $30,600 - $7,000 = $126,025
```

### Assessment

The control produces a strong benefit even though it is only compensating. This is important because MedDefense cannot patch Windows XP back into vendor support. The ALE calculation therefore supports the earlier risk-treatment decision: **isolate now, replace later**.

---

# Risk 5 — Compromise or Disruption of the BD Alaris Pump Environment

```yaml
Risk: Unauthorized access to the Alaris environment disrupts medication delivery or unsafe device configuration

Source:
  Gap IDs: GAP-003, GAP-018, GAP-001, GAP-011
  Vulnerability Findings: Finding 010
  Threat Actor: Insider — Malicious; Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime

Asset: BD Alaris infusion-pump estate (A-032)

Asset Value (AV): $1,200,000
  Replacement/recovery cost: $300,000
  Revenue loss during downtime: $100,000 per day × 2 days = $200,000
  Regulatory penalties: $300,000
  Reputation/patient trust impact: $400,000

Exposure Factor (EF): 45%
  Reasoning: >
    The pump estate supports direct medication delivery, so Integrity and
    Availability failures can become patient-safety events rather than only IT
    incidents. The EF is kept below the MRI and EHR values because the exact
    Finding 010 CVE applicability is not confirmed and a cyber event would not
    necessarily compromise every pump simultaneously.

SLE: $1,200,000 × 0.45 = $540,000

ARO: 0.20 per year
  Reasoning: >
    Project 1x01 explicitly models an insider path to the Alaris environment in
    Kill Chain 5, and medical IoT is broadly reachable because the 10.10.3.0/24
    range is not an enforced security boundary. However, Project 1x02 found that
    MedDefense's recorded Alaris version may already address CVE-2020-25165.
    The broader isolation and credential-hardening gaps remain real, but this
    uncertainty supports a lower ARO than the confirmed billing and MRI
    exposures.

ALE: $540,000 × 0.20 = $108,000

Proposed Control: >
  Create a dedicated medical-IoT security zone for the Alaris estate, allow
  only vendor-required Systems Manager and infrastructure flows, restrict
  management access, validate device versions and monitor unexpected traffic.

Control Annual Cost: $18,000
  Note: >
    This is the Project 1x00 planning allocation for medical-IoT isolation and
    monitoring. It covers the broader device-security programme rather than one
    CVE patch.

Estimated ALE After Control: $24,000
  New EF: 25%
  New ARO: 0.08
  Calculation: $1,200,000 × 0.25 × 0.08 = $24,000
  Reasoning: >
    Dedicated segmentation substantially reduces who can reach the pump
    environment and limits the impact of a compromised device. Version
    validation and traffic monitoring also reduce the chance that an exploitable
    condition persists unnoticed.

Net Benefit: $108,000 - $24,000 - $18,000 = $66,000
```

### Assessment

The specific scanner match for **Finding 010 / CVE-2020-25165 must not be treated as confirmed**. Project 1x02 found that MedDefense records Alaris version 12.1.2 and that the older CVE may already be addressed for the relevant component.

The investment case remains valid because the broader risk is independently supported by **GAP-003**, **GAP-018**, the flat internal network and later vendor security guidance. The control is therefore justified as **medical-IoT risk reduction**, not as a claim that one unverified CVE will definitely be exploited.

---

# Risk Prioritization by ALE

| Rank | Risk | AV | EF | SLE | ARO | ALE Before Control | Control Cost | ALE After Control | Net Benefit |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **1** | Ransomware double extortion against EHR | $5,000,000 | 60% | $3,000,000 | 0.35 | **$1,050,000** | $25,000 | $612,500 | **$412,500** |
| **2** | Opportunistic compromise of `billing-srv-01` | $650,000 | 60% | $390,000 | 0.60 | **$234,000** | $19,500 | $39,000 | **$175,500** |
| **3** | Active Directory privileged compromise | $1,000,000 | 70% | $700,000 | 0.30 | **$210,000** | $1,000 | $168,000 | **$41,000** |
| **4** | Windows XP MRI exploitation/disruption | $850,000 | 55% | $467,500 | 0.35 | **$163,625** | $7,000 | $30,600 | **$126,025** |
| **5** | Alaris pump environment compromise/disruption | $1,200,000 | 45% | $540,000 | 0.20 | **$108,000** | $18,000 | $24,000 | **$66,000** |

---

# Investment Summary

The quantitative analysis reinforces several conclusions from the earlier projects.

First, **ransomware against the EHR remains the dominant financial risk**. Even after segmentation, the residual ALE remains high because segmentation limits impact but does not stop phishing, credential theft or every ransomware attempt.

Second, the billing server shows why **frequency matters**. Its asset value is much lower than the EHR or Alaris estate, but repeated compromise history and multiple confirmed vulnerabilities produce the second-highest ALE.

Third, some low-cost controls have strong economic justification. LDAP-signing remediation costs approximately **$1,000** in the existing plan and produces a positive modeled net benefit even when only a modest reduction in AD-compromise likelihood is assumed.

Finally, controls do not need to eliminate risk to be financially justified. The five modeled treatments reduce combined annualized risk while addressing the same structural weaknesses repeatedly identified across Projects 1x00–1x02.

## Combined Model

```text
Total ALE before controls:
$1,050,000 + $234,000 + $210,000 + $163,625 + $108,000
= $1,765,625

Total modeled first-year control cost:
$25,000 + $19,500 + $1,000 + $7,000 + $18,000
= $70,500

Total ALE after controls:
$612,500 + $39,000 + $168,000 + $30,600 + $24,000
= $874,100

Total modeled net benefit:
$1,765,625 - $874,100 - $70,500
= $821,025
```

The **$70,500** control total is not a new budget to add on top of previous project allocations. These controls reuse planning allocations and remediation costs already identified in Projects 1x00 and 1x02. The purpose of this workshop is to test whether those investments are economically justified against the risks they address.

---

# Evidence Basis

This workshop cross-references the following prior MedDefense work:

- Project 1x00 `7-asset_registry.md`
- Project 1x00 `8-criticality_assessment.md`
- Project 1x00 `14-risk_decisions.md`
- Project 1x00 `16-security_posture_assessment.md`
- Project 1x01 `2-ransomware_assessment.md`
- Project 1x01 `10-kill_chains.md`
- Project 1x01 `15-gap_threat_correlation.md`
- Project 1x01 `16-threat_priority_assessment.md`
- Project 1x01 `18-threat_landscape_report.md`
- Project 1x02 `17-cvss_contextualizer.md`
- Project 1x02 `18-threat_vuln_correlation.md`
- Project 1x02 `20-priority_matrix.md`
- Project 1x02 `21-vulnerability_assessment.md`
