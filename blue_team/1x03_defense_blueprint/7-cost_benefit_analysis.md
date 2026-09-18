# 7. The Cost-Benefit Analysis

## Purpose

This analysis evaluates eight proposed MedDefense security controls using formal cost-benefit analysis.

A control is financially justified when:

> **ALE Reduction > Annual Cost**

Where:

```text
ALE Reduction = ALE Before Control - ALE After Control
Net Value = ALE Reduction - Annual Cost
```

The Task 6 ALE baseline is:

| T6 Risk | Risk | ALE Before Control |
|---|---|---:|
| **Risk 1** | Ransomware double extortion against the EHR | **$1,050,000** |
| **Risk 2** | Active Directory privileged compromise | **$210,000** |
| **Risk 3** | Opportunistic compromise of `billing-srv-01` | **$234,000** |
| **Risk 4** | Windows XP MRI exploitation/disruption | **$163,625** |
| **Risk 5** | Alaris pump environment compromise/disruption | **$108,000** |

> **Important modeling rule:** Each control is evaluated independently against the current Task 6 baseline. Several controls address the same risk, especially ransomware. Their ALE reductions therefore **overlap and must not be added together as if they were independent savings**.

> **Cost note:** Costs are Year-1 annual planning estimates for the $120,000 MedDefense security budget. Where a prior project already established a planning allocation, that figure is retained. New estimates are identified as assumptions rather than vendor quotations.

## Verdict Scale

- **Justified** — ALE reduction clearly exceeds annual cost.
- **Marginal** — ALE reduction exceeds annual cost, but the margin is small or highly dependent on assumptions.
- **Not Justified** — annual cost is greater than the modeled ALE reduction.

---

# Control 1 — Network Segmentation

```yaml
Control 1: Network segmentation
CIS Control Reference: CIS Control 12 — Network Infrastructure Management

Annual Cost: $25,000
  License / network changes: $8,000
  Implementation labor: $12,000
  Maintenance / rule review: $5,000
  Assumption: >
    Uses the existing Project 1x00 first-year planning allocation for GAP-001.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 2 — Active Directory privileged compromise
  - Risk 3 — Opportunistic compromise of billing-srv-01
  - Risk 4 — Windows XP MRI exploitation/disruption
  - Risk 5 — Alaris pump environment compromise/disruption

ALE Reduction: $437,500
  ALE before: $1,050,000
  ALE after: $612,500
  Calculation: $1,050,000 - $612,500 = $437,500
  Assumption: >
    To remain conservative and directly traceable to Task 6, only the quantified
    Risk 1 reduction is counted here. Segmentation also reduces blast radius for
    Risks 2-5, but those additional benefits are not added to the financial case.

Net Value: $437,500 - $25,000 = $412,500

Verdict: Justified

Recommendation: Implement — the control has the highest modeled net value and breaks lateral-movement paths that recur across multiple MedDefense threats.
```

### Why the ALE Changes

Task 6 modeled segmentation as reducing the EHR ransomware **Exposure Factor from 60% to 35%** while leaving the attack frequency unchanged.

```text
Before:
$5,000,000 AV × 60% EF × 0.35 ARO = $1,050,000 ALE

After segmentation:
$5,000,000 AV × 35% EF × 0.35 ARO = $612,500 ALE

ALE reduction:
$1,050,000 - $612,500 = $437,500
```

Segmentation is valuable because it does not depend on stopping every phishing attempt. It limits how far an attacker can move after an initial foothold.

---

# Control 2 — MFA on VPN and Administrative Accounts

```yaml
Control 2: MFA deployment on VPN and administrative accounts
CIS Control Reference: CIS Control 6 — Access Control Management

Annual Cost: $4,000
  Incremental license cost: $0
  Implementation labor: $3,000
  Maintenance / enrollment support: $1,000
  Assumption: >
    The task specifies use of MedDefense's existing O365 E3 licenses, so no
    additional license charge is included.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 2 — Active Directory privileged compromise

ALE Reduction: $280,000
  Risk 1 reduction: $210,000
  Risk 2 reduction: $70,000

Net Value: $280,000 - $4,000 = $276,000

Verdict: Justified

Recommendation: Implement — the incremental cost is very low and the control directly reduces the usefulness of stolen remote and privileged credentials.
```

### Risk 1 Calculation

MFA does not eliminate ransomware, because phishing, vulnerable software and compromised endpoints still exist. It is modeled as reducing the Risk 1 ARO from **0.35 to 0.28**.

```text
SLE remains: $3,000,000

ALE before:
$3,000,000 × 0.35 = $1,050,000

ALE after MFA:
$3,000,000 × 0.28 = $840,000

Risk 1 ALE reduction:
$1,050,000 - $840,000 = $210,000
```

### Risk 2 Calculation

For Active Directory compromise, MFA is modeled as reducing ARO from **0.30 to 0.20**.

```text
SLE remains: $700,000

ALE before:
$700,000 × 0.30 = $210,000

ALE after MFA:
$700,000 × 0.20 = $140,000

Risk 2 ALE reduction:
$210,000 - $140,000 = $70,000
```

```text
Total ALE reduction:
$210,000 + $70,000 = $280,000
```

---

# Control 3 — Enterprise SIEM Using Wazuh

```yaml
Control 3: Enterprise SIEM deployment using Wazuh
CIS Control Reference: CIS Control 8 — Audit Log Management

Annual Cost: $22,000
  Software license: $0
  Deployment / integration labor: $14,000
  Ongoing tuning / review labor: $8,000
  Assumption: >
    Wazuh is treated as open-source as specified in the task. The cost is labor
    for log onboarding, rules, tuning, alert review and maintenance.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 2 — Active Directory privileged compromise
  - Risk 3 — Opportunistic compromise of billing-srv-01
  - Risk 5 — Alaris pump environment compromise/disruption

ALE Reduction: $215,000
  Risk 1 reduction: $140,000
  Risk 2 reduction: $24,000
  Risk 3 reduction: $39,000
  Risk 5 reduction: $12,000

Net Value: $215,000 - $22,000 = $193,000

Verdict: Justified

Recommendation: Implement — MedDefense already produces useful security logs, and centralized correlation addresses GAP-011 without the cost of immediate 24/7 SOC staffing.
```

### Modeling Assumption

A SIEM is primarily a **detection and response** control. It does not stop the initial attempt, so the model reduces Exposure Factor rather than pretending that the threat disappears.

#### Risk 1 — EHR Ransomware

```text
Before:
$5,000,000 × 60% × 0.35 = $1,050,000

After SIEM:
$5,000,000 × 52% × 0.35 = $910,000

Reduction = $140,000
```

#### Risk 2 — Active Directory

```text
Before:
$1,000,000 × 70% × 0.30 = $210,000

After SIEM:
$1,000,000 × 62% × 0.30 = $186,000

Reduction = $24,000
```

#### Risk 3 — `billing-srv-01`

```text
Before:
$650,000 × 60% × 0.60 = $234,000

After SIEM:
$650,000 × 50% × 0.60 = $195,000

Reduction = $39,000
```

#### Risk 5 — Alaris Environment

```text
Before:
$1,200,000 × 45% × 0.20 = $108,000

After SIEM:
$1,200,000 × 40% × 0.20 = $96,000

Reduction = $12,000
```

```text
Total ALE reduction:
$140,000 + $24,000 + $39,000 + $12,000
= $215,000
```

---

# Control 4 — Offsite Immutable Backup Replication

```yaml
Control 4: Offsite backup replication using AWS S3 Glacier / immutable storage
CIS Control Reference: CIS Control 11 — Data Recovery

Annual Cost: $15,000
  Cloud storage / replication: $8,000
  Setup and integration labor: $4,000
  Restore testing / maintenance: $3,000
  Assumption: >
    This is a planning estimate. Final cost depends on retained data volume,
    retention period, retrieval frequency and actual AWS configuration.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 3 — Opportunistic compromise of billing-srv-01

ALE Reduction: $321,000
  Risk 1 reduction: $262,500
  Risk 3 reduction: $58,500

Net Value: $321,000 - $15,000 = $306,000

Verdict: Justified

Recommendation: Implement — immutable offsite recovery materially reduces ransomware and destructive-compromise impact at a relatively low annual cost.
```

### Risk 1 Calculation

Backups do not prevent patient-data theft, so the model does **not** reduce ransomware ARO. Instead, resilient recovery reduces the Exposure Factor from **60% to 45%**.

```text
Before:
$5,000,000 × 60% × 0.35 = $1,050,000

After offsite immutable backup:
$5,000,000 × 45% × 0.35 = $787,500

Risk 1 reduction:
$1,050,000 - $787,500 = $262,500
```

### Risk 3 Calculation

For the billing server, the EF is reduced from **60% to 45%** because recovery is faster even if the host is compromised.

```text
Before:
$650,000 × 60% × 0.60 = $234,000

After backup control:
$650,000 × 45% × 0.60 = $175,500

Risk 3 reduction:
$234,000 - $175,500 = $58,500
```

```text
Total ALE reduction:
$262,500 + $58,500 = $321,000
```

---

# Control 5 — Endpoint Detection and Response Upgrade

```yaml
Control 5: Upgrade Sophos basic protection to Sophos Intercept X across endpoints and servers
CIS Control Reference: CIS Control 10 — Malware Defenses

Annual Cost: $36,000
  Subscription uplift: $27,000
  Deployment labor: $5,000
  Ongoing administration / maintenance: $4,000
  Assumption: >
    Planning estimate based on roughly 400 managed endpoints and servers.
    Actual licensing must be validated against MedDefense's final endpoint count
    and negotiated vendor pricing.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 2 — Active Directory privileged compromise
  - Risk 3 — Opportunistic compromise of billing-srv-01

ALE Reduction: $298,500
  Risk 1 reduction: $180,000
  Risk 2 reduction: $21,000
  Risk 3 reduction: $97,500

Net Value: $298,500 - $36,000 = $262,500

Verdict: Justified

Recommendation: Implement — EDR directly reduces endpoint execution, persistence and credential-theft opportunities that feed the highest-priority ransomware and privilege-escalation paths.
```

### Risk 1 Calculation

EDR is modeled as reducing ransomware ARO from **0.35 to 0.29**.

```text
Before:
$3,000,000 SLE × 0.35 = $1,050,000

After EDR:
$3,000,000 × 0.29 = $870,000

Reduction = $180,000
```

### Risk 2 Calculation

EDR can detect credential dumping and malicious activity on endpoints before AD compromise. The AD ARO is modeled as falling from **0.30 to 0.27**.

```text
Before:
$700,000 × 0.30 = $210,000

After EDR:
$700,000 × 0.27 = $189,000

Reduction = $21,000
```

### Risk 3 Calculation

The billing-server risk ARO is modeled as falling from **0.60 to 0.35**.

```text
Before:
$390,000 SLE × 0.60 = $234,000

After EDR:
$390,000 × 0.35 = $136,500

Reduction = $97,500
```

```text
Total ALE reduction:
$180,000 + $21,000 + $97,500
= $298,500
```

---

# Control 6 — Dedicated Westside Clinic Firewall

```yaml
Control 6: Dedicated enterprise firewall for Westside Clinic
CIS Control Reference: CIS Control 12 — Network Infrastructure Management

Annual Cost: $15,000
  Firewall / security subscription: $8,000
  Installation and migration labor: $4,000
  Maintenance / support: $3,000
  Assumption: >
    Retains the existing Project 1x00 and 1x02 planning allocation for replacing
    the Westside consumer router.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR

ALE Reduction: $30,000
  ALE before: $1,050,000
  ALE after: $1,020,000
  Modeling change: Risk 1 ARO reduced from 0.35 to 0.34

Net Value: $30,000 - $15,000 = $15,000

Verdict: Marginal

Recommendation: Defer — the control has positive value and closes a documented site-edge weakness, but its financial return is much smaller than the higher-leverage controls competing for the same $120,000 budget.
```

### Why the Reduction Is Limited

Westside is only **one possible entry route** into MedDefense. Replacing the consumer router improves the clinic perimeter and VPN boundary, but it does not materially reduce phishing, compromised credentials, EHR database exposure or attacks originating at Central.

```text
Risk 1 SLE = $3,000,000

Before:
$3,000,000 × 0.35 = $1,050,000

After Westside firewall:
$3,000,000 × 0.34 = $1,020,000

ALE reduction:
$30,000
```

This is still a worthwhile security improvement, but it is sensitive to the assumed proportion of ransomware risk attributable to the Westside path.

---

# Control 7 — Outsourced 24/7 Security Operations Center

```yaml
Control 7: 24/7 Security Operations Center staffing through an outsourced managed SOC
CIS Control Reference: CIS Control 13 — Network Monitoring and Defense

Annual Cost: $240,000
  Managed SOC service: $216,000
  Onboarding / integration labor: $12,000
  Internal oversight / service management: $12,000
  Assumption: >
    Planning estimate for continuous external monitoring. Exact pricing would
    depend on log volume, endpoint count, response scope and service-level
    agreement.

Risk(s) Addressed:
  - Risk 1 — Ransomware double extortion against the EHR
  - Risk 2 — Active Directory privileged compromise
  - Risk 3 — Opportunistic compromise of billing-srv-01
  - Risk 4 — Windows XP MRI exploitation/disruption
  - Risk 5 — Alaris pump environment compromise/disruption

ALE Reduction: $161,575

Net Value: $161,575 - $240,000 = -$78,425

Verdict: Not Justified

Recommendation: Reject — 24/7 managed SOC coverage costs more than the modeled annual risk reduction and should not be purchased before MedDefense has built the cheaper SIEM/logging foundation.
```

### ALE Calculation

The managed SOC is modeled conservatively as reducing **impact through earlier detection**, not eliminating the underlying vulnerabilities.

#### Risk 1

```text
Before: $1,050,000
After:  $5,000,000 × 54% × 0.35 = $945,000
Reduction: $105,000
```

#### Risk 2

```text
Before: $210,000
After:  $1,000,000 × 65% × 0.30 = $195,000
Reduction: $15,000
```

#### Risk 3

```text
Before: $234,000
After:  $650,000 × 55% × 0.60 = $214,500
Reduction: $19,500
```

#### Risk 4

```text
Before: $163,625
After:  $850,000 × 50% × 0.35 = $148,750
Reduction: $14,875
```

#### Risk 5

```text
Before: $108,000
After:  $1,200,000 × 42% × 0.20 = $100,800
Reduction: $7,200
```

```text
Total ALE reduction:
$105,000 + $15,000 + $19,500 + $14,875 + $7,200
= $161,575

Net Value:
$161,575 - $240,000
= -$78,425
```

The negative value does **not** mean monitoring is unnecessary. It means MedDefense should first build centralized logging and SIEM capability at a much lower cost instead of buying a full 24/7 managed SOC immediately.

---

# Control 8 — Full Medical Device Network Isolation and Monitoring

```yaml
Control 8: Full medical device network isolation with dedicated monitoring
CIS Control Reference: CIS Control 12 — Network Infrastructure Management

Annual Cost: $18,000
  Network / security changes: $6,000
  Clinical engineering and implementation labor: $9,000
  Monitoring / maintenance: $3,000
  Assumption: >
    Retains the Project 1x00 planning allocation for GAP-003 medical-IoT
    isolation and monitoring.

Risk(s) Addressed:
  - Risk 5 — Alaris pump environment compromise/disruption

ALE Reduction: $84,000
  ALE before: $108,000
  ALE after: $24,000
  Calculation: $108,000 - $24,000 = $84,000

Net Value: $84,000 - $18,000 = $66,000

Verdict: Justified

Recommendation: Implement — the control produces a positive financial return and also reduces a direct patient-safety exposure that cannot be treated as an ordinary endpoint risk.
```

### Task 6 Calculation Reused

Task 6 modeled dedicated device isolation as reducing both the probability of unauthorized reachability and the potential blast radius.

```text
Before:
$1,200,000 × 45% × 0.20 = $108,000

After:
$1,200,000 × 25% × 0.08 = $24,000

ALE reduction:
$108,000 - $24,000 = $84,000
```

The control remains justified even though the specific Finding 010 CVE match is validation-gated. The broader isolation and monitoring weakness is independently supported by GAP-003, GAP-018 and the flat medical-device network.

---

# Cost-Benefit Summary

## Ranked by Net Value

| Rank | Control | CIS Control | Annual Cost | ALE Reduction | Net Value | Verdict | Budget Decision |
|---:|---|---|---:|---:|---:|---|---|
| **1** | Network segmentation | **12** | $25,000 | $437,500 | **$412,500** | Justified | **Fund** |
| **2** | Offsite immutable backup replication | **11** | $15,000 | $321,000 | **$306,000** | Justified | **Fund** |
| **3** | MFA on VPN/admin accounts | **6** | $4,000 | $280,000 | **$276,000** | Justified | **Fund** |
| **4** | Sophos Intercept X EDR upgrade | **10** | $36,000 | $298,500 | **$262,500** | Justified | **Fund** |
| **5** | Wazuh SIEM | **8** | $22,000 | $215,000 | **$193,000** | Justified | **Fund** |
| **6** | Medical-device isolation and monitoring | **12** | $18,000 | $84,000 | **$66,000** | Justified | **Fund** |
| **7** | Westside enterprise firewall | **12** | $15,000 | $30,000 | **$15,000** | Marginal | **Defer** |
| **8** | Outsourced 24/7 SOC | **13** | $240,000 | $161,575 | **-$78,425** | Not Justified | **Reject** |

---

# $120,000 Budget Fit

All controls except the outsourced SOC are individually below the $120,000 annual budget, but the seven positive-value controls **cannot all be funded together**.

```text
Control 1 — Network segmentation:          $25,000
Control 2 — MFA:                            $4,000
Control 3 — Wazuh SIEM:                    $22,000
Control 4 — Offsite immutable backup:      $15,000
Control 5 — EDR upgrade:                   $36,000
Control 8 — Medical-device isolation:      $18,000
---------------------------------------------------
Selected annual programme:                $120,000
Annual security budget:                   $120,000
Remaining headroom:                            $0
```

## Controls That Fit in the Recommended $120,000 Portfolio

- **Control 1 — Network segmentation**
- **Control 2 — MFA**
- **Control 3 — Wazuh SIEM**
- **Control 4 — Offsite immutable backup**
- **Control 5 — EDR upgrade**
- **Control 8 — Medical-device isolation and monitoring**

## Deferred

**Control 6 — Westside enterprise firewall** is financially positive but marginal compared with the other controls. Funding it as well would increase the programme to:

```text
$120,000 + $15,000 = $135,000
```

It should therefore move to the next funding cycle unless savings are found elsewhere or the Board chooses to replace a higher-cost control with the Westside project.

## Rejected for This Budget Cycle

**Control 7 — Outsourced 24/7 SOC** should not be funded under the current $120,000 limit. Its estimated annual cost alone is approximately twice the entire security budget, and the modeled ALE reduction does not recover the cost.

---

# CFO Interpretation

The analysis does not support spending the budget evenly across eight controls.

The strongest financial case is **network segmentation**, with an estimated **$412,500 net annual value** even when only the quantified ransomware benefit from Task 6 is counted. Offsite immutable backup, MFA, EDR and SIEM also show strong positive returns.

The Westside firewall remains a valid security improvement, but its **$15,000 net value** is much more assumption-sensitive because Westside represents only one possible attack route into MedDefense. It therefore loses the current budget competition despite being individually cost-justified.

The outsourced 24/7 SOC is the clearest example of a control that is **not yet economically justified**. MedDefense can obtain much of the immediate detection benefit by first centralizing existing logs with Wazuh for approximately **$22,000**, then reconsider 24/7 managed monitoring after the security programme and budget mature.

The resulting $120,000 portfolio concentrates spending on controls that either:

1. reduce the likelihood of compromise;
2. limit lateral movement and blast radius;
3. improve detection before impact;
4. preserve recovery capability; or
5. protect patient-safety-critical medical devices.

This is a stronger investment argument than purchasing controls because they are considered industry best practice.

---

# Evidence and Assumptions

This analysis uses the following MedDefense project evidence:

- Project 1x00 Asset Registry and Criticality Assessment
- Project 1x00 Risk Treatment Decisions
- Project 1x01 Threat Landscape and ransomware intelligence
- Project 1x01 Kill Chains and threat-informed gap reprioritization
- Project 1x02 Vulnerability Assessment and remediation costs
- Project 1x03 Task 6 `6-ale_workshop.md`

New cost estimates in this task are planning assumptions where no earlier MedDefense figure existed. They should be replaced with actual vendor quotations before procurement.

ALE changes are estimates, not guarantees. They are intended to compare investments consistently using the evidence available to MedDefense.
