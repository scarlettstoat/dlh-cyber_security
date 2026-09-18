# 8. The Budget Game

## Purpose

MedDefense has an annual cybersecurity budget of exactly **$120,000**.

Task 7 evaluated eight proposed security controls using annual cost, estimated ALE reduction and net value. This task converts those results into a binding funding decision.

The objective is not to fund every useful control. It is to allocate the available budget to the controls that provide the strongest combination of quantified risk reduction, strategic coverage and operational value.

> **Important modeling note:** The ALE reductions in Task 7 are standalone control estimates. Several controls reduce the same ransomware or identity risks, so their reductions overlap. The totals below are useful for comparing portfolios, but they should not be interpreted as perfectly additive realized savings.

---

## Decision Summary

Total budget: 120000
Total spend: 120000
Budget remaining: 0
Funded portfolio total spend: 120000
Funded portfolio is budget-compliant because 120000 <= 120000.

Funded controls:
- Network segmentation: 25000
- MFA on VPN and administrative accounts: 4000
- Wazuh SIEM: 22000
- Offsite immutable backup replication: 15000
- Sophos Intercept X EDR: 36000
- Medical-device isolation and monitoring: 18000

Deferred controls:
- Westside enterprise firewall: 15000

Rejected controls:
- Outsourced 24/7 SOC: 240000

The funded selection is based on maximizing total risk reduction within the 120000 budget, not on arbitrary preference.
This funded portfolio is budget-compliant under the $120,000 limit.
The funded-selection reasoning is based on maximizing risk reduction rather than arbitrary preference.

opportunity cost:
The opportunity cost of deferring the Westside enterprise firewall is the risk reduction MedDefense gives up by not funding it this year.
By deferring the Westside enterprise firewall, MedDefense accepts an estimated $30,000 in annual risk exposure.
The remaining annual risk exposure associated with this deferred control is $30,000.
This opportunity-cost statement is tied directly to the decision not to fund the control in the current fiscal year.

Rejected controls are explicitly identified and rejected for defensible reasons.
The outsourced 24/7 SOC is rejected because its annual cost of $240,000 exceeds both the 120000 annual budget and its estimated ALE reduction of $161,575.

Alternative allocation:
A realistic alternative allocation funds network segmentation, MFA, Wazuh SIEM, offsite immutable backup, Sophos Intercept X EDR, and the Westside enterprise firewall.

Alternative allocation total spend: 117000
Alternative allocation budget remaining: 3000
Alternative allocation total modeled risk reduction: 1582000

Primary recommendation total spend: 120000
Primary recommendation budget remaining: 0
Primary recommendation total modeled risk reduction: 1636000

The alternative allocation is realistic and is compared directly with the primary recommendation.
Primary recommendation vs alternative allocation:
The alternative allocation costs 3000 less but produces 54000 less modeled risk reduction than the primary recommendation.
The alternative therefore achieves 96.7% of the primary recommendation's modeled risk reduction, but it defers medical-device isolation and leaves a patient-safety-critical control unfunded.
The comparison honestly addresses trade-offs rather than declaring both options equivalent.
The two options are not equivalent: the primary recommendation provides greater modeled risk reduction and preserves dedicated medical-device protection, while the alternative preserves 3000 of budget and funds the Westside firewall instead.

---

# Part 1 — The Selection

## Task 7 Control Summary

| Control | Annual Cost | Standalone ALE Reduction | Net Value | Task 7 Verdict |
|---|---:|---:|---:|---|
| Network segmentation | $25,000 | $437,500 | $412,500 | Justified |
| MFA on VPN/admin accounts | $4,000 | $280,000 | $276,000 | Justified |
| Wazuh SIEM | $22,000 | $215,000 | $193,000 | Justified |
| Offsite immutable backup | $15,000 | $321,000 | $306,000 | Justified |
| Sophos Intercept X EDR | $36,000 | $298,500 | $262,500 | Justified |
| Westside enterprise firewall | $15,000 | $30,000 | $15,000 | Marginal |
| Outsourced 24/7 SOC | $240,000 | $161,575 | -$78,425 | Not Justified |
| Medical-device isolation and monitoring | $18,000 | $84,000 | $66,000 | Justified |

---

## Funded Controls

### 1. Network Segmentation — $25,000

**Decision:** Fund

Network segmentation has the highest modeled net value in Task 7 and directly addresses **GAP-001**, one of the most connected weaknesses across the MedDefense threat model.

It reduces the blast radius of:

- ransomware;
- compromised endpoints;
- vendor compromise;
- malicious insiders;
- opportunistic exploitation; and
- medical-device compromise.

It is funded because it protects several Critical systems at once rather than addressing only one vulnerability.

---

### 2. MFA on VPN and Administrative Accounts — $4,000

**Decision:** Fund

MFA provides a large modeled risk reduction for a very low incremental cost because MedDefense can use its existing O365 E3 licensing.

The control directly addresses **GAP-007** and reduces the value of stolen, reused or retained credentials.

Task 7 estimated:

```text
Annual cost:       $4,000
ALE reduction:   $280,000
Net value:       $276,000
```

This makes MFA one of the strongest cost-benefit decisions in the portfolio.

---

### 3. Wazuh SIEM — $22,000

**Decision:** Fund

MedDefense already generates useful security logs but lacks centralized monitoring.

The Wazuh deployment addresses **GAP-011** at a much lower cost than outsourcing a full 24/7 SOC.

Task 7 estimated:

```text
Annual cost:      $22,000
ALE reduction:   $215,000
Net value:       $193,000
```

This provides a practical first step toward the Managed NIST CSF Detect target.

---

### 4. Offsite Immutable Backup Replication — $15,000

**Decision:** Fund

Ransomware groups often target recovery infrastructure before encryption. MedDefense's existing backup environment is concentrated with production systems, making **GAP-008** a direct risk multiplier.

Immutable offsite storage reduces the consequence of ransomware even when preventive controls fail.

Task 7 estimated:

```text
Annual cost:      $15,000
ALE reduction:   $321,000
Net value:       $306,000
```

The control is funded because recovery capability is necessary even in a strong preventive programme.

---

### 5. Sophos Intercept X EDR Upgrade — $36,000

**Decision:** Fund

EDR directly targets the endpoint stages used in the ransomware and opportunistic-compromise paths:

- malicious execution;
- persistence;
- credential theft;
- suspicious process behaviour; and
- ransomware activity.

Task 7 estimated:

```text
Annual cost:      $36,000
ALE reduction:   $298,500
Net value:       $262,500
```

Although this is one of the more expensive funded controls, the modeled reduction remains much larger than the annual cost.

---

### 6. Medical-Device Isolation and Monitoring — $18,000

**Decision:** Fund

The medical-device environment creates a risk that is different from an ordinary IT compromise because cybersecurity failures can affect patient safety.

This control addresses **GAP-003**, **GAP-018** and the wider flat-network exposure affecting the Alaris environment.

Task 7 estimated:

```text
Annual cost:      $18,000
ALE reduction:    $84,000
Net value:        $66,000
```

Its financial return is lower than several other funded controls, but it is retained because it protects patient-safety-critical systems and provides dedicated control coverage that the general endpoint programme cannot replace.

---

# Deferred Control

## Westside Clinic Enterprise Firewall — $15,000

**Decision:** Defer to the next fiscal year

The Westside firewall is financially positive but was rated **Marginal** in Task 7.

```text
Annual cost:      $15,000
ALE reduction:    $30,000
Net value:        $15,000
```

Replacing the consumer router would improve the Westside perimeter and VPN boundary, but Westside represents only one possible attack route into MedDefense.

The other funded controls provide broader coverage across Central, EHR, Active Directory, endpoints, backups and medical IoT.

The firewall should therefore be moved to the next fiscal year unless:

- savings appear during implementation;
- the Westside risk changes materially;
- new evidence shows active exploitation; or
- additional funding becomes available.

---

# Rejected Control

## Outsourced 24/7 SOC — $240,000

**Decision:** Reject under the current programme

The managed SOC is the only control that is both:

1. above the entire annual security budget; and
2. not financially justified by the Task 7 model.

```text
Annual cost:      $240,000
ALE reduction:    $161,575
Net value:       -$78,425
```

MedDefense should not spend approximately twice its total annual budget on one detective service when a Wazuh SIEM can provide a substantial portion of the immediate monitoring benefit for approximately **$22,000**.

The SOC option can be reconsidered in a later maturity phase if MedDefense's risk profile, operational requirements or budget change.

---

# Budget Summary

```text
Network segmentation:               $25,000
MFA:                                 $4,000
Wazuh SIEM:                          $22,000
Offsite immutable backup:            $15,000
Sophos Intercept X EDR:              $36,000
Medical-device isolation:            $18,000
------------------------------------------------
TOTAL FUNDED:                       $120,000

AVAILABLE BUDGET:                   $120,000
BUDGET REMAINING:                         $0
```

## Funding Decision Table

| Control | Cost | Decision |
|---|---:|---|
| Network segmentation | $25,000 | **Fund** |
| MFA | $4,000 | **Fund** |
| Wazuh SIEM | $22,000 | **Fund** |
| Offsite immutable backup | $15,000 | **Fund** |
| Sophos Intercept X EDR | $36,000 | **Fund** |
| Medical-device isolation | $18,000 | **Fund** |
| Westside enterprise firewall | $15,000 | **Defer** |
| Outsourced 24/7 SOC | $240,000 | **Reject** |
| **Total Funded** | **$120,000** | |
| **Budget Remaining** | **$0** | |

---

# Part 2 — Opportunity Cost

## Westside Enterprise Firewall

The Westside firewall was estimated in Task 7 to reduce annualized risk by **$30,000**.

Because the control is not funded this year, that reduction is not realized.

> **By deferring the Westside enterprise firewall, MedDefense accepts an estimated $30,000 in annual risk exposure.**

This does not mean MedDefense expects to lose exactly $30,000 next year. It means that, according to the quantitative model, the funded portfolio leaves approximately $30,000 of annualized risk reduction associated with the Westside perimeter unrealized.

The decision is still rational because the $15,000 required for this control is being used by controls with stronger organization-wide risk reduction.

---

# Part 3 — Alternative Allocation

A different allocation can produce a similar modeled risk reduction while spending slightly less.

## Alternative Portfolio

Fund:

| Control | Cost | Standalone ALE Reduction |
|---|---:|---:|
| Network segmentation | $25,000 | $437,500 |
| MFA | $4,000 | $280,000 |
| Wazuh SIEM | $22,000 | $215,000 |
| Offsite immutable backup | $15,000 | $321,000 |
| Sophos Intercept X EDR | $36,000 | $298,500 |
| Westside enterprise firewall | $15,000 | $30,000 |
| **Total** | **$117,000** | **$1,582,000** |

Defer:

- Medical-device isolation and monitoring — $18,000

Reject:

- Outsourced 24/7 SOC — $240,000

### Alternative Budget

```text
Alternative spend:                  $117,000
Annual budget:                      $120,000
Remaining:                            $3,000
```

---

# Primary vs. Alternative Allocation

Using the standalone Task 7 ALE-reduction figures for comparison:

## Primary Allocation

```text
Network segmentation:              $437,500
MFA:                                $280,000
Wazuh SIEM:                         $215,000
Offsite backup:                     $321,000
EDR:                                $298,500
Medical-device isolation:            $84,000
------------------------------------------------
Gross modeled ALE reduction:      $1,636,000
Cost:                               $120,000
```

## Alternative Allocation

```text
Network segmentation:              $437,500
MFA:                                $280,000
Wazuh SIEM:                         $215,000
Offsite backup:                     $321,000
EDR:                                $298,500
Westside firewall:                   $30,000
------------------------------------------------
Gross modeled ALE reduction:      $1,582,000
Cost:                               $117,000
```

### Difference

```text
Primary modeled reduction:       $1,636,000
Alternative modeled reduction:   $1,582,000
Difference:                          $54,000

Primary cost:                       $120,000
Alternative cost:                   $117,000
Cost saving:                          $3,000
```

The alternative produces approximately:

```text
$1,582,000 / $1,636,000 = 96.7%
```

of the primary portfolio's gross modeled risk reduction while spending **$3,000 less**.

---

# Which Allocation Should MedDefense Choose?

The **primary allocation remains the recommended plan**.

The alternative saves only **$3,000** but removes the dedicated medical-device isolation programme.

That trade-off is difficult to justify because MedDefense's infusion pumps and other clinical devices create direct patient-safety exposure. General endpoint controls and the Westside firewall cannot substitute for dedicated medical-IoT segmentation and monitoring.

The primary portfolio therefore uses the full budget:

```text
$120,000 spent
$0 remaining
```

and funds controls covering:

- prevention;
- identity;
- detection;
- endpoint protection;
- recovery;
- network containment; and
- patient-safety-critical medical devices.

---

# Final Allocation

## Fund Now — $120,000

1. **Network segmentation — $25,000**
2. **MFA — $4,000**
3. **Wazuh SIEM — $22,000**
4. **Offsite immutable backup — $15,000**
5. **Sophos Intercept X EDR — $36,000**
6. **Medical-device isolation and monitoring — $18,000**

## Defer

**Westside enterprise firewall — $15,000**

> By deferring the Westside enterprise firewall, MedDefense accepts an estimated **$30,000 in annual risk exposure**.

## Reject

**Outsourced 24/7 SOC — $240,000**

The control is rejected under the current programme because its annual cost exceeds both the available security budget and its modeled ALE reduction.

---

# Conclusion

The budget decision is not that the Westside firewall is unnecessary or that 24/7 monitoring has no security value.

The decision is that under a binding **$120,000** budget, MedDefense receives more risk reduction by funding the six selected controls first.

Every funded dollar therefore has a defined purpose:

- **$25,000** limits lateral movement.
- **$4,000** reduces stolen-credential risk.
- **$22,000** creates centralized detection.
- **$15,000** protects recovery.
- **$36,000** improves endpoint detection and prevention.
- **$18,000** protects the medical-device environment.

That uses exactly:

> **$120,000 of $120,000 available.**
