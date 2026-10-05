# 7. The Risk Register Update

## MedDefense Health Systems

**Project:** `1x05_board_briefing`  
**Repository path:** `blue_team/1x05_board_briefing/7-risk_register_update.md`

---

# Part 1 - Update Existing Ransomware Risk

## RISK-001 - Ransomware Double Extortion Against the EHR

The original register already identified ransomware as MedDefense's highest-priority external risk. Crimson Tide does not replace that risk; it makes it more specific and more urgent.

### Updated Entry

| Field | Updated Value |
|---|---|
| **Risk ID** | **RISK-001** |
| **Risk Description** | Crimson Tide compromises MedDefense through the vulnerable FortiGate, moves through the flat network, abuses credentials, steals patient and billing data, targets backups and deploys ransomware across Critical systems. |
| **Risk Category** | Financial |
| **Threat Source** | **Crimson Tide (CT) group / organized ransomware operation** |
| **Vulnerability** | CVE-2023-27997 plus Findings **003, 007, 015, 021 and 030** |
| **Affected Asset(s)** | FortiGate 100F **A-016**; `ehr-srv-01` **A-001**; `ehr-db-01` **A-002**; EHR application **A-036**; Active Directory **A-005/A-006**; backup infrastructure **A-009/A-010/A-041** |
| **Likelihood** | **5 - Almost Certain**; updated ARO from T5 = **0.90/year** |
| **Impact** | **5 - Critical** |
| **Inherent Risk Score** | **25 - Critical** |
| **ALE** | **$2,700,000/year** |
| **Risk Owner** | Deputy CISO - **James Chen** |
| **Treatment Decision** | **Mitigate - accelerated to emergency treatment** |
| **Treatment Justification** | The original decision still holds, but the timeline does not. MedDefense now matches the campaign's known attack path, including the vulnerable FortiGate, flat network, credential weaknesses and reachable backups. The planned controls remain appropriate, but the highest-value actions must move into the 72-hour response window. |
| **Planned Control(s)** | Emergency FortiGate patching; MFA; network segmentation; Wazuh SIEM; offsite immutable backup; EDR; temporary SSL-VPN and lateral-movement restrictions |
| **Residual Risk** | **15 - High** *(Likelihood 3 × Impact 5)* after the main controls are deployed. The likelihood should fall, but a successful hospital-wide ransomware event would still have Critical impact. |
| **KRI** | **Any confirmed FortiGate SSL-VPN activity or IOC matching the Crimson Tide/CVE-2023-27997 attack pattern from an untrusted source. Threshold: ≥1 confirmed match triggers incident response.** |
| **Review Date** | **Immediate out-of-cycle review; then weekly while the Crimson Tide campaign remains active** |

## Updated ALE

The original ransomware calculation from `1x03` was:

```text
Asset Value (AV): $5,000,000
Exposure Factor (EF): 60%

SLE = AV × EF
SLE = $5,000,000 × 0.60
SLE = $3,000,000
```

The original ARO was `0.35`, producing:

```text
Original ALE = $3,000,000 × 0.35
Original ALE = $1,050,000/year
```

T5 increased the ransomware ARO to:

```text
New ARO = 0.90
```

Therefore:

```text
Updated ALE = SLE × ARO
Updated ALE = $3,000,000 × 0.90
Updated ALE = $2,700,000/year
```

### Change

```text
Original ALE: $1,050,000/year
Updated ALE:  $2,700,000/year

Increase:     $1,650,000/year
Increase:     approximately 157%
```

The impact has not changed because the original model already treated a successful EHR ransomware event as Critical. What changed is the **likelihood**: MedDefense now has a confirmed vulnerable entry point that matches an active campaign targeting nearby hospitals.

---

# Part 2 - New Entry: FortiGate Vulnerability

## RISK-NEW-001 - CVE-2023-27997 on the FortiGate

| Field | Value |
|---|---|
| **Risk ID** | **RISK-NEW-001** |
| **Risk Description** | An unauthenticated attacker exploits CVE-2023-27997 on MedDefense's Internet-facing FortiGate 100F and gains an initial foothold that can be used for credential theft, reconnaissance and further movement into the internal network. |
| **Risk Category** | Operational |
| **Threat Source** | **Crimson Tide (CT) group / external ransomware actor** |
| **Vulnerability** | **CVE-2023-27997 - FortiOS SSL-VPN heap-based buffer overflow**. MedDefense runs **FortiOS 7.0.9**, inside the affected `7.0.0-7.0.11` range. |
| **Affected Asset(s)** | FortiGate 100F **A-016** and all internal systems reachable if the perimeter device is compromised |
| **Likelihood** | **5 - Almost Certain**; ARO **0.90/year** based on the updated T5 threat estimate |
| **Impact** | **5 - Critical** |
| **Inherent Risk Score** | **25 - Critical** |
| **ALE** | **$2,700,000/year** as the initial-access component of the updated ransomware scenario |
| **Risk Owner** | IT Director - **Sarah Park** |
| **Treatment Decision** | **Mitigate immediately** |
| **Treatment Justification** | Renew the FortiGate support contract for **$2,400**, download the supported firmware and patch to FortiOS **7.0.14**. The cost is extremely small compared with the annualized exposure created by leaving the known initial-access vulnerability open. |
| **Planned Control(s)** | Renew support; verify firmware hash; upgrade to FortiOS 7.0.14; disable/restrict SSL-VPN until patched; review FortiGate logs for earlier exploitation; rotate exposed administrative/VPN credentials where required |
| **Residual Risk** | **5 - Moderate** *(Likelihood 1 × Impact 5)* once the patch is applied and verified. A perimeter compromise would still be serious, but this specific CVE should no longer provide the same attack path. |
| **KRI** | FortiGate running an affected firmware version or any confirmed exploit/IOC activity against SSL-VPN. **Threshold: either condition = immediate escalation.** |
| **Review Date** | **Within 24 hours after patching, then at the next weekly emergency review** |

## Is the $2,400 Patching Cost Justified?

Yes.

For this calculation I am using the same ransomware consequence model as RISK-001 because the FortiGate vulnerability is the **entry point into that attack chain**, rather than pretending that the financial impact is limited to the value of the firewall hardware.

```text
SLE = $3,000,000
ARO = 0.90

ALE = $3,000,000 × 0.90
ALE = $2,700,000/year
```

The support renewal costs:

```text
$2,400
```

Compare that with the ALE:

```text
$2,700,000 ÷ $2,400 = 1,125
```

The annualized exposure is therefore **1,125 times the support-renewal cost**.

Another way to look at it:

```text
$2,400 ÷ $2,700,000 = 0.000889
                       = 0.089%
```

The patch only needs to reduce this risk by about **0.09%** for the $2,400 renewal to break even.

Since the patch removes the exact vulnerable FortiOS condition being used for initial access, the treatment is clearly justified.

> **Important:** RISK-NEW-001 and RISK-001 are linked parts of the same attack chain. Their ALE values should **not be added together**, because that would double-count the same ransomware loss.

---

# Part 3 - Register Governance Test

## Original Governance Trigger

The `1x03` Risk Register states:

> **"An out-of-cycle review is triggered by a new Critical vulnerability, confirmed security incident, material change to a threat actor or attack path, failure of a planned control, major infrastructure or vendor change, audit finding, or breach of a defined KRI threshold."**

## Does Crimson Tide Trigger an Out-of-Cycle Review?

**Yes. Definitely.**

At least two of the existing trigger criteria are directly met.

### 1. New Critical Vulnerability

CVE-2023-27997 is a Critical vulnerability and MedDefense's exact FortiOS `7.0.9` version is affected.

This alone is enough to trigger the review.

### 2. Material Change to a Threat Actor or Attack Path

The original register treated ransomware as a general threat.

Crimson Tide provides much more specific intelligence:

```text
FortiGate exploitation
        ↓
Internal reconnaissance
        ↓
Credential abuse / Kerberoasting
        ↓
Lateral movement
        ↓
Database exfiltration
        ↓
Backup destruction
        ↓
Ransomware + extortion
```

That attack path closely matches weaknesses already identified at MedDefense.

The threat has therefore changed from:

```text
"Ransomware is a credible healthcare threat"
```

to:

```text
"An active ransomware campaign is using a vulnerability and attack path
that directly match MedDefense's current environment."
```

That is a material change and requires immediate reassessment.

## Governance Decision

```text
Out-of-cycle review required: YES
Reason:
- New Critical vulnerability
- Material change to threat actor / attack path
- Updated ARO materially increases ransomware ALE

Original RISK-001 ALE: $1,050,000/year
Updated RISK-001 ALE:  $2,700,000/year

Treatment: MITIGATE
Response: ACCELERATE
```

The Risk Register should therefore be updated immediately rather than waiting for the normal monthly review.

---

# Final Risk Position

| Risk | Previous Position | Updated Position |
|---|---|---|
| **RISK-001 - Ransomware** | 25 Critical; ALE $1.05M | **25 Critical; ALE $2.7M; emergency mitigation** |
| **RISK-NEW-001 - FortiGate CVE** | Not previously recorded | **25 Critical; ALE $2.7M; patch immediately** |

Crimson Tide does not change the basic decision to mitigate ransomware. It changes **how quickly MedDefense needs to act**.

The existing six-month strategy is still useful, but the parts that directly break the Crimson Tide chain now need to happen in hours and days rather than months.
