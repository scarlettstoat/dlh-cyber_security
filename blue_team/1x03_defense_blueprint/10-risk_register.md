# 10. The Risk Register

## MedDefense Health Systems — Cybersecurity Risk Register

**Register Owner:** Deputy CISO — James Chen  
**Operational Maintainer:** Security Analyst  
**Review Cadence:** Monthly, with out-of-cycle review when defined triggers occur  
**Next Scheduled Review:** 18 October 2026

---

# Scoring Method

## Likelihood Scale

| Score | Definition |
|---:|---|
| **1 — Rare** | Event is exceptional and not expected under normal conditions |
| **2 — Unlikely** | Event is possible but not expected in a normal year |
| **3 — Possible** | Event could occur and credible attack paths exist |
| **4 — Likely** | Event is strongly supported by current exposure, prior incidents or sector evidence |
| **5 — Almost Certain** | Event is expected to be attempted or has very strong evidence of recurrence |

## Impact Scale

| Score | Definition |
|---:|---|
| **1 — Insignificant** | Minimal operational effect and no material sensitive-data impact |
| **2 — Minor** | Limited disruption or recoverable local impact |
| **3 — Moderate** | Noticeable operational, financial or data impact requiring management attention |
| **4 — Major** | Serious operational disruption, material financial loss or significant sensitive-data exposure |
| **5 — Critical** | Major clinical disruption, patient-safety consequences, organization-wide compromise or severe regulatory/business impact |

## Risk Score

```text
Inherent Risk Score = Likelihood × Impact
```

| Score | Risk Level |
|---:|---|
| **1–4** | Low |
| **5–9** | Moderate |
| **10–15** | High |
| **16–25** | Critical |

Residual risk uses the same scale after the planned controls are considered.

---

# RISK-001 — Ransomware Double Extortion Against the EHR

| Field | Description |
|---|---|
| **Risk ID** | **RISK-001** |
| **Risk Description** | A ransomware affiliate compromises MedDefense, exfiltrates patient data and encrypts EHR-related systems, causing clinical disruption, recovery cost and extortion pressure. |
| **Risk Category** | Financial |
| **Threat Source** | Ransomware Groups / Organized Crime |
| **Vulnerability** | Findings **003, 007, 015, 021 and 030** |
| **Affected Asset(s)** | `ehr-srv-01` **A-001**; `ehr-db-01` **A-002**; EHR application **A-036**; Active Directory **A-005/A-006**; backup infrastructure **A-009/A-010/A-041** |
| **Likelihood** | **5 — Almost Certain** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **25 — Critical** |
| **ALE** | **$1,050,000/year** from Task 6 |
| **Risk Owner** | Deputy CISO — **James Chen** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Ransomware is MedDefense's highest-priority external threat and the combination of EHR criticality, flat internal reachability, credential weaknesses, monitoring gaps and reachable backups makes acceptance disproportionate. |
| **Planned Control(s)** | **T7 Control 1:** Network segmentation; **T7 Control 2:** MFA; **T7 Control 3:** Wazuh SIEM; **T7 Control 4:** Offsite immutable backup; **T7 Control 5:** EDR upgrade |
| **Residual Risk** | **15 — High** *(Likelihood 3 × Impact 5)*; controls materially reduce likelihood and blast radius, but successful ransomware against a hospital EHR can still have Critical impact. |
| **KRI** | Number of Critical EHR/AD/backup assets reachable from general workstation networks outside approved flows. **Threshold: >0.** |
| **Review Date** | **18 October 2026** |

---

# RISK-002 — Active Directory Privileged Compromise

| Field | Description |
|---|---|
| **Risk ID** | **RISK-002** |
| **Risk Description** | An attacker compromises Active Directory and gains privileged control that can be used to alter identities, expand access or deploy ransomware across MedDefense. |
| **Risk Category** | Operational |
| **Threat Source** | Ransomware Groups / Organized Crime; Insider — Malicious |
| **Vulnerability** | Findings **007 and 021** |
| **Affected Asset(s)** | `ad-dc-01` **A-005**; `ad-dc-02` **A-006** |
| **Likelihood** | **4 — Likely** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **20 — Critical** |
| **ALE** | **$210,000/year** from Task 6 |
| **Risk Owner** | IT Director — **Sarah Park** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Active Directory is a shared authentication dependency, so privileged compromise can become an organization-wide access and ransomware multiplier. |
| **Planned Control(s)** | **T7 Control 2:** MFA on administrative accounts; **T7 Control 3:** Wazuh SIEM; **T7 Control 1:** Network segmentation |
| **Residual Risk** | **10 — High** *(Likelihood 2 × Impact 5)*; identity controls can sharply reduce compromise likelihood, but the consequence of domain-level control remains Critical. |
| **KRI** | Percentage of privileged, administrative or VPN-capable accounts without MFA. **Threshold: >0%.** |
| **Review Date** | **18 October 2026** |

---

# RISK-003 — Backup and Recovery Infrastructure Neutralized During Ransomware

| Field | Description |
|---|---|
| **Risk ID** | **RISK-003** |
| **Risk Description** | A ransomware actor reaches MedDefense's locally concentrated backup infrastructure and deletes, encrypts or disables recovery copies before attacking production systems. |
| **Risk Category** | Operational |
| **Threat Source** | Ransomware Groups / Organized Crime |
| **Vulnerability** | Findings **015 and 030** |
| **Affected Asset(s)** | `backup-srv-01` **A-009**; `NAS-01` **A-010**; Veeam Backup & Replication **A-041** |
| **Likelihood** | **4 — Likely** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **20 — Critical** |
| **ALE** | **Not separately calculated in Task 6.** The financial effect of backup loss is included within RISK-001's ransomware ALE. |
| **Risk Owner** | IT Director — **Sarah Park** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Recovery capability is the final control when prevention fails, and ransomware actors deliberately target backups to increase downtime and extortion pressure. |
| **Planned Control(s)** | **T7 Control 4:** Offsite immutable backup replication; **T7 Control 1:** Network segmentation; **T7 Control 3:** Wazuh SIEM |
| **Residual Risk** | **8 — Moderate** *(Likelihood 2 × Impact 4)*; immutable offsite copies and restricted administration materially improve recoverability even if production systems are compromised. |
| **KRI** | Failed immutable-backup or Critical-system restore tests. **Threshold: ≥1 failed test.** |
| **Review Date** | **18 October 2026** |

---

# RISK-004 — Opportunistic Compromise of `billing-srv-01`

| Field | Description |
|---|---|
| **Risk ID** | **RISK-004** |
| **Risk Description** | An opportunistic attacker exploits the vulnerable and unsupported billing server and uses the compromised host as a foothold for wider internal activity. |
| **Risk Category** | Operational |
| **Threat Source** | Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime |
| **Vulnerability** | Findings **001, 002, 009, 011 and 026** |
| **Affected Asset(s)** | `billing-srv-01` **A-004** |
| **Likelihood** | **4 — Likely** |
| **Impact** | **4 — Major** |
| **Inherent Risk Score** | **16 — Critical** |
| **ALE** | **$234,000/year** from Task 6 |
| **Risk Owner** | IT Director — **Sarah Park** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | The host has previous compromise history and multiple compounding weaknesses, making repeated exploitation more credible than accepting the exposure. |
| **Planned Control(s)** | **T7 Control 5:** EDR upgrade; **T7 Control 3:** Wazuh SIEM; **T7 Control 1:** Network segmentation |
| **Residual Risk** | **8 — Moderate** *(Likelihood 2 × Impact 4)* after endpoint detection, centralized monitoring and containment controls reduce repeat compromise and pivot opportunities. |
| **KRI** | Number of Critical or High vulnerabilities on `billing-srv-01` that exceed the remediation SLA. **Threshold: ≥1 overdue finding.** |
| **Review Date** | **18 October 2026** |

---

# RISK-005 — Negligent Insider or Unmanaged Endpoint Creates a Foothold

| Field | Description |
|---|---|
| **Risk ID** | **RISK-005** |
| **Risk Description** | A legitimate employee introduces unmanaged technology, mishandles credentials or uses an uncontrolled endpoint in a way that exposes patient data or creates an internal attacker foothold. |
| **Risk Category** | Operational |
| **Threat Source** | Insider — Negligent |
| **Vulnerability** | Finding **028** |
| **Affected Asset(s)** | Central Windows workstation estate **A-020**; physician iPad estate **A-028**; undocumented host `UNKNOWN-01` **A-012**; Westside unknown Linux host **A-014** |
| **Likelihood** | **4 — Likely** |
| **Impact** | **4 — Major** |
| **Inherent Risk Score** | **16 — Critical** |
| **ALE** | **Not separately calculated in Task 6.** |
| **Risk Owner** | IT Director — **Sarah Park** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Project 1x01 ranked negligent insider activity as a high-likelihood threat and MedDefense has already identified unmanaged and incompletely managed endpoints. |
| **Planned Control(s)** | **T7 Control 5:** EDR upgrade; **T7 Control 1:** Network segmentation |
| **Residual Risk** | **8 — Moderate** *(Likelihood 2 × Impact 4)*; managed endpoint coverage and segmentation reduce both the chance of a persistent foothold and the damage from one unmanaged device. |
| **KRI** | Number of unknown or unmanaged devices detected on production networks. **Threshold: >0 after inventory reconciliation.** |
| **Review Date** | **18 October 2026** |

---

# RISK-006 — Unsupported Windows XP MRI Workstation Exploited

| Field | Description |
|---|---|
| **Risk ID** | **RISK-006** |
| **Risk Description** | An attacker exploits the unsupported Windows XP MRI control workstation, disrupting Radiology operations or using the host as an internal pivot. |
| **Risk Category** | Operational |
| **Threat Source** | Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime |
| **Vulnerability** | Findings **004 and 012** |
| **Affected Asset(s)** | `WS-RAD-01` — MRI control workstation **A-022** |
| **Likelihood** | **3 — Possible** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **15 — High** |
| **ALE** | **$163,625/year** from Task 6 |
| **Risk Owner** | IT Director — **Sarah Park**, with Radiology operational ownership |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Windows XP cannot be returned to normal vendor support, so compensating network controls are required until the clinical platform can be replaced. |
| **Planned Control(s)** | **T7 Control 1:** Network segmentation; **T7 Control 3:** Wazuh SIEM |
| **Residual Risk** | **10 — High** *(Likelihood 2 × Impact 5)*; isolation reduces reachability but the underlying unsupported operating system remains vulnerable. |
| **KRI** | Number of non-approved systems able to reach `WS-RAD-01` over RDP, SMB or other management paths. **Threshold: >0.** |
| **Review Date** | **18 October 2026** |

---

# RISK-007 — Alaris Pump Environment Compromise or Disruption

| Field | Description |
|---|---|
| **Risk ID** | **RISK-007** |
| **Risk Description** | Unauthorized access to the Alaris environment disrupts medication delivery or changes device-related configuration in a way that creates patient-safety risk. |
| **Risk Category** | Operational |
| **Threat Source** | Insider — Malicious; Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime |
| **Vulnerability** | Finding **010** *(specific CVE applicability remains validation-gated; broader isolation weakness is confirmed)* |
| **Affected Asset(s)** | BD Alaris infusion-pump estate **A-032** |
| **Likelihood** | **3 — Possible** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **15 — High** |
| **ALE** | **$108,000/year** from Task 6 |
| **Risk Owner** | IT Director — **Sarah Park**, with Clinical Engineering involvement |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | The specific scanner CVE requires validation, but the broader lack of device-specific isolation and monitoring creates an independently supported patient-safety exposure. |
| **Planned Control(s)** | **T7 Control 8:** Full medical-device network isolation and dedicated monitoring; **T7 Control 3:** Wazuh SIEM |
| **Residual Risk** | **10 — High** *(Likelihood 2 × Impact 5)*; isolation lowers reachability and attack likelihood, but the clinical consequence of a successful device compromise remains Critical. |
| **KRI** | Number of Alaris management or service paths reachable from non-clinical or non-approved networks. **Threshold: >0.** |
| **Review Date** | **18 October 2026** |

---

# RISK-008 — Trusted Vendor / Supply-Chain Compromise Reaches the EHR

| Field | Description |
|---|---|
| **Risk ID** | **RISK-008** |
| **Risk Description** | An attacker compromises a trusted technology vendor and uses legitimate maintenance access to reach the EHR environment or expand toward other Critical MedDefense systems. |
| **Risk Category** | Strategic |
| **Threat Source** | Organized Crime / Ransomware Group using a compromised third party; Nation-State APT as a lower-likelihood downstream actor |
| **Vulnerability** | Findings **003 and 007** |
| **Affected Asset(s)** | `ehr-srv-01` **A-001**; `ehr-db-01` **A-002**; EHR application **A-036**; Active Directory **A-005/A-006** |
| **Likelihood** | **3 — Possible** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **15 — High** |
| **ALE** | **Not separately calculated in Task 6.** |
| **Risk Owner** | Deputy CISO — **James Chen** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Vendor access can bypass normal perimeter assumptions, so MedDefense must reduce standing trust and constrain what a compromised third-party identity can reach. |
| **Planned Control(s)** | **T7 Control 2:** MFA on administrative/vendor access; **T7 Control 1:** Network segmentation; **T7 Control 3:** Wazuh SIEM |
| **Residual Risk** | **10 — High** *(Likelihood 2 × Impact 5)*; access controls reduce the chance and scope of vendor compromise, but trusted maintenance relationships cannot be eliminated entirely. |
| **KRI** | Number of active vendor privileged accounts without MFA, named ownership or time-bounded approval. **Threshold: >0.** |
| **Review Date** | **18 October 2026** |

---

# RISK-009 — Malicious Insider Misuses Legitimate EHR Access

| Field | Description |
|---|---|
| **Risk ID** | **RISK-009** |
| **Risk Description** | A current or former employee abuses legitimate credentials to access or disclose patient information without a valid care or business reason. |
| **Risk Category** | Compliance |
| **Threat Source** | Insider — Malicious |
| **Vulnerability** | Finding **021** as evidence of incomplete centralized event visibility; the EHR-specific monitoring weakness is also documented in GAP-011 |
| **Affected Asset(s)** | EHR application **A-036**; `ehr-db-01` **A-002** |
| **Likelihood** | **3 — Possible** |
| **Impact** | **5 — Critical** |
| **Inherent Risk Score** | **15 — High** |
| **ALE** | **Not separately calculated in Task 6.** |
| **Risk Owner** | Department Heads acting as Data Owners, coordinated by Deputy CISO **James Chen** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Legitimate-account abuse can bypass perimeter controls, so MedDefense needs centralized monitoring and stronger identity controls to detect inappropriate access quickly. |
| **Planned Control(s)** | **T7 Control 3:** Wazuh SIEM; **T7 Control 2:** MFA |
| **Residual Risk** | **8 — Moderate** *(Likelihood 2 × Impact 4)* after identity strengthening and active review of high-risk access patterns. |
| **KRI** | Number of anomalous or high-risk EHR access alerts remaining unreviewed for more than 24 hours. **Threshold: >0.** |
| **Review Date** | **18 October 2026** |

---

# RISK-010 — Westside Clinic Perimeter Compromise

| Field | Description |
|---|---|
| **Risk ID** | **RISK-010** |
| **Risk Description** | An attacker compromises the consumer-grade Westside Clinic edge device or weak site boundary and uses the trusted VPN path to disrupt the clinic or attempt movement toward Central. |
| **Risk Category** | Operational |
| **Threat Source** | Unskilled / Opportunistic Attacker; Ransomware Groups / Organized Crime |
| **Vulnerability** | Finding **014** |
| **Affected Asset(s)** | Westside Netgear router **A-015**; Westside server **A-013**; Westside unknown Linux host **A-014** |
| **Likelihood** | **3 — Possible** |
| **Impact** | **4 — Major** |
| **Inherent Risk Score** | **12 — High** |
| **ALE** | **Not separately calculated in Task 6.** Task 7 estimated that the dedicated firewall control would reduce approximately **$30,000/year** of modeled risk exposure. |
| **Risk Owner** | IT Director — **Sarah Park** |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | The consumer router is not an appropriate long-term boundary for a clinical site connected to Central, but the dedicated firewall was deferred in Task 8 because higher-value controls consumed the current $120,000 budget. |
| **Planned Control(s)** | **T7 Control 6:** Dedicated Westside enterprise firewall; **T7 Control 3:** Wazuh SIEM |
| **Residual Risk** | **8 — Moderate** *(Likelihood 2 × Impact 4)* **after** the dedicated firewall is funded and deployed; until then the risk remains **12 — High**. |
| **KRI** | Any Critical router vulnerability, unauthorized inbound rule or unapproved VPN path at Westside. **Threshold: ≥1.** |
| **Review Date** | **18 October 2026** |

---

# Risk Register Summary

| Risk ID | Risk | Category | Likelihood | Impact | Inherent Score | ALE | Treatment | Residual Risk |
|---|---|---|---:|---:|---:|---:|---|---|
| **RISK-001** | EHR ransomware double extortion | Financial | 5 | 5 | **25 Critical** | **$1,050,000** | Mitigate | **15 High** |
| **RISK-002** | Active Directory privileged compromise | Operational | 4 | 5 | **20 Critical** | **$210,000** | Mitigate | **10 High** |
| **RISK-003** | Backup/recovery neutralization | Operational | 4 | 5 | **20 Critical** | Included in RISK-001 | Mitigate | **8 Moderate** |
| **RISK-004** | `billing-srv-01` compromise | Operational | 4 | 4 | **16 Critical** | **$234,000** | Mitigate | **8 Moderate** |
| **RISK-005** | Negligent insider / unmanaged endpoint | Operational | 4 | 4 | **16 Critical** | Not calculated | Mitigate | **8 Moderate** |
| **RISK-006** | Windows XP MRI exploitation | Operational | 3 | 5 | **15 High** | **$163,625** | Mitigate | **10 High** |
| **RISK-007** | Alaris environment compromise | Operational | 3 | 5 | **15 High** | **$108,000** | Mitigate | **10 High** |
| **RISK-008** | Vendor / supply-chain compromise | Strategic | 3 | 5 | **15 High** | Not calculated | Mitigate | **10 High** |
| **RISK-009** | Malicious insider EHR misuse | Compliance | 3 | 5 | **15 High** | Not calculated | Mitigate | **8 Moderate** |
| **RISK-010** | Westside perimeter compromise | Operational | 3 | 4 | **12 High** | Not calculated | Mitigate | **8 Moderate after funded control** |

---

# Risk Register Governance Note

The **Deputy CISO, James Chen, owns the MedDefense Risk Register**, while the **Security Analyst maintains the working record**, collects evidence from IT and Department Heads, updates KRIs, and records treatment progress. The register is reviewed **monthly** with James, IT Director Sarah Park and the relevant business or clinical risk owners, with material changes escalated to the CEO. An **out-of-cycle review** is triggered by a new Critical vulnerability, confirmed security incident, material change to a threat actor or attack path, failure of a planned control, major infrastructure or vendor change, audit finding, or breach of a defined KRI threshold. When a KRI threshold is breached, the Security Analyst validates the evidence and immediately escalates it to the risk owner and Deputy CISO; the owner must determine whether treatment must be accelerated, an additional control is required, or the residual risk must be formally escalated for executive acceptance. The register is then updated with the decision, owner, due date and revised residual-risk position.
