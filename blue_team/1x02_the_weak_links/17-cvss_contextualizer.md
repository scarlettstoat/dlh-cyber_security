# 17. The CVSS Contextualizer

**Project:** `1x02_the_weak_links`  
**Goal:** Recalculate and contextualize MedDefense's highest-priority actionable findings using asset criticality, kill-chain position, exploitability and compensating controls.  
**Repository path:** `blue_team/1x02_the_weak_links/17-cvss_contextualizer.md`  
**Assessment date:** 16 September 2026

---

## 1. Method and Selection

Task 16 produced **seven Actionable Critical findings**: 004, 003, 007, 001, 002, 011 and 009. Those seven are carried forward automatically.

For the eighth finding, this assessment selects **Finding 010 — the BD Alaris infusion-pump finding**. Task 16 moved Finding 010 to Actionable Standard because the exact CVE-to-version match requires validation, but it remains one of the most important findings to contextualize because it affects a Critical patient-treatment asset, appears directly in a Project 1x01 kill chain and has a numeric CVSS vector that demonstrates how business/clinical context can change the score.

### CVSS scoring rule used here

CVSS v3.1 separates the concepts used in this task:

- **Environmental Security Requirements (`CR`, `IR`, `AR`)** represent how important Confidentiality, Integrity and Availability are in MedDefense's environment.
- **Modified Base Metrics** should only be changed where an actual environmental control changes the exploit conditions or technical impact.
- **Kill-chain position** is not a formal CVSS metric.
- **Exploit availability / KEV evidence** informs final remediation priority; it is not silently converted into an Environmental metric.
- For findings that are **configuration/lifecycle weaknesses with no valid CVE/Base vector**, a legitimate NIST Environmental score cannot be calculated. This report records **N/A** rather than inventing a vector.

To translate the 1x00 four-level CIA scale into the three-level CVSS Security Requirement scale:

| 1x00 CIA Rating | CVSS Requirement |
|---|---|
| Critical | High (`H`) |
| High | Medium (`M`) |
| Moderate | Low (`L`) |
| Low | Low (`L`) |

This mapping prevents a Project 1x00 **High** rating from being treated as equivalent to the project's maximum **Critical** rating.

---

# 2. Finding 004 — Unsupported Windows XP MRI Workstation / BlueKeep Representative

```text
Finding 004 - Compound legacy Windows vulnerabilities
Representative CVE for Environmental calculation: CVE-2019-0708 (BlueKeep)

CVSS Base Score:
9.8 Critical for CVE-2019-0708.
Finding 004 also contains other legacy Windows vulnerabilities, so the final
finding priority considers the compound exposure rather than pretending that
one CVSS score represents all three CVEs.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  WS-RAD-01 — A-022, Windows XP SP3 MRI control workstation.

  CIA Rating:
  PACS / Medical Imaging:
  Confidentiality = Critical
  Integrity = Critical
  Availability = High
  Overall = Critical

  Criticality Impact on Priority:
  Raises urgency. Compromise can affect Restricted imaging information,
  imaging integrity and MRI availability during patient care. For CVSS
  Environmental scoring this maps to CR:H / IR:H / AR:M.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  None explicitly identified by Finding ID.

  Chain Role:
  A lateral-movement target and possible secondary foothold after an attacker
  has entered the flat internal network. The host exposes RDP/SMB and is an
  unsupported clinical endpoint.

  Kill Chain Impact on Priority:
  Raises urgency. The vulnerability is not a likely Internet entry point, but
  GAP-001 means one compromised internal endpoint can supply the network
  position needed to attack it. After compromise it can also become a pivot
  toward PACS, AD and other Central systems.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  5/5 for the mature legacy Windows RCE path represented by BlueKeep.

  CISA KEV:
  Yes.

  Exploit Impact on Priority:
  Strongly raises urgency. Mature public exploitation and KEV evidence remove
  much of the uncertainty about whether this class of weakness is practically
  exploitable once network reachability exists.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-002 — FortiGate default-deny perimeter rule provides some protection
  against direct external reachability.
  No implemented MRI-specific segmentation, detective monitoring or modern
  endpoint protection is documented.

  Control Impact on Priority:
  Does not materially lower urgency. The perimeter control does not stop an
  attacker who is already inside Central, and the exact compensating control
  most needed — MRI network isolation — is still a recommended treatment,
  not an existing control.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  Base metrics retained for CVE-2019-0708.
  CR:H / IR:H / AR:M.
  Modified metrics remain Not Defined because no implemented control changes
  the exploit conditions of the vulnerable RDP service.

  Environmental Vector:
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:M

  Adjusted Score:
  9.8 Critical

Final Priority:
Critical

Final Justification:
Finding 004 remains Critical after contextualization because the technical
score was already near the top of the CVSS scale and the environmental
context provides no meaningful reduction. The MRI workstation is an
unsupported clinical asset, mature exploitation exists, and the flat network
means an attacker who obtains any internal foothold can potentially reach the
RDP/SMB services. The perimeter firewall is not an adequate compensating
control for east-west attacks. The correct response is immediate isolation
and a supported replacement path rather than relying on conventional patching.
```

**NIST calculator vector:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AH%2FCR%3AH%2FIR%3AH%2FAR%3AM&version=3.1

---

# 3. Finding 003 — EHR PostgreSQL Exposed to the Wider Internal Network

```text
Finding 003 - Unrestricted PostgreSQL exposure on ehr-db-01

CVSS Base Score:
N/A — this is a MedDefense configuration/access-control weakness rather than
a CVE, so there is no legitimate NVD Base vector.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  ehr-db-01 — A-002, EHR PostgreSQL database.

  CIA Rating:
  Confidentiality = Critical
  Integrity = Critical
  Availability = Critical
  Overall = Critical

  Criticality Impact on Priority:
  Raises urgency to the highest level. The database contains Restricted
  patient information and directly supports a clinical system where all
  three CIA dimensions are Critical.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  Kill Chain #1 — Phishing -> AD -> EHR double extortion.
  Kill Chain #3 — Compromised MedTech access -> EHR.

  Chain Role:
  Lateral-movement destination and high-value final target. Both chains show
  attackers reaching ehr-db-01 after obtaining an earlier foothold.

  Kill Chain Impact on Priority:
  Strongly raises urgency. This is not a theoretical architecture concern:
  the exact broad database exposure is already present in two threat-informed
  attack paths.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  N/A — no software exploit is required for the exposure itself.

  CISA KEV:
  N/A — no CVE.

  Exploit Impact on Priority:
  The lack of a CVE does not lower urgency. The dangerous condition is that a
  compromised internal system can already reach TCP/5432 and then attempt
  stolen credentials, password attacks or database-specific techniques.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-016 — nightly VM backup.
  C-026 — Linux syslog.
  C-028 — EHR application audit logging.
  C-035 — paper-record outage fallback.

  Control Impact on Priority:
  Only slightly reduces consequence. Backups help recovery and logs provide
  evidence, but no strong preventive control restricts PostgreSQL access to
  the EHR application tier. Application audit logging may also not capture
  direct database activity in the same way as normal application access.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  N/A — NIST CVSS Environmental scoring requires a valid Base vector.
  Creating a synthetic vector for a deployment misconfiguration would give a
  misleading appearance of precision.

  Adjusted Score:
  N/A

Final Priority:
Critical

Final Justification:
Finding 003 demonstrates why vulnerability priority cannot be reduced to CVSS.
It has no CVE and therefore no calculable Environmental score, yet it affects
MedDefense's most critical information system and appears directly in two
documented kill chains. Existing backup and logging controls are primarily
detective/corrective and do not stop an attacker from reaching the database.
The direct route to Restricted patient information and clinical-data integrity
makes immediate network restriction of PostgreSQL one of the highest-value
remediation actions in the project.
```

---

# 4. Finding 007 — LDAP Signing Not Enforced on `ad-dc-01`

```text
Finding 007 - LDAP signing not enforced

CVSS Base Score:
N/A — this is an Active Directory security configuration weakness, not a
single software CVE with a valid NVD Base vector.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  ad-dc-01 — A-005, primary Active Directory domain controller.

  CIA Rating:
  Identity and Access Management:
  Confidentiality = High
  Integrity = Critical
  Availability = Critical
  Overall = Critical

  Criticality Impact on Priority:
  Raises urgency. AD is a shared trust dependency; compromise of authentication
  or directory integrity can affect many otherwise separate systems.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  Kill Chain #1 — Phishing -> AD -> EHR double extortion.
  Kill Chain #4 — Retained insider access -> Active Directory compromise.
  The exact LDAP-signing finding is not named verbatim, but both chains depend
  on escalation or abuse of the AD environment.

  Chain Role:
  Credential/identity abuse and lateral-movement enabler.

  Kill Chain Impact on Priority:
  Raises urgency because weakening AD communication integrity can support the
  same identity-compromise stage that allows an attacker to expand from one
  account or endpoint to domain-wide influence.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  N/A — T4 did not assign an exploit score to this configuration finding.

  CISA KEV:
  N/A — no CVE.

  Exploit Impact on Priority:
  No reduction. Relay-style abuse of unsigned LDAP is a known attack technique,
  but this report does not invent a 1-5 T4 score that was never assigned.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-009 to C-013 — password requirements, AD enforcement, lockout, password
  history and shared-account departure controls.
  C-025 / C-029 — Windows and AD event logging.
  C-016 — backup.
  C-030 — secondary domain controller.

  Control Impact on Priority:
  Partially lowers likelihood/impact but does not close the weakness. AD has
  several preventive/detective/corrective controls, yet MFA/PAM is incomplete,
  monitoring is manual and those controls do not substitute for LDAP signing.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  N/A — no Base vector exists for this configuration weakness.

  Adjusted Score:
  N/A

Final Priority:
Critical

Final Justification:
Finding 007 is promoted by context rather than by a numeric score. The affected
asset is one of MedDefense's Critical shared dependencies, and AD compromise
is central to both the ransomware and insider attack paths developed in
Project 1x01. Existing password, logging, backup and redundancy controls are
useful but do not prevent unsigned LDAP relay/manipulation and are weakened by
the lack of broad MFA/PAM and centralized monitoring. Because identity
compromise can expand one foothold into access across the organisation, the
finding remains an immediate Critical priority.
```

---

# 5. Finding 001 — CVE-2021-44790 Apache `mod_lua` Memory Corruption

```text
Finding 001 - CVE-2021-44790

CVSS Base Score:
9.8 Critical
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  billing-srv-01 — A-004.

  CIA Rating:
  Administrative and Business Systems:
  Confidentiality = High
  Integrity = High
  Availability = High
  Overall = High

  Criticality Impact on Priority:
  Maintains high urgency but does not raise the business system to the same
  CIA requirement level as the EHR or clinical-device estates. Under the
  mapping used here this is CR:M / IR:M / AR:M.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  None explicitly identified by CVE/Finding ID.

  Chain Role:
  Alternative initial foothold / server compromise before the discovery and
  lateral-movement stages seen in the ransomware kill chains.

  Kill Chain Impact on Priority:
  Raises practical urgency because a compromised billing server is not
  contained. GAP-001 allows the host to become a stepping stone toward EHR,
  AD, backup and clinical systems.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  4/5.

  CISA KEV:
  No.

  Exploit Impact on Priority:
  Raises urgency. T4 identified a working public PoC and the scan confirms
  that mod_lua is loaded. The absence of a KEV listing prevents treating it
  as equivalent to the mature legacy Windows exploits, but exploitability is
  still strong.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-002 — FortiGate default-deny perimeter rule.
  C-016 — nightly VM backups.
  C-026 — Linux syslog.
  C-027 — Apache log retention.

  Control Impact on Priority:
  Only slightly lowers risk. The firewall may reduce unapproved perimeter
  access, but billing-srv-01 is reachable internally; backups and logs are
  detective/corrective rather than preventive, and logs are not continuously
  monitored.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  CR:M / IR:M / AR:M.
  Modified Base metrics remain Not Defined because the documented controls do
  not change the intrinsic exploit conditions once the Apache service is
  reachable.

  Environmental Vector:
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M

  Adjusted Score:
  9.8 Critical

Final Priority:
Critical

Final Justification:
Finding 001 stays Critical numerically and operationally. Its Base score is
already 9.8, the vulnerable module is confirmed present and T4 found public
exploit material. Although billing is a High rather than Critical asset in
the 1x00 matrix, MedDefense's flat internal network means successful code
execution can become an enterprise foothold. Existing backups and local logs
help recovery and investigation but do not stop exploitation or lateral
movement, so they do not materially reduce the urgency.
```

**NIST calculator vector:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AH%2FCR%3AM%2FIR%3AM%2FAR%3AM&version=3.1

---

# 6. Finding 002 — CVE-2019-0211 Apache Local Privilege Escalation

```text
Finding 002 - CVE-2019-0211

CVSS Base Score:
7.8 High
Vector: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  billing-srv-01 — A-004.

  CIA Rating:
  Confidentiality = High
  Integrity = High
  Availability = High
  Overall = High

  Criticality Impact on Priority:
  Maintains a High priority. CVSS Environmental requirements are
  CR:M / IR:M / AR:M.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  None explicitly identified by Finding ID.

  Chain Role:
  Privilege-escalation step after a foothold and before credential harvesting,
  persistence or lateral movement.

  Kill Chain Impact on Priority:
  Raises urgency because Finding 001 exists on the same server. The local
  prerequisite is therefore credible: an Apache foothold can potentially be
  followed by escalation to root.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  4/5 using the T4 rubric; Task 4 identified verified public exploit material,
  while Task 10 carried the score forward because it was not one of T4's final
  five scored rows.

  CISA KEV:
  Yes.

  Exploit Impact on Priority:
  Raises urgency substantially. Public exploit material and KEV evidence make
  this more than a theoretical local weakness, although prior execution is
  still required.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-016 — nightly VM backup.
  C-026 — Linux syslog.
  C-027 — Apache logs.
  C-002 — FortiGate default-deny perimeter rule.

  Control Impact on Priority:
  Limited reduction. These controls can support investigation/recovery but do
  not prevent a process already executing on billing-srv-01 from attempting
  local privilege escalation.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  CR:M / IR:M / AR:M.
  Modified metrics unchanged because no existing control alters the required
  local access or privilege-escalation mechanics.

  Environmental Vector:
  AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M

  Adjusted Score:
  7.8 High

Final Priority:
High

Final Justification:
Finding 002 remains High in isolation, but it should be remediated in the
same emergency change package as Finding 001. Its Base and Environmental
scores remain 7.8 because billing's CIA requirements map to Medium CVSS
requirements and the existing controls do not change the exploit mechanics.
The reason it receives urgent operational treatment is therefore the attack
chain: a network-reachable Apache foothold and a KEV-listed local escalation
weakness coexist on the same repeatedly compromised server.
```

**NIST calculator vector:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AL%2FAC%3AL%2FPR%3AL%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AH%2FCR%3AM%2FIR%3AM%2FAR%3AM&version=3.1

---

# 7. Finding 011 — Unsupported Ubuntu 18.04 Lifecycle State

```text
Finding 011 - Ubuntu 18.04 without an active supported security-maintenance path

CVSS Base Score:
N/A as a single score. End-of-support / lifecycle status is not one CVE and
can expose the host to many different vulnerabilities with different vectors.
The scan classifies the lifecycle issue as Medium.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  billing-srv-01 — A-004.

  CIA Rating:
  Confidentiality = High
  Integrity = High
  Availability = High
  Overall = High

  Criticality Impact on Priority:
  Raises urgency above an ordinary lifecycle warning because the server
  supports revenue operations and has already accumulated multiple security
  findings.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  None explicitly identified.

  Chain Role:
  Initial-access / foothold enabler over time. Unsupported software increases
  the pool of known vulnerabilities an opportunistic or ransomware attacker
  may be able to exploit.

  Kill Chain Impact on Priority:
  Raises urgency indirectly. The lifecycle condition does not define one
  exploit path, but it makes future vulnerable-software entry and persistence
  increasingly likely.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  N/A — there is no single exploit associated with "Ubuntu 18.04 EOL."

  CISA KEV:
  N/A as a lifecycle finding. Individual unpatched CVEs may have their own
  KEV status.

  Exploit Impact on Priority:
  The absence of one exploit score does not make the finding safe; it means
  remediation must address the unsupported platform rather than one CVE.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-002 — perimeter firewall.
  C-016 — nightly VM backup.
  C-026 — Linux syslog.
  C-027 — Apache log retention.

  Control Impact on Priority:
  Small reduction in impact/detection only. None restores a supported patch
  lifecycle. Logs are locally reviewed and backups cannot prevent exploitation.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  N/A — there is no single Base vector to modify.

  Adjusted Score:
  N/A

Final Priority:
High

Final Justification:
The scanner's Medium lifecycle label understates the operational urgency of
Finding 011. The host is a High-value business server with repeated compromise
history and several additional vulnerabilities, while the existing controls
mainly support detection and recovery rather than preventing exploitation.
Because an unsupported patch state continuously creates new exposure, the
correct response is a supported upgrade/maintenance path and short-term
containment, not individual CVE cleanup alone.
```

---

# 8. Finding 009 — Password-Based SSH Authentication on `billing-srv-01`

```text
Finding 009 - Password-based SSH authentication enabled

CVSS Base Score:
N/A — SSH password authentication is a configuration choice rather than a
software vulnerability with a CVE/Base vector. The scan classifies it High.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  billing-srv-01 — A-004.

  CIA Rating:
  Confidentiality = High
  Integrity = High
  Availability = High
  Overall = High

  Criticality Impact on Priority:
  Maintains High urgency because authenticated shell access to the billing
  server provides direct access to a sensitive business asset and a foothold
  inside the flat network.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  None explicitly by Finding ID.

  Chain Role:
  Credential-based initial access / persistence. It aligns with the 1x01
  ransomware preference for valid/stolen credentials.

  Kill Chain Impact on Priority:
  Raises urgency because successful credential abuse produces a legitimate
  remote session and places the attacker directly inside the same network used
  for later discovery and lateral movement.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  N/A — no exploit is required.

  CISA KEV:
  N/A — no CVE.

  Exploit Impact on Priority:
  No numerical reduction. The relevant threat is password theft/reuse/guessing,
  not exploit-code availability.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-009 — general password requirements, rated Weak.
  C-026 — Linux syslog.
  C-002 — perimeter default-deny rule.
  MedDefense has demonstrated C-005 key-only SSH on ehr-srv-01, but that
  stronger control is not implemented on billing-srv-01.

  Control Impact on Priority:
  Only slightly lowers likelihood. Password policy and logging provide some
  resistance/evidence, but no billing-specific key-only authentication or
  broadly implemented MFA/PAM is documented.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  N/A — no valid Base vector exists.

  Adjusted Score:
  N/A

Final Priority:
High

Final Justification:
Finding 009 remains High because it exposes a practical credential-based route
to a repeatedly compromised server. It is not a software exploit and therefore
cannot be meaningfully scored in the NIST CVSS calculator, but the threat
context is clear: ransomware actors prefer valid credentials and GAP-001 turns
a successful SSH login into a useful internal foothold. The weak general
password control and lack of key-only/MFA protection on this server provide
insufficient compensating protection.
```

---

# 9. Finding 010 — BD Alaris Network Session Authentication Weakness

```text
Finding 010 - CVE-2020-25165

CVSS Base Score:
7.5 High
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

Applicability gate:
MedDefense records Alaris software/firmware 12.1.2. BD states that PC Unit
software 12.1.1 and newer addresses CVE-2020-25165. The Environmental score
below therefore describes the risk IF the affected component/version is
confirmed; it does not override the version-validation requirement.

Factor 1 - Asset Criticality (from 1x00):
  Asset:
  BD Alaris infusion-pump estate — A-032.

  CIA Rating:
  Confidentiality = High
  Integrity = Critical
  Availability = Critical
  Overall = Critical

  Criticality Impact on Priority:
  Strongly raises urgency. The Base vector contains Availability impact only,
  and Availability is Critical to medication delivery. CVSS requirements map
  to CR:M / IR:H / AR:H.

Factor 2 - Kill Chain Position (from 1x01):
  Appears in Kill Chain(s):
  Kill Chain #5 — Malicious insider -> medical-device access -> BD Alaris
  disruption.

  Chain Role:
  Clinical target / objective execution. The attacker reaches the pump
  environment after obtaining internal access and abuses device-management or
  network weaknesses to disrupt operation.

  Kill Chain Impact on Priority:
  Raises urgency because this is not merely an IT support service. Successful
  disruption can force manual medication workflows and affect patient care.

Factor 3 - Exploitability (from T4):
  Exploitability Score:
  2/5 using the same Task 4 rubric, assessed later in Task 10 because Finding
  010 was not one of T4's selected five CVEs.

  CISA KEV:
  No.

  Exploit Impact on Priority:
  Lowers immediate exploit urgency relative to Findings 004/001/002 because
  no mature weaponized exploit/KEV evidence was established and exact version
  applicability is uncertain.

Factor 4 - Compensating Controls (from 1x00):
  Existing Controls:
  C-002 — perimeter firewall.
  C-003 — firewall traffic logging where traffic crosses the FortiGate.
  C-023 — annual awareness training.

  Control Impact on Priority:
  Minimal reduction. The Alaris estate is rated Under-Protected in the Control
  Matrix: no device-specific segmentation, corrective recovery capability or
  compensating control is documented.

Environmental CVSS (recalculated):
  Environmental Metrics Applied:
  CR:M / IR:H / AR:H.
  Modified metrics unchanged because MedDefense's current controls do not
  materially restrict the vulnerable network path within the flat environment.

  Environmental Vector:
  AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/CR:M/IR:H/AR:H

  Adjusted Score:
  9.3 Critical — conditional on the CVE actually applying to the installed
  Alaris component/version.

Final Priority:
High (validation-first; Critical if affected version is confirmed)

Final Justification:
Finding 010 produces the largest numerical contextual increase: the Base score
of 7.5 becomes 9.3 when MedDefense's Critical Availability requirement is
applied. That is exactly the patient-safety effect CVSS Environmental metrics
are intended to expose. However, contextual scoring cannot repair an
applicability problem. Because BD indicates that PC Unit 12.1.1+ addresses
CVE-2020-25165 and MedDefense records 12.1.2, the first action is to verify the
exact affected component and version. If the vulnerable condition is
confirmed, the combination of Critical clinical Availability and weak device
isolation makes the finding Critical; if not, the CVE should be closed while
the broader Alaris segmentation and later-vulnerability work remains open.
```

**NIST calculator vector:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AN%2FI%3AN%2FA%3AH%2FCR%3AM%2FIR%3AH%2FAR%3AH&version=3.1

---

# 10. Priority Comparison Table

| Finding | Base CVSS / Scan Severity | Environmental Score | Adjusted Priority | Change Direction |
|---|---|---:|---|---|
| **004** | 9.8 Critical representative (BlueKeep) | **9.8** | **Critical** | Same |
| **003** | N/A — Critical misconfiguration | N/A | **Critical** | **Higher by context / unscored technically** |
| **007** | N/A — High misconfiguration | N/A | **Critical** | **Higher** |
| **001** | 9.8 Critical | **9.8** | **Critical** | Same |
| **002** | 7.8 High | **7.8** | **High** | Same |
| **011** | N/A — Medium lifecycle finding | N/A | **High** | **Higher** |
| **009** | N/A — High misconfiguration | N/A | **High** | Same |
| **010** | 7.5 High | **9.3 Critical*** | **High now / Critical if confirmed** | **Higher numerically, validation-gated** |

\* **Finding 010 is the clearest significant CVSS change:** 7.5 -> 9.3 when the Critical Availability requirement of the infusion-pump estate is applied. The score is conditional on CVE-2020-25165 actually applying to the installed component/version.

### Significant Contextual Changes

**Finding 003** shows the opposite problem from a high-CVSS false positive: it has **no CVSS score at all**, yet threat context makes it Critical because it exposes the EHR database and appears directly in two kill chains.

**Finding 007** moves from a High scanner/configuration concern to a **Critical organisational priority** because it sits on Active Directory, a shared identity dependency used in multiple attack paths.

**Finding 011** moves from a Medium lifecycle observation to **High** because unsupported software is not an isolated defect; on `billing-srv-01` it is the condition underneath a growing collection of exploitable weaknesses.

**Finding 010** moves from **7.5 to 9.3 numerically** when clinical Availability is weighted correctly, but its final remediation state remains gated by exact-version validation.

---

# 11. Overall Contextualized Priority

The contextualized results confirm that **CVSS is one input, not the remediation queue**. Findings 001 and 004 remain Critical because strong technical exploitability and high-impact assets already align with their Base scores. Finding 002 remains High numerically but is operationally urgent because it chains directly with Finding 001. Findings 003 and 007 demonstrate that unscored configuration weaknesses can be more dangerous than many named CVEs when they sit on the EHR database or Active Directory and appear inside credible attack paths. Finding 010 shows the value of true Environmental scoring: a 7.5 Availability-only vulnerability becomes 9.3 when the affected function is medication delivery, although applicability still has to be proven before the CVE is treated as confirmed. The resulting priority therefore follows the model developed across all three projects:

**technical severity + asset criticality + attack-path position + exploit evidence + existing controls + applicability validation = MedDefense remediation priority**

---

# Sources

## MedDefense Project Evidence

- Project 1x00 — Asset Registry
- Project 1x00 — Asset Criticality Assessment
- Project 1x00 — Complete Control Matrix
- Project 1x00 — Prioritized Gap Analysis
- Project 1x01 — Threat Actor Matrix
- Project 1x01 — Critical Kill Chains
- Project 1x02 — `4-exploit_hunt.md`
- Project 1x02 — `10-critical_cves.md`
- Project 1x02 — `15-medical_iot.md`
- Project 1x02 — `16-triage.md`

## CVSS Methodology

- NVD CVSS v3.1 Calculator:  
  https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- FIRST CVSS v3.1 Specification:  
  https://www.first.org/cvss/v3-1/specification-document
- FIRST CVSS v3.1 User Guide:  
  https://www.first.org/cvss/v3-1/user-guide
