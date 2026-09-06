# MedDefense Health Systems — Critical Kill Chains

## Selection Basis

The five kill chains below are selected from the highest-impact intersections in `9-vector_asset_matrix.md`. The selection prioritises paths that combine **credible MedDefense exposure, high-value Critical assets and severe clinical or operational consequences**.

The paths are:

1. Phishing → Active Directory → EHR ransomware and data theft
2. VPN exploitation → internal network → backup neutralisation → ransomware
3. Supply-chain compromise → MedTech maintenance access → EHR compromise
4. Malicious insider → retained/privileged access → Active Directory compromise
5. Malicious insider → medical-device access → BD Alaris disruption

These chains are scenarios, not claims that each event has already occurred. Where a technical condition is not proven—for example, a currently exploitable FortiGate vulnerability—the chain states it as a possible attack path rather than an observed fact.

---

# Kill Chain #1 — Phishing to EHR Double Extortion

**Threat Actor:** **Ransomware Groups / Organized Crime** — Task 6 rates ransomware as MedDefense's highest-priority external threat, with Critical/Very High likelihood and Medium-High capability. Common entry methods include phishing, valid credentials and exploitation of public-facing services.

**Target Asset:** **EHR System** — `ehr-srv-01` (**A-001**), `ehr-db-01` (**A-002**) and EHR application (**A-036**)

**Expected Impact:** Loss of EHR availability during patient care, theft of Restricted patient information and potential corruption/encryption of clinical data — **Confidentiality, Integrity and Availability**

## Step 1 — Initial Access

**Vector:** Phishing / Spear Phishing  
**Surface:** Human  
**Detail:** A BlackReef-style affiliate sends a convincing healthcare or vendor-themed phishing message to a MedDefense employee. The attacker either captures a valid password or delivers malware to a managed or incompletely protected workstation, creating the first authenticated foothold.

## Step 2 — Establish Foothold

**Action:** The attacker reuses the stolen account or maintains remote access through the compromised endpoint while beginning internal reconnaissance.

**MedDefense Weakness:** **GAP-007** means MFA and privileged-access controls are not broadly implemented, so a stolen password may remain useful. **GAP-013** also means endpoint-security coverage is incomplete, while **GAP-011** reduces the chance that unusual authentication or endpoint activity is correlated quickly.

## Step 3 — Lateral Movement / Escalation

**Action:** The affiliate enumerates Active Directory, searches for higher-privilege credentials and moves from the user endpoint toward `ad-dc-01` / `ad-dc-02` and the EHR environment. Once sufficient privileges are obtained, the attacker can reach `ehr-srv-01` and can also attempt direct interaction with `ehr-db-01`, whose PostgreSQL service on TCP 5432 is reachable from the wider internal network.

**MedDefense Weakness:** **GAP-001 — no effective internal segmentation** allows workstation, server and medical-device environments to remain broadly reachable. **GAP-002** specifically exposes `ehr-db-01` beyond the EHR application server, while **GAP-007** increases the value of stolen privileged credentials.

## Step 4 — Objective Execution

**Action:** The attacker exfiltrates patient information before encrypting EHR-related systems and other reachable hosts. If Active Directory administrative control is obtained, centralized mechanisms such as Group Policy can be abused to increase the scale of ransomware deployment.

**Data/System Affected:** Restricted EHR patient records, laboratory/clinical information, `ehr-srv-01`, `ehr-db-01`, the EHR application and potentially other Windows systems reachable through the domain.

## Step 5 — Impact

**Business Impact:** Clinicians may lose timely access to current patient information, forcing paper-based fallback and disrupting care. Data theft creates privacy, regulatory and reputational consequences even if systems are restored, while encryption creates financial loss and extortion pressure.

**CIA Pillars:**
- **Confidentiality:** Restricted patient information is exfiltrated.
- **Integrity:** Ransomware or attacker activity modifies/encrypts systems and data.
- **Availability:** EHR services become unavailable to clinical staff.

**Gaps Exploited:** `GAP-007`, `GAP-013`, `GAP-011`, `GAP-001`, `GAP-002`, potentially `GAP-008`

## Break Points

1. **Step 1 — Prevent credential-based entry:** Enforce phishing-resistant MFA for remote and Critical-system access and continue user awareness under **C-023**. **C-014/C-015** should cover the full endpoint estate so delivered malware is blocked or contained.
2. **Step 2 — Detect the foothold:** Centralize authentication, Windows, EHR and firewall logs and alert on unusual logins, impossible travel, abnormal endpoint behavior and credential use, directly addressing **GAP-011**.
3. **Step 3 — Stop lateral movement:** Enforce internal VLAN/security zones and inter-zone firewall rules so a compromised workstation cannot freely reach AD, EHR database and other Critical systems; restrict PostgreSQL 5432 on `ehr-db-01` to required application paths.
4. **Step 4 — Reduce ransomware impact:** Isolate/off-site recovery copies and verify restores so ransomware cannot remove the only practical recovery path.

---

# Kill Chain #2 — VPN Entry to Backup Neutralisation

**Threat Actor:** **Ransomware Groups / Organized Crime** — Task 6 identifies exploitation of public-facing services and remote access as preferred ransomware vectors. Task 2 also shows that RaaS affiliates deliberately search for backups before encryption.

**Target Asset:** **Backup / Recovery Infrastructure** — `backup-srv-01` (**A-009**), `NAS-01` (**A-010**) and Veeam (**A-041**)

**Expected Impact:** Loss or degradation of MedDefense's ability to restore Critical systems during ransomware, increasing downtime and ransom pressure — primarily **Availability and Integrity**, with Confidentiality also at risk if data is stolen before encryption.

## Step 1 — Initial Access

**Vector:** VPN Exploit  
**Surface:** External  
**Detail:** An attacker exploits a vulnerability in an Internet-facing VPN/perimeter service and obtains an authenticated or network-level foothold. MedDefense's current evidence does **not** prove that the FortiGate 100F is presently vulnerable or unpatched; the risk exists because the organisation lacks a documented end-to-end vulnerability and patch-management programme for exposed systems.

## Step 2 — Establish Foothold

**Action:** The attacker maintains access through the compromised remote-access path and begins network discovery, including identification of Active Directory, file servers and recovery infrastructure.

**MedDefense Weakness:** **GAP-016** weakens assurance that exposed vulnerabilities are identified and remediated systematically. **GAP-011** means FortiGate and server logs exist but are not continuously correlated and alerted on.

## Step 3 — Lateral Movement / Escalation

**Action:** The attacker harvests credentials, attempts to obtain elevated privileges and traverses the flat Central environment until `backup-srv-01` and `NAS-01` are reachable. `NAS-01` management ports 5000/5001 are accessible from the wider internal network.

**MedDefense Weakness:** **GAP-001** enables broad east-west movement, **GAP-007** increases the value of stolen privileged credentials and **GAP-008** places recovery systems in the same local network/physical environment as production.

## Step 4 — Objective Execution

**Action:** The attacker deletes, encrypts or otherwise disrupts reachable backup copies and recovery services, then deploys ransomware to production systems. A BlackReef-style affiliate may also exfiltrate sensitive information before encryption.

**Data/System Affected:** `backup-srv-01`, `NAS-01`, Veeam recovery operations and backed-up copies of EHR, billing, Active Directory and other in-scope virtual machines.

## Step 5 — Impact

**Business Impact:** MedDefense loses confidence in its fastest recovery path at the same time production systems are encrypted. Clinical outages can last substantially longer, manual procedures remain in use, revenue is interrupted and leadership faces greater pressure to pay.

**CIA Pillars:**
- **Availability:** Recovery copies and production systems may become unavailable simultaneously.
- **Integrity:** Backup sets or configurations may be deleted or altered.
- **Confidentiality:** If the attacker exfiltrates data before encryption, backup or production data may also be exposed.

**Gaps Exploited:** `GAP-016`, `GAP-011`, `GAP-001`, `GAP-007`, `GAP-008`

## Break Points

1. **Step 1 — Close the exposed entry path:** Implement formal vulnerability scanning, patch ownership, emergency remediation and verification for Internet-facing VPN/perimeter devices under **GAP-016**.
2. **Step 2 — Detect abnormal remote access:** Correlate **C-003/C-024 FortiGate logs** with identity and endpoint telemetry and alert on unusual VPN behavior, addressing **GAP-011**.
3. **Step 3 — Restrict recovery-system reachability:** Segment backup administration from ordinary user/server traffic and limit NAS/backup management access to dedicated administrative paths.
4. **Step 4 — Preserve recovery:** Maintain isolated/off-site or otherwise protected recovery copies and conduct current restore tests so destruction of locally reachable backups does not remove MedDefense's ability to recover.

---

# Kill Chain #3 — Compromised MedTech Access to the EHR

**Threat Actor:** **Ransomware Groups / Organized Crime** — Task 6 includes trusted third-party access among realistic ransomware entry paths. Task 5 rates MedTech Solutions as a Critical supply-chain dependency because it has direct maintenance access to MedDefense's EHR environment.

**Target Asset:** **EHR System** — `ehr-srv-01` (**A-001**) and EHR application (**A-036**), with a possible route toward `ehr-db-01` (**A-002**)

**Expected Impact:** Compromise of MedDefense's most important clinical application through a trusted vendor channel, potentially resulting in patient-data theft, EHR manipulation or ransomware disruption — **Confidentiality, Integrity and Availability**

## Step 1 — Initial Access

**Vector:** Supply Chain Compromise  
**Surface:** External  
**Detail:** The attacker first compromises a MedTech engineer's credentials, workstation or maintenance platform outside MedDefense. The attacker then uses the legitimate vendor relationship to reach the documented MedTech maintenance scope on `ehr-srv-01`.

## Step 2 — Establish Foothold

**Action:** Once the trusted maintenance path is accepted, the attacker attempts to maintain access within the EHR server/application environment and blend activity with legitimate vendor administration.

**MedDefense Weakness:** The Control Matrix does not document a vendor-specific allowlist, privileged-access-management workflow, session recording or just-in-time/time-limited MedTech access. This aligns most closely with **GAP-007** and is made harder to detect by **GAP-011**.

## Step 3 — Lateral Movement / Escalation

**Action:** From `ehr-srv-01`, the attacker enumerates reachable systems and attempts to move toward `ehr-db-01`, Active Directory or other Central servers. MedTech is not documented as having authorized direct database access, but the database service is reachable more broadly than necessary.

**MedDefense Weakness:** **GAP-001** permits wider internal reachability, while **GAP-002** allows PostgreSQL 5432 on `ehr-db-01` to be reached from more than the EHR application path.

## Step 4 — Objective Execution

**Action:** The attacker steals EHR-accessible patient data, tampers with application components or deploys ransomware within the EHR environment. If additional privileges are obtained, the compromise can expand beyond the original vendor maintenance scope.

**Data/System Affected:** EHR application, `ehr-srv-01`, potentially `ehr-db-01`, Restricted patient records and associated clinical workflows.

## Step 5 — Impact

**Business Impact:** A trusted maintenance relationship becomes the path to a Critical clinical outage or privacy breach. MedDefense may also face a difficult investigation because malicious activity can initially resemble authorized vendor work.

**CIA Pillars:**
- **Confidentiality:** EHR-accessible patient information may be stolen.
- **Integrity:** Application components or records may be altered.
- **Availability:** EHR service may be encrypted or disrupted.

**Gaps Exploited:** `GAP-007`, `GAP-011`, `GAP-001`, `GAP-002`

## Break Points

1. **Step 1 — Constrain vendor authentication:** Require named vendor accounts, strong MFA, source restrictions and just-in-time/time-limited maintenance access instead of standing trust.
2. **Step 2 — Monitor vendor sessions:** Centralize and alert on vendor logins, commands, file changes and activity outside approved maintenance windows, addressing **GAP-011**.
3. **Step 3 — Enforce least network privilege:** Allow the MedTech maintenance path to reach only the systems and services explicitly required; block unnecessary movement from `ehr-srv-01` toward other internal zones.
4. **Step 4 — Use existing EHR/SSH controls effectively:** **C-004 to C-008** and **C-028** provide server hardening and audit evidence; regular review and correlation of those logs could identify abnormal vendor behavior before impact.

---

# Kill Chain #4 — Retained Insider Access to Active Directory

**Threat Actor:** **Insider — Malicious** — Task 6 rates malicious insiders Medium likelihood but potentially High effective capability because legitimate knowledge and access can bypass perimeter defenses. Task 3 also identified the risk of contractor accounts remaining active after termination.

**Target Asset:** **Active Directory** — `ad-dc-01` (**A-005**) and `ad-dc-02` (**A-006**)

**Expected Impact:** Unauthorized control of authentication, accounts or privileges across MedDefense, potentially causing widespread access loss or enabling further compromise — **Integrity and Availability**, with Confidentiality at risk through unauthorized access.

## Step 1 — Initial Access

**Vector:** Insider — Malicious / retained valid account  
**Surface:** External  
**Detail:** A former or departing IT user whose VPN/account access was not disabled uses still-valid credentials to reconnect after their legitimate relationship with MedDefense has ended.

## Step 2 — Establish Foothold

**Action:** The insider continues using the valid account during off-hours and attempts to preserve access by retaining credentials, creating additional access where privileges permit, or locating reusable administrative credentials.

**MedDefense Weakness:** **GAP-017** means offboarding is not formally integrated with HR/contract termination events. **GAP-011** means post-termination authentication can be logged without necessarily being detected immediately.

## Step 3 — Lateral Movement / Escalation

**Action:** The insider uses knowledge of MedDefense's environment to identify domain controllers and attempts to obtain or reuse privileged credentials. If successful, the insider can modify accounts, groups or authentication policy centrally.

**MedDefense Weakness:** **GAP-007** reflects incomplete MFA/PAM and administrative-account separation, while **GAP-001** means the wider internal environment remains broadly reachable once the VPN foothold is established.

## Step 4 — Objective Execution

**Action:** The insider changes privileged group membership, creates unauthorized accounts, disables legitimate accounts or modifies authentication-related configuration to maintain control or cause disruption.

**Data/System Affected:** `ad-dc-01`, `ad-dc-02`, user and administrator identities, authentication services and downstream systems that depend on Active Directory.

## Step 5 — Impact

**Business Impact:** Users may be unable to authenticate to clinical and business systems, or the attacker may gain unauthorized access across multiple systems through centrally altered privileges. Investigation and recovery become more difficult if identity records themselves are modified.

**CIA Pillars:**
- **Integrity:** Accounts, groups and authentication configuration are changed without authorization.
- **Availability:** Legitimate users may lose access to systems that depend on AD.
- **Confidentiality:** Unauthorized privileges can expose data in connected applications and file services.

**Gaps Exploited:** `GAP-017`, `GAP-011`, `GAP-007`, `GAP-001`

## Break Points

1. **Step 1 — Remove access at termination:** Implement an automated or centrally coordinated joiner-mover-leaver process that disables VPN, AD and application access at the documented contract/employment end time.
2. **Step 2 — Alert on residual accounts:** Correlate HR/contract status with active-account and VPN logs; any successful post-termination login should generate immediate investigation.
3. **Step 3 — Restrict privileged escalation:** Deploy PAM, separate standard and administrative identities, require MFA for privileged operations and use least privilege so an ordinary support account cannot become a domain-wide account.
4. **Step 4 — Detect directory changes:** Use **C-029 Active Directory Critical Event Logging** with centralized alerting for new privileged accounts, group membership changes and unusual account disablement.

---

# Kill Chain #5 — Insider Abuse of the Alaris Pump Environment

**Threat Actor:** **Insider — Malicious** — Task 6 notes that insiders may have low technical sophistication but high effective capability because they can begin with legitimate clinical or technical access. For medical devices, trusted access is particularly important because the systems support direct patient care.

**Target Asset:** **BD Alaris Infusion-Pump Estate — A-032**

**Expected Impact:** Unauthorized changes or disruption affecting medication-delivery systems and associated Restricted information — primarily **Integrity and Availability**, with potential patient-safety consequences.

## Step 1 — Initial Access

**Vector:** Insider — Malicious  
**Surface:** Human / Internal  
**Detail:** A clinical, biomedical or technical user with legitimate access to the MedDefense environment intentionally abuses that access to reach the medical-device estate rather than performing an authorized patient-care or maintenance function.

## Step 2 — Establish Foothold

**Action:** The insider uses an approved workstation or existing device-management access and identifies the Alaris pump estate and its management interfaces.

**MedDefense Weakness:** **GAP-018** exists because MedDefense has not verified a medical-device-specific credential-hardening baseline or confirmed that vendor-default credentials have been removed across embedded clinical systems. **GAP-011** also means device-related activity is not covered by strong centralized behavioral monitoring.

## Step 3 — Lateral Movement / Escalation

**Action:** The insider reaches infusion-pump interfaces from the broader internal environment and attempts to obtain administrative-level device access or misuse whatever management functions their existing access permits.

**MedDefense Weakness:** **GAP-003** means medical IoT lacks dedicated isolation and monitoring, while **GAP-001** means the `10.10.3.0/24` addressing range is not an enforced security zone. The Asset Registry also records known Alaris CVEs and absence of recommended network isolation.

## Step 4 — Objective Execution

**Action:** The insider performs unauthorized configuration changes, disables or disrupts device-management functions, or accesses medication/patient information available through the management interface. The exact device capabilities available to a given account must be verified, so the scenario does not assume that every pump setting can be changed remotely.

**Data/System Affected:** BD Alaris infusion pumps, medication/dosage information and associated clinical availability.

## Step 5 — Impact

**Business Impact:** Device disruption could delay or complicate medication delivery and force clinical teams to move to manual or alternative workflows. Unauthorized access to medication information creates privacy exposure, while configuration changes create a direct patient-safety concern.

**CIA Pillars:**
- **Integrity:** Unauthorized device/configuration changes can undermine confidence in medication-delivery settings.
- **Availability:** Pumps or their management functions may be disrupted.
- **Confidentiality:** Patient or medication information accessible through the device environment may be exposed.

**Gaps Exploited:** `GAP-018`, `GAP-003`, `GAP-001`, `GAP-011`

## Break Points

1. **Step 1 — Limit legitimate access:** Define named, role-based device-management accounts and remove shared/default administrative access where the platform supports it.
2. **Step 2 — Harden device credentials:** Establish and verify a medical-device credential baseline, including replacement of vendor-default credentials where technically supported, directly addressing **GAP-018**.
3. **Step 3 — Isolate medical IoT:** Place infusion pumps in dedicated clinical-device security zones and permit only the specific systems and protocols required for care and management, addressing **GAP-003/GAP-001**.
4. **Step 4 — Detect misuse:** Monitor medical-device management traffic and alert on unusual administrative access, configuration changes or communication patterns.

---

# Cross-Chain Defensive Priorities

The five kill chains repeatedly depend on the same small set of weaknesses. **GAP-001** appears in every chain that requires movement beyond the initial foothold, while **GAP-011** repeatedly gives malicious activity more time to continue before detection. **GAP-007** makes stolen or retained credentials more valuable, and **GAP-008**, **GAP-017** and **GAP-018** create high-impact weaknesses in recovery, offboarding and medical-device administration respectively.

The defensive conclusion is therefore consistent across the threat landscape: MedDefense should not attempt to build a separate defence for every attacker. The highest-value controls are those that **break several kill chains at once** — strong MFA/PAM and account lifecycle controls, enforced internal segmentation, centralized monitoring and alerting, protected recovery infrastructure, systematic vulnerability management and dedicated medical-IoT isolation.
