# MedDefense Health Systems — Integrated Threat Scenarios

## Purpose

These three scenarios consolidate the threat-actor, attack-vector, attack-surface, kill-chain, STRIDE and MITRE ATT&CK analysis completed in Project `1x01_know_your_enemy`.

Each scenario uses a **different threat actor type and a different primary vector**:

1. Organized Crime / RaaS — spear phishing
2. Malicious Insider — legitimate EHR access abused
3. Nation-State APT — compromised vendor maintenance pathway

The scenarios are evidence-based possibilities, not claims that the described attacks have occurred. Where a condition is uncertain, the scenario keeps that uncertainty explicit.

> **STRIDE note:** The current project artifacts include the EHR STRIDE model from Task 11. No separate Task 12 STRIDE artifact is present in the available project files, so EHR threat IDs from Task 11 are referenced where applicable and category-level STRIDE mappings are used where no exact existing threat ID applies.

---

# Scenario 1 — BlackReef: From a Phished IT Director to Hospital-Wide Ransomware

**Threat Actor:** **Ransomware Groups / Organized Crime — BlackReef RaaS affiliate profile from Tasks 2 and 6.** Ransomware is MedDefense's highest-priority external threat because the organization matches the mid-size healthcare victim profile and its internal gaps align closely with a RaaS attack lifecycle.

**Motivation:** **Financial gain / blackmail**

**Initial Vector:** **Phishing / Spear Phishing** — a Fortinet-themed message targets Sarah Park, IT Director.

**Attack Surface Exploited:** **Human surface first, then Internal surface.** Sarah's privileged IT role makes her a high-value social-engineering target; after the first endpoint is compromised, Central's flat internal network becomes the main attack surface.

## Attack Sequence

### Step 1 — Spear phishing creates the initial foothold — **Initial Access**

A BlackReef affiliate sends Sarah Park a convincing Fortinet support message warning of an urgent security issue. She follows the malicious link and opens the delivered file, giving the attacker execution on her workstation through the same type of spear-phishing path mapped in Task 13.

**ATT&CK reference:** Initial Access — Phishing: Spearphishing Link (`T1566.002`); execution may follow through User Execution / PowerShell.

### Step 2 — The attacker establishes persistence on the workstation — **Persistence**

The attacker installs a scheduled task or similar recurring mechanism so access survives a reboot and appears to blend with normal Windows activity. The foothold can remain active because endpoint and identity events are not continuously correlated.

**MedDefense factor:** **GAP-011** limits continuous detection, while **GAP-013** means endpoint-security coverage cannot be assumed complete across the full estate.

### Step 3 — Active Directory and Critical systems are mapped — **Discovery**

The affiliate enumerates domain controllers, privileged groups, EHR systems, backup infrastructure and other reachable servers. Central's `10.10.1.0/24`, `10.10.2.0/24` and `10.10.3.0/24` ranges are addressing conventions rather than enforced security zones.

**MedDefense factor:** **GAP-001** allows one internal foothold to discover systems that should be separated.

### Step 4 — Privileged credentials are obtained — **Credential Access / Privilege Escalation**

The attacker attempts credential dumping from the compromised workstation and searches for reusable administrative credentials. If an NTLM hash or privileged account is obtained, the attacker can move from a normal endpoint compromise toward domain-level control.

**MedDefense factor:** **GAP-007** means MFA, PAM and separated administrative identities are not broadly implemented.

### Step 5 — The attacker reaches Active Directory and the EHR — **Lateral Movement**

Using the stolen privileged material, the affiliate authenticates to Active Directory and moves toward `ehr-srv-01` (**A-001**) and `ehr-db-01` (**A-002**). PostgreSQL TCP 5432 on `ehr-db-01` is reachable from the wider internal environment rather than only from the EHR application server.

**MedDefense factor:** **GAP-001** enables lateral movement and **GAP-002** provides an unnecessarily broad direct path to the EHR database.

### Step 6 — Patient and business information is stolen — **Collection / Exfiltration**

The attacker collects EHR data and other valuable information, compresses the material and transfers it to attacker-controlled infrastructure before encryption. This gives BlackReef double-extortion leverage even if MedDefense later restores its systems.

**MedDefense factor:** **GAP-011** makes it difficult to correlate abnormal database activity, unusually large collections and outbound transfer. The wider absence of organization-wide DLP under **GAP-020** also reduces visibility into sensitive-data movement.

### Step 7 — Recovery capability is weakened — **Impact**

Before ransomware deployment, the affiliate targets `backup-srv-01` (**A-009**), `NAS-01` (**A-010**) and local recovery mechanisms. `NAS-01` management ports 5000/5001 are reachable internally and the backup infrastructure remains concentrated in the same local network/physical environment as production.

**MedDefense factor:** **GAP-008** allows a production compromise and a recovery compromise to occur within the same event.

### Step 8 — BlackReef encrypts reachable systems — **Impact**

With privileged access established and recovery weakened, the attacker deploys ransomware to Windows systems through domain-level mechanisms and targets reachable Linux systems separately. EHR, authentication, billing and other clinical/business services can become unavailable at the same time.

**ATT&CK reference:** Data Encrypted for Impact (`T1486`); Group Policy modification may be used as a deployment mechanism.

## STRIDE Categories Triggered

- **Spoofing — `EHR-S1`:** stolen identity/credentials are used as a legitimate-looking foothold.
- **Tampering — `EHR-T1` / `EHR-T2`:** privileged access can modify database records or EHR application components.
- **Repudiation — `EHR-R2`:** activity performed with compromised identities may initially appear to belong to legitimate users.
- **Information Disclosure — `EHR-I1`:** patient data can be extracted from `ehr-db-01`.
- **Denial of Service — `EHR-D1`:** ransomware makes the EHR unavailable.
- **Elevation of Privilege — `EHR-E1`:** a user-level compromise escalates through Active Directory.

## MedDefense Assets Impacted

- `ehr-srv-01` — **A-001**
- `ehr-db-01` — **A-002**
- `ad-dc-01` / `ad-dc-02` — **A-005 / A-006**
- `backup-srv-01` — **A-009**
- `NAS-01` — **A-010**
- Central Windows workstation estate — **A-020**
- EHR application — **A-036**
- Veeam Backup & Replication — **A-041**
- Potentially other reachable clinical and administrative systems

## Business Impact

**Clinical:** EHR and authentication outages can interrupt access to current patient histories, laboratory data and clinical documentation, forcing staff to paper fallback and slowing patient care.

**Financial:** Recovery costs, lost revenue, operational downtime and possible ransom payment could be substantial.

**Regulatory:** Exfiltration of Restricted patient information creates breach-notification, privacy and regulatory exposure even if systems are restored.

**Reputational:** A large ransomware event involving patient-data theft can reduce patient, partner and Board confidence in MedDefense's ability to protect clinical information.

## Gaps Exploited

- **GAP-013 — Incomplete endpoint/device-management coverage:** the initial endpoint may not have complete protective coverage.
- **GAP-011 — Fragmented, non-continuous monitoring:** persistence, discovery, credential abuse and data transfer can occur without timely correlation.
- **GAP-007 — MFA/PAM not broadly implemented:** stolen or harvested credentials remain more useful than they should be.
- **GAP-001 — No effective internal segmentation:** one compromised workstation can become a route toward Critical systems.
- **GAP-002 — EHR database reachable from the wider internal network:** direct PostgreSQL access expands EHR exposure.
- **GAP-008 — Backup infrastructure locally concentrated:** attackers can weaken production and recovery in the same campaign.
- **GAP-015 — No formal IR/BCP/DR programme:** response and recovery may be slower and more improvised.
- **GAP-020 — No organization-wide DLP/removable-media controls:** sensitive-data movement lacks a dedicated prevention/detection layer.

## Detection Opportunities

1. **Step 1 — Email and endpoint detection:** secure-email controls, lookalike-domain detection and `C-023` awareness training could identify the malicious Fortinet-themed message before execution.
2. **Step 2 — Persistence detection:** full EDR coverage plus centralized Windows telemetry could alert on a new scheduled task, suspicious PowerShell execution or recurring outbound connection.
3. **Steps 3–4 — Discovery and credential access:** a SIEM could correlate unusual AD enumeration, LSASS access, privileged-group queries and credential-dumping behavior.
4. **Step 5 — Lateral movement:** centralized AD and network telemetry could alert on unusual NTLM use, pass-the-hash indicators, new Domain Admin activity and unexpected workstation-to-server connections.
5. **Step 6 — Data theft:** database activity monitoring, DLP and egress analytics could flag bulk EHR queries, archive creation and large outbound HTTPS transfers.
6. **Step 7 — Recovery attack:** alerts on Veeam/NAS administrative changes, `vssadmin` use and bulk backup deletion could trigger containment before ransomware deployment.
7. **Step 8 — Domain-wide impact:** centralized monitoring of GPO changes and abnormal remote execution could identify mass-deployment behavior before encryption reaches the full estate.

---

# Scenario 2 — The Curious Employee: A High-Profile Patient Privacy Breach

**Threat Actor:** **Insider — Malicious, based on Task 3 Scenario 4 ("The Curious Employee").** The registration clerk already has legitimate EHR access appropriate to her work but intentionally uses it outside a valid care or business need.

**Motivation:** **Data exfiltration / unauthorized disclosure** — the insider deliberately obtains and releases patient information for non-business purposes.

**Initial Vector:** **Legitimate access abused**

**Attack Surface Exploited:** **Human / Internal surface.** No perimeter exploit is required because the employee begins inside MedDefense with an authenticated EHR account.

## Attack Sequence

### Step 1 — The clerk uses her legitimate account — **Initial Access**

The registration clerk signs into the EHR with her normal MedDefense identity. The authentication itself is legitimate; the malicious behavior begins when she decides to use that access for a purpose unrelated to her role.

**ATT&CK analogue:** Valid Accounts (`T1078`) is the closest operational mapping because the insider starts with an authorized identity.

### Step 2 — She searches for the local politician — **Collection**

The clerk searches for and opens the politician's EHR record despite having no registration, treatment or billing workflow requiring access to that patient.

**MedDefense factor:** **C-028** records EHR activity, but MedDefense does not continuously review the audit trail or automatically correlate access with care relationship and job role.

### Step 3 — She gathers sensitive visit information — **Collection**

The clerk reads information about the politician's hospital visit and retains the details she considers interesting. No technical exploit is necessary because the application accepts her authenticated session.

**MedDefense factor:** The core weakness is not lack of authentication; it is the inability to distinguish normal authorized access from inappropriate use quickly enough.

### Step 4 — She discloses the information to a friend — **Exfiltration**

The clerk communicates the confidential visit information to a friend outside MedDefense. This is a human disclosure rather than a traditional network exfiltration technique, but operationally the Restricted information has crossed the MedDefense trust boundary.

### Step 5 — The information is posted publicly — **Impact**

The friend posts the politician's treatment information on social media. By the time MedDefense becomes aware of the incident, the privacy loss cannot be reversed simply by disabling the employee's account.

## STRIDE Categories Triggered

- **Information Disclosure:** Restricted patient information is deliberately exposed to an unauthorized person.
- **Repudiation:** If the employee denies the disclosure, MedDefense may have audit evidence of record access but not direct technical proof of the later verbal/personal disclosure.
- **Closest Task 11 parallels:** `EHR-R1` / `EHR-R2` demonstrate the attribution problem around account activity, although this scenario is deliberate use of the employee's own authorized account rather than stolen or hijacked credentials.

No exact Task 11 threat ID describes **authorized-user curiosity followed by human disclosure**, so this scenario is not forced into an inaccurate EHR threat identifier.

## MedDefense Assets Impacted

- EHR application — **A-036**
- EHR patient records / `ehr-db-01` — **A-002**
- Registration/clinical endpoint used for EHR access — part of the Central workstation estate **A-020**
- Restricted patient information associated with the high-profile patient

## Business Impact

**Clinical:** Direct treatment availability is unlikely to be affected, but patients may become less willing to disclose sensitive information if they do not trust MedDefense to preserve confidentiality.

**Financial:** Legal response, investigation, notification and potential regulatory costs may follow the privacy breach.

**Regulatory:** Deliberate access without a job-related need and disclosure of health information creates serious patient-privacy and compliance exposure.

**Reputational:** Publication of a local politician's hospital visit could attract immediate media attention and create the perception that MedDefense staff can browse sensitive records without effective oversight.

## Gaps Exploited

- **GAP-011 — Security logging is fragmented and not continuously monitored:** the EHR records the access, but MedDefense does not have automated, timely detection of unusual patient-record access.

**Control-boundary note:** Project 1x00 did not assign a separate Gap ID for EHR "care relationship" or VIP-access controls. It would therefore be inaccurate to invent one or to treat **GAP-007** as the primary weakness, because the clerk is using her own legitimate non-privileged account rather than stolen or elevated credentials.

## Detection Opportunities

1. **Step 2 — VIP/high-risk record access:** EHR monitoring could flag any access to designated high-profile patient records for immediate review.
2. **Step 2 — Care-relationship analytics:** an automated rule could alert when a registration clerk accesses a record with no active registration, treatment, billing or departmental relationship.
3. **Step 3 — Behavioral analytics:** repeated searches outside the employee's normal patient population or unusual access patterns could create a risk score before disclosure occurs.
4. **Before Step 4 — Supervisor/security review:** centralized access alerts tied to `C-028` could allow Security to question the access while the information is still inside MedDefense.

The critical defensive point is that **the best opportunity is before disclosure**. Once the employee communicates the information verbally or through a personal channel, technical containment cannot restore confidentiality.

---

# Scenario 3 — Trusted Update, Untrusted Code: MedTech Supply-Chain Espionage

**Threat Actor:** **Nation-State APT — Task 6 profile.** Nation-state capability is Very High, but direct targeting likelihood against MedDefense is Low because MedDefense has no documented research programme. This scenario is therefore framed as a **downstream supply-chain compromise**: the attacker targets MedTech Solutions for access to multiple healthcare customers, and MedDefense becomes one affected customer rather than the primary strategic target.

**Motivation:** **Espionage**

**Initial Vector:** **Supply Chain Compromise / Vendor Access Pathway**

**Attack Surface Exploited:** **External third-party surface → Internal surface.** The initial trust relationship is MedTech's maintenance access to the EHR; once that access is abused, Central's internal architecture becomes the attacker's expansion path.

## Attack Sequence

### Step 1 — The attacker compromises MedTech — **Resource Development / Initial Access**

A nation-state actor compromises a MedTech engineer's workstation, credentials or maintenance platform outside MedDefense. The objective is to inherit MedTech's trusted access to downstream healthcare customers.

**MedDefense factor:** MedDefense cannot prevent the original compromise inside MedTech, so the security boundary must be the amount of trust MedDefense grants the vendor.

### Step 2 — The attacker enters MedDefense through the legitimate maintenance pathway — **Initial Access**

Using the compromised vendor identity or maintenance platform, the attacker connects to the documented MedTech maintenance scope on `ehr-srv-01` (**A-001**) and the EHR application (**A-036**).

**MedDefense factor:** Task 5 found no documented vendor-specific network allowlist, PAM workflow, session recording or just-in-time/time-limited MedTech access.

### Step 3 — Activity is made to resemble normal maintenance — **Persistence / Defense Evasion**

The attacker establishes a mechanism for repeat access within the EHR server environment and schedules or times activity to resemble authorized vendor administration.

**MedDefense factor:** **GAP-011** limits continuous monitoring of SSH, server and EHR audit data, making trusted administrator activity harder to distinguish from attacker activity.

### Step 4 — The attacker maps the EHR environment and internal dependencies — **Discovery**

From `ehr-srv-01`, the attacker identifies `ehr-db-01`, Active Directory, network paths and other reachable internal systems.

**MedDefense factor:** **GAP-001** means the server, workstation and medical-device environments are not separated by enforced internal security zones.

### Step 5 — The attacker expands beyond the intended vendor scope — **Lateral Movement / Elevation of Privilege**

The attacker attempts to move from the application server toward `ehr-db-01` and, if useful, Active Directory. MedTech is **not** documented as having authorized direct database access, but PostgreSQL TCP 5432 is reachable more broadly than the EHR application path.

**MedDefense factor:** **GAP-002** turns a vendor foothold on `ehr-srv-01` into a possible direct route toward the database; **GAP-007** increases the value of any privileged credentials obtained during the intrusion.

### Step 6 — Patient and operational information is collected — **Collection**

The attacker queries EHR-accessible information, database content or supporting system information valuable for intelligence purposes. Because the objective is espionage, the attacker prioritizes quiet, sustained collection rather than immediate disruption.

### Step 7 — Information leaves through a trusted or encrypted channel — **Exfiltration**

Collected information is transferred outside MedDefense using a channel designed to resemble normal encrypted administrative traffic or other legitimate outbound communication.

**MedDefense factor:** **GAP-011** means MedDefense lacks the centralized correlation needed to connect unusual vendor login times, large data access and outbound traffic into one incident.

## STRIDE Categories Triggered

- **Spoofing:** the attacker presents as a legitimate MedTech maintenance user.
- **Repudiation — closest to `EHR-R2`:** malicious activity may initially be attributed to the compromised vendor identity.
- **Information Disclosure — `EHR-I1`:** Restricted EHR data can be extracted from the database environment.
- **Elevation of Privilege — `EHR-E2`:** trusted maintenance access expands beyond the vendor's intended scope.
- **Tampering — potential `EHR-T2`:** if the attacker modifies application components to preserve access, EHR application integrity is affected.

**Denial of Service is not a primary objective in this scenario** because the actor is seeking long-term intelligence collection rather than ransomware-style disruption.

## MedDefense Assets Impacted

- `ehr-srv-01` — **A-001**
- `ehr-db-01` — **A-002**
- `ad-dc-01` / `ad-dc-02` — **A-005 / A-006**, if escalation reaches identity infrastructure
- EHR application — **A-036**
- Restricted patient records
- MedTech vendor trust relationship

## Business Impact

**Clinical:** The most serious clinical risk is loss of confidence in EHR integrity if the attacker modifies application components or records while maintaining covert access.

**Financial:** Investigation, forensic support, legal response and vendor remediation could create substantial unplanned costs even without a destructive outage.

**Regulatory:** Exfiltration of Restricted patient information through a trusted vendor still creates MedDefense breach-response and privacy obligations.

**Reputational:** Patients and the Board may view a third-party breach as a MedDefense governance failure if vendor access was broader or less monitored than necessary.

**Strategic:** A nation-state actor could retain long-term visibility into a healthcare environment without needing to attack MedDefense's perimeter directly.

## Gaps Exploited

- **GAP-011 — Fragmented, non-continuous monitoring:** trusted vendor activity is not continuously correlated with server, identity, database and network events.
- **GAP-001 — No effective internal segmentation:** a foothold intended for one EHR server can become a route toward other internal systems.
- **GAP-002 — EHR database reachable from the wider internal network:** the vendor foothold can potentially reach PostgreSQL outside its documented maintenance scope.
- **GAP-007 — MFA/PAM and privileged-access governance are incomplete:** any privileged credentials exposed during the compromise have greater value.

**Vendor-governance note:** Project 1x00 did not assign a dedicated numbered third-party-risk gap for MedTech. Task 5 nevertheless documented the absence of a vendor-specific allowlist, session recording, PAM workflow and just-in-time access. This scenario therefore uses the existing numbered gaps above rather than inventing a new Gap ID.

## Detection Opportunities

1. **Step 2 — Vendor access control:** require named vendor accounts, strong MFA, approved source restrictions and just-in-time access; alert on logins outside approved maintenance windows.
2. **Step 3 — Session visibility:** record and monitor privileged vendor sessions and correlate `C-008` SSH logs with `C-028` EHR audit events.
3. **Step 4 — Discovery detection:** alert when an EHR maintenance session begins enumerating unrelated hosts, Active Directory or services outside the approved vendor scope.
4. **Step 5 — Network segmentation:** block the chain technically by allowing the MedTech maintenance path to reach only the exact systems/services required; `ehr-db-01` should accept PostgreSQL connections only from approved application/administrative hosts.
5. **Step 6 — Database monitoring:** detect unusual query volume, broad patient-record access or database activity inconsistent with a maintenance window.
6. **Step 7 — Egress monitoring:** correlate vendor-session identity with outbound transfer volume and destination, using DLP/network analytics where appropriate.

---

# Cross-Scenario Assessment

These scenarios begin differently—**a phished employee, a malicious employee and a compromised vendor**—but they converge on the same MedDefense weaknesses. **GAP-011** appears in all three because useful logs exist without continuous correlation; this allows external, internal and third-party activity to look normal for too long. **GAP-001** is the major multiplier for the two external scenarios because once trust is obtained, the internal network allows the compromise to expand beyond the original foothold. The scenarios therefore show why MedDefense should prioritize controls that break multiple attack paths at once: centralized detection and alerting, internal segmentation, stronger identity/PAM controls, least-privilege vendor access, database access restrictions and protected recovery capability.

## Project Cross-References

- Project 1x01 Task 2 — `2-ransomware_assessment.md`
- Project 1x01 Task 3 — `3-insider_assessment.md`
- Project 1x01 Task 5 — `5-supply_chain_assessment.md`
- Project 1x01 Task 6 — `6-threat_actor_matrix.md`
- Project 1x01 Task 7 — `7-attack_surface_map.md`
- Project 1x01 Task 8 — `8-technical_vectors.md`
- Project 1x01 Task 10 — `10-kill_chains.md`
- Project 1x01 Task 11 — `11-stride_ehr.md`
- Project 1x01 Task 13 — `13-attck_mapping.md`
- Project 1x00 — `7-asset_registry.md`
- Project 1x00 — `12-gap_analysis.md`
- Project 1x00 — `15-predecessor_review.md`
