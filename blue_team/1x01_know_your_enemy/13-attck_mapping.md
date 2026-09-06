# MedDefense Health Systems — MITRE ATT&CK Mapping

## Scope

This assessment maps the two supplied MedDefense attack narratives to the MITRE ATT&CK Enterprise framework. Each numbered narrative step is assigned the **primary tactic** that best represents the attacker's main action at that point and the **most specific defensible technique**. Where a step contains more than one ATT&CK behavior, the strongest alternative mapping is noted.

The supplied scenarios occasionally describe preparatory or business-context actions that do not fit ATT&CK perfectly. In those cases, the closest operational mapping is used and the limitation is stated explicitly rather than forcing a false level of precision.

---

# Scenario Alpha — Operation Flatline

**Threat Actor:** BlackReef affiliate — Organized Crime / Ransomware-as-a-Service  
**Objective:** Double extortion through patient-data theft and ransomware encryption

## Step 1 — Target list of healthcare organizations with FortiGate appliances

**Brief Description:**  
The affiliate purchases a target list built by scanning Internet-facing FortiGate infrastructure and cross-referencing healthcare organizations.

**Tactic:** **Reconnaissance**

**Technique:** **Search Open Technical Databases: Scan Databases — T1596.005**

**Alternative:** **Active Scanning: Vulnerability Scanning — T1595.002** would apply if the affiliate performed the Internet scanning directly rather than consuming information gathered by the broker.

**MedDefense Factor:**  
MedDefense operates a Fortinet FortiGate 100F at its Internet edge. Project 1x00 also identified **GAP-016**, meaning vulnerability and patch management for exposed and Critical systems is not governed through a complete formal programme. The scenario does not prove that the MedDefense FortiGate currently has an exploitable vulnerability; it shows how its externally identifiable technology can place MedDefense on an attacker target list.

---

## Step 2 — Spear phishing Sarah Park with a fake Fortinet support portal

**Brief Description:**  
Sarah receives a Fortinet-themed spear phishing email, follows a malicious link, downloads a document and opens it; a macro launches PowerShell and executes a reverse-shell payload.

**Tactic:** **Initial Access**

**Technique:** **Phishing: Spearphishing Link — T1566.002**

**Alternatives:**  
- **User Execution: Malicious File — T1204.002** for Sarah opening the downloaded document
- **Command and Scripting Interpreter: PowerShell — T1059.001** for execution of the PowerShell command

**MedDefense Factor:**  
Sarah is the IT Director and therefore a high-value target for a believable security-vendor message. MedDefense has annual security-awareness training (**C-023**), but Task 4 showed how urgency and vendor impersonation could still exploit trusted administrative workflows. Endpoint coverage is also incomplete under **GAP-013**.

---

## Step 3 — Scheduled-task backdoor on Sarah's workstation

**Brief Description:**  
The reverse shell establishes attacker access and a scheduled task disguised as Windows Update reconnects every 30 minutes.

**Tactic:** **Persistence**

**Technique:** **Scheduled Task/Job: Scheduled Task — T1053.005**

**Alternative:**  
The active reverse-shell connection also represents **Command and Control**, but the narrative does not identify the application-layer protocol clearly enough to assign a more specific C2 technique confidently.

**MedDefense Factor:**  
The attacker has compromised `WS-HQ-01` and can retain access through a normal Windows scheduling mechanism. MedDefense's **GAP-011** is important here because endpoint, Windows and network logs are not centrally correlated and continuously monitored.

---

## Step 4 — Discovery of MedDefense systems and Domain Admins

**Brief Description:**  
The affiliate uses `nltest`, `net group "Domain Admins" /domain` and `arp -a` to identify domain infrastructure, privileged groups and reachable hosts.

**Tactic:** **Discovery**

**Technique:** **Remote System Discovery — T1018**

**Alternative:** **Permission Groups Discovery: Domain Groups — T1069.002** specifically maps the `net group "Domain Admins" /domain` command.

**MedDefense Factor:**  
HQ connects to Central through a site-to-site VPN, and Central's apparent workstation, server and medical-device subnets are not enforced security zones. **GAP-001** therefore allows a compromised endpoint to discover a much wider environment than necessary, including AD, EHR, billing and backup systems.

---

## Step 5 — Mimikatz dumps cached credentials from memory

**Brief Description:**  
Mimikatz extracts credentials from Sarah's workstation and recovers the NTLM hash of the `svc_backup` domain administrator account.

**Tactic:** **Credential Access**

**Technique:** **OS Credential Dumping: LSASS Memory — T1003.001**

**MedDefense Factor:**  
A Domain Admin credential had previously been used on Sarah's workstation during backup troubleshooting, leaving high-value credential material available to the compromised host. **GAP-007** reflects MedDefense's incomplete privileged-access management and administrative-account separation.

---

## Step 6 — Pass-the-hash to `ad-dc-01`

**Brief Description:**  
The affiliate uses the captured `svc_backup` NTLM hash to authenticate to `ad-dc-01` and gains Domain Admin access.

**Tactic:** **Lateral Movement**

**Technique:** **Use Alternate Authentication Material: Pass the Hash — T1550.002**

**Alternative:**  
The follow-on query for domain computer objects is also **Discovery**, but the defining action in this step is movement to the domain controller using the stolen hash.

**MedDefense Factor:**  
Active Directory is a Critical shared dependency, and **GAP-007** means stronger PAM/MFA controls are not broadly implemented. **GAP-001** also means the attacker can reach the domain controllers from the compromised internal position.

---

## Step 7 — Patient and business data are collected and exfiltrated with Rclone

**Brief Description:**  
The affiliate exports the EHR database with `pg_dump`, collects HR and financial documents, compresses the data and sends it to attacker-controlled cloud storage using Rclone over HTTPS.

**Tactic:** **Exfiltration**

**Technique:** **Exfiltration Over Web Service: Exfiltration to Cloud Storage — T1567.002**

**Alternatives:**  
- **Data from Information Repositories — T1213** for collecting records from the EHR database
- **Archive Collected Data — T1560.001** for compressing the stolen material before transfer

**MedDefense Factor:**  
`ehr-db-01` exposes PostgreSQL TCP 5432 to the wider internal network under **GAP-002**, while **GAP-001** enables broad reachability and **GAP-011** means no central detection platform is present to correlate the database access, large data collection and outbound transfer.

---

## Step 8 — Backups and Volume Shadow Copies are destroyed

**Brief Description:**  
The attacker deletes NAS backup jobs and stored backups, then removes Windows Volume Shadow Copies with `vssadmin`.

**Tactic:** **Impact**

**Technique:** **Inhibit System Recovery — T1490**

**MedDefense Factor:**  
`NAS-01` management ports 5000/5001 are reachable internally, and the backup server and NAS are concentrated in the same local network/physical environment as production systems. This directly aligns with **GAP-008** and gives the attacker an opportunity to weaken recovery before ransomware deployment.

---

## Step 9 — Ransomware is deployed through Group Policy and SSH

**Brief Description:**  
The attacker uses a malicious GPO to push BlackReef ransomware to domain-joined Windows systems and separately targets Linux servers through SSH.

**Tactic:** **Impact**

**Technique:** **Data Encrypted for Impact — T1486**

**Alternative:** **Domain or Tenant Policy Modification: Group Policy Modification — T1484.001** maps the use of a GPO as the ransomware distribution mechanism.

**MedDefense Factor:**  
Once the affiliate controls Active Directory, the domain becomes a centralized deployment mechanism. Central's flat internal environment (**GAP-001**) and locally reachable production systems increase the blast radius, while weak recovery isolation (**GAP-008**) makes encryption more damaging.

---

# Scenario Beta — The Quiet Departure

**Threat Actor:** Malicious Insider — Billing Department  
**Objective:** Patient-record and financial-data theft for resale

## Step 1 — Maria decides to abuse her existing access

**Brief Description:**  
Maria learns she will be laid off and decides to use her legitimate billing and read-only EHR access to steal patient records.

**Tactic:** **Initial Access — closest operational mapping**

**Technique:** **Valid Accounts — T1078**

**Mapping Note:**  
The decision to steal data is motivation rather than an ATT&CK technique. The closest operational behavior is Maria's ability to begin the attack using an existing legitimate account instead of exploiting a technical entry point.

**MedDefense Factor:**  
Healthcare workflows require employees to have legitimate access to sensitive data. Task 6 identified malicious insiders as especially dangerous because legitimate access can bypass perimeter defenses, while **GAP-011** limits MedDefense's ability to detect when legitimate use becomes illegitimate.

---

## Step 2 — Maria determines what information her applications expose

**Brief Description:**  
Maria uses the billing and EHR interfaces to inspect the patient and financial information available through her normal account.

**Tactic:** **Collection**

**Technique:** **Data from Information Repositories — T1213**

**Mapping Note:**  
There is no strong ATT&CK Discovery technique for simply reviewing application data that an insider is already authorized to see. T1213 is the closest fit because she is accessing structured information repositories to identify valuable records.

**MedDefense Factor:**  
Maria's billing role legitimately exposes identity, insurance, diagnosis and financial information, while her EHR read-only access extends visibility into medical histories and prescriptions. The EHR does not alert on abnormal record-view volumes, reinforcing **GAP-011**.

---

## Step 3 — Bulk EHR exports to CSV

**Brief Description:**  
Maria accesses roughly 200 records per day and uses the EHR's built-in export function to save patient records as CSV files on her workstation.

**Tactic:** **Collection**

**Technique:** **Data from Information Repositories — T1213**

**Alternative:**  
The local CSV files also create a **Data Staging** condition before removal from MedDefense, but the defining behavior is bulk collection from the EHR repository.

**MedDefense Factor:**  
The application permits all read-authorized users to use the export function without additional authorization, and the audit records are not reviewed proactively. **C-028** records EHR access, but **GAP-011** prevents that existing evidence from functioning as timely detection.

---

## Step 4 — Patient records are copied to a personal USB drive

**Brief Description:**  
Maria transfers the CSV files from her workstation to removable USB storage and accumulates approximately 2,800 patient records.

**Tactic:** **Exfiltration**

**Technique:** **Exfiltration Over Physical Medium: Exfiltration over USB — T1052.001**

**MedDefense Factor:**  
Project 1x00 later confirmed **GAP-020 — no organization-wide DLP or removable-media control**. USB storage is unrestricted, and routine employee use has normalized the behavior, allowing large quantities of Restricted patient data to leave without a technical block.

---

## Step 5 — Maria deletes local CSV evidence

**Brief Description:**  
Maria deletes the exported CSV files and empties the workstation recycle bin to conceal the activity.

**Tactic:** **Defense Evasion**

**Technique:** **Indicator Removal: File Deletion — T1070.004**

**MedDefense Factor:**  
The local copies can be deleted without a centralized security workflow detecting the cleanup. The EHR still retains its separate audit records, but **C-028** is weakened operationally because MedDefense must request exports and the logs are not reviewed proactively, again reflecting **GAP-011**.

---

## Step 6 — Maria steals billing database credentials from a configuration file

**Brief Description:**  
Maria copies a configuration file containing direct `billing-srv-01` database credentials to her USB drive.

**Tactic:** **Credential Access**

**Technique:** **Unsecured Credentials: Credentials In Files — T1552.001**

**Alternative:**  
Copying the credential file to USB also repeats **Exfiltration Over Physical Medium: Exfiltration over USB — T1052.001**, but the strategically important behavior is acquisition of reusable database credentials.

**MedDefense Factor:**  
Credentials stored in a user-accessible configuration file allow Maria to retain a direct authentication path that is separate from her normal application workflow. This illustrates weak credential handling and increases the consequence of delayed offboarding.

---

## Step 7 — Her account remains valid after employment ends

**Brief Description:**  
HR submits the termination request, but IT does not disable Maria's access for five business days, leaving her VPN credentials usable.

**Tactic:** **Persistence**

**Technique:** **Valid Accounts — T1078**

**Mapping Note:**  
The delay itself is a MedDefense process failure rather than an adversary-created persistence mechanism. Operationally, however, the still-valid account gives Maria persistent access after her authorization should have ended.

**MedDefense Factor:**  
This maps directly to **GAP-017 — identity lifecycle and offboarding controls are not formally integrated with HR events**. There is no automated deactivation or offboarding SLA to close the access path promptly.

---

## Step 8 — Maria returns through the VPN and accesses the billing database

**Brief Description:**  
Three days after leaving MedDefense, Maria connects from home using her still-active VPN credentials, uses the copied database credentials and extracts another 400 records.

**Tactic:** **Initial Access**

**Technique:** **External Remote Services — T1133**

**Alternatives:**  
- **Valid Accounts — T1078** for use of the still-active VPN identity
- **Data from Information Repositories — T1213** for extracting additional records from the billing database

**MedDefense Factor:**  
The VPN remains available because the offboarding process failed under **GAP-017**, and the retained database credential gives Maria a second access layer after the VPN connection succeeds. **GAP-011** also means successful post-termination authentication may be logged without generating an immediate alert.

---

# ATT&CK Coverage Assessment

Across both scenarios, the recurring ATT&CK behaviors are **Initial Access, Persistence, Credential Access, Collection and Exfiltration**. Operation Flatline reaches those stages through phishing, credential dumping and a ransomware affiliate's tooling, while The Quiet Departure reaches them through legitimate insider access, retained accounts, unrestricted exports and USB storage. The common lesson is that MedDefense most urgently needs detection around **identity use and sensitive-data movement**: unusual authentication, privileged credential access, abnormal EHR/database query volumes, large exports and outbound/removable-media transfers should be correlated centrally. This priority aligns directly with **GAP-011**, because MedDefense already generates useful firewall, Windows, Linux, EHR and AD logs but does not continuously aggregate and alert on them. It also reinforces the need to close **GAP-007**, **GAP-017** and **GAP-020**, since stronger MFA/PAM, rapid offboarding and DLP/removable-media controls would interrupt techniques shared across otherwise very different attacks.

---

## ATT&CK Technique References Used

- T1596.005 — Search Open Technical Databases: Scan Databases
- T1595.002 — Active Scanning: Vulnerability Scanning
- T1566.002 — Phishing: Spearphishing Link
- T1204.002 — User Execution: Malicious File
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1053.005 — Scheduled Task/Job: Scheduled Task
- T1018 — Remote System Discovery
- T1069.002 — Permission Groups Discovery: Domain Groups
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1550.002 — Use Alternate Authentication Material: Pass the Hash
- T1213 — Data from Information Repositories
- T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- T1490 — Inhibit System Recovery
- T1486 — Data Encrypted for Impact
- T1484.001 — Domain or Tenant Policy Modification: Group Policy Modification
- T1078 — Valid Accounts
- T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB
- T1070.004 — Indicator Removal: File Deletion
- T1552.001 — Unsecured Credentials: Credentials In Files
- T1133 — External Remote Services

## Project Cross-References

- Project 1x00 — `7-asset_registry.md`
- Project 1x00 — `10-complete_control_matrix.md`
- Project 1x00 — `12-gap_analysis.md`
- Project 1x00 — `15-predecessor_review.md`
- Project 1x01 — `6-threat_actor_matrix.md`
- Project 1x01 — `8-technical_vectors.md`
- Project 1x01 — `10-kill_chains.md`
