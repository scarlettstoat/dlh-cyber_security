# MedDefense Health Systems — The Misconfiguration Findings

**Project:** `1x02_the_weak_links`  
**Task:** 6 — The Misconfiguration Findings  
**Repository path:** `blue_team/1x02_the_weak_links/6-misconfiguration_analysis.md`

> **Evidence note:** Finding 003 is preserved with its exact scan ID in the available project evidence. The remaining five misconfigurations are confirmed in the scan-derived MedDefense documentation, but their exact numeric finding IDs were not preserved in the retrieved copy of the source report. Rather than invent IDs, they are marked **Verify in source scan**. The technical analysis and cross-references below are based on the confirmed scan evidence.

---

## 1. Unrestricted PostgreSQL Access to the EHR Database

**Finding ID:** **003**  
**Host:** `ehr-db-01` — A-002  
**CVE:** N/A  

**Misconfiguration:**  
PostgreSQL on TCP/5432 is reachable from the wider MedDefense internal network instead of being restricted to the EHR application server. The scan evidence shows PostgreSQL listening broadly, with `listen_addresses = '*'`, and `pg_hba.conf` permitting connections from the wider `10.10.0.0/16` environment.

**Why No CVE:**  
PostgreSQL is functioning as configured. The weakness is not a defect in PostgreSQL code; it is an overly permissive access-control and network configuration chosen for the deployment. Because the insecure state is created by MedDefense's settings rather than a vendor software flaw, there is no CVE identifier.

**Severity Assessment:** **Critical**

The database contains Restricted EHR data and is reachable from far more systems than necessary. In MedDefense's effectively flat internal environment, any compromised workstation or server can attempt direct interaction with the database. A successful credential attack, credential reuse or application-account compromise could expose or alter patient records outside the normal EHR application path. The potential impact covers both Confidentiality and Integrity and can directly affect clinical decision-making.

**Cross-Reference 1x00:**  
This directly confirms **GAP-002 — EHR database reachable from the wider internal network** and is amplified by **GAP-001 — no effective internal segmentation**. It is also a **1x00 T7 network-scan finding**, because TCP/5432 was observed reachable beyond `ehr-srv-01`. The Asset Registry identifies `ehr-db-01` as **A-002**, the EHR database. The later threat work shows that ransomware operators and other attackers can use a single internal foothold to discover and reach critical services across the flat network.

**Comparable CVE Risk:** **CVE-2021-44790 — Apache `mod_lua` RCE, 9.8 Critical**

CVE-2021-44790 can provide unauthorized code execution on a server. This PostgreSQL misconfiguration creates a different path but can produce similarly serious consequences: direct access to MedDefense's most sensitive clinical data from an internal foothold. The absence of a CVSS score does not reduce the impact of unauthorized reading or modification of EHR records.

---

## 2. MySQL Exposed Across the Internal Network

**Finding ID:** **Verify in source scan — unrestricted MySQL exposure finding**  
**Host:** `billing-srv-01` — A-004  
**CVE:** N/A  

**Misconfiguration:**  
MySQL TCP/3306 on `billing-srv-01` is reachable across the wider internal network instead of being restricted to only the systems and application components that require database access.

**Why No CVE:**  
The MySQL service is not being described as containing a specific software defect. The problem is the network exposure and access scope configured by MedDefense. A legitimate database product can be deployed securely or insecurely depending on binding, firewall and access-control settings; that deployment choice is why this finding has no CVE.

**Severity Assessment:** **High**

`billing-srv-01` stores billing, financial and insurance-claims information and has already experienced both ransomware and a later crypto-mining compromise. Broad database reachability gives an attacker with any internal foothold another service to enumerate, attack or access with stolen credentials. The weakness is particularly significant because the same server already contains several other vulnerabilities and is not isolated from the wider environment.

**Cross-Reference 1x00:**  
This is a **T7 network-scan finding** and maps strongly to **GAP-001 — no effective internal segmentation**. It also supports **GAP-016 — no formal vulnerability and patch-management programme**, because the server combines unnecessary service exposure with outdated and vulnerable software. The Asset Registry records `billing-srv-01` as **A-004** and explicitly notes that MySQL 3306 is exposed across the internal network.

**Comparable CVE Risk:** **CVE-2019-0211 — Apache Local Privilege Escalation, 7.8 High**

CVE-2019-0211 becomes valuable once an attacker has an initial foothold. The MySQL exposure has a similar "second-stage" risk: after compromising one internal system, an attacker can immediately probe the billing database rather than first defeating a segmentation control. In a flat network, unnecessary reachability can make lateral movement almost as operationally useful as a software vulnerability.

---

## 3. Password-Based SSH Authentication on `billing-srv-01`

**Finding ID:** **Verify in source scan — SSH password-authentication finding**  
**Host:** `billing-srv-01` — A-004  
**CVE:** N/A  

**Misconfiguration:**  
SSH password authentication remains enabled on `billing-srv-01`. This is weaker than the key-only SSH configuration already implemented on `ehr-srv-01`, because password authentication remains exposed to password guessing, reuse of stolen credentials and credential-stuffing attacks.

**Why No CVE:**  
OpenSSH supports password authentication by design. Enabling it is not a bug in OpenSSH; the security issue comes from how the service has been configured and which authentication methods MedDefense permits. The same software can be hardened by disabling password authentication and requiring stronger credentials or keys.

**Severity Assessment:** **High**

Password authentication does not mean that an attacker automatically has access, but it creates a practical route for compromised credentials. This matters more on `billing-srv-01` because the server has repeatedly been compromised and sits inside a flat network. A successful SSH login would provide a legitimate remote session rather than requiring exploitation of a memory-corruption flaw.

**Cross-Reference 1x00:**  
This finding connects to the **T5 control landscape** because `ehr-srv-01` already has **C-005 — SSH Key-Only Authentication**, showing that MedDefense knows how to deploy stronger SSH controls but has not applied them consistently. It also relates to **GAP-007 — incomplete MFA/PAM coverage** and **GAP-001 — no effective internal segmentation**. The 1x01 Threat Actor Matrix identifies valid/stolen credentials as a common ransomware initial-access method.

**Comparable CVE Risk:** **CVE-2019-0211 — 7.8 High**

CVE-2019-0211 requires an attacker to have some local execution before privilege escalation. Weak SSH authentication can provide that initial authenticated foothold if a password is guessed, reused or stolen. In practice, a configuration weakness that permits credential-based remote access can be just as useful to an attacker as a High-severity local software flaw.

---

## 4. LDAP Signing Not Enforced on Active Directory

**Finding ID:** **Verify in source scan — LDAP-signing finding**  
**Host:** `ad-dc-01` — A-005  
**CVE:** N/A  

**Misconfiguration:**  
LDAP signing is not fully enforced on the Active Directory domain controller. This allows LDAP clients to communicate without requiring cryptographic signing of the LDAP session, weakening protection against manipulation or relay-style abuse on reachable network paths.

**Why No CVE:**  
LDAP signing is a security configuration option in Active Directory. The domain controller is behaving according to its configured policy; the weakness exists because the required protection has not been enforced. No individual software defect is necessary for the insecure state to exist.

**Severity Assessment:** **High**

Active Directory is a shared authentication dependency for MedDefense. A weakness affecting the integrity of directory communications can have consequences far beyond one server because compromised or manipulated identity traffic may support credential abuse, account compromise or further lateral movement. The flat internal network increases the number of systems from which an attacker could interact with AD services.

**Cross-Reference 1x00:**  
The Asset Registry identifies `ad-dc-01` as **A-005**, the primary domain controller. This is a **T7 network-scan finding** and relates to **GAP-007 — MFA/PAM and privileged-access controls are incomplete**, **GAP-011 — monitoring is fragmented**, and **GAP-001 — no effective internal segmentation**. T5 already documents AD password, lockout and event-logging controls, but those controls do not compensate for unsigned LDAP traffic.

**Comparable CVE Risk:** **CVE-2017-0144 — EternalBlue / MS17-010, 8.1 High in the scan**

EternalBlue and weak LDAP signing are technically very different, but both can become highly significant once an attacker can reach the relevant internal service. EternalBlue provides direct code execution; unsigned LDAP can enable identity-focused attack paths. Because AD controls authentication across the organisation, compromise of the identity layer can create an impact comparable to compromising an individual High-severity server.

---

## 5. DNS Zone Transfer Allowed on `ad-dc-01`

**Finding ID:** **Verify in source scan — DNS zone-transfer finding**  
**Host:** `ad-dc-01` — A-005  
**CVE:** N/A  

**Misconfiguration:**  
The DNS service on `ad-dc-01` permits zone-transfer behaviour more broadly than required. An attacker able to request a transfer may obtain a structured view of DNS names and records that reveals internal systems and services.

**Why No CVE:**  
DNS zone transfers are a legitimate administrative feature. The weakness is not that the DNS software incorrectly implements AXFR; it is that MedDefense has configured the service so that unnecessary clients can request information that should be restricted to authorized secondary DNS servers.

**Severity Assessment:** **Medium**

A zone transfer does not by itself provide code execution or database access, but it can dramatically improve reconnaissance by exposing hostnames, service naming conventions and internal infrastructure. In a flat network, better reconnaissance makes subsequent attacks faster and more targeted. This is therefore a meaningful enabling weakness even though its direct impact is lower than an RCE.

**Cross-Reference 1x00:**  
This is a **T7 network-scan finding** against **A-005 `ad-dc-01`**. It also connects to **GAP-001 — no effective internal segmentation**, because information learned through DNS can be acted upon across broadly reachable internal systems, and **GAP-011 — fragmented/manual monitoring**, because reconnaissance may not be detected quickly. T5 documents DNS/AD-related logging controls only partially; there is no documented control that makes unnecessary zone transfers acceptable.

**Comparable CVE Risk:** **CVE-2023-38408 — OpenSSH `ssh-agent` RCE, scanner-rated Medium**

CVE-2023-38408 has a high theoretical CVSS score but was rated Medium by the scanner because exploitation depends on specific environmental conditions. The DNS transfer misconfiguration is also context-dependent: it is not destructive on its own, but in MedDefense's environment it can materially improve attacker discovery and targeting. Both show why operational context matters more than the presence or absence of a CVSS number.

---

## 6. NAS Management Interface Reachable Network-Wide

**Finding ID:** **Verify in source scan — exposed NAS-management-interface finding**  
**Host:** `NAS-01` — A-010  
**CVE:** N/A  

**Misconfiguration:**  
The Synology NAS management interfaces on TCP/5000 and TCP/5001 are reachable from the entire internal network rather than being limited to a dedicated management network or a small set of authorized administrator systems.

**Why No CVE:**  
The management service is intentionally provided by the NAS platform. The weakness is the decision to expose the administrative interface broadly inside MedDefense. No bug is required: firewall rules, segmentation and management-access restrictions determine whether the interface is appropriately protected.

**Severity Assessment:** **High**

`NAS-01` stores MedDefense's Veeam backup copies. Broad management reachability gives any compromised internal endpoint a direct path to the interface of a recovery-critical asset. An attacker who obtains valid credentials or finds another weakness in the management plane could alter, delete or disable backups. This is especially serious for ransomware because damaging recovery infrastructure increases the impact of an otherwise recoverable incident.

**Cross-Reference 1x00:**  
The Asset Registry identifies `NAS-01` as **A-010** and records TCP/5000 and 5001 as network-wide reachable. This is a **T7 network-scan finding** and directly reinforces **GAP-008 — backup infrastructure concentrated in the same network/physical environment** and **GAP-001 — no effective internal segmentation**. It also connects to the **T3 physical walk-through**, which established that backup infrastructure is concentrated with other server-room assets rather than being strongly separated. Project 1x01 identifies backup systems as deliberate ransomware targets.

**Comparable CVE Risk:** **CVE-2020-25165 — BD Alaris Availability Vulnerability, 7.5 High**

CVE-2020-25165 is High because successful exploitation can disrupt the availability of a clinically important device. Broad access to the backup-management plane can create a similarly serious Availability problem at a different layer: if ransomware can reach and disable recovery copies, an incident that should be recoverable can become an extended organisation-wide outage. The absence of a CVE does not make that consequence less real.

---

# Why "Our CVE Scan Shows Nothing Critical, We Are Secure" Is Dangerous False Assurance

The statement is dangerous because **CVE coverage measures only one class of security problem**. A system can be fully patched and still expose a database to the wrong network, permit weak authentication, allow unnecessary directory or DNS behaviour, expose administrative interfaces or operate without effective segmentation. None of those conditions requires a software bug, so they may have no CVE, no NVD record and no CVSS score even when the potential impact is Critical. MedDefense demonstrates the problem clearly: the EHR database can be reached directly from the wider internal environment, the billing database and NAS management interfaces are unnecessarily exposed, and identity services contain configuration weaknesses, all inside a network with weak east-west separation. Automated tools that prioritize only CVEs can therefore produce a reassuring dashboard while leaving practical attack paths untouched. A defensible vulnerability-management programme must assess **CVE vulnerabilities, misconfigurations, asset criticality, service exposure, threat relevance and control gaps together** rather than treating "no CVE" as "no risk."
