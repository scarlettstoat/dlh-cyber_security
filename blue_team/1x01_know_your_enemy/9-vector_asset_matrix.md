# MedDefense Health Systems — Vector-to-Asset Matrix

## Scope and Column Selection

This matrix cross-references eight attack vectors against MedDefense's Critical assets to show where different entry methods can converge on the same high-value systems.

Project 1x00's documented **Top 5 Critical Assets** are:

1. EHR System — `ehr-srv-01`, `ehr-db-01`, EHR application
2. Pharmacy Management System — **A-038**
3. BD Alaris Infusion-Pump Estate — **A-032**
4. Network Core and Connectivity
5. Active Directory — `ad-dc-01`, `ad-dc-02`

The task asks for those five **plus Medical IoT and Active Directory, for seven columns total**. Because Active Directory is already the fifth Top 5 asset, duplicating it would not add analytical value. To preserve seven distinct columns, this matrix uses **Medical IoT (excluding the separately listed Alaris pumps)** and **Backup / Recovery Infrastructure** as the two additional Critical dependencies. Backup/recovery is a Critical Project 1x00 asset category and is directly relevant to ransomware attack paths.

A populated cell means the evidence supports a credible direct or indirect attack path. Empty cells indicate that the current MedDefense evidence does not establish a sufficiently defensible path.

---

# Vector-to-Asset Matrix

| Attack Vector | **EHR System** | **Pharmacy System** | **BD Alaris Pumps** | **Network Core** | **Active Directory** | **Medical IoT** | **Backup / Recovery** |
|---|---|---|---|---|---|---|---|
| **Phishing / Spear Phishing** | Phishing → clinician credentials or infected workstation → EHR access / flat network → `ehr-db-01` on PostgreSQL 5432 → Restricted patient data. | Phishing → pharmacy user credentials → legitimate pharmacy workflow abused → medication/dosage information exposed or altered. | Phishing → compromised clinical workstation → flat network → reachable infusion-pump interfaces → attempted device access or disruption. | Spear phishing → IT administrator credentials → privileged network-management access → firewall/switch configuration can be altered. | Phishing → valid MedDefense credentials → AD-authenticated foothold → privilege escalation or credential harvesting → domain services targeted. | Phishing → compromised clinician endpoint → flat network → reachable monitor/device management interfaces → patient-monitoring systems targeted. | Spear phishing → compromised IT/backup administrator account → internal access → `backup-srv-01` / `NAS-01` targeted before ransomware deployment. |
| **VPN Exploit** | VPN compromise → internal foothold → flat network → `ehr-srv-01` / `ehr-db-01` reachable → EHR data or availability targeted. |  | VPN compromise → internal network access → no effective medical-IoT isolation → Alaris estate reachable for reconnaissance or exploitation. | VPN appliance compromise → trusted internal entry point → network infrastructure and site connectivity become reachable from inside the perimeter. | VPN compromise → internal reconnaissance → reachable AD services on `ad-dc-01` / `ad-dc-02` → credentials and privileges targeted. | VPN compromise → flat network → patient monitors, nurse-call systems and other IoT interfaces reachable without a dedicated security boundary. | VPN compromise → internal foothold → `backup-srv-01` and network-reachable `NAS-01` discovered → recovery infrastructure targeted. |
| **Default / Shared Credentials** |  |  | If vendor-default device credentials remain unchanged → reachable Alaris management interface → unauthorized pump administration; MedDefense has not yet verified credential hardening. | Exposed/shared switch-management credentials → unauthorized network-device administration → traffic or connectivity can be altered. |  | If vendor-default credentials remain unchanged → reachable medical-device management interface → unauthorized configuration or data access; GAP-018 exists because this hardening has not been verified. |  |
| **Vulnerable Software Exploit** | Vulnerable Internet-facing or internal service → foothold on `web-srv-01` or another host → flat network → EHR server/database targeted. |  | Known medical-device vulnerability → reachable Alaris interface → device compromise or disruption because recommended isolation is not implemented. | Exploitation of a vulnerable internal host → flat network → attacker reaches network-management surfaces and uses the core as a pivot or disruption target. | Vulnerable server compromise → internal reconnaissance → reachable Kerberos/LDAP/SMB services → AD credentials or privileges targeted. | Outdated firmware such as `MON-VITALS-3F-01` → HTTP management surface → compromise of patient-monitoring infrastructure. | Vulnerable server compromise → flat network → `backup-srv-01` / `NAS-01` reachable → backups deleted, encrypted or otherwise disrupted. |
| **Supply Chain Compromise** | Compromised MedTech maintenance account/platform → trusted vendor access → `ehr-srv-01` → EHR application and patient data affected. |  |  |  | Compromised Sophos management/update path → malicious code reaches managed endpoints → internal footholds → AD credentials and domain services targeted. | Compromised Siemens maintenance laptop/update media → `WS-RAD-01` / MRI environment → clinical imaging environment compromised. | Compromised Sophos management path → many internal endpoints become footholds → flat network → backup infrastructure discovered and targeted. |
| **Insider — Malicious** | Authorized clinical user → deliberate EHR snooping/export → Restricted patient records disclosed without needing perimeter compromise. | Authorized pharmacy/administrative user → legitimate application access abused → medication records altered, viewed or exported. | Privileged clinical/biomedical insider → legitimate device access → infusion-pump configuration or dosage functions deliberately misused. | Privileged IT insider → legitimate switch/firewall access → routing, ACLs or connectivity deliberately changed to intercept or disrupt traffic. | Privileged IT insider → legitimate domain administration → accounts, groups or authentication controls deliberately changed. | Biomedical/clinical insider → legitimate access to monitors or other devices → configurations or patient-monitoring information deliberately misused. | Backup administrator or privileged IT insider → legitimate recovery access → backups deleted, altered or disabled before another destructive action. |
| **Insider — Negligent** | Unattended logged-in EHR session or unsafe credential handling → another person gains patient-record access under a legitimate account. | Unsafe change or administrative shortcut → pharmacy data/configuration changed without adequate validation → incorrect dosage information reaches users. | Weak device-handling or credential practices → unauthorized person gains access to pump-management functions or sensitive medication data. | Posted switch credentials / weak physical handling of network infrastructure → unauthorized person gains a route to network administration. | Plaintext administrative credentials or unsafe password-sharing practice → privileged AD credentials exposed to another user or malware. | Shadow IT or unmanaged device connected by staff → flat network → medical-device interfaces become reachable from an uncontrolled endpoint. | Backup misconfiguration or unsafe administrative practice → recent recoverable copies are unavailable when ransomware or system failure occurs. |
| **Physical Access** | Unattended EHR workstation or unauthorized server-room access → local/session access → EHR data or hosting infrastructure exposed. |  | Physical access to infusion pumps or their local management environment → device tampering or unauthorized configuration becomes possible. | Unlocked second-floor network closet + exposed switch credentials → physical entry → network configuration can be changed or traffic disrupted. | Unauthorized server-room access → physical access to infrastructure hosting domain services → authentication availability or integrity can be affected. | Physical access to clinical devices → local ports/interfaces or maintenance functions used to alter monitoring equipment. | Broad server-room access → physical access to `backup-srv-01` and `NAS-01` → recovery systems can be disconnected, damaged or tampered with. |

---

# Connection Count

| Asset | Number of Viable Vectors |
|---|---:|
| **EHR System** | **7** |
| **Pharmacy System** | **3** |
| **BD Alaris Pumps** | **7** |
| **Network Core** | **7** |
| **Active Directory** | **7** |
| **Medical IoT** | **8** |
| **Backup / Recovery** | **7** |

| Vector | Number of Assets Reached |
|---|---:|
| **Phishing / Spear Phishing** | **7** |
| **VPN Exploit** | **6** |
| **Default / Shared Credentials** | **3** |
| **Vulnerable Software Exploit** | **6** |
| **Supply Chain Compromise** | **4** |
| **Insider — Malicious** | **7** |
| **Insider — Negligent** | **7** |
| **Physical Access** | **6** |

---

# Three Most Connected Assets

## 1. Medical IoT — 8 vectors

**Medical IoT is the most connected asset group because every assessed vector can plausibly reach or affect it, while GAP-001, GAP-003 and GAP-018 combine broad internal reachability, weak device isolation and unverified credential hardening around systems that directly support patient care.**

## 2. EHR System — 7 vectors

**The EHR is reachable through seven vector types and remains MedDefense's highest-criticality information system, so the intersection of broad attack-path exposure with Restricted patient data and clinical dependence makes it a priority even when the initial compromise begins elsewhere.**

## 3. Active Directory — 7 vectors

**Active Directory is reachable through seven vectors and acts as an access multiplier: successful compromise can convert one credential, endpoint or trusted connection into broader control over identities and systems across MedDefense.**

> **Tie note:** BD Alaris, Network Core and Backup/Recovery also have seven populated vector paths. EHR and Active Directory are selected for the Top 3 because Project 1x00 identified them as shared Critical dependencies whose compromise can amplify access to multiple other assets.

---

# Three Most Versatile Vectors

## 1. Phishing / Spear Phishing — 7 assets

**Phishing is highly versatile because one compromised user or privileged credential can become an authenticated internal foothold, after which the flat network allows the attacker to pivot toward clinical, identity, network and recovery systems.**

## 2. Insider — Malicious — 7 assets

**A malicious insider can reach all seven asset groups because legitimate organizational access bypasses the external perimeter and, depending on role, may already include clinical applications, devices or privileged infrastructure.**

## 3. Insider — Negligent — 7 assets

**Negligent insider behavior can expose all seven asset groups because unsafe credential handling, Shadow IT, poor change practices and physical shortcuts can either cause direct harm or create a foothold for an external attacker.**

> **Near-tie:** VPN Exploitation, Vulnerable Software Exploitation and Physical Access each reach six of the seven asset groups, showing that MedDefense has several different ways for a single initial foothold to converge on the same Critical systems.

---

# Priority Intersection Assessment

The matrix shows that MedDefense's highest-risk intersections are not isolated vulnerabilities but **routes that repeatedly converge on shared Critical systems**. Medical IoT has the broadest vector exposure, while the EHR and Active Directory combine high connectivity with organization-wide clinical or identity impact. At the vector level, phishing and insider activity are especially dangerous because they begin with legitimate-looking access and can bypass parts of the perimeter. Across almost every path, **GAP-001 — lack of effective internal segmentation** is the common multiplier: it allows an initial compromise from a user, VPN, vulnerable service, vendor, unmanaged device or physical foothold to expand toward assets that should not otherwise be reachable.
