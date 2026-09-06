# MedDefense Health Systems — Technical Vector Assessment

## Scope

This assessment applies the Security+ 2.2 technical-vector categories to concrete MedDefense evidence from Project 1x00. The focus is on **non-human entry points and lateral-movement opportunities** identified through the Network Scan, Asset Registry, Control Matrix, Gap Analysis and later validation work.

Where Project 1x00 did not prove a condition directly, the limitation is stated rather than inferred.

---

## 1. Vulnerable Software

**Vector Category:** **Vulnerable Software**

**MedDefense Evidence:**  
`billing-srv-01` (**A-004**) runs **Ubuntu 18.04**, for which standard support ended in June 2023 and Extended Security Maintenance is not enabled. The server also runs **Apache 2.4.29**; Marcus had flagged that version for known remote-code-execution vulnerabilities, and the later root-cause investigation found attacker-controlled code under `/var/www/html/.cache` running as `www-data`. This makes the Apache/web layer a **credible suspected entry point**, although the exact initial exploit has not been proven. Other dated software includes `MON-VITALS-3F-01` (**A-033**) with firmware **2.1.3 last updated in 2019**, while the BD Alaris pump estate (**A-032**) is recorded with known CVEs.

**Affected Asset(s):**  
- `billing-srv-01` — **A-004**
- `MON-VITALS-3F-01` — **A-033**
- BD Alaris infusion-pump estate — **A-032**
- Other exposed or Critical systems covered by the wider vulnerability-management gap

**Actor Most Likely to Exploit:** **Unskilled / Opportunistic Attacker.**  
Task 6 assessed opportunistic actors as highly exposed to MedDefense because they rely on scanners, public exploits and known vulnerabilities rather than organisation-specific targeting. Ransomware affiliates could also exploit the same weakness, but automated opportunistic exploitation is the clearest fit for outdated publicly known software flaws.

**Exploitation Scenario:**  
An attacker scans for a known vulnerable service and uses a public exploit against an unpatched or outdated component. If code execution is obtained on `billing-srv-01` or another reachable system, the attacker can establish a foothold and, because Central lacks effective segmentation, attempt reconnaissance and lateral movement toward higher-value systems.

**Current Protection:**  
**C-026 — Linux Server Syslog** and **C-027 — Apache Log Retention** provide some detective evidence on Linux/Apache systems, while **C-002 — Default Deny Firewall Rule** limits unsolicited traffic crossing the FortiGate. These controls do not replace timely vulnerability identification and remediation, and the logs are not continuously centralised.

**Gap Reference:**  
- **GAP-016 — No formal vulnerability and patch-management programme for exposed and Critical systems**
- **GAP-011 — Security logging is fragmented and manually reviewed**
- **GAP-001 — No effective internal segmentation**, which increases the blast radius after compromise

---

## 2. Unsupported Systems

**Vector Category:** **Unsupported Systems**

**MedDefense Evidence:**  
The Network Scan identifies `WS-RAD-01` (**A-022**) as a **Windows XP SP3 MRI control workstation**, an end-of-life platform that cannot receive normal security support. `print-srv-01` (**A-008**) is confirmed active on **Windows Server 2012 R2**, which reached end of support in October 2023. These systems remain connected to the same broadly reachable Central environment as supported endpoints and Critical clinical systems.

**Affected Asset(s):**  
- `WS-RAD-01` MRI control workstation — **A-022**
- Siemens MAGNETOM MRI environment — **A-029**
- `print-srv-01` — **A-008**
- PACS and other Central systems that could be reached from a compromised legacy host

**Actor Most Likely to Exploit:** **Unskilled / Opportunistic Attacker.**  
Unsupported platforms are attractive to actors using known exploits because vulnerabilities may remain permanently unpatched. A ransomware group could exploit the same systems during lateral movement, but opportunistic actors require less capability to take advantage of old, publicly documented weaknesses.

**Exploitation Scenario:**  
An attacker who can reach the legacy system uses a known exploit that the unsupported operating system can no longer remediate normally. Compromise of `WS-RAD-01` could disrupt MRI availability or provide an internal foothold, while compromise of `print-srv-01` could give an attacker a lower-value persistence point from which to probe more Critical systems.

**Current Protection:**  
The FortiGate perimeter (**C-002**) reduces direct Internet exposure, and **C-025 — Windows Server Event Logging** provides some detective evidence for Windows servers such as `print-srv-01`. However, Project 1x00 identified **no currently implemented MRI-specific compensating control** that isolates `WS-RAD-01`; network isolation was recommended as the required treatment.

**Gap Reference:**  
- **GAP-006 — MRI control environment relies on unsupported Windows XP**
- **GAP-016 — Vulnerability/patch-management programme missing**
- **GAP-001 — No effective internal segmentation**

---

## 3. Open Service Ports

**Vector Category:** **Open Service Ports**

**MedDefense Evidence:**  
The Network Scan confirms several services that are reachable more broadly than their business need requires:

- `ehr-db-01` (**A-002**) exposes **PostgreSQL TCP 5432** across the wider internal network rather than only to `ehr-srv-01`.
- `billing-srv-01` (**A-004**) exposes **MySQL TCP 3306** across the internal network.
- `pacs-srv-01` (**A-003**) exposes SMB and DICOM-related services on **TCP 4242 and 11112**.
- `NAS-01` (**A-010**) exposes management ports **5000/5001** network-wide.
- `ws-srv-01` at Westside (**A-013**) has **SMB and RDP** exposed.
- `WS-WC-XRAY` (**A-025**) exposes **HTTP TCP 80** and **TCP 4242**.
- `MON-VITALS-3F-01` (**A-033**) exposes **HTTP TCP 80**.
- `UNKNOWN-01` (**A-012**) exposes SSH plus **8888/9090**.
- Westside's unknown Linux host (**A-014**) exposes SSH, HTTP and **TCP 3000**.

The consolidated Asset Registry confirms RDP on `ws-srv-01`; it does **not** provide enough evidence to claim that RDP is enabled across the wider workstation estate.

**Affected Asset(s):**  
EHR database, billing server, PACS, backup NAS, Westside server, X-ray workstation, medical IoT and undocumented Linux hosts.

**Actor Most Likely to Exploit:** **Ransomware Groups / Organized Crime.**  
Task 6 ranked ransomware as MedDefense's highest-priority threat. Once an affiliate gains a foothold, broadly reachable database, management, SMB and remote-access services provide exactly the type of internal attack surface used for discovery, credential abuse, lateral movement, data theft and recovery-system targeting.

**Exploitation Scenario:**  
After compromising one endpoint, an attacker scans the internal network and discovers PostgreSQL, MySQL, SMB, RDP and device-management services. Because those services are not separated by enforced internal security zones, the attacker can attempt authentication, exploitation or credential reuse directly against systems containing Restricted data or supporting recovery and clinical operations.

**Current Protection:**  
Host and application logging exists through controls such as **C-025 — Windows Server Event Logging**, **C-026 — Linux Server Syslog**, **C-027 — Apache Log Retention** and **C-028 — EHR Application Audit Logging**. **C-002** protects the Internet boundary, but it does not solve unnecessary east-west reachability inside Central.

**Gap Reference:**  
- **GAP-001 — No effective internal segmentation**
- **GAP-002 — `ehr-db-01` reachable from the wider internal network**
- **GAP-003 — Medical IoT lacks device-specific isolation and monitoring**
- **GAP-011 — Fragmented/manual monitoring**
- **GAP-014 — Westside consumer-router / weak site-perimeter exposure**

---

## 4. Default Credentials

**Vector Category:** **Default Credentials**

**MedDefense Evidence:**  
MedDefense has a **confirmed shared PACS account**, `raduser/radiology1`, used by multiple Radiology technicians. This is a shared-credential weakness rather than a vendor-default credential. For medical IoT, the later Project 1x00 reality check established **GAP-018** because MedDefense has **not verified that vendor-default administrative credentials have been changed** across BD Alaris pumps, Philips IntelliVue monitors and other embedded clinical devices. Therefore, it would be inaccurate to claim that MedDefense's Alaris pumps are confirmed to still use vendor defaults; the documented problem is that credential hardening has not been verified.

**Affected Asset(s):**  
- PACS server and Radiology workflow — **A-003**
- BD Alaris infusion pumps — **A-032**
- Philips IntelliVue monitors — **A-031**
- Other medical IoT and embedded management interfaces
- MRI/legacy clinical systems where vendor credentials may exist

**Actor Most Likely to Exploit:** **Unskilled / Opportunistic Attacker.**  
Default or weak shared credentials require little technical sophistication once the relevant service is reachable. A malicious insider could also abuse the shared PACS account because it reduces accountability, but opportunistic exploitation is the strongest match for unchanged or guessable device credentials.

**Exploitation Scenario:**  
An attacker who reaches PACS or a medical-device management interface attempts known vendor credentials, common passwords or credentials already shared among staff. Successful access could permit viewing of Restricted imaging/clinical information, configuration changes or interference with patient-monitoring and medication-delivery functions.

**Current Protection:**  
**C-009 to C-012** provide general password-policy and Active Directory controls where those systems are within AD scope. **C-013 — Shared Account Password Change on Departure** applies to shared accounts but is rated Weak and does not remove the underlying accountability problem. No device-specific credential baseline is documented.

**Gap Reference:**  
- **GAP-007 — MFA and privileged-access controls are incomplete**
- **GAP-018 — No verified credential-hardening standard for medical-device and embedded-system management interfaces**
- **GAP-003 — Medical IoT lacks device-specific isolation and monitoring**

---

## 5. Unsecure Networks

**Vector Category:** **Unsecure Networks**

**MedDefense Evidence:**  
Central uses separate addressing ranges for workstations (`10.10.1.0/24`), servers (`10.10.2.0/24`) and medical devices (`10.10.3.0/24`), but the scan confirms that these are **not enforced VLAN/security boundaries**; systems remain broadly reachable across the internal environment. Westside uses a **Netgear Nighthawk consumer router** with no dedicated enterprise firewall and connects back to Central through a site-to-site VPN. Central also has twelve UniFi wireless access points. **C-034** documents a separate guest Wi-Fi SSID, but the actual isolation of that guest network from internal resources has **never been verified**.

**Affected Asset(s):**  
- Central workstations, servers and medical-device estates
- EHR, Active Directory, PACS, backups and network core
- Westside server/endpoints and the VPN path to Central
- Central wireless users and devices

**Actor Most Likely to Exploit:** **Ransomware Groups / Organized Crime.**  
Ransomware operators benefit heavily from weak internal separation because it converts one successful foothold into access to many additional systems. Task 2 already mapped the BlackReef-style path from initial access to undetected reconnaissance, lateral movement and backup neutralisation.

**Exploitation Scenario:**  
A ransomware affiliate compromises one workstation or account and begins scanning the internal environment. Because Central lacks enforced segmentation, the attacker can move toward Active Directory, EHR, PACS, medical IoT and backup systems without crossing strong east-west security controls; a compromised Westside host could also attempt to use the trusted site VPN path toward Central.

**Current Protection:**  
**C-002 — Default Deny Firewall Rule** protects traffic traversing the FortiGate, **C-031 — Site-to-Site VPN Protection** encrypts inter-site traffic, and **C-034 — Separate Guest Wi-Fi SSID** provides a nominal wireless separation control. C-034 is rated Weak specifically because actual guest isolation has not been verified.

**Gap Reference:**  
- **GAP-001 — No effective internal segmentation**
- **GAP-014 — Westside uses a consumer router with no dedicated firewall**
- **GAP-003 — Medical IoT lacks isolation and monitoring**
- **GAP-021 — HQ third-party network dependency lacks documented security assurance** where the advanced Project 1x00 findings are included

---

## 6. Removable Devices / Unmanaged Endpoints

**Vector Category:** **Removable Devices**

**MedDefense Evidence:**  
Marcus's predecessor notes record **unrestricted USB storage on MedDefense workstations**, and no organisation-wide DLP or removable-media control is documented (**GAP-020**). Endpoint governance is also incomplete: approximately **25 physician iPads** exist but central MDM status is unclear; Sophos protects **372 managed Windows 10/11 endpoints**, fewer than the broader documented Windows estate; and multiple Shadow IT systems have been identified, including `UNKNOWN-01` (**A-012**), the Westside unknown Linux device (**A-014**), Dr. Patel's personal NAS (**A-054**), a Marketing Google Drive under a personal Gmail account (**A-055**) and a Raspberry Pi network monitor (**A-056**). Incident F also documented an IT intern's personal laptop on the internal network.

**Affected Asset(s):**  
- User workstations and laptops
- Physician iPads — **A-028**
- EHR-access endpoints and systems containing Restricted data
- `UNKNOWN-01` — **A-012**
- Westside unknown Linux host — **A-014**
- Personal NAS — **A-054**
- Raspberry Pi network monitor — **A-056**
- Other systems reachable from an unmanaged foothold

**Actor Most Likely to Exploit:** **Insider — Negligent.**  
Task 6 ranked negligent insiders as MedDefense's second-highest threat because unsafe convenience behaviours are already documented. Personal devices, USB storage and Shadow IT are often introduced without malicious intent, but once connected they can expose data directly or create a foothold that an opportunistic attacker or ransomware group can later abuse.

**Exploitation Scenario:**  
A staff member connects an infected USB device or introduces an unmanaged endpoint that lacks MedDefense's normal protection, patching and monitoring. Malware can then execute inside the trusted network, or sensitive patient/financial data can be copied to removable media or personal storage without DLP controls; because Central is flat, an infected unmanaged device can also become a lateral-movement starting point.

**Current Protection:**  
**C-014 — Sophos Endpoint Malware Protection** and **C-015 — Sophos Automated Threat Containment** protect 372 managed Windows endpoints, while **C-023 — Annual Security Awareness Training** provides general user guidance. These controls do not cover every documented endpoint, do not establish MDM for the physician iPads and do not provide organisation-wide USB/DLP enforcement.

**Gap Reference:**  
- **GAP-020 — No organisation-wide data-loss prevention or removable-media control**
- **GAP-013 — Endpoint and device-management coverage is incomplete**
- **GAP-012 — Undocumented Shadow IT operates on production networks**
- **GAP-001 — No effective internal segmentation**, which increases the consequence of an infected unmanaged device

---

# Technical Vector Summary

MedDefense's most serious technical-vector problem is not that six independent weaknesses exist; it is that they **chain together**. Vulnerable or unsupported software, open services, weak credential governance, insecure network design and unmanaged endpoints can each create an initial foothold, while **GAP-001** allows that foothold to reach far more of the environment than necessary and **GAP-011** reduces the chance of rapid detection. The highest-value technical risk reduction remains enforced internal segmentation, supported by systematic vulnerability management, device-credential hardening, endpoint/MDM coverage, removable-media controls and centralised monitoring.
