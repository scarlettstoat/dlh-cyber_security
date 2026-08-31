# MedDefense Health Systems — Asset Registry

This registry consolidates asset information identified across the MedDefense onboarding documentation, incident history, physical walk-through, existing-control artifacts, MRI context and the network scan summary. Where ownership, platform or location is not documented, the field is marked accordingly rather than inferred.

> **Network note:** The scan separates Central systems into `10.10.1.0/24`, `10.10.2.0/24` and `10.10.3.0/24` for addressing purposes, but confirms that these networks are not separated by VLANs or firewall controls. They operate on the same reachable internal network.

## Asset Registry

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| **A-001** | `ehr-srv-01` | Server | Central Hospital | Not documented (IT-administered) | Ubuntu 20.04 | EHR application | `10.10.2.0/24` — `10.10.2.10` | Active | Scan confirms SSH, HTTPS and port 8080. Task 4 confirms key-only SSH authentication and EHR audit logging. |
| **A-002** | `ehr-db-01` | Data Store | Central Hospital | Not documented (IT/DBA-administered) | Ubuntu 20.04 / PostgreSQL | EHR database | `10.10.2.0/24` — `10.10.2.11` | Active | PostgreSQL on 5432 is reachable from the entire internal network rather than only `ehr-srv-01`. |
| **A-003** | `pacs-srv-01` | Server | Central Hospital | Not documented (Radiology service) | Windows Server 2016 | PACS / medical imaging | `10.10.2.0/24` — `10.10.2.12` | Active | Scan confirms SMB and medical-imaging ports 4242 and 11112. Documentation also records a shared PACS user account. |
| **A-004** | `billing-srv-01` | Server | Central Hospital | Not documented (billing/finance service) | Ubuntu 18.04 | Billing and insurance claims | `10.10.2.0/24` — `10.10.2.15` | Deprecated | Still operational, but Ubuntu 18.04 standard support ended in June 2023 and ESM is not activated. Ransomware encrypted this server in January. MySQL 3306 is exposed across the internal network. |
| **A-005** | `ad-dc-01` | Server | Central Hospital | Not documented (IT-administered) | Windows Server 2019 | Active Directory, authentication and directory services | `10.10.2.0/24` — `10.10.2.20` | Active | Primary documented domain controller; scan confirms DNS, Kerberos, LDAP, SMB and LDAPS services. |
| **A-006** | `ad-dc-02` | Server | Central Hospital | Not documented (IT-administered) | Windows Server 2019 | Active Directory redundancy and authentication | `10.10.2.0/24` — `10.10.2.21` | Active | Secondary domain controller confirmed by scan. |
| **A-007** | `file-srv-01` | Server | Central Hospital | Not documented (IT-administered) | Windows Server 2016 | Department file shares | `10.10.2.0/24` — `10.10.2.30` | Active | Confirmed by scan. A partial backup restoration test was previously performed against this server. |
| **A-008** | `print-srv-01` | Server | Central Hospital | Not documented (IT-administered) | Windows Server 2012 R2 | Centralized printing | `10.10.2.0/24` — `10.10.2.31` | Deprecated | Task 0 marked the asset unverified, but the scan confirms it is active on the network. Windows Server 2012 R2 reached end of support in October 2023. |
| **A-009** | `backup-srv-01` | Server | Central Hospital server room | Not documented (IT-administered) | Ubuntu 22.04 | Backup and recovery | `10.10.2.0/24` — `10.10.2.40` | Active | Scan confirms SSH. Veeam performs nightly backups of documented in-scope virtual machines. |
| **A-010** | `NAS-01` | Data Store | Central Hospital server room | Not documented (IT-administered) | Synology DSM 7 | Local backup storage | `10.10.2.0/24` — `10.10.2.41` | Active | Stores Veeam backups with 14-day retention. Management ports 5000/5001 are reachable from the entire internal network. Located in the same rack/network as the backup server. |
| **A-011** | `web-srv-01` | Server | Central Hospital | Not documented | Ubuntu 20.04 | Public website and patient portal | `10.10.2.0/24` — `10.10.2.50`; also documented as DMZ | Active | Scan places the host in the Central server subnet, while the draft topology and firewall configuration describe it as a DMZ host. Requires reconciliation. |
| **A-012** | `UNKNOWN-01` | Server | Central Hospital | Unknown | Linux 4.x | Unknown | `10.10.2.0/24` — `10.10.2.99` | Shadow IT (unmanaged) | Not present in any documentation or DNS. Responds on SSH and web-service ports 8888 and 9090. |
| **A-013** | `ws-srv-01` | Server | Westside Clinic | Not documented (IT/Westside service) | Windows Server 2016 | Local file sharing and scheduling | `10.10.10.0/24` — `10.10.10.10` | Active | Confirmed by scan with SMB and RDP exposed. |
| **A-014** | Westside unknown Linux device (`10.10.10.200`) | Server | Westside Clinic | Unknown | Linux 5.x | Unknown | `10.10.10.0/24` — `10.10.10.200` | Shadow IT (unmanaged) | Not present in documentation. SSH, HTTP and port 3000 are open; Sarah notes it may be an unofficial monitoring tool. |
| **A-015** | Westside Netgear router | Network Device | Westside Clinic | Not documented | Netgear firmware | Internet access and IPSec VPN to Central | `10.10.10.0/24` — `10.10.10.1` | Active | Task 0 identifies a Netgear Nighthawk consumer router and no separate firewall at Westside. Scan confirms the router and VPN-connected site subnet. |
| **A-016** | Fortinet FortiGate 100F | Network Device | Central Hospital | IT | FortiOS / FortiGate 100F | Internet edge, firewalling and site VPN termination | Internet edge / internal network / DMZ | Active | Documented in Task 0 and Task 4. No corresponding management IP is listed in the internal scan summary. |
| **A-017** | Central Cisco core switch | Network Device | Central Hospital | IT | Cisco; model unknown | Core network switching | Central internal network | Active | Documented in onboarding materials but no individual switch management address appears in the scan. |
| **A-018** | Central Cisco access-switch estate | Network Device | Central Hospital floors | IT | Cisco; models unknown | Floor access switching | Central internal network | Active | Documentation states two access switches per floor, but exact count and placement remain unverified. Task 3 observed an unlocked second-floor network closet containing switches and patch panels. |
| **A-019** | Central UniFi wireless AP estate | Network Device | Central Hospital | IT | Ubiquiti UniFi | Corporate and wireless access | `10.10.1.0/24` — `10.10.1.200-211` | Active | Twelve APs are documented and twelve AP host entries are visible in the scan, covering floors, lobby, cafeteria, garage, basement and ER. |
| **A-020** | Central Windows workstation estate | Endpoint | Central Hospital | Not documented | Windows 10 | Clinical and administrative workstation access | `10.10.1.0/24` | Active | Task 0 estimated ~320 workstations. Scan lists 19 named Windows workstations plus approximately 290 additional systems, or roughly 309 responding Windows workstations. |
| **A-021** | Central ER thin-client estate | Endpoint | Central Hospital ER / clinical areas | Not documented | Linux thin client | Clinical endpoint access | `10.10.1.0/24` — `10.10.1.100-103` | Active | Task 0 estimated ~60 thin clients; only four (`TC-ER-01` through `TC-ER-04`) are shown as responding in the scan. |
| **A-022** | `WS-RAD-01` — MRI control workstation | Endpoint | Radiology, Central Hospital | Not documented (Radiology user group) | Windows XP SP3 | MRI control | `10.10.1.0/24` — `10.10.1.70` | Deprecated | Scan explicitly identifies this as the MRI control workstation and marks Windows XP as end-of-life. |
| **A-023** | `WS-RAD-02` | Endpoint | Radiology, Central Hospital | Not documented (Radiology user group) | Windows 10 | Radiology workstation services | `10.10.1.0/24` — `10.10.1.71` | Active | Named radiology workstation detected in the network scan. Exact application role is not documented. |
| **A-024** | Westside Windows workstation estate | Endpoint | Westside Clinic | Not documented | Windows 10 | Outpatient clinical and administrative access | `10.10.10.0/24` | Active | Task 0 estimated ~45 workstations; the scan identifies 36 systems (`WS-WC-01` through `WS-WC-36`). |
| **A-025** | `WS-WC-XRAY` | Endpoint | Westside Clinic | Not documented (Radiology/imaging user group) | Unknown vendor-specific platform | X-ray imaging | `10.10.10.0/24` — `10.10.10.100` | Active | Scan identifies a vendor-specific X-ray workstation with ports 80 and 4242. |
| **A-026** | Corporate HQ workstation estate | Endpoint | Corporate HQ | Not documented | Windows 10/11 | Administrative and corporate work | `10.10.20.0/24` | Active | Approximately 120 workstations detected, consistent with the approximate count in Task 0. |
| **A-027** | Corporate HQ laptop estate | Endpoint | Corporate HQ / mobile workforce | Not documented | Windows 11 detected; full mix unknown | Remote/mobile corporate work | `10.10.20.0/24` when on-site | Active | Task 0 estimated ~30 laptops. Approximately 25 were detected during the scan window, consistent with intermittent mobile use. |
| **A-028** | Physician iPad estate | Endpoint | Site assignment not documented | Not documented | iPadOS version unknown | Physician rounds / clinical access | Unknown | Active | Approximately 25 iPads are documented. Central management/MDM status is unclear, and no corresponding devices are identified in the scan summary. |
| **A-029** | Siemens MAGNETOM MRI scanner | IoT Medical | Radiology, Central Hospital | Not documented (Radiology user group) | Documentation associates the MRI with Windows XP; exact component unclear | MRI medical imaging | Not identified separately in scan | Deprecated | Task 0 documents one MRI unit. The new scan identifies Windows XP specifically on `WS-RAD-01`, the MRI control workstation, rather than a separately scanned MRI host. |
| **A-030** | GE Revolution CT scanner | IoT Medical | Central Hospital | Not documented (Radiology user group) | Unknown | CT medical imaging | Unknown | Active | One unit is documented in Task 0 but no clearly corresponding CT device appears in the scan summary. |
| **A-031** | Philips IntelliVue monitor estate | IoT Medical | Central Hospital | Not documented (clinical user groups) | Philips IntelliVue | Patient monitoring | `10.10.3.0/24` | Active | Task 0 estimates ~80 monitors. Scan shows 13 named monitors plus approximately 65 additional devices (~78 total). Management interfaces are reachable across the internal network. |
| **A-032** | BD Alaris infusion-pump estate | IoT Medical | Central Hospital | Not documented (clinical user groups) | BD Alaris firmware 12.1.2 | Medication infusion and dosage updates | `10.10.3.0/24` | Active | Task 0 estimates ~120 pumps. Scan shows seven named pumps plus approximately 110 additional devices (~117 total). Scan notes known CVEs and that recommended network isolation has not been implemented. |
| **A-033** | `MON-VITALS-3F-01` | IoT Medical | Third floor, Central Hospital | Not documented | Unknown vendor; displayed firmware v2.1.3, last updated 2019 | Connected vital-sign monitoring | `10.10.3.0/24` — `10.10.3.47` | Active | Same device observed during Task 3. Scan confirms HTTP on port 80. Although separately addressed from workstation subnet, it shares the same unsegmented physical network. |
| **A-034** | IP nurse-call system (`NURSE-CALL-01/02`) | IoT Medical | Central Hospital; exact coverage not documented | Not documented | IP-based system | Nurse-call / clinical communication | `10.10.3.0/24` — `10.10.3.50-51` | Active | Task 0 identified an IP-based nurse-call system integrated with telephony; scan confirms two networked components. |
| **A-035** | HID badge-reader/access-control system | Physical Infrastructure | Central Hospital; exact door coverage incomplete | Not documented | HID Global | Physical access control | `10.10.3.0/24` — `10.10.3.60-62` | Active | Scan identifies badge readers for main entrance, server area and ER. Task 0 states the badge system connects to Active Directory for some doors. |
| **A-036** | EHR application | Application | Hosted at Central Hospital | Not documented | Hosted on `ehr-srv-01`; vendor maintained | Electronic Health Record | Via `ehr-srv-01` / internal network | Active | Critical clinical service used by physicians and other clinical staff. Experienced a nine-hour outage during a planned migration. |
| **A-037** | Patient portal | Application | Hosted on `web-srv-01` | Not documented | Platform not documented | Patient access to health information | Via `web-srv-01` / internet-facing | Active | Incident history records broken access control allowing authenticated patients to view other patients' lab results by modifying a URL parameter. |
| **A-038** | Pharmacy management system | Application | Used across all three MedDefense sites | Not documented (Pharmacy user group) | Platform not documented | Medication/dosage management | Network location not documented | Active | Incident history records incorrect medication dosages for approximately six hours after a faulty database update script. No corresponding host is identified in the scan. |
| **A-039** | Microsoft O365 E3 | Application | Cloud / organization-wide | Not documented (IT-administered) | Microsoft 365 | Email and productivity | Cloud / Internet | Active | Main documented organization-wide cloud service; not expected to appear in the internal Nmap scan. |
| **A-040** | Sophos Endpoint Protection | Application | Endpoint estate | IT | Sophos Endpoint Protection | Endpoint malware protection | Installed on managed endpoints | Active | Task 4 reports deployment to 372 Windows 10/11 workstations. This is materially lower than the broader documented Windows endpoint population and requires coverage reconciliation. |
| **A-041** | Veeam Backup & Replication | Application | Central Hospital | IT | Veeam | Backup and recovery | Backup infrastructure / `10.10.2.0/24` | Active | Performs full backups daily at 02:00 with storage on `NAS-01`; documented scope includes six virtual machines. |
| **A-042** | VMware cluster | Physical Infrastructure | Central Hospital | IT | VMware | Virtual-machine hosting | Network details not documented | Active | Task 4 backup configuration identifies an in-scope VMware cluster, but the cluster/hosts do not appear as separately named assets in the scan summary. |
| **A-043** | Central server room | Physical Infrastructure | Central Hospital — location contradictory | IT operational area | Physical facility | Hosts core server and backup infrastructure | N/A | Active | Task 0 places primary server infrastructure on a basement server-room level; Task 3 describes the server room as ground floor near the cafeteria corridor. Access uses generic employee badges and lacks door camera/visitor logging. |
| **A-044** | Second-floor network closet | Physical Infrastructure | Second floor, Central Hospital | IT | Physical network closet | Houses switches and patch panels | Central internal network | Active | Task 3 found the closet unlocked and ajar with switch-management credentials posted beside the switch stack. No individual management address is identified in the scan. |
| **A-045** | Central CCTV / standalone DVR system | Physical Infrastructure | Central Hospital | Not documented | Four analog cameras + standalone DVR | Physical-security monitoring | Standalone / network status not documented | Active | Cameras cover the main entrance, ER entrance and parking garage; recordings are retained for 30 days. |
| **A-046** | Central UPS | Physical Infrastructure | Central Hospital | Not documented | UPS model unknown | Short-term power continuity | N/A | Active | Task 0 documents approximately 20 minutes of power support; exact protected systems and capacity are unknown. |
| **A-047** | Westside front-entrance camera | Physical Infrastructure | Westside Clinic | Not documented | Local camera / SD-card storage | Physical-security monitoring | Network status not documented | Active | Task 4 documents one camera with approximately 48 hours of local footage before overwrite. |
| **A-048** | Possible second Westside server | Server | Westside server closet | Unknown | Unknown | Unknown | Unknown | Unknown | Marcus noted that another server might exist in the Westside closet but never confirmed it. No additional documented server identity can be matched confidently to the scan. |
| **A-049** | IT intern personal laptop | Endpoint | Previously connected to MedDefense internal Wi-Fi | IT intern / personal device | Not documented | None authorized | Internal network; exact IP not documented | Shadow IT (unmanaged) | Incident history states the personal laptop ran a torrent client and remained on the internal rather than guest network for three weeks, on the same reachable network as the HR file share. |
| **A-050** | HR file share | Data Store | Hosting system/location not explicitly identified | HR | Platform not documented | HR departmental file storage | Internal network; exact host/IP not documented | Active | Mentioned in the June incident. It may reside on a documented file server, but the source does not identify which host, so no host mapping is assumed. |
| **A-051** | Integrated phone system | Application | Site coverage not documented | Not documented | Platform unknown | Telephony and nurse-call integration | Network details unknown | Active | Mentioned in onboarding documentation through its integration with the IP nurse-call system. No separate scan identity is established. |
| **A-052** | Westside unmanaged switch | Network Device | Westside server closet | Not documented | Brand/model unknown | Local network switching | `10.10.10.0/24` environment | Active | Documented in Task 0; no management IP is expected/identified in the scan because the switch is described as unmanaged. |
| **A-053** | Public MedDefense website | Application | Hosted on `web-srv-01` | Not documented | Platform not documented | Public web presence | Internet-facing via `web-srv-01` | Active | Defaced in April and restored from backup within two hours. The website is documented as containing no patient data. |

# Reconciliation Notes

## 1. Assets Found in the Network Scan but Not in Existing Documentation

### `10.10.2.99` — `UNKNOWN-01`
This is the clearest undocumented Central asset. It is a Linux 4.x system on the server addressing subnet with SSH and web services on ports 8888 and 9090. It has no DNS hostname and is explicitly marked in the scan as absent from all documentation. It is therefore recorded as **Shadow IT (unmanaged)** pending identification.

### `10.10.10.200` — Unknown Westside Linux Device
This system is also explicitly absent from existing documentation. It exposes SSH, HTTP and port 3000. Sarah Park notes that it may be an unofficial monitoring system, but its purpose and owner are not established. It is recorded as **Shadow IT (unmanaged)**.

### Newly Identified Named Systems Within Already Documented Categories
The scan provides specific hostnames and IP addresses that were not present in the earlier high-level inventory, including:

- `WS-RAD-01` and `WS-RAD-02`
- `WS-WC-XRAY`
- `TC-ER-01` through `TC-ER-04`
- Twelve named UniFi APs
- Named Philips IntelliVue monitors
- Named BD Alaris infusion pumps
- `NURSE-CALL-01` and `NURSE-CALL-02`
- `BADGE-READER-MAIN`, `BADGE-READER-SVR` and `BADGE-READER-ER`

These are not treated as shadow IT because they fit asset categories and systems already evidenced in earlier documentation.

## 2. Assets Mentioned in Documentation but Not Identified in the Network Scan

The following documented assets do not have a clearly corresponding host entry in the scan:

- Fortinet FortiGate 100F
- Central Cisco core switch
- Central Cisco access switches
- Westside unmanaged switch
- Siemens MAGNETOM MRI scanner as a distinct network host
- GE Revolution CT scanner
- Approximately 25 physician iPads
- Integrated phone system
- Central UPS
- Central CCTV / standalone DVR system
- Westside front-entrance camera
- VMware cluster / individual virtualization hosts
- Possible second server in the Westside server closet
- The IT intern's personal laptop from the June incident
- Logical services/data assets such as the HR file share, pharmacy management application, EHR application, patient portal and O365

Absence from the scan does **not** establish that these assets are decommissioned. Some are non-IP physical assets, cloud services, logical applications, unmanaged Layer-2 devices, mobile devices that may have been offline, or systems for which the scan summary may not expose a separate identity.

## 3. Discrepancies and Contradictions Between Sources

### MRI / Windows XP Identification
The onboarding documentation associates the Siemens MAGNETOM MRI with Windows XP. The network scan is more specific: it identifies `WS-RAD-01` (`10.10.1.70`) as a **Windows XP SP3 MRI control workstation**. The MRI scanner itself does not appear as a separate scan entry. It must therefore be confirmed whether Windows XP runs only on the control workstation, on an embedded MRI component, or both.

### Central Server Room Location
The onboarding documentation describes Central as having a basement mechanical/server-room level, while the Task 3 walk-through states that the server room is on the **ground floor** beside a corridor shared with the cafeteria. The authoritative physical location must be confirmed.

### `web-srv-01` Network Placement
The draft topology and firewall configuration describe `web-srv-01` as a **DMZ** host. The scan identifies it at `10.10.2.50` within the Central server addressing subnet. The actual zone/VLAN placement and firewall enforcement require verification.

### Flat Network Versus Addressing Subnets
Earlier documentation described Central as a flat `10.10.0.0/16` network. The scan uses separate `/24` addressing ranges for workstations, servers and medical devices, but explicitly confirms that these are **addressing conventions only**: there is no VLAN or firewall separation, and Sarah's HQ workstation could reach every internal subnet. The earlier flat-network concern is therefore confirmed.

### Task 3 Medical-Device Addressing
During the walk-through, the vital-signs monitor at `10.10.3.47` appeared to be on the same IP range as nurse-station workstations. The scan shows nurse workstations in `10.10.1.0/24` and medical devices in `10.10.3.0/24`. They are not the same addressing subnet, but they remain on the same unsegmented physical/reachable network. The security concern remains valid, while the addressing description should be corrected.

### `print-srv-01` Verification
Task 0 marked `print-srv-01` as **unverified**. The new scan confirms that `10.10.2.31` is live and identifies it as Windows Server 2012. The existence of the server is therefore now verified, although its operating system remains end-of-life.

### Endpoint Counts
Earlier documentation relied on an eight-month-old Active Directory report and estimated:

- Central: ~320 Windows workstations
- Westside: ~45 Windows workstations
- HQ: ~120 Windows workstations
- HQ: ~30 laptops
- Central clinical areas: ~60 thin clients

The new scan found approximately:

- Central: ~309 responding Windows workstations (19 named plus ~290 omitted)
- Westside: 36 Windows workstations
- HQ: ~120 Windows workstations
- HQ: ~25 laptops
- Central: only 4 explicitly identified thin clients

These differences may reflect stale inventory data, powered-off systems, retired/replaced endpoints or devices absent during the scan. They require physical/management-platform reconciliation before an authoritative count can be established.

### Medical-Device Counts
Task 0 estimated approximately **80 Philips monitors** and **120 BD Alaris pumps**. The scan represents approximately **78 Philips monitors** (13 named + ~65 additional) and **117 pumps** (7 named + ~110 additional). The figures are close but not identical and should be reconciled against procurement/clinical-engineering records.

### Sophos Coverage Versus Endpoint Population
Task 4 reports Sophos Endpoint Protection on **372 Windows 10/11 workstations**. The documented Windows endpoint estate across Central, Westside and HQ is materially larger than 372 systems. This does not prove that every remaining endpoint is unmanaged, but it means current endpoint-protection coverage cannot be assumed to be complete.

### Backup Scope Clarification
Task 0 described the exact backup scope as unknown. Task 4 provides additional detail: the Veeam job covers `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01` and `web-srv-01`. Other documented servers, including `pacs-srv-01`, `ad-dc-02`, `print-srv-01` and `ws-srv-01`, are not listed in that backup job and therefore cannot be assumed to be protected by it.
