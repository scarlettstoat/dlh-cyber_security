# MedDefense Health Systems — Structured Environment Summary

## 1. Organization Overview

### Sites

| Site | Location Type | Primary Function | Approximate Headcount | Relevant Details |
|---|---|---|---:|---|
| **MedDefense Central Hospital** | Downtown acute-care hospital | 350-bed hospital providing Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory and Administration services | ~1,400 | Six floors plus a basement mechanical/server-room level. Underground staff parking and a surface visitor lot. Primary on-premise server and network infrastructure is located here. |
| **Westside Clinic** | Suburban outpatient facility, approximately 12 minutes from Central | Primary care, diagnostic imaging (X-ray and ultrasound, no MRI), blood work, minor procedures and physical therapy | ~180 | Two-story medical office complex with parking shared with an adjacent retail plaza. Shares some IT services with Central but has a local server closet for basic needs. |
| **Corporate HQ** | Leased administrative office space in Greenfield Business Park, approximately 15 minutes from Central | Finance, HR, Legal, Marketing, Executive Leadership and IT | ~220 | Occupies the third floor of a five-story commercial building. No on-premise servers are documented. Network/internet is managed by the building landlord; MedDefense has its own VLAN and connects to Central through a site-to-site VPN. |

The documentation states that MedDefense has approximately **2,000 employees organization-wide**. The listed site headcounts total approximately **1,800**, leaving a difference that is not explained in the packet.

### Security-Relevant Departments and Reporting Structure

- **CEO:** Dr. Patricia Morales.
- **CFO:** Robert Kim.
- **COO:** Angela Torres, with Clinical Directors reporting through the COO.
- **General Counsel:** David Park.
- **CISO:** Position is vacant.
- **James Chen, Deputy CISO:** Acting security leader. The org chart states that he formally reports to the vacant CISO position but, in practice, reports directly to the CEO.
- **Security Analyst:** Reports to James Chen and replaces former analyst Marcus Webb.
- **Sarah Park, IT Director:** Peer to James Chen. James has authority over security policy but not IT operations.
- **IT Department:** Located at Corporate HQ and documented as 12 staff total. The org chart lists:
  - 3 System Administrators
  - 2 Network Technicians
  - 1 Database Administrator
  - 2 Helpdesk Analysts, including Mike Torres as lead
  - 2 Desktop Support Technicians
  - 1 IT Intern position, currently vacant

The packet explicitly notes friction between security and IT because James controls security policy but does not control IT operations.

## 2. IT Infrastructure Identified

### Servers — MedDefense Central Hospital

| Name / Type | Function | Location | Technical Details / Current Documentation |
|---|---|---|---|
| `ehr-srv-01` | EHR application server | Central | Ubuntu 20.04 LTS. Marcus began migrating Linux servers from SSH password authentication to key-only authentication and completed this server. |
| `ehr-db-01` | EHR database | Central | Ubuntu 20.04 LTS; PostgreSQL. Documented as reachable from the entire `10.10.0.0/16` network rather than only from the EHR application server. |
| `pacs-srv-01` | PACS medical imaging server | Central | Windows Server 2016. Radiology is documented as using a shared PACS workstation account. |
| `billing-srv-01` | Billing and claims processing | Central | Ubuntu 18.04 LTS. Repeated performance problems are documented; IT has been restarting the server. Marcus also records that ransomware affected this server in January. |
| `ad-dc-01` | Primary Active Directory domain controller | Central | Windows Server 2019. |
| `ad-dc-02` | Secondary Active Directory domain controller | Central | Windows Server 2019. |
| `file-srv-01` | Department file shares | Central | Windows Server 2016. |
| `print-srv-01` | Print server | Central | Windows Server 2012 R2; marked **[UNVERIFIED]** in the asset list. Marcus notes that the operating system reached end of support in October 2023. |
| `backup-srv-01` | Backup server | Central | Ubuntu 22.04 LTS; Veeam agent. Runs nightly backups to a local NAS located in the same server room, on the same network and in the same rack. |
| `web-srv-01` | Public website and patient portal | Central | Ubuntu 20.04 LTS. Marcus's draft network diagram places this server in a DMZ. |

### Servers — Westside Clinic

| Name / Type | Function | Location | Technical Details / Current Documentation |
|---|---|---|---|
| `ws-srv-01` | Local file server and scheduling | Westside | Windows Server 2016. |

Marcus recorded that there **might be an additional server** in the Westside server closet, but he never physically confirmed it. This is therefore treated as an unknown rather than a confirmed asset.

### Servers — Corporate HQ

No on-premise servers are documented at Corporate HQ. HQ staff use cloud services and connect to Central infrastructure through a site-to-site VPN.

### Network and Connectivity Infrastructure

| Site | Component | Function / Details |
|---|---|---|
| Central | Fortinet FortiGate 100F | Internet-edge firewall. Westside and HQ VPN connections terminate toward Central through the FortiGate. Fortinet support contract is active. |
| Central | Cisco core switch | Core switching. Exact model is not documented. |
| Central | Cisco access switches | Documented as two access switches per floor. Exact deployed count is not confirmed by the packet. |
| Central | Internal network | Marcus documents a flat `10.10.0.0/16` broadcast domain containing servers, workstations and medical devices, with no VLANs configured on the internal network. |
| Central | Ubiquiti UniFi wireless access points | 12 APs documented. A UniFi controller licence/service is also listed in the contracts summary. |
| Central | Guest Wi-Fi | Separate SSID exists, but actual network isolation has not been verified. |
| Central | DMZ | Marcus's draft topology shows `web-srv-01` in a DMZ. The exact implementation is not documented. |
| Westside | Unmanaged switch | One unmanaged switch; brand is unknown. |
| Westside | Netgear Nighthawk consumer router | Direct connection to the ISP and carries the site-to-site/IPSec VPN to Central. Marcus states Westside has no firewall. |
| Westside | Wireless network | The asset list records Westside Wi-Fi as unknown; its existence, equipment and configuration are not confirmed. |
| HQ | Building-managed network and internet | Managed by Greenfield Building Management. MedDefense is assigned its own VLAN. |
| HQ | Site-to-site VPN | Connects HQ to Central through the building-managed network. Marcus states the VPN appears properly configured but its ACLs were not audited. |

### Endpoints

| Category | Location | Approximate Quantity | Technical Details |
|---|---|---:|---|
| Windows workstations | Central | ~320 | Windows 10. |
| Thin clients | Central clinical areas | ~60 | Exact models and operating environment are not documented. |
| Windows workstations | Westside | ~45 | Windows 10. |
| Windows workstations | HQ | ~120 | Windows 10/11. |
| Laptops | HQ | ~30 | Remote-capable; exact operating system mix and management configuration are not documented. |
| iPads | Site not specified | ~25 | Used by physicians for rounds. Management status is explicitly unclear. |

The endpoint quantities came from an Active Directory report that was already **eight months old** when Marcus documented them. The packet states that no one has a complete endpoint count.

### Medical Devices and Connected Clinical Systems

| Device / System | Function | Location | Technical Details |
|---|---|---|---|
| Philips IntelliVue patient monitors | Connected patient monitoring | Central | ~80 units. Connected to the same network as other Central systems. |
| BD Alaris infusion pumps | Medication infusion; network connectivity used for dosage updates | Central topology | ~120 units. Marcus notes they are reachable on the same network as other devices and systems. |
| Siemens MAGNETOM MRI scanner | Medical imaging | Radiology, Central | One unit. Documented as running Windows XP. |
| GE Revolution CT scanner | Medical imaging | Central | One unit. Operating system is unknown. |
| IP-based nurse call system | Clinical communication / nurse call | Site not specified | Integrated with the phone system. |
| Phone system | Telephony and nurse-call integration | Site not specified | Mentioned indirectly through the nurse call system; platform and architecture are not documented. |
| HID Global badge/access system | Physical access control | Site coverage not specified | Connected to Active Directory for some doors. |

### Supporting Security, Backup and Physical Infrastructure

| Component / Service | Location / Scope | Details |
|---|---|---|
| Local backup NAS | Central server room | Receives nightly Veeam backups from `backup-srv-01`; located on the same network and in the same rack as the backup server. |
| UPS | Central | Documented as supporting Central during power loss for approximately 20 minutes. Exact unit(s), capacity and protected systems are not listed. |
| Sophos Endpoint Protection | Scope not fully documented | Endpoint protection service with an annual contract. Marcus did not confirm whether protection was current on every endpoint. |
| Microsoft O365 E3 | Organization-wide | Main documented cloud service. |
| Security cameras | Central | Cameras are documented at the parking garage and ER entrance. No cameras are documented in the server-room corridor. |
| ClearView Security guard service | Central main entrance | One guard, Monday-Friday, 7:00 AM-7:00 PM. No weekend or night coverage. No guard service is documented at Westside or HQ. |

## 3. Data and Services

### Data Types Identified

| Data Type | Where / How It Is Handled | Primary Users / Stakeholders Identified |
|---|---|---|
| Electronic health records and patient clinical data | EHR application and PostgreSQL database (`ehr-srv-01`, `ehr-db-01`) | Clinical staff across hospital departments; exact user groups and access permissions are not documented. |
| Medical imaging data | PACS, MRI, CT, X-ray and ultrasound services | Radiology and other clinical users. |
| Patient monitoring data | Philips IntelliVue monitors | Clinical staff at Central. |
| Infusion / dosage update data | Network-connected BD Alaris infusion pumps | Clinical users; exact operational workflow is not documented. |
| Laboratory / blood-work data | Laboratory services at Central and blood-work services at Westside | Laboratory and clinical users; supporting IT systems are not identified in the packet. |
| Billing and claims data | `billing-srv-01` | Billing/administrative functions; exact department and user population are not specified. |
| Scheduling data | `ws-srv-01` at Westside | Westside staff; exact users and application are not documented. |
| Identity and authentication data | Active Directory domain controllers and the AD-connected badge system | MedDefense workforce and IT administrators; exact account population is not documented. |
| Department shared files | `file-srv-01` at Central and `ws-srv-01` at Westside | Department staff; exact contents and permissions are not documented. |
| Email and productivity data | Microsoft O365 E3 | Organization-wide users. |
| Patient portal data | `web-srv-01` | Patients and internal portal administrators/users; exact data fields and workflows are not documented. |
| Public website content | `web-srv-01` | Public users and internal website administrators; administrative ownership is not documented. |
| Backup copies of organizational data | `backup-srv-01` and local NAS | IT staff for backup/recovery; exact datasets, retention periods and restore procedures are not documented. |
| Corporate/administrative information | Finance, HR, Legal, Marketing and Executive Leadership functions at HQ imply administrative data handling | Relevant HQ departments. Exact datasets, applications and classifications are not documented. |

### Critical IT-Dependent Services Identified

| Service | Main Supporting Infrastructure | Who Depends on It |
|---|---|---|
| Electronic Health Record (EHR) | `ehr-srv-01`, `ehr-db-01`, network infrastructure and authentication services | Clinical staff and departments delivering patient care. |
| Medical imaging / PACS | `pacs-srv-01`, MRI, CT and diagnostic imaging equipment | Radiology and clinical users. |
| Patient monitoring | Philips IntelliVue monitors and Central network | Clinical teams at Central. |
| Medication infusion / dosage updates | BD Alaris infusion pumps and Central network | Clinical teams using infusion pumps. |
| Billing and claims processing | `billing-srv-01` | Administrative/billing functions. |
| Westside scheduling | `ws-srv-01` | Westside staff. |
| Authentication and directory services | `ad-dc-01`, `ad-dc-02` | Workforce and systems using Active Directory. |
| Department file sharing | `file-srv-01`, `ws-srv-01` | Department users at Central and Westside. |
| Printing | `print-srv-01` | Staff relying on centralized printing; exact user groups are not documented. |
| Backup and recovery | `backup-srv-01`, Veeam and local NAS | IT and all services whose data is included in backups. Exact protected scope is not documented. |
| Public website and patient portal | `web-srv-01`, DMZ/internet connectivity | Public users, patients and internal administrators. |
| Email and productivity | Microsoft O365 E3 | Organization-wide users. |
| Site connectivity | FortiGate, Central network, Westside router/IPSec VPN, HQ site-to-site VPN and landlord-managed HQ network | Staff and systems at all three sites, particularly Westside and HQ users accessing Central resources. |
| Nurse call / telephony | IP-based nurse call system and integrated phone system | Clinical operations; exact users and site scope are not documented. |
| Physical access control | HID Global badge system and Active Directory integration | Staff requiring controlled-door access. |

### External Service and Vendor Dependencies Identified

- **Sophos:** Endpoint Protection.
- **Veeam:** Backup software.
- **Fortinet:** FortiGate support.
- **Microsoft:** O365 E3, organization-wide.
- **Ubiquiti:** UniFi controller licensing/service.
- **Greenfield Building Management:** HQ network and internet, included with the lease.
- **ClearView Security:** Central main-entrance guard service.
- **MedTech Solutions:** EHR maintenance, including software updates. The contract specifies a four-hour response for critical issues and 24-hour response for standard issues; hardware is excluded.

## 4. Known Unknowns

### Asset Inventory and Ownership

- The ServiceDesk asset list is explicitly **partial** and does not represent a complete inventory.
- Some assets marked **[UNVERIFIED]** have not been physically confirmed in more than a year; `print-srv-01` is specifically marked unverified.
- Endpoint counts are based on an Active Directory report that was already eight months old when Marcus recorded them.
- The current exact number of workstations, laptops, thin clients, tablets and other endpoints is unknown.
- Marcus recorded a possible second server in the Westside server closet, but its existence, purpose, operating system and ownership were never confirmed.
- Asset owners, business owners and system custodians are not documented for the listed infrastructure.
- The exact current filled headcount of the IT department is unclear because the packet states 12 IT staff total while also listing an IT intern position as currently vacant.

### Site and Network Topology

- Central is described as a six-floor building plus basement, while Marcus's simplified network diagram only depicts Floors 1-4. The exact physical and network distribution by floor is therefore incomplete.
- The exact model of the Central Cisco core switch is unknown.
- The asset list says there are two Cisco access switches per floor, but the exact total, placement and models are not confirmed.
- Marcus states the Central topology diagram is simplified and that the real topology is more complex; the full topology is unknown.
- The relationship between the documented flat `10.10.0.0/16` internal network and the separately drawn DMZ for `web-srv-01` is not fully documented.
- Guest Wi-Fi exists at Central, but whether it is actually isolated from internal systems has not been verified.
- Westside Wi-Fi equipment, configuration and security are unknown.
- Westside uses a Netgear Nighthawk router and is documented as having no firewall, but the exact router model, firmware level and configuration are not provided.
- HQ networking is managed by the building landlord. MedDefense's VLAN details, underlying equipment and network controls are not documented.
- Marcus did not audit the HQ VPN ACLs, so the permitted traffic between HQ and Central is not confirmed.
- IP addressing, routing and segmentation details for Westside and HQ are not documented.
- Firewall rules, ACLs, remote-access configuration, logging, network monitoring and any IDS/IPS capability are not documented.

### Endpoint, Server and Medical Device Status

- It is unclear whether the approximately 25 physician iPads are centrally managed, and their site assignment is not specified.
- Sophos endpoint protection exists under contract, but current installation, update and coverage status across all endpoints is unknown.
- No formal vulnerability assessment of all servers has been completed.
- Patch levels and update status are not documented beyond the listed operating-system versions.
- `billing-srv-01` has recurring unexplained performance problems. The cause and current security status are unknown.
- The January ransomware incident involving `billing-srv-01` was handled ad hoc. The packet does not document root cause, entry vector, scope, affected data, remediation or whether persistence was ruled out.
- The CT scanner operating system is unknown.
- A complete medical-device/IoT inventory does not exist in the packet. Models, operating systems, firmware versions and support status are missing for most devices.
- The nurse call system and integrated phone system are mentioned but their platforms, network architecture, site coverage and dependencies are not documented.
- The HID badge/access system is connected to Active Directory for some doors, but the exact doors, sites, access rules and system architecture are not documented.

### Authentication and Access Control

- The password policy is documented as eight characters minimum, 90-day rotation and complexity enabled, but enforcement scope and exceptions are not documented.
- MFA is documented only for James Chen's personal account. The packet does not identify any broader MFA deployment.
- Radiology uses a shared PACS login (`raduser`), but the number of shared accounts elsewhere in the environment is unknown.
- Marcus began moving Linux servers from SSH password authentication to key-only authentication and completed `ehr-srv-01`; current SSH configuration on every Linux server has not been independently revalidated since his departure.
- Active Directory group structure, privileged accounts, service accounts, account lifecycle controls and access review processes are not documented.

### Data and Cloud Services

- No complete cloud-service inventory exists. O365 is documented as the main service, but Marcus suspected individual departments use additional cloud services.
- The exact data stored in each system, file share and cloud service is not documented.
- Formal data classification, data ownership, retention requirements and disposal procedures are not documented in the packet.
- Encryption controls for data at rest and in transit are not documented.
- Patient portal architecture, authentication method, data flows and administrative ownership are not documented.
- The supporting systems for laboratory/blood-work services are not identified.
- Corporate systems used by Finance, HR, Legal, Marketing and Executive Leadership are not identified beyond O365 and access to Central infrastructure.

### Backup, Recovery and Continuity

- Veeam performs nightly backups to a local NAS, but the exact systems and datasets included in backups are not documented.
- Backup retention periods, encryption, access controls and restore-test history are not documented.
- No offsite or cloud backup is documented.
- The backup server and NAS are located in the same Central server room, on the same network and in the same rack, but no additional backup copy is identified.
- The Central UPS is documented as providing approximately 20 minutes of support, but the systems connected to it, tested runtime and shutdown procedures are unknown.
- No formal business continuity plan exists.
- No formal disaster recovery plan exists.
- There is no documented procedure for maintaining clinical operations during a Central power loss that exceeds UPS capacity.

### Physical Security

- Central server-room badge access uses the same generic badge issued broadly to staff; the packet does not document a restricted server-room access list.
- No cameras are documented in the Central server-room corridor.
- Westside's server closet does not lock, and no other physical controls protecting its IT equipment are documented.
- There is no guard at Westside or HQ. Central guard coverage is limited to the main entrance, Monday-Friday, 7:00 AM-7:00 PM.
- Physical security arrangements for HQ IT equipment are not documented beyond the building-managed environment.

### Governance, Compliance and Security Operations

- HIPAA Security Rule compliance has never been formally assessed. Legal states that MedDefense is compliant, but the packet says there is no supporting evidence.
- No formal incident response plan exists.
- No formal business continuity plan or disaster recovery plan exists.
- A complete threat landscape analysis was started but not finished.
- No documented continuous security monitoring, centralized logging, SIEM, vulnerability-management process or security testing programme is identified in the packet.
- The CISO position is vacant, and the long-term security reporting structure is therefore unresolved.
- James Chen has authority over security policy but not IT operations, creating a documented governance boundary between security requirements and operational implementation.
- The listed site headcounts total approximately 1,800, while the organization-wide total is stated as approximately 2,000. The location or role of the remaining approximately 200 employees is not explained.
