# 14. The Segmentation Architecture

## MedDefense Health Systems — Network Segmentation Design

## Purpose

MedDefense currently uses different IP ranges for workstations, servers and medical devices, but those ranges do not function as consistently enforced security boundaries. The purpose of this design is to turn the existing flat environment into a **default-deny segmented architecture** where systems can communicate only when there is a documented clinical, business or administrative need.

The design follows four principles:

1. **Separate systems by function and risk.**
2. **Block unnecessary east-west traffic.**
3. **Allow administration only from the Management zone.**
4. **Permit only explicitly approved inter-zone flows, with everything else denied by default.**

> **Design note:** The IP ranges below are proposed target VLAN ranges. Existing systems may require staged readdressing or transitional firewall rules during implementation. For example, the MRI workstation currently uses an address in the workstation range but should move into the Medical Device zone as part of this design.

---

# Part 1 — Zone Definition

## Proposed Zone Summary

| VLAN | Zone | Proposed IP Range | Primary Purpose |
|---:|---|---|---|
| **VLAN 10** | Clinical Workstations | `10.10.1.0/24` | Nurse stations, physician workstations and approved clinical user endpoints |
| **VLAN 20** | Server Zone | `10.10.2.0/24` | EHR, billing, file services, Active Directory and other core servers |
| **VLAN 30** | Medical Device Zone | `10.10.3.0/24` | PACS, monitors, infusion pumps, MRI and other clinical devices |
| **VLAN 40** | Management Zone | `10.10.4.0/24` | IT admin workstations, Wazuh/SIEM, management services and security tooling |
| **VLAN 50** | Guest / Non-Clinical IoT | `10.10.5.0/24` | Visitor Wi-Fi and non-clinical IoT |
| **VLAN 60** | Backup / Recovery Zone | `10.10.6.0/24` | Backup server, NAS, Veeam and recovery infrastructure |

The required five zones are included. A sixth **Backup / Recovery Zone** is added because ransomware actors deliberately target recovery infrastructure, and MedDefense has already identified broad internal access to its backup environment as a major risk.

---

## Zone 1 — Clinical Workstation Zone

```yaml
Zone Name: Clinical Workstation Zone
VLAN: 10
IP Range: 10.10.1.0/24

Systems Included:
  - Nurse-station workstations
  - Physician workstations
  - Other approved clinical user endpoints

Purpose:
  - Provide clinicians with access to the EHR and approved clinical services
  - Keep ordinary user endpoints separated from servers, medical-device
    management interfaces and administrative systems

Allowed Outbound Connections:
  - HTTPS to EHR application services in the Server Zone
  - Required Active Directory authentication and DNS services
  - Approved printing/file services where operationally required
  - Internet access through the existing security gateway
  - Security telemetry to approved monitoring services

Allowed Inbound Connections:
  - Approved management traffic from the Management Zone
  - Required server responses to connections initiated by clinical endpoints
  - No unsolicited connections from Guest/IoT or Medical Device zones
```

### Security Intent

A compromised nurse or physician workstation should **not** become a launch point for unrestricted scanning of Active Directory, database services, backup infrastructure, medical devices or administrative systems.

---

## Zone 2 — Server Zone

```yaml
Zone Name: Server Zone
VLAN: 20
IP Range: 10.10.2.0/24

Systems Included:
  - ehr-srv-01
  - ehr-db-01
  - billing-srv-01
  - File servers
  - ad-dc-01
  - ad-dc-02
  - Other approved core application servers

Purpose:
  - Host critical business, identity and EHR services
  - Prevent ordinary endpoints from directly reaching sensitive backend
    services unless the connection is specifically required

Allowed Outbound Connections:
  - Required database/application communication inside the Server Zone
  - Security logs to Wazuh in the Management Zone
  - Approved backup traffic to the Backup / Recovery Zone
  - Required DNS, update and security-management services
  - Approved clinical integration traffic to the Medical Device Zone

Allowed Inbound Connections:
  - HTTPS to the EHR application from Clinical Workstations
  - Approved authentication traffic to Active Directory
  - Administrative traffic from the Management Zone
  - Approved PACS/medical integration flows
  - No direct database access from ordinary workstation networks
```

### Security Intent

The Server Zone becomes a protected application tier rather than an extension of the workstation network. In particular, `ehr-db-01` should not accept PostgreSQL connections directly from general clinical workstations.

---

## Zone 3 — Medical Device Zone

```yaml
Zone Name: Medical Device Zone
VLAN: 30
IP Range: 10.10.3.0/24

Systems Included:
  - BD Alaris infusion pumps
  - Philips IntelliVue monitors
  - PACS / imaging systems
  - MRI control environment including WS-RAD-01
  - Other medical IoT and embedded clinical devices

Purpose:
  - Isolate patient-care devices from ordinary user and server networks
  - Limit the blast radius of vulnerable or unsupported clinical technology
  - Protect devices that cannot support normal endpoint-security controls

Allowed Outbound Connections:
  - Approved clinical data flows to specific EHR/PACS integration services
  - Approved DNS/NTP services where required
  - Security/network telemetry to the Management Zone
  - Vendor connections only through explicitly approved controlled paths

Allowed Inbound Connections:
  - Approved administration from dedicated Management Zone hosts
  - Required EHR/PACS clinical communications
  - No direct Guest/IoT access
  - No general workstation access to device-management interfaces
```

### Security Intent

Medical devices are treated as a **restricted clinical trust zone**, not as normal workstations. This is especially important for the Windows XP MRI workstation and devices with limited patching or endpoint-security capability.

---

## Zone 4 — Management Zone

```yaml
Zone Name: Management Zone
VLAN: 40
IP Range: 10.10.4.0/24

Systems Included:
  - Dedicated IT administrator workstations
  - Wazuh SIEM
  - Security management servers
  - Network-management systems
  - Approved privileged-access tools
  - Vulnerability-management systems where applicable

Purpose:
  - Provide a controlled location for administrative activity
  - Centralize security monitoring
  - Prevent privileged management interfaces from being exposed to
    ordinary clinical users or guest devices

Allowed Outbound Connections:
  - Approved SSH, RDP, HTTPS and other administrative protocols to managed assets
  - Security scanning and monitoring traffic
  - Configuration-management traffic
  - Access to backup, server and medical-device management interfaces
    only from designated admin hosts

Allowed Inbound Connections:
  - Wazuh/security telemetry from managed zones
  - Administrator authentication from specifically approved admin endpoints
  - No inbound access from Guest/IoT devices
  - No general clinical workstation access
```

### Security Intent

Administrative access is separated from ordinary browsing, email and day-to-day clinical activity. An attacker who compromises a user workstation should therefore not automatically inherit access to privileged management interfaces.

---

## Zone 5 — Guest / Non-Clinical IoT Zone

```yaml
Zone Name: Guest / Non-Clinical IoT Zone
VLAN: 50
IP Range: 10.10.5.0/24

Systems Included:
  - Visitor Wi-Fi clients
  - Personal guest devices
  - Non-clinical IoT devices
  - Other low-trust devices that do not require access to MedDefense systems

Purpose:
  - Provide Internet connectivity without creating a trusted path into
    MedDefense clinical or business networks

Allowed Outbound Connections:
  - Internet HTTP/HTTPS
  - Approved DNS and DHCP infrastructure
  - Required cloud services for non-clinical IoT where documented

Allowed Inbound Connections:
  - Return traffic for established sessions
  - No unsolicited inbound traffic from MedDefense internal zones
```

### Security Intent

This is the **lowest-trust zone**. Guest and non-clinical IoT systems should have no direct route to EHR, Active Directory, medical devices, backups or administrative systems.

---

## Zone 6 — Backup / Recovery Zone

```yaml
Zone Name: Backup / Recovery Zone
VLAN: 60
IP Range: 10.10.6.0/24

Systems Included:
  - backup-srv-01
  - NAS-01
  - Veeam Backup & Replication
  - Recovery-management infrastructure

Purpose:
  - Prevent ransomware operating in the production network from easily
    reaching and destroying recovery infrastructure

Allowed Outbound Connections:
  - Required offsite immutable replication
  - Security telemetry to the Management Zone
  - Required update services

Allowed Inbound Connections:
  - Approved backup jobs from specifically authorized production servers
  - Administrative access only from designated Management Zone systems
  - No direct access from Clinical Workstations
  - No direct access from Guest/IoT
  - No general Medical Device access
```

### Security Intent

Backup infrastructure should not share the same trust level as normal production systems. Separating it reduces the chance that a ransomware actor can encrypt production systems and then immediately destroy the recovery path.

---

# Proposed Architecture

```text
                               INTERNET
                                   |
                            [Perimeter Firewall]
                                   |
          +------------------------+------------------------+
          |                        |                        |
          |                        |                        |
   VLAN 50 Guest/IoT       Approved Remote/VPN       Internet-facing
     10.10.5.0/24              Access Path             services
          |                        |
          |                   Policy Enforcement
          |                        |
          +------------------------+
                                   |
                         [Internal Segmentation
                              Firewall / ACLs]
                                   |
       +-------------+-------------+-------------+-------------+-------------+
       |             |             |             |             |             |
       v             v             v             v             v             v
   VLAN 10       VLAN 20       VLAN 30       VLAN 40       VLAN 60      Default Deny
   Clinical       Servers       Medical      Management      Backup      Between Zones
 10.10.1/24     10.10.2/24    10.10.3/24    10.10.4/24   10.10.6/24

 Workstations     EHR           Pumps          Wazuh         Veeam
 Physicians       AD            Monitors       Admin PCs     NAS
 Nurses           Billing       PACS           Sec Tools     Backup Server
                                 MRI
```

The firewall or Layer-3 security gateway becomes the enforcement point between VLANs. VLAN separation without ACL/firewall enforcement would not be sufficient.

---

# Part 2 — Critical Firewall Rules

## Rule 1 — Clinical Workstations to EHR Application

```text
Clinical Workstation Zone → Server Zone : TCP/443 : ALLOW
```

**Purpose:** Allows clinicians to reach the EHR web/application interface over HTTPS.

**What it prevents:** Users receive application access without receiving unrestricted access to the whole Server Zone.

---

## Rule 2 — EHR Application Server to EHR Database

```text
ehr-srv-01 → ehr-db-01 : TCP/5432 : ALLOW
```

**Purpose:** Allows the EHR application tier to communicate with PostgreSQL.

**What it prevents:** PostgreSQL is no longer exposed directly to every workstation on the internal network. The EHR application server becomes one of the explicitly approved database clients.

---

## Rule 3 — Clinical Workstations to Active Directory

```text
Clinical Workstation Zone → Approved AD/DNS Servers : TCP/UDP 53, 88; TCP 389/636 : ALLOW
```

**Purpose:** Allows DNS resolution, Kerberos authentication and approved directory communication required for normal domain operation.

**What it prevents:** Authentication remains functional without opening unrestricted server-to-workstation connectivity.

> Exact Microsoft domain-service requirements should be validated before production deployment. Only required AD services should be permitted.

---

## Rule 4 — Management Zone to Server Administration

```text
Management Zone → Server Zone : TCP/22,443,3389,5986 : ALLOW
```

**Purpose:** Permits approved SSH, HTTPS management, RDP and secure WinRM administration from dedicated IT management systems.

**What it prevents:** Ordinary clinical endpoints cannot directly administer servers.

---

## Rule 5 — MRI / Imaging Systems to PACS

```text
Approved MRI/Imaging Hosts → PACS : TCP/104 : ALLOW
```

**Purpose:** Allows approved DICOM imaging transfer between designated imaging systems.

**What it prevents:** The entire Medical Device zone does not gain unrestricted access simply because imaging systems require PACS connectivity.

> The actual DICOM port must be confirmed against the MedDefense PACS configuration before implementation.

---

## Rule 6 — Medical Devices to Approved Clinical Integration Services

```text
Medical Device Zone → Approved EHR/Integration Gateway : Approved clinical interface TCP ports only : ALLOW
```

**Purpose:** Allows required monitor/pump clinical data flows without giving medical devices broad access to the entire Server Zone.

**What it prevents:** A compromised pump or monitor cannot freely scan or connect to Active Directory, billing, backup or unrelated servers.

> The final port list must be taken from the vendor and MedDefense interface documentation rather than assumed.

---

## Rule 7 — Managed Systems to Wazuh

```text
Clinical + Server + Medical + Backup Zones → Wazuh SIEM : TCP/1514,1515 and approved secure syslog : ALLOW
```

**Purpose:** Allows supported hosts and security gateways to send telemetry to centralized monitoring.

**What it prevents:** Segmentation does not create blind spots by accidentally blocking required security logging.

---

## Rule 8 — Guest / Non-Clinical IoT to Internet

```text
Guest/IoT Zone → Internet : TCP/80,443; Approved DNS : ALLOW
```

**Purpose:** Provides normal visitor Internet access and required cloud access for approved non-clinical IoT.

**What it prevents:** Guest access remains useful without creating a reason to permit internal network access.

---

## Rule 9 — Guest / Non-Clinical IoT to Internal Networks

```text
Guest/IoT Zone → Clinical + Server + Medical + Management + Backup Zones : ANY : DENY
```

**Purpose:** Completely separates the low-trust guest/IoT environment from MedDefense production systems.

**What it prevents:** A compromised visitor device, smart device or rogue client cannot scan, authenticate to or attack internal clinical systems.

---

## Rule 10 — Default Inter-Zone Deny

```text
ANY Zone → ANY Other Internal Zone : ANY traffic not explicitly permitted above : DENY
```

**Purpose:** Enforces least privilege between network zones.

**What it prevents:** New services, forgotten systems or compromised hosts do not automatically receive lateral access simply because they have an internal IP address.

This is the most important rule in the architecture. The allowed rules are exceptions to this default-deny policy.

---

# Firewall Rule Summary

| # | Source | Destination | Port / Protocol | Action |
|---:|---|---|---|---|
| **1** | Clinical Workstations | EHR application | TCP/443 | **ALLOW** |
| **2** | `ehr-srv-01` | `ehr-db-01` | TCP/5432 | **ALLOW** |
| **3** | Clinical Workstations | AD/DNS | TCP/UDP 53, 88; TCP 389/636 | **ALLOW** |
| **4** | Management | Servers | TCP/22,443,3389,5986 | **ALLOW** |
| **5** | Approved MRI/imaging hosts | PACS | TCP/104 | **ALLOW** |
| **6** | Medical Devices | Approved EHR/integration gateway | Approved clinical TCP ports | **ALLOW** |
| **7** | Managed zones | Wazuh SIEM | TCP/1514,1515 + approved secure syslog | **ALLOW** |
| **8** | Guest/IoT | Internet | TCP/80,443 + approved DNS | **ALLOW** |
| **9** | Guest/IoT | All internal production zones | ANY | **DENY** |
| **10** | Any zone | Any other internal zone | Any unapproved flow | **DENY** |

---

# Part 3 — Kill Chain Impact

## Kill Chain #1 — Phishing to EHR Double Extortion

The Project 1x01 ransomware chain is:

```text
Spear phishing
      ↓
Compromised endpoint or credentials
      ↓
Foothold / persistence
      ↓
Active Directory discovery and credential theft
      ↓
Lateral movement toward EHR
      ↓
EHR data theft
      ↓
Ransomware / double extortion
```

Segmentation does **not** claim to prevent the phishing email itself. Its value begins after the attacker has already obtained a foothold.

---

## Step 1 — Initial Access

### Original attack

A ransomware affiliate sends a convincing phishing message to a MedDefense employee and captures credentials or compromises the user's workstation.

### Effect of segmentation

```text
Result: NOT BROKEN YET
```

Network segmentation does not stop a user from clicking a malicious link or entering credentials into a phishing site.

Other controls such as MFA, email security and EDR are still needed at this stage.

---

## Step 2 — Establish Foothold

### Original attack

The attacker keeps access through the compromised endpoint or stolen account and begins internal reconnaissance.

### Effect of segmentation

```text
Result: PARTIALLY DISRUPTED
```

The compromised endpoint is now located inside the **Clinical Workstation Zone** rather than on a broadly trusted internal network.

The attacker can see only the services explicitly allowed from that zone. Direct scanning and connection attempts toward:

- the Management Zone;
- the Backup Zone;
- most medical-device interfaces; and
- unnecessary server services

are blocked.

The attacker still has a foothold, but its usefulness is reduced.

---

## Step 3 — Active Directory Discovery / Credential Access

### Original attack

The attacker enumerates Active Directory, searches for higher privileges and attempts to move toward domain controllers.

### Effect of segmentation

```text
Result: DISRUPTED / CONSTRAINED
```

Clinical workstations are allowed only the Active Directory services required for normal authentication.

They do **not** receive general administrative access to the Server Zone.

Administrative protocols such as RDP, SSH and secure WinRM are permitted from the **Management Zone**, not from general clinical workstations.

This makes it more difficult to turn one phished endpoint into unrestricted access to domain controllers and other servers.

---

## Step 4 — Lateral Movement Toward the EHR

### Original attack

The attacker moves from the compromised user environment toward `ehr-srv-01` and `ehr-db-01`.

The original chain specifically benefits from PostgreSQL TCP/5432 being reachable from the wider internal network.

### Effect of segmentation

```text
Result: PRIMARY BREAK POINT
```

The new design permits:

```text
Clinical Workstation → EHR application : TCP/443 : ALLOW
```

but does **not** permit:

```text
Clinical Workstation → ehr-db-01 : TCP/5432
```

Instead, PostgreSQL is limited to:

```text
ehr-srv-01 → ehr-db-01 : TCP/5432 : ALLOW
```

This directly removes one of the attack paths identified in the ransomware kill chain.

The attacker would now have to compromise an explicitly authorized intermediary such as the EHR application server rather than connecting directly to the database from an ordinary workstation foothold.

---

## Step 5 — EHR Data Theft

### Original attack

After reaching the EHR environment, the attacker exfiltrates Restricted patient data.

### Effect of segmentation

```text
Result: SUBSTANTIALLY HARDER
```

Segmentation does not make data theft impossible if the EHR application itself is fully compromised.

However, the attacker can no longer treat the whole Server Zone as equally reachable from the original workstation foothold.

The EHR application tier and database tier have separate permitted flows, reducing the number of usable paths.

---

## Step 6 — Ransomware Deployment and Backup Neutralisation

### Original attack

The attacker encrypts EHR and other reachable systems. If backup infrastructure is accessible, the attacker may also attack the recovery environment before encryption.

### Effect of segmentation

```text
Result: DISRUPTED
```

The dedicated **Backup / Recovery Zone** is not directly reachable from the Clinical Workstation Zone.

Administrative access to backup infrastructure comes only from approved systems in the Management Zone, while production systems receive only the specific backup communication they require.

This means a compromised workstation or ordinary production host cannot simply browse to NAS management interfaces or directly attack backup administration services.

Segmentation therefore reduces both:

- ransomware blast radius; and
- the chance that production compromise automatically becomes recovery compromise.

---

# Ransomware Kill Chain — Before vs. After

```text
BEFORE

Phished workstation
      |
      +----> AD
      |
      +----> EHR server
      |
      +----> EHR database
      |
      +----> Medical devices
      |
      +----> Backup/NAS
      |
      +----> Other internal systems

Broad internal reachability allows one foothold to spread.


AFTER

Phished workstation
      |
      +----> EHR HTTPS only
      |
      +----> Required AD authentication only
      |
      X----> Direct PostgreSQL access
      |
      X----> Backup management
      |
      X----> Medical-device management
      |
      X----> Management Zone
      |
      X----> Unapproved server services

The initial compromise may still occur, but lateral movement is constrained.
```

---

# Impact on the Top Five Kill Chains

The five Project 1x01 kill chains are:

1. **Phishing → Active Directory → EHR double extortion**
2. **VPN exploitation → internal network → backup neutralisation → ransomware**
3. **Compromised MedTech vendor access → EHR compromise**
4. **Retained insider access → Active Directory compromise**
5. **Malicious insider → Alaris pump environment**

## Estimated Segmentation Effect

| Kill Chain | Segmentation Break Point | Disrupted? |
|---|---|---|
| **1 — Phishing → AD → EHR** | Limits workstation-to-server lateral movement and blocks direct PostgreSQL access | **Yes** |
| **2 — VPN → Backup → Ransomware** | VPN access can be terminated into a restricted zone; backup management isolated in VLAN 60 | **Yes** |
| **3 — Vendor → EHR** | Vendor access can be limited to specifically authorized systems instead of broad internal reachability | **Yes** |
| **4 — Retained Insider → AD** | Standard remote/user access does not permit general administrative protocols to AD; privileged management is confined to VLAN 40 | **Yes** |
| **5 — Insider → Alaris** | Medical devices are isolated in VLAN 30 and management paths are restricted to approved management systems | **Yes** |

```text
Kill chains disrupted at one or more stages: 5
Total top kill chains:                        5

5 / 5 × 100 = 100%
```

## Estimated Result

**Approximately 100% of the top five modeled kill chains would be disrupted at least once by this segmentation architecture.**

This does **not** mean segmentation alone prevents 100% of attacks.

It means each of the five modeled chains currently depends on broad internal reachability at some point, and the proposed design removes or constrains that reachability.

Some initial-access steps would still succeed:

- phishing can still compromise a workstation;
- a vulnerable VPN could still provide an initial foothold;
- a trusted vendor account could still be compromised;
- a retained insider account could still authenticate;
- an insider could still attempt unauthorized activity.

The difference is that the attacker would no longer receive broad access to the rest of MedDefense simply because one endpoint or identity had been compromised.

---

# Implementation Priorities

The segmentation programme should be implemented in stages to avoid disrupting clinical care.

## Phase 1 — Discovery and Validation

- Confirm current asset inventory and switch-port mapping.
- Validate which systems actually need to communicate.
- Document EHR, AD, PACS, MRI, Alaris, monitor and backup dependencies.
- Identify vendor remote-access requirements.
- Capture current traffic before enforcing restrictive ACLs.

## Phase 2 — Create VLANs and Routing Boundaries

- Create VLAN 10 — Clinical Workstations.
- Create VLAN 20 — Server Zone.
- Create VLAN 30 — Medical Device Zone.
- Create VLAN 40 — Management Zone.
- Create VLAN 50 — Guest / Non-Clinical IoT.
- Create VLAN 60 — Backup / Recovery Zone.
- Route inter-VLAN traffic through a firewall or equivalent policy-enforcement point.

## Phase 3 — Apply Explicit Allow Rules

Implement the required clinical and administrative flows first.

Use logging on all inter-zone rules so blocked or unexpected dependencies can be identified safely.

## Phase 4 — Enable Default Deny

After required traffic has been validated:

```text
ANY internal zone
    ↓
ANY other internal zone
    ↓
DENY unless explicitly approved
```

## Phase 5 — Monitor and Tune

- Forward segmentation-firewall logs to Wazuh.
- Alert on denied lateral-movement attempts.
- Review rule usage.
- Remove temporary exceptions.
- Test clinical workflows with department owners.
- Revalidate vendor and medical-device requirements after major changes.

---

# Key Design Decisions

### 1. Different subnets are not enough

MedDefense already uses different address ranges for workstations, servers and medical devices. The weakness is that the ranges remain broadly reachable.

The security improvement comes from **enforced firewall policy between the VLANs**, not simply changing IP addresses.

### 2. The Management Zone is deliberately separate

Administrative protocols create high-value attack paths. RDP, SSH and management HTTPS should originate from dedicated IT administration systems rather than ordinary user workstations.

### 3. Medical devices receive compensating controls

Some medical devices cannot be patched or run modern EDR. Network isolation therefore becomes one of the most important compensating controls.

### 4. Backups receive their own trust boundary

Ransomware recovery infrastructure should not be administered from the same general network that may become compromised.

### 5. Default deny is the final enforcement principle

Every permitted inter-zone flow should answer the question:

> **What specific clinical, business or security function requires this connection?**

If there is no documented reason, the traffic should be blocked.

---

# Final Architecture Summary

```text
                    MEDDEFENSE SEGMENTED NETWORK

                         [Internet / VPN]
                               |
                        [Perimeter FW]
                               |
                    [Segmentation Firewall]
                               |
       +----------+----------+----------+----------+----------+----------+
       |          |          |          |          |          |
       v          v          v          v          v          v
    VLAN 10    VLAN 20    VLAN 30    VLAN 40    VLAN 50    VLAN 60
    Clinical    Servers     Medical    Management Guest/IoT   Backup
    10.10.1     10.10.2     10.10.3    10.10.4    10.10.5    10.10.6
       |          |          |          |          |          |
  Nurses/MDs   EHR/AD     Pumps/MRI   Wazuh     Visitors    Veeam/NAS
               Billing      PACS       Admin       IoT       Recovery

             INTER-ZONE POLICY = DEFAULT DENY
                       +
              EXPLICIT ALLOW RULES
```

The result is an architecture in which compromise of one endpoint no longer means compromise of the whole internal network.

Segmentation therefore directly addresses the MedDefense weakness that appears across all five threat-informed kill chains and provides a foundation for the other funded controls: MFA, Wazuh monitoring, EDR, protected backups and medical-device isolation.
