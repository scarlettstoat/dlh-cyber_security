# Security Control Inventory

## C-001 — Inbound Web Firewall Restriction

**Control ID:** C-001  
**Control Name:** Inbound Web Firewall Restriction  
**Description:** The FortiGate permits inbound traffic from `wan1` to `web-srv-01` in the DMZ only for HTTP and HTTPS under the `Allow-Web-Inbound` policy.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** `web-srv-01` and the DMZ  
**Source:** Artifact 1 — Firewall Configuration Extract (FortiGate 100F)

---

## C-002 — Default Deny Firewall Rule

**Control ID:** C-002  
**Control Name:** Default Deny Firewall Rule  
**Description:** The FortiGate includes an enabled `Deny-All` rule that denies traffic not permitted by an earlier firewall policy.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** MedDefense network zones and systems behind the FortiGate  
**Source:** Artifact 1 — Firewall Configuration Extract (FortiGate 100F)

---

## C-003 — Firewall Traffic Logging

**Control ID:** C-003  
**Control Name:** Firewall Traffic Logging  
**Description:** The FortiGate firewall policies are configured to log traffic, including all traffic for the inbound web and deny-all rules and UTM logging for the VPN and outbound rules.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Network traffic passing through the FortiGate  
**Source:** Artifact 1 — Firewall Configuration Extract (FortiGate 100F)

---

## C-004 — SSH Root Login Disabled

**Control ID:** C-004  
**Control Name:** SSH Root Login Disabled  
**Description:** Direct SSH login as the root account is disabled on `ehr-srv-01` through `PermitRootLogin no`.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** `ehr-srv-01`  
**Source:** Artifact 2 — SSH Configuration (`ehr-srv-01`)

---

## C-005 — SSH Key-Only Authentication

**Control ID:** C-005  
**Control Name:** SSH Key-Only Authentication  
**Description:** `ehr-srv-01` permits public-key authentication and disables password authentication, requiring SSH users to authenticate with keys rather than passwords.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** `ehr-srv-01`  
**Source:** Artifact 2 — SSH Configuration (`ehr-srv-01`)

---

## C-006 — SSH Authentication Attempt Limit

**Control ID:** C-006  
**Control Name:** SSH Authentication Attempt Limit  
**Description:** SSH authentication on `ehr-srv-01` is limited to three attempts per connection through `MaxAuthTries 3`.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** `ehr-srv-01`  
**Source:** Artifact 2 — SSH Configuration (`ehr-srv-01`)

---

## C-007 — SSH Forwarding Restrictions

**Control ID:** C-007  
**Control Name:** SSH Forwarding Restrictions  
**Description:** X11 forwarding and TCP forwarding are disabled on `ehr-srv-01`, limiting the ability to use an SSH session to create additional forwarding paths.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** `ehr-srv-01` and network resources reachable from it  
**Source:** Artifact 2 — SSH Configuration (`ehr-srv-01`)

---

## C-008 — SSH Authentication Logging

**Control ID:** C-008  
**Control Name:** SSH Authentication Logging  
**Description:** `ehr-srv-01` sends SSH authentication activity to the `AUTH` syslog facility with `VERBOSE` logging enabled.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** `ehr-srv-01`  
**Source:** Artifact 2 — SSH Configuration (`ehr-srv-01`)

---

## C-009 — Password Requirements Policy

**Control ID:** C-009  
**Control Name:** Password Requirements Policy  
**Description:** MedDefense has an approved password policy requiring a minimum length of eight characters, character complexity, 90-day rotation and a history of the previous five passwords for employees, contractors and vendors.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** MedDefense information systems and user accounts within the policy scope  
**Source:** Artifact 3 — Password Policy

---

## C-010 — Active Directory Password Policy Enforcement

**Control ID:** C-010  
**Control Name:** Active Directory Password Policy Enforcement  
**Description:** Password requirements are enforced for Windows systems through Active Directory Group Policy.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Windows systems and Active Directory user accounts  
**Source:** Artifact 3 — Password Policy

---

## C-011 — Account Lockout

**Control ID:** C-011  
**Control Name:** Account Lockout  
**Description:** User accounts lock for 30 minutes after five failed authentication attempts.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** User accounts subject to the password requirements  
**Source:** Artifact 3 — Password Policy

---

## C-012 — Password History Enforcement

**Control ID:** C-012  
**Control Name:** Password History Enforcement  
**Description:** The system retains the previous five passwords to prevent immediate reuse of recently used passwords.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** User accounts subject to the password requirements  
**Source:** Artifact 3 — Password Policy

---

## C-013 — Shared Account Password Change on Departure

**Control ID:** C-013  
**Control Name:** Shared Account Password Change on Departure  
**Description:** The password policy requires shared-account passwords to be changed when a person with access to the account leaves the organization.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** MedDefense systems using shared accounts  
**Source:** Artifact 3 — Password Policy

---

## C-014 — Sophos Endpoint Malware Protection

**Control ID:** C-014  
**Control Name:** Sophos Endpoint Malware Protection  
**Description:** Sophos Endpoint Protection is deployed to 372 Windows 10/11 workstations and uses malware signatures to identify and block malicious or unwanted software.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** 372 managed Windows 10/11 workstations  
**Source:** Artifact 4 — Sophos Antivirus Status Report

---

## C-015 — Sophos Automated Threat Containment

**Control ID:** C-015  
**Control Name:** Sophos Automated Threat Containment  
**Description:** Sophos automatically blocks or quarantines detected threats, as shown by recent blocked and quarantined malware, phishing and potentially unwanted application detections.  
**Category:** Technical  
**Function:** Corrective  
**Asset(s) Protected:** Windows workstations covered by Sophos Endpoint Protection  
**Source:** Artifact 4 — Sophos Antivirus Status Report

---

## C-016 — Nightly Virtual Machine Backups

**Control ID:** C-016  
**Control Name:** Nightly Virtual Machine Backups  
**Description:** Veeam Backup & Replication performs a full backup every day at 02:00 of the in-scope virtual machines on the VMware cluster at Central and stores the backups on `NAS-01` with 14-day retention.  
**Category:** Technical  
**Function:** Corrective  
**Asset(s) Protected:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01` and `web-srv-01`  
**Source:** Artifact 5 — Backup Configuration

---

## C-017 — Backup Restore Testing

**Control ID:** C-017  
**Control Name:** Backup Restore Testing  
**Description:** MedDefense has performed a partial restoration test of `file-srv-01` to verify that backed-up data could be restored; the most recent documented test was eight months ago.  
**Category:** Administrative  
**Function:** Detective  
**Asset(s) Protected:** Backup and recovery capability for systems covered by Veeam  
**Source:** Artifact 5 — Backup Configuration

---

## C-018 — Main Entrance Security Guard

**Control ID:** C-018  
**Control Name:** Main Entrance Security Guard  
**Description:** A uniformed security guard is positioned at the MedDefense Central main entrance from 07:00 to 19:00, Monday through Friday.  
**Category:** Physical  
**Function:** Deterrent  
**Asset(s) Protected:** MedDefense Central main entrance and facility occupants  
**Source:** Artifact 6 — Physical Security Contract

---

## C-019 — Visitor Registration and Badge Verification

**Control ID:** C-019  
**Control Name:** Visitor Registration and Badge Verification  
**Description:** Visitors entering MedDefense Central through the main entrance are registered at the security desk and their badges are verified by the security guard.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** MedDefense Central and areas accessed through the main entrance  
**Source:** Artifact 6 — Physical Security Contract

---

## C-020 — Security Guard Incident Reporting

**Control ID:** C-020  
**Control Name:** Security Guard Incident Reporting  
**Description:** Incident reporting is an assigned duty of the contracted main-entrance security guard.  
**Category:** Administrative  
**Function:** Detective  
**Asset(s) Protected:** MedDefense Central and incidents observed at the main entrance  
**Source:** Artifact 6 — Physical Security Contract

---

## C-021 — Central CCTV Monitoring and Recording

**Control ID:** C-021  
**Control Name:** Central CCTV Monitoring and Recording  
**Description:** MedDefense Central has four analog cameras covering the main entrance, emergency room entrance and parking garage entrance, with footage stored on a standalone DVR for 30 days.  
**Category:** Physical  
**Function:** Detective  
**Asset(s) Protected:** Main entrance, ER entrance and parking garage entrance at MedDefense Central  
**Source:** Artifact 6 — Physical Security Contract

---

## C-022 — Westside Entrance Camera

**Control ID:** C-022  
**Control Name:** Westside Entrance Camera  
**Description:** Westside Clinic has one camera covering its front entrance, with recordings stored locally on an SD card for approximately 48 hours before overwrite.  
**Category:** Physical  
**Function:** Detective  
**Asset(s) Protected:** Westside Clinic front entrance  
**Source:** Artifact 6 — Physical Security Contract

---

## C-023 — Annual Security Awareness Training

**Control ID:** C-023  
**Control Name:** Annual Security Awareness Training  
**Description:** MedDefense requires all staff to complete the annual 45-minute `CyberSafe Basics` training covering password hygiene, phishing recognition, physical security awareness and reporting suspicious activity.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** MedDefense personnel, systems and information handled by staff  
**Source:** Artifact 7 — Training Records

---

## C-024 — FortiGate Local Log Retention

**Control ID:** C-024  
**Control Name:** FortiGate Local Log Retention  
**Description:** The FortiGate retains its logs locally for 30 days, allowing recent firewall activity to be reviewed after an event.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** FortiGate and network traffic handled by the firewall  
**Source:** Artifact 8 — Log Management

---

## C-025 — Windows Server Event Logging

**Control ID:** C-025  
**Control Name:** Windows Server Event Logging  
**Description:** Windows servers record system and security-related events in Windows Event Viewer for manual review when required.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Windows servers  
**Source:** Artifact 8 — Log Management

---

## C-026 — Linux Server Syslog

**Control ID:** C-026  
**Control Name:** Linux Server Syslog  
**Description:** Linux servers generate standard syslog records under `/var/log`, providing local records of system activity.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Linux servers  
**Source:** Artifact 8 — Log Management

---

## C-027 — Apache Log Retention

**Control ID:** C-027  
**Control Name:** Apache Log Retention  
**Description:** Apache logs on `web-srv-01` and `billing-srv-01` are rotated weekly using `logrotate` and retained for four weeks.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** `web-srv-01` and `billing-srv-01`  
**Source:** Artifact 8 — Log Management

---

## C-028 — EHR Application Audit Logging

**Control ID:** C-028  
**Control Name:** EHR Application Audit Logging  
**Description:** The EHR application maintains an audit log managed by the vendor, and MedDefense can request exports of the records.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** EHR application activity and associated patient-record access  
**Source:** Artifact 8 — Log Management

---

## C-029 — Active Directory Critical Event Logging

**Control ID:** C-029  
**Control Name:** Active Directory Critical Event Logging  
**Description:** Active Directory records critical events that can be reviewed manually when investigating system problems or security-relevant activity.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Active Directory and domain activity  
**Source:** Artifact 8 — Log Management

---

# Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | C-001, C-002, C-004, C-005, C-006, C-007, C-010, C-011, C-012, C-014 | C-003, C-008, C-024, C-025, C-026, C-027, C-028, C-029 | C-015, C-016 |  |  |
| **Administrative** | C-009, C-013, C-019, C-023 | C-017, C-020 |  |  |  |
| **Physical** |  | C-021, C-022 |  |  | C-018 |
