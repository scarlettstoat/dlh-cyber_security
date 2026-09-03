# MedDefense Health Systems — Shadow Systems Assessment

## Scope

This assessment reviews the three newly disclosed Shadow IT systems: Dr. Patel's personal NAS, the Marketing team's Google Drive linked to a personal Gmail account, and the second-floor Raspberry Pi originally configured as a network monitor. Because these systems sit outside normal IT governance, controls from the official Task 10 matrix are **not assumed to apply unless their scope is explicitly documented**.

---

# 1. Personal NAS — Cardiology Research Storage

## Risk Assessment

### Sensitive data that may be contained or accessible

Dr. Patel uses the NAS to store **research data**. The exact contents are not documented, so it would be inappropriate to assume that it contains PHI; however, research datasets may include clinical information, participant information, unpublished research results or other sensitive material. The data should therefore be treated as at least **Confidential pending review**, and as **Restricted** if identifiable patient or clinical-study information is found.

The NAS is also physically connected to a MedDefense wall port. Because Central lacks effective internal segmentation, the device may have network reachability beyond the data stored locally and could become a path toward other internal systems if compromised.

### Official controls that do not cover the system

The following Task 10 controls either do not apply or cannot be assumed to protect the NAS:

- **C-010 to C-012 — Active Directory password controls:** the NAS is personally purchased and there is no evidence that its accounts are joined to or governed by Active Directory.
- **C-014 / C-015 — Sophos malware protection and containment:** coverage is documented for managed Windows 10/11 workstations, not a personal NAS appliance.
- **C-016 — Veeam backup:** the documented backup job covers six named MedDefense virtual machines; the NAS is not in scope.
- **C-024 to C-029 — documented technical logging controls:** these cover the FortiGate and specific Windows, Linux, Apache, EHR and AD systems. No NAS-specific audit logging or central collection is documented.
- **Asset-management and patch-management coverage:** no official owner, firmware status, configuration standard or maintenance process exists for this device.

General perimeter protection may still affect Internet traffic that crosses the FortiGate, but it does not make the unmanaged NAS an approved or adequately controlled internal asset.

### Worst-case scenario

If the NAS is compromised, an attacker could obtain sensitive research or patient-related information stored on it and use the device as a persistent foothold inside the Central network. From that position, the attacker could attempt reconnaissance or lateral movement toward more critical systems, while ransomware or malicious modification could also destroy the only copy of research data if no approved backup exists.

## Recommended Response — **Migrate**

The appropriate strategy is to **migrate the research data to an approved MedDefense storage platform** that has defined ownership, access controls, backup, logging and support. Before migration, IT and Security should identify and classify the data, review who currently has access and scan the NAS for signs of compromise.

After successful migration and validation, the personal NAS should be securely wiped and removed from the MedDefense network. This approach preserves the legitimate research need while eliminating an unnecessary unmanaged storage device.

---

# 2. Marketing Google Drive Linked to a Personal Gmail Account

## Risk Assessment

### Sensitive data that may be contained or accessible

The shared Google Drive contains **media files and press communications**. Final public material may be Public, but drafts, embargoed announcements, internal communications, contact information, campaign plans or unreleased business information may be **Internal or Confidential**.

The larger concern is ownership: the service is linked to an individual's **personal Gmail account**, meaning MedDefense does not have assured administrative control over the account, its sharing settings, access history, retention or continued availability if the owner leaves.

### Official controls that do not cover the system

The following Task 10 controls do not adequately cover this service:

- **C-010 to C-012 — Active Directory authentication controls:** a personal Gmail account is outside MedDefense's AD password and lockout enforcement.
- **C-014 / C-015 — Sophos endpoint protection and containment:** these protect covered endpoints, not the cloud account or its access-control configuration.
- **C-016 — Veeam backup:** the personal Google Drive is outside the documented MedDefense backup scope.
- **C-024 to C-029 — security logging:** the official matrix contains no documented collection or monitoring of audit events from this personal Google account.
- **Formal organizational ownership and access governance:** no control in the matrix establishes MedDefense administrative ownership of this personal cloud service or guarantees removal of access when staff change roles or leave.

Annual security-awareness training (C-023) may reduce unsafe user behavior generally, but it does not provide technical or administrative control over the personal Google account.

### Worst-case scenario

If the personal Gmail account is compromised, inaccessible or retained by an individual after leaving MedDefense, the organization could lose control of its files. An attacker could disclose Confidential drafts, delete or alter media, distribute fraudulent press material, or use trusted communications to support phishing or reputational attacks. MedDefense may also have difficulty proving who accessed or changed the information.

## Recommended Response — **Migrate**

The Google Drive content should be **migrated to an approved organization-controlled collaboration platform**, such as the existing Microsoft 365 environment, with MedDefense-owned identities, role-based access and auditable sharing.

After the migration is verified, sharing from the personal Google account should be revoked and MedDefense copies should be removed from that account where legally and operationally appropriate. The business need—easy collaboration on large media files—remains valid, but it should be met through a service MedDefense can govern.

---

# 3. Second-Floor Raspberry Pi Network Monitor

## Risk Assessment

### Sensitive data that may be contained or accessible

The Raspberry Pi was reportedly configured by a previous intern as some form of network monitor at Marcus's request. Its exact configuration is unknown. If it was collecting network telemetry or packet data, it **may** contain IP addresses, hostnames, network topology information, credentials or sensitive payload information depending on what was captured; this must be verified rather than assumed.

More importantly, the device is connected inside Central's broadly reachable internal environment. Even if it stores no sensitive data itself, it may provide access to systems that handle Restricted and Confidential information.

### Official controls that do not cover the system

The following Task 10 controls do not adequately cover, or cannot be assumed to cover, the Pi:

- **C-010 to C-012 — Active Directory controls:** there is no evidence that authentication on the Pi is integrated with AD.
- **C-014 / C-015 — Sophos malware protection and containment:** these controls cover managed Windows 10/11 endpoints, not this Raspberry Pi.
- **C-004 to C-008 — SSH hardening and logging:** the strong SSH configuration is specifically evidenced for `ehr-srv-01`; it cannot be assumed to apply to the Pi.
- **C-016 — Veeam backup:** the Raspberry Pi is not part of the documented backup job.
- **C-026 — Linux syslog:** although the Pi is likely Linux-based, its logging configuration is unknown, so the documented Linux logging control cannot be assumed to be active or reviewed on this unmanaged host.
- **C-024 to C-029 — centralized detection:** the existing controls do not provide centralized monitoring or alerting for this device.

The Task 7 scan already demonstrates why undocumented Linux hosts require caution: `UNKNOWN-01` and the Westside Linux device were discovered without established ownership or purpose. The Raspberry Pi should **not** be assumed to be either of those systems until hostname, IP address, MAC address and physical location are reconciled.

### Worst-case scenario

If the Raspberry Pi has been compromised, an attacker could use an overlooked, always-connected device as a persistent internal foothold for reconnaissance, traffic observation or lateral movement. Because nobody has been maintaining or reviewing it, malicious access could persist for an extended period without being noticed. If the Pi contains packet captures or monitoring credentials, compromise could additionally expose sensitive network information.

## Recommended Response — **Legitimize and Secure**

The monitoring function may have legitimate security value, especially given MedDefense's limited centralized visibility, so the preferred strategy is to **legitimize and secure the device rather than automatically discard the function**.

IT and Security should first identify and isolate the Pi while its integrity is assessed. If the monitoring requirement is still valid, MedDefense should reimage it from a trusted source, assign an official owner, record it in the asset inventory, fully patch it, restrict management access, use strong authenticated administration, place it on an appropriate management/monitoring network, define exactly what traffic it may observe, and forward relevant logs to an approved monitoring process. If the review shows that the device is no longer required or cannot be trusted, it should instead be decommissioned rather than returned to service.

---

# 4. Asset Registry Update

The following entries should be added to the Task 7 Asset Registry. These IDs continue the existing registry after A-053.

| Asset ID | Name | Type | Location | Owner (Dept) | OS / Platform | Critical Services / Purpose | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| **A-054** | Dr. Patel personal NAS | Data Store | Dr. Patel's office, Cardiology, Central Hospital | Dr. Patel / Cardiology — personally acquired, not IT-managed | NAS platform/firmware unknown | Research-data storage | Connected to office wall port; IP/segment not yet identified | **Shadow IT** | Personally purchased device storing research data because the approved shared drive was considered too slow. Data contents, access permissions, encryption, backup, patch status and network exposure require assessment. Migrate data to approved storage and remove the NAS from the network. |
| **A-055** | Marketing shared Google Drive | Application / Cloud Service | Cloud / external service | Marketing use; account ownership tied to an individual's personal Gmail | Google Drive / personal Google account | Media-file and press-communications collaboration | Internet / cloud | **Shadow IT** | Not administered through MedDefense identity or cloud governance. Exact sharing permissions, retention and audit history are unknown. Migrate to an approved organization-controlled collaboration platform. |
| **A-056** | Second-floor Raspberry Pi network monitor | Server / Monitoring Appliance | Second floor, Central Hospital; exact port/location to confirm | Previous intern / original request reportedly from Marcus Webb; current owner unassigned | Raspberry Pi / Linux version unknown | Reported network-monitoring function | Internal network; IP/segment not yet reconciled | **Shadow IT** | Device has reportedly been unattended since the previous intern and Marcus left. Identify, isolate and assess before reuse. Possible correspondence with an existing unidentified scan host must be verified technically; do not merge with A-012 `UNKNOWN-01` without evidence. If retained, reimage and bring under formal IT/security governance. |

---

# 5. Shadow IT Policy Recommendation

MedDefense should adopt a **mandatory technology approval and registration policy** requiring IT/Security approval **before any device, software-as-a-service account or storage service is connected to the MedDefense network or used to store/process MedDefense data**. The policy should prohibit personal cloud accounts and personally acquired network devices for business data unless a documented exception is approved, assign an accountable business and technical owner to every approved system, and require registration in the asset inventory before use. This single change addresses the common cause behind all three cases: staff solved legitimate business problems outside the official process because no effective governance checkpoint prevented an unmanaged device or service from becoming part of the MedDefense environment.
