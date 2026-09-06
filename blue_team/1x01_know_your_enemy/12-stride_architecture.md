# MedDefense Health Systems — STRIDE Across the Architecture

## Purpose

This assessment applies a rapid STRIDE threat-model pass to three additional Critical MedDefense systems: **PACS / Medical Imaging, Active Directory and Network Infrastructure**. Unlike the deeper EHR analysis in Task 11, this task identifies the **single most important threat in each STRIDE category** for each system.

Severity uses the Project 1x00 scale:

- **C — Critical:** compromise can directly threaten patient safety, cause regulatory violation or halt clinical operations
- **H — High:** compromise can cause significant operational disruption, financial loss or sensitive-data exposure
- **M — Medium:** compromise causes moderate disruption that can be recovered through standard procedures
- **L — Low:** limited operational or security impact

---

# 1. PACS / Medical Imaging

**System:** **PACS / Medical Imaging**

**Architecture Notes:**  
The imaging environment centres on `pacs-srv-01` (**A-003**) and the Radiology workstation estate. The network scan identified SMB and DICOM-related services on **TCP 4242 and 11112** on the PACS server. Radiology uses the shared `raduser/radiology1` account, which weakens individual accountability. The imaging environment also depends on `WS-RAD-01` (**A-022**), the Windows XP SP3 MRI control workstation, and other Radiology workstations such as `WS-RAD-02`. PACS and the MRI environment remain reachable within Central's broadly connected internal network because the workstation, server and medical-device ranges are not enforced security zones (**GAP-001**). The task evidence also identifies unencrypted imaging-data exposure as a concern.

| STRIDE | Threat | Impact | Severity |
|---|---|---|---|
| **S — Spoofing** | An attacker or insider uses the shared `raduser` PACS account and appears to be an authorised Radiology user because multiple technicians authenticate with the same identity. | Unauthorized image access or changes may appear legitimate, and MedDefense cannot reliably attribute activity to one individual. | **H** |
| **T — Tampering** | A compromised internal workstation reaches PACS/DICOM services and alters, substitutes or mismatches diagnostic images or associated metadata. | Clinicians could make diagnosis or treatment decisions using incorrect imaging information, creating direct patient-safety risk. | **C** |
| **R — Repudiation** | A Radiology user denies viewing, exporting or modifying an image because activity is recorded against the shared `raduser` identity rather than a unique named account. | Incident investigation, disciplinary action and privacy-breach reconstruction become unreliable because individual accountability is lost. | **H** |
| **I — Information Disclosure** | A compromised internal host accesses broadly reachable PACS/DICOM services or intercepts inadequately protected imaging traffic and obtains identifiable diagnostic images. | Sensitive patient imaging data could be exposed, creating privacy, regulatory and reputational consequences. | **C** |
| **D — Denial of Service** | An attacker exploits or disrupts the unsupported Windows XP MRI control environment, PACS server or network path between imaging workstations and PACS. | Imaging may become unavailable or significantly delayed, affecting diagnosis, treatment decisions and Radiology workflow. | **C** |
| **E — Elevation of Privilege** | An attacker compromises the Windows XP MRI workstation or another Radiology endpoint and uses Central's flat network to move from a low-trust clinical endpoint toward PACS or other internal systems. | A device-level compromise can expand into broader access to Critical imaging data and potentially other MedDefense systems. | **C** |

**Top Threat:** **Tampering — Critical.** PACS Integrity is the most dangerous threat because diagnostic images are used directly for clinical decisions. An attacker who changes or substitutes imaging data may cause harm while the system remains available and appears trustworthy. The risk is amplified by **GAP-001** (flat internal reachability), **GAP-006** (unsupported MRI environment), **GAP-007** (shared/weak identity governance) and **GAP-011** (fragmented monitoring).

---

# 2. Active Directory

**System:** **Active Directory — `ad-dc-01` and `ad-dc-02`**

**Architecture Notes:**  
`ad-dc-01` (**A-005**) and `ad-dc-02` (**A-006**) provide central authentication and directory services across MedDefense. The network scan confirms the expected domain services, including **DNS, Kerberos, LDAP, SMB and LDAPS**. Project 1x00 documents password-policy enforcement, account lockout, AD critical-event logging and a secondary Domain Controller, but MFA and formal privileged-access management are not broadly implemented. AD logs are reviewed manually rather than through centralized continuous monitoring, and both Domain Controllers remain dependent on Central's broadly reachable internal environment.

| STRIDE | Threat | Impact | Severity |
|---|---|---|---|
| **S — Spoofing** | An attacker uses stolen or retained MedDefense credentials to authenticate as a legitimate user or administrator and access AD-connected systems. | Malicious activity can appear to originate from an authorised identity, enabling access to clinical and business systems while complicating attribution. | **C** |
| **T — Tampering** | A compromised Domain Admin account modifies users, privileged groups, Group Policy, authentication settings or service accounts. | The attacker can change who has access to MedDefense systems, weaken controls or distribute malicious configuration across domain-joined hosts. | **C** |
| **R — Repudiation** | A privileged user or attacker operating through a compromised administrator account denies making directory changes because identity and AD events are not continuously correlated with endpoint and VPN activity. | MedDefense may struggle to prove who performed high-impact account or policy changes and reconstruct the attack timeline. | **H** |
| **I — Information Disclosure** | An attacker with internal access enumerates directory users, groups, service accounts, computers and trust relationships or extracts credential material from AD-connected systems. | Directory intelligence and credentials can expose organisational structure and support attacks against EHR, servers, staff and privileged accounts. | **H** |
| **D — Denial of Service** | An attacker disables large numbers of accounts, damages directory services, alters authentication policy or disrupts both Domain Controllers. | Staff may be unable to authenticate to clinical and administrative systems, causing organisation-wide operational disruption. | **C** |
| **E — Elevation of Privilege** | A compromised standard account or endpoint is used to obtain privileged credentials or hashes and escalate to Domain Admin. | A single user compromise becomes domain-wide control, providing access paths toward EHR, backups, servers and other Critical systems. | **C** |

**Top Threat:** **Elevation of Privilege — Critical.** AD is MedDefense's central trust layer, so the most dangerous outcome is turning a limited user foothold into Domain Admin control. That transition changes the incident from one compromised account or endpoint into an organisation-wide compromise. **GAP-007** (MFA/PAM weakness), **GAP-001** (flat network), **GAP-011** (manual/fragmented monitoring) and **GAP-017** (offboarding weakness) make this escalation particularly dangerous.

---

# 3. Network Infrastructure

**System:** **Network Infrastructure — FortiGate, Central switching, Westside router and VPN connectivity**

**Architecture Notes:**  
The MedDefense network depends on the Fortinet FortiGate 100F (**A-016**) at Central, the Central Cisco core switch (**A-017**) and access-switch estate (**A-018**), UniFi wireless infrastructure (**A-019**), the Westside Netgear Nighthawk router (**A-015**) and site-to-site VPN connections between locations. The FortiGate provides the principal Internet-edge firewall control and terminates site VPN connectivity. Westside has a consumer-grade router and no dedicated enterprise firewall. Central's workstation, server and medical-device addressing ranges are **not enforced as security zones**, and the second-floor network closet was found unlocked with switch-management credentials exposed. Site VPNs provide trusted inter-site connectivity; Project 1x00 also found that relevant ACLs had not been fully audited, so the exact restriction of some inter-site paths remains uncertain.

| STRIDE | Threat | Impact | Severity |
|---|---|---|---|
| **S — Spoofing** | An attacker obtains network-device or VPN credentials and authenticates as an authorised administrator or trusted remote user/site. | The attacker may enter MedDefense through a trusted path or make malicious network administration appear legitimate. | **C** |
| **T — Tampering** | An attacker uses exposed switch credentials, compromised network administration or firewall access to change VLANs, routing, ACLs, DNS handling or VPN policy. | Traffic can be redirected, isolation weakened and multiple clinical systems exposed or disconnected simultaneously. | **C** |
| **R — Repudiation** | A network administrator or attacker makes configuration changes that cannot be reliably attributed because device logging is local/fragmented and no comprehensive configuration-change audit process is documented. | MedDefense may be unable to prove who changed a Critical network control or determine exactly when the environment became exposed. | **H** |
| **I — Information Disclosure** | A compromised switch, wireless path or poorly restricted internal segment allows an attacker to observe or redirect traffic between workstations, servers and clinical devices. | Credentials, patient information or internal system details could be exposed and used for further compromise. | **C** |
| **D — Denial of Service** | An attacker disrupts the FortiGate, core switch, Westside router or VPN tunnels, or makes malicious routing/configuration changes that interrupt network connectivity. | EHR, imaging, patient monitoring, authentication and inter-site services may fail at the same time because they share the network fabric. | **C** |
| **E — Elevation of Privilege** | A foothold on a low-value workstation, Westside host or wireless-connected device is used to reach server, AD, backup and medical-device networks because Central lacks effective east-west segmentation. | A small endpoint compromise gains access to asset classes that should require stronger trust, dramatically increasing blast radius. | **C** |

**Top Threat:** **Tampering — Critical.** Network configuration determines the security boundaries on which every other MedDefense control depends. Unauthorized changes to firewall rules, switch configuration, VPN policy or routing can simultaneously remove isolation, redirect traffic and disrupt multiple Critical services. The risk is amplified by **GAP-001** (no internal segmentation), **GAP-005** (unlocked closet and exposed switch credentials), **GAP-014** (Westside consumer router), **GAP-016** (vulnerability/patch-management weakness) and **GAP-011** (fragmented monitoring).

---

# Cross-System STRIDE Summary

| System | Top STRIDE Threat | Why It Dominates |
|---|---|---|
| **PACS / Medical Imaging** | **Tampering** | Incorrect or substituted diagnostic images can directly affect clinical diagnosis while still appearing trustworthy. |
| **Active Directory** | **Elevation of Privilege** | Domain Admin compromise converts a limited foothold into broad control over identities and access across MedDefense. |
| **Network Infrastructure** | **Tampering** | Malicious network configuration can remove security boundaries and disrupt several Critical services at once. |

The three systems expose a common pattern: **Integrity and trust relationships are more dangerous than isolated confidentiality loss alone**. PACS must be trusted to show the correct clinical image, Active Directory must be trusted to identify who is authorised, and the network must be trusted to enforce where systems may communicate. In all three cases, **GAP-001 and GAP-011 act as cross-cutting amplifiers**: broad internal reachability increases what an attacker can touch, while fragmented monitoring increases how long malicious changes can remain undetected.

## Project Cross-References

- Project 1x00 — `7-asset_registry.md`
- Project 1x00 — `8-criticality_assessment.md`
- Project 1x00 — `10-complete_control_matrix.md`
- Project 1x00 — `12-gap_analysis.md`
- Project 1x00 — `13-reality_check.md`
- Project 1x01 — `7-attack_surface_map.md`
- Project 1x01 — `8-technical_vectors.md`
- Project 1x01 — `11-stride_ehr.md`
