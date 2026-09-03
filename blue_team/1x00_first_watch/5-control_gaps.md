# MedDefense Health Systems — Significant Control Gaps

## Scope

This analysis reviews the control landscape established in Task 4 and focuses on what is **missing or materially incomplete**, rather than simply restating the controls that already exist. The Task 4 matrix is weighted toward Technical Preventive and Technical Detective controls, while several category/function combinations are empty and some existing controls do not adequately cover Critical assets.

---

## G-001 — No Centralized Security Monitoring or Automated Alerting

**Gap ID:** G-001  
**Gap Description:** MedDefense generates firewall, Windows, Linux, Apache, EHR and Active Directory logs, but there is no centralized SIEM, intrusion-detection capability or continuously monitored alerting process that correlates suspicious activity across systems.  
**Category x Function Missing:** Technical Detective  
**Affected Asset(s) or Zone:** `billing-srv-01`, EHR systems, Active Directory, network infrastructure, internet-facing services and the wider Central environment.  
**Risk if Unaddressed:** Unauthorized activity can remain undetected after preventive controls are bypassed, increasing attacker dwell time and allowing Confidentiality and Integrity compromise to continue until an Availability impact or other visible symptom reveals the incident. The recurring compromise of `billing-srv-01` demonstrates the practical consequence of weak detection.  
**Evidence:** Task 4 records several detective controls (C-003, C-008 and C-024 through C-029), but they consist mainly of local logs or manually reviewed records. No centralized SIEM, IDS or automated security-alerting capability is documented.

---

## G-002 — No Effective Internal Network Segmentation

**Gap ID:** G-002  
**Gap Description:** MedDefense has perimeter firewall controls, but no documented internal VLAN or firewall enforcement separates general workstations, servers and network-connected medical devices at Central.  
**Category x Function Missing:** Technical Preventive  
**Affected Asset(s) or Zone:** EHR servers, Active Directory, billing, PACS, workstations, medical IoT and other systems on the Central internal network.  
**Risk if Unaddressed:** A compromise of one reachable endpoint could provide an attacker with a path toward other sensitive or Critical systems. This increases the potential blast radius of an incident across Confidentiality, Integrity and Availability, including exposure of patient information, alteration of clinical systems and disruption of patient-care services.  
**Evidence:** The environment documentation describes Central as a flat `10.10.0.0/16` network with segmentation planned but not implemented. Task 4 contains perimeter firewall controls, but no control providing enforced east-west segmentation between internal asset groups.

---

## G-003 — No Technical Compensating Control for the Legacy MRI Environment

**Gap ID:** G-003  
**Gap Description:** The legacy MRI control environment cannot be treated like a normally supported endpoint, yet Task 4 contains no Technical Compensating control that reduces its exposure when normal patching or replacement is not immediately available.  
**Category x Function Missing:** Technical Compensating  
**Affected Asset(s) or Zone:** Siemens MRI environment and its Windows XP control workstation, with potential exposure to PACS and the wider Central network.  
**Risk if Unaddressed:** A legacy system that cannot receive normal security updates remains exposed to known or future exploitation. Without isolation or tightly restricted communications, compromise could affect the Confidentiality of diagnostic information, the Integrity of imaging workflows or the Availability of a Critical clinical service, and could also provide a route toward other internal systems.  
**Evidence:** Task 4 contains no Compensating controls in the Technical category. Earlier MedDefense documentation identifies the MRI environment as dependent on Windows XP, while no isolation control is documented.

---

## G-004 — No Formal Administrative Corrective Incident-Response Process

**Gap ID:** G-004  
**Gap Description:** MedDefense has no documented incident-response plan defining containment, eradication, recovery, escalation, evidence handling or post-incident review. Existing response has been ad hoc.  
**Category x Function Missing:** Administrative Corrective  
**Affected Asset(s) or Zone:** Organization-wide; particularly Critical systems such as billing, EHR, Active Directory, medical devices and internet-facing services.  
**Risk if Unaddressed:** When an incident occurs, MedDefense may restore service without removing the root cause, allowing repeated compromise. Delayed or inconsistent containment can increase data exposure, unauthorized modification and service disruption across all three CIA pillars.  
**Evidence:** Task 4 contains no Administrative Corrective control. The onboarding material states that MedDefense has no formal incident-response plan and that the January ransomware incident was handled ad hoc.

---

## G-005 — Backup Exists, but Recovery Is Not Adequately Tested or Formalized

**Gap ID:** G-005  
**Gap Description:** MedDefense performs nightly backups for selected systems, but it lacks a current, tested recovery procedure demonstrating that Critical services can be restored reliably within acceptable timeframes.  
**Category x Function Missing:** Administrative Corrective  
**Affected Asset(s) or Zone:** EHR, billing, Active Directory, file services, `web-srv-01` and other systems dependent on the backup environment.  
**Risk if Unaddressed:** Backups may exist but still fail when needed, extending an Availability outage and potentially causing loss of current or reliable data. In a ransomware or infrastructure-failure scenario, MedDefense could discover recovery problems only after production services are already unavailable.  
**Evidence:** C-016 provides Technical Corrective backup capability, but C-017 records only a partial restore test of `file-srv-01` performed eight months earlier. The January ransomware incident also showed that the available billing backup was three weeks old because of a misconfigured backup job.

---

## G-006 — Critical Physical Infrastructure Lacks Adequate Preventive Access Control

**Gap ID:** G-006  
**Gap Description:** Physical security controls exist at facility entrances, but they do not adequately prevent unauthorized access to the server room and network infrastructure. The server room accepts broadly issued employee badges, and the second-floor network closet was found unlocked.  
**Category x Function Missing:** Physical Preventive  
**Affected Asset(s) or Zone:** Central server room, second-floor network closet, servers, backup infrastructure, switching equipment and connected Critical services.  
**Risk if Unaddressed:** An unauthorized person could physically access systems or networking equipment, creating opportunities to steal data, alter configurations, connect unauthorized devices or disrupt infrastructure. This creates Confidentiality, Integrity and Availability risk simultaneously.  
**Evidence:** Task 4 contains no Physical Preventive control in the original control matrix. The physical walk-through found broad server-room badge access and an unlocked network closet with administrative credentials displayed nearby.

---

## G-007 — Physical Detective Controls Do Not Cover Critical Infrastructure Areas

**Gap ID:** G-007  
**Gap Description:** MedDefense has CCTV at selected entrances, but there is no camera covering the Central server-room entrance and no documented monitoring of access to the network closet.  
**Category x Function Missing:** Physical Detective  
**Affected Asset(s) or Zone:** Central server room and internal network closets supporting Critical infrastructure.  
**Risk if Unaddressed:** Unauthorized entry or tampering may occur without timely detection or sufficient evidence for investigation. MedDefense could therefore lose Confidentiality or Integrity through physical access and only discover the event after equipment failure, configuration changes or service disruption affect Availability.  
**Evidence:** C-021 provides Central CCTV coverage, but Task 3 confirms that the server-room entrance is outside camera coverage. The observed network closet also had no documented surveillance or access logging.

---

## G-008 — Endpoint Protection Does Not Demonstrably Cover the Full Endpoint Estate

**Gap ID:** G-008  
**Gap Description:** Sophos malware protection is deployed to 372 managed Windows 10/11 workstations, but MedDefense's documented Windows endpoint population is materially larger. Protection therefore cannot be assumed to cover every workstation and laptop, and the control does not address legacy or medical-device operating environments.  
**Category x Function Missing:** Technical Preventive  
**Affected Asset(s) or Zone:** Windows workstations and laptops across Central, Westside and HQ; unmanaged or unsupported endpoints remain particularly exposed.  
**Risk if Unaddressed:** An unprotected endpoint may become an initial foothold for malware or an attacker. Because Central lacks effective internal segmentation, one compromised endpoint could expose Confidential information, enable unauthorized modification or lateral movement, and contribute to wider service disruption.  
**Evidence:** C-014 documents Sophos on 372 Windows 10/11 workstations. Earlier asset documentation identifies approximately 320 Central workstations, 45 Westside workstations, 120 HQ workstations and around 30 remote-capable HQ laptops, showing that the documented estate exceeds the confirmed Sophos deployment.

---

## Overall Pattern

MedDefense's control posture is **more prevention-oriented than detection-oriented**, but the deeper problem is that its detective controls are largely passive, fragmented and manually reviewed rather than centralized and continuously monitored. This means that if a preventive control fails, MedDefense has limited ability to recognize and contain the compromise quickly, increasing the likelihood that an attacker remains undetected until data, systems or clinical operations are already affected.
