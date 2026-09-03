# MedDefense Health Systems — Legacy MRI Compensating Control Strategy

## 1. Risk Analysis

The MRI control workstation represents a **Critical risk to the wider MedDefense network**, not only to Radiology, because it runs Windows XP Embedded, an unsupported platform that has received no security patches since April 2014; any vulnerabilities discovered or left unresolved after support ended can therefore remain exploitable. The risk is amplified by the current network architecture: the workstation is not effectively isolated from the wider hospital environment, so compromise of the MRI workstation could provide an attacker with a foothold from which to attempt lateral movement toward systems such as PACS, Active Directory or other clinical services. Because the workstation must remain network-connected to transmit imaging studies, its exposure cannot be removed simply by disconnecting it. A successful compromise could therefore affect **Confidentiality** of diagnostic information, **Integrity** of systems or imaging workflows, and **Availability** of a service supporting approximately 45 MRI studies per day.

---

## 2. Compensating Control Strategy

The purpose of these controls is not to make Windows XP secure. That is not possible while the underlying operating system remains unsupported. Instead, the strategy reduces the workstation's **exposure, attack surface and blast radius**, while preserving the PACS connectivity required for patient care.

### Control 1 — Isolate the MRI Workstation and Allow Only Required PACS Traffic

**What it does:**  
Move the MRI control workstation into a dedicated MRI VLAN/security zone and place a firewall or equivalent filtering control between that zone and the rest of MedDefense. Configure an explicit allow-list permitting only the source/destination addresses, ports and protocols required for communication between the MRI workstation and `pacs-srv-01`, plus any separately approved management service that is genuinely necessary. All other communication—including direct Internet access and unnecessary connections to user, server and medical-device networks—should be denied by default.

**Classification:** **Technical + Compensating** *(with a preventive effect)*

**How it reduces risk without modifying the OS:**  
The control is enforced by the network rather than by Windows XP. It therefore does not require a patch, operating-system upgrade or change to the certified MRI software. Restricting connectivity greatly reduces the number of systems that can reach the vulnerable workstation and, critically, limits the ability of an attacker who compromises it to move laterally into the rest of MedDefense.

**Limitations / Residual Risk:**  
Windows XP remains vulnerable, and network isolation does not remove vulnerabilities in the workstation itself. A compromised PACS server, an attack using explicitly allowed traffic, a local physical attack or a firewall misconfiguration could still expose the system. The rule set must also be tested carefully with Radiology and clinical engineering because blocking a required PACS flow could interrupt imaging operations.

---

### Control 2 — Monitor the MRI Zone for Abnormal Network Activity

**What it does:**  
Deploy passive network monitoring or intrusion-detection capability at the boundary of the MRI zone. Establish a baseline of legitimate MRI-to-PACS communication and alert on unexpected destinations, new protocols, scanning behaviour, repeated connection attempts, unusual data volumes or attempts by the MRI workstation to communicate outside its approved path.

**Classification:** **Technical + Detective**

**How it reduces risk without modifying the OS:**  
Monitoring can be performed from the network infrastructure, so no agent or software needs to be installed on the certified Windows XP workstation. It gives MedDefense visibility into suspicious behaviour that the unsupported endpoint may not be capable of detecting itself and provides earlier warning if the workstation is compromised.

**Limitations / Residual Risk:**  
This control detects suspicious activity but does not prevent exploitation by itself. Encrypted or unusual proprietary traffic may limit visibility, and poor alert tuning could produce false positives or miss subtle malicious activity. Someone must also be responsible for reviewing and responding to alerts; monitoring without response would provide little practical protection.

---

### Control 3 — Establish a Formal Legacy-System Security Exception and Review Process

**What it does:**  
Create a documented security exception for the MRI workstation identifying its business owner, technical owner, reason it cannot be patched, required network communications, approved users, compensating controls, residual risk and planned replacement date. Require periodic review—at least quarterly for this Critical system—and require Security, Radiology/Clinical Engineering and IT approval before network, vendor-access or configuration changes are made.

**Classification:** **Administrative + Compensating**

**How it reduces risk without modifying the OS:**  
The control manages the risk around the system rather than changing the operating system. It ensures the legacy device does not become a permanently accepted but forgotten exception and gives MedDefense a defined owner, review cycle and escalation path if the risk changes.

**Limitations / Residual Risk:**  
Administrative governance cannot technically stop an exploit. Its effectiveness depends on staff following the process and acting on review findings. The Windows XP vulnerability remains until the MRI environment can ultimately be replaced or moved to a vendor-supported platform.

---

### Control 4 — Restrict Physical and Removable-Media Access to the MRI Workstation

**What it does:**  
Limit physical access to the MRI control workstation to authorized Radiology, Clinical Engineering and IT personnel. Where operationally feasible, use physical USB-port blockers or controlled removable-media procedures so that unapproved USB devices cannot be connected casually to the workstation.

**Classification:** **Physical + Preventive**

**How it reduces risk without modifying the OS:**  
These measures act outside the operating system and therefore do not alter the certified Windows XP configuration. They reduce the risk of malware introduction, unauthorized local access and tampering through removable media or direct console access.

**Limitations / Residual Risk:**  
Physical restrictions do not protect against remote network exploitation and may complicate legitimate vendor servicing if not accompanied by a controlled maintenance process. Authorized personnel or approved removable media could still introduce risk, so this control must complement—not replace—the network controls.

---

## 3. Implementation Priority

If MedDefense can implement only **one control immediately**, the highest priority should be **Control 1: isolate the MRI workstation in a dedicated network zone and restrict communication to the PACS server and explicitly required services**.

This provides the greatest immediate risk reduction because it addresses both sides of the problem: it reduces the number of systems capable of reaching the unpatchable workstation and limits how far an attacker could move if the workstation were compromised. The Windows XP vulnerabilities would still exist, but the vulnerable system would no longer have unrestricted access to the wider MedDefense environment, substantially reducing the potential blast radius while preserving the network connectivity required for approximately 45 daily MRI studies. This also directly addresses MedDefense's broader architectural weakness: Critical and legacy systems are currently too reachable from the rest of the internal network.

---

## Conclusion

MedDefense cannot remove the underlying Windows XP vulnerability without violating operational, certification or budget constraints, so the correct response is **risk reduction through defence in depth** rather than pretending the risk can be eliminated. Network isolation should be implemented first, supported by network monitoring, formal legacy-system governance and controlled physical access. Together, these controls preserve the MRI's clinical function while making compromise harder, easier to detect and less capable of spreading into the wider hospital environment.
