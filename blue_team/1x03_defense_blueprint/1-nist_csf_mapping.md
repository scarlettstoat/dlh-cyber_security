# 1. NIST CSF 2.0 Current Profile — MedDefense Health Systems

## Purpose

This profile assesses MedDefense Health Systems against the six functions of the NIST Cybersecurity Framework (CSF) 2.0: **Govern, Identify, Protect, Detect, Respond, and Recover**.

The assessment uses the following maturity scale:

| Level | Description |
|---|---|
| **Not Implemented** | No meaningful activity exists |
| **Partial** | Some activity exists, but it is informal, inconsistent, or incomplete |
| **Managed** | Activity is documented, repeatable, and covers most of the scope |
| **Optimized** | Activity is continuous, measured, and actively improved |

MedDefense's earlier framework assessment selected **NIST CSF 2.0 as the strategic backbone**, with CIS Controls v8 used to support practical implementation. This Current Profile therefore focuses on where MedDefense stands today and where it should realistically be within six months.

---

## 1. Govern

**Function:** Govern

**Current Level:** Partial

**Evidence:**  
MedDefense has security leadership and has now completed a Security Posture Assessment, Threat Landscape Report, and Vulnerability Assessment. This means the organization has a much clearer picture of its security risks than it did before.

However, Project 1x00 showed that security governance was still largely informal. MedDefense had not formally adopted a cybersecurity framework, several controls did not have clear ownership, and areas such as Shadow IT, vulnerability management, access control, and recovery were not being managed through one consistent governance process.

The fact that the auditors had previously asked which framework MedDefense followed and the answer was effectively “none formally” also shows that governance exists, but is not yet structured or repeatable.

**Key Gaps:**  
The main gap is the absence of a formal governance structure linking security risks, control ownership, policies, priorities, and management oversight.

**Target Level:** Managed

Within six months, MedDefense should formally adopt NIST CSF 2.0, assign clear owners to major risks and controls, document its security governance structure, and establish a regular review process for risks, policies, and security performance.

A target of **Managed** is realistic because MedDefense first needs to make its governance repeatable and documented before it can begin measuring and continuously improving it.

---

## 2. Identify

**Function:** Identify

**Current Level:** Partial

**Evidence:**  
Project 1x00 required the creation and consolidation of MedDefense's asset inventory. This included critical systems such as the EHR environment, Active Directory, servers, workstations, medical devices, and supporting infrastructure.

The important point is that the inventory was built during the project. MedDefense did not already have a complete, reliable, and continuously maintained asset inventory before this work began.

Projects 1x01 and 1x02 improved the Identify function further by documenting relevant threat actors, likely attack paths, exposed services, vulnerabilities, and critical systems. However, these assessments were carried out as individual projects rather than as part of a recurring organizational risk-management process.

Previous work also identified unmanaged or poorly tracked technology, including Shadow IT, a personal NAS, legacy systems, and medical devices requiring additional review.

**Key Gaps:**  
MedDefense still lacks a repeatable process for keeping its asset inventory, risk information, threat information, and vulnerability data continuously up to date.

**Target Level:** Managed

Within six months, MedDefense should maintain a centralized asset inventory with ownership and criticality information and introduce scheduled vulnerability, threat, and risk reviews.

The work from Projects 1x00–1x02 provides the starting point. The next step is to turn that one-time visibility into a normal operational process.

---

## 3. Protect

**Function:** Protect

**Current Level:** Partial

**Evidence:**  
MedDefense has protective controls, but Projects 1x00 and 1x02 showed that they are incomplete and inconsistently applied.

The Security Posture Assessment identified weaknesses in areas including:

- MFA and privileged access
- Network segmentation
- Vulnerability management
- Removable media
- User offboarding
- Shadow IT
- Legacy systems
- Medical-device security

Project 1x02 reinforced this assessment. The vulnerability scan found multiple Critical and High severity vulnerabilities affecting important systems, including the EHR database environment, billing infrastructure, and radiology-related systems.

Examples included weak authentication or access settings, unsupported software, exposed services, and insecure configurations. This shows that safeguards exist, but they do not yet provide consistent protection across the environment.

**Key Gaps:**  
The largest gap is inconsistent protection of critical systems, especially around identity and access control, patching, secure configuration, segmentation, and legacy technology.

**Target Level:** Managed

Within six months, MedDefense should establish repeatable processes for MFA, privileged access, patching, vulnerability remediation, secure configuration, segmentation, removable media, and access to critical systems.

Controls should be prioritized according to the attack paths identified in Project 1x01 and the vulnerabilities confirmed in Project 1x02, rather than being selected simply because they are considered “best practice.”

---

## 4. Detect

**Function:** Detect

**Current Level:** Not Implemented

**Evidence:**  
Detection is currently one of MedDefense's weakest functions.

Marcus's notes described the organization as having effectively **zero monitoring capability**. Project 1x00 also identified weaknesses in monitoring and logging, with no evidence of a mature centralized SIEM or equivalent capability continuously collecting and correlating security events across critical systems.

Project 1x01 showed that realistic attacks against MedDefense could involve stolen credentials, exploitation of vulnerable public-facing services, lateral movement, ransomware, and data theft. Without effective monitoring, these activities may continue for a significant period before anyone notices them.

There may be individual logs or alerts available on separate systems, but this is not the same as a documented and repeatable detection capability.

**Key Gaps:**  
The primary gap is the absence of centralized monitoring, alert correlation, and a repeatable process for investigating suspicious activity.

**Target Level:** Managed

Within six months, MedDefense should centralize logs from its most critical systems, define priority alerts, document investigation and escalation procedures, and establish a repeatable monitoring process.

The immediate goal does not need to be a fully developed 24/7 SOC. A realistic target is dependable monitoring of the systems and attack paths that present the highest risk.

---

## 5. Respond

**Function:** Respond

**Current Level:** Partial

**Evidence:**  
MedDefense has shown that its IT staff can react to incidents. For example, earlier project evidence showed that `billing-srv-01` had previously been rebuilt after a ransomware incident.

However, being able to restore or rebuild a system after an incident does not mean the organization has a complete incident-response capability.

There is no strong evidence that MedDefense currently follows a documented and regularly tested process covering:

- Triage
- Containment
- Investigation
- Escalation
- Internal and external communication
- Evidence handling
- Lessons learned

The weakness in Detect also affects Respond. MedDefense cannot respond quickly to an incident if it does not identify the incident quickly in the first place.

**Key Gaps:**  
The main gap is the lack of a documented, tested, and repeatable incident-response process with clear responsibilities and escalation paths.

**Target Level:** Managed

Within six months, MedDefense should establish a formal Incident Response Plan, assign responsibilities, create playbooks for high-priority scenarios such as ransomware and compromised accounts, and conduct at least one tabletop exercise.

This would move incident response from an improvised activity to a repeatable process that staff can follow under pressure.

---

## 6. Recover

**Function:** Recover

**Current Level:** Partial

**Evidence:**  
MedDefense has previously recovered systems following security incidents, so recovery capability is not completely absent.

However, Project 1x00 identified weaknesses in backup and recovery arrangements. Previous ransomware-related recovery also showed that rebuilding systems has happened in practice, but there is not enough evidence that recovery is consistently planned, tested, and measured across all critical services.

There is also no strong evidence that MedDefense has clearly defined recovery objectives for its most important systems or that backup restoration is regularly tested against ransomware-style scenarios.

This is particularly important for healthcare systems such as the EHR, where extended downtime can directly affect business operations and patient care.

**Key Gaps:**  
The main gap is the lack of a fully documented and tested recovery process for critical systems, including resilient backup arrangements and defined recovery priorities.

**Target Level:** Managed

Within six months, MedDefense should define recovery priorities and recovery objectives for critical systems, improve backup resilience, document recovery procedures, and regularly test restoration.

The first priority should be systems whose loss would create the greatest operational or patient-care impact.

---

## Current and Target Profile Summary

| NIST CSF Function | Current Level | 6-Month Target |
|---|---|---|
| Govern | Partial | Managed |
| Identify | Partial | Managed |
| Protect | Partial | Managed |
| Detect | Not Implemented | Managed |
| Respond | Partial | Managed |
| Recover | Partial | Managed |

---

## Overall Assessment

MedDefense currently has security activity across most of the NIST CSF functions, but much of it is still **informal, reactive, or incomplete**.

The work completed in Projects 1x00, 1x01, and 1x02 has significantly improved MedDefense's visibility of its assets, threats, vulnerabilities, and security weaknesses. However, completing those assessments does not automatically mean the underlying processes are mature.

The clearest example is **Identify**: MedDefense now has an asset inventory because one was built during Project 1x00, but it still needs a repeatable process to maintain that inventory.

The largest current maturity gap is **Detect**, where MedDefense lacks an effective centralized monitoring capability. **Protect** is also a major concern because the vulnerability assessment confirmed weaknesses on important systems.

A realistic six-month goal is therefore to move all six functions to **Managed**. The priority is not to claim optimization too early, but to make MedDefense's security activities documented, owned, repeatable, and consistently applied.
