# MedDefense Health Systems — Insider Threat Assessment

## Scenario 1 — The Shared Login

**Classification:** **Negligent.** Radiology staff are deliberately using a shared PACS account, but the scenario gives no indication that they intend to harm MedDefense or misuse patient data. The risk comes from an unsafe convenience practice that removes individual accountability and leaves sessions continuously available.

**Behavioral Indicators:**
- The same `raduser` account authenticates repeatedly across different technicians, shifts or workstations.
- PACS audit activity cannot be tied reliably to a named individual because multiple users share one identity.
- Long-lived or continuously active sessions remain open between patients with no normal logout pattern.

**Existing Control (from 1x00):** **C-013 — Shared Account Password Change on Departure** partially addresses shared-account governance, but it is rated Weak and does not prevent routine credential sharing. **C-023 — Annual Security Awareness Training** also applies broadly but does not enforce individual accountability.

**Gap Exploited (from 1x00):** **GAP-007 — MFA and privileged-access controls are not broadly implemented.** The gap is broader than PACS alone, but it reflects MedDefense's weak identity-governance model; the shared `raduser` account is a specific example of access that is not tied strongly enough to an individual user.

**Recommended Mitigation:** **Technical — eliminate the shared PACS login and issue unique named user accounts for each technician**, using individual authentication and MFA where the PACS platform supports it. This restores accountability and allows audit records to identify who accessed each patient record.

---

## Scenario 2 — The Ghost Account

**Classification:** **Malicious.** The failure to disable the contractor's account was a negligent administrative control failure, but the three off-hours authentications after the contract ended are unauthorized use. Once the individual no longer had a legitimate business relationship with MedDefense, continued access became malicious regardless of whether the account technically remained enabled.

**Behavioral Indicators:**
- The VPN account remains active after the contractor's documented termination date.
- Successful VPN authentications occur after termination, particularly during off-hours.
- The account authenticates from a source IP, device or usage pattern inconsistent with the contractor's former normal activity.

**Existing Control (from 1x00):** **C-024 — FortiGate Local Log Retention** and **C-029 — Active Directory Critical Event Logging** can provide evidence of post-termination authentication, but neither ensures that the account is disabled. **C-013** applies only to changing shared-account passwords when someone leaves and therefore does not adequately cover individual contractor offboarding.

**Gap Exploited (from 1x00):** **GAP-017 — User account lifecycle and offboarding controls are not formally integrated with HR events**, identified during the advanced reality-check analysis. MedDefense lacks a reliably enforced process linking employment or contract termination to immediate deactivation and verification of access across VPN, Active Directory and other systems.

**Recommended Mitigation:** **Administrative/Technical — implement a formal joiner-mover-leaver process that automatically triggers account disablement when HR or procurement records a termination or contract end date**, with Security or IT verifying completion across VPN, AD and application accounts.

---

## Scenario 3 — The Personal NAS

**Classification:** **Negligent.** Dr. Patel has intentionally bypassed approved IT storage by connecting a personal NAS and keeping patient-file copies for convenience, but the scenario does not show an intent to steal or expose the information. The negligence is serious because the device stores Restricted patient data while being unencrypted, unbacked-up and outside IT visibility.

**Behavioral Indicators:**
- An unknown MAC address or storage device appears on Dr. Patel's office network port.
- Network monitoring shows SMB/NAS-style storage traffic to an unregistered device in Cardiology.
- Large or repeated transfers of patient files move from approved systems to an unmanaged local destination.

**Existing Control (from 1x00):** **No existing control directly governs or blocks this personal NAS.** **C-023 — Annual Security Awareness Training** is the nearest general preventive control, but the 1x00 Shadow Systems Assessment established that AD controls, Sophos, Veeam and documented logging controls cannot be assumed to cover the device.

**Gap Exploited (from 1x00):** **GAP-012 — Undocumented Shadow IT systems operate on production networks.** The personal NAS exists outside normal ownership, patching, encryption, backup and monitoring processes. **GAP-001 — lack of internal segmentation** further increases the consequence if the NAS itself is compromised.

**Recommended Mitigation:** **Technical — deploy network access control (NAC) that permits only registered and approved devices onto MedDefense internal networks.** Dr. Patel's patient files should then be moved to an approved encrypted storage platform before the NAS is removed.

---

## Scenario 4 — The Curious Employee

**Classification:** **Malicious.** The registration clerk intentionally accesses a patient's EHR without a job-related need and then discloses the information to another person. She does not alter the record, but deliberate unauthorized access and disclosure are still malicious actions and directly compromise patient confidentiality.

**Behavioral Indicators:**
- EHR audit logs show a registration clerk accessing the politician's clinical record without a treatment, registration or billing workflow that requires it.
- Access to a high-profile patient's record occurs from a user whose role or department has no care relationship with the patient.
- The account performs unusual record searches or views outside its normal patient population or work responsibilities.

**Existing Control (from 1x00):** **C-028 — EHR Application Audit Logging** records patient-record access and is the most directly relevant existing control. Its effectiveness is limited because MedDefense must request exports and has no documented continuous internal review.

**Gap Exploited (from 1x00):** **GAP-011 — Security logging is fragmented and not continuously monitored.** The EHR may record the inappropriate access, but without active monitoring the organization can discover the privacy breach only after the information has already been disclosed.

**Recommended Mitigation:** **Technical — implement automated EHR access monitoring that alerts on high-risk or anomalous access**, such as VIP records, users without a care relationship, unusually broad searches or access inconsistent with the user's role.

---

## Scenario 5 — The Overworked Admin

**Classification:** **Negligent.** The sysadmin is attempting to reduce workload rather than harm MedDefense, but storing an Active Directory administrator password in plaintext and emailing the script creates an avoidable exposure of a highly privileged credential. Good intent does not reduce the security impact of unsafe privileged-access handling.

**Behavioral Indicators:**
- A script or configuration file in the administrator's user profile contains a plaintext privileged credential.
- Email or collaboration logs show a script containing passwords or other secrets being sent to another employee.
- Repeated password-reset or administrative actions originate from an automation script using the same privileged identity rather than a controlled service account.

**Existing Control (from 1x00):** **C-023 — Annual Security Awareness Training** should discourage unsafe credential handling, while **C-029 — Active Directory Critical Event Logging** records important AD activity. However, neither control prevents an administrator from embedding a privileged password in a local file or sending it by email.

**Gap Exploited (from 1x00):** **GAP-007 — MFA and privileged-access controls are not broadly implemented.** The Gap Analysis specifically identifies the absence of formal privileged-access management and separated administrative identities, allowing privileged credentials to be handled manually and insecurely.

**Recommended Mitigation:** **Technical — deploy privileged-access management (PAM) for administrative automation**, using vaulted or short-lived credentials so scripts retrieve approved secrets at execution time instead of storing passwords in plaintext.

---

# Pattern Assessment

MedDefense's systemic insider-risk weakness is that **legitimate access is broad while identity governance, asset governance and continuous detection are comparatively weak**. Project 1x00 already showed that privileged and sensitive access is not consistently protected by MFA or formal privileged-access management (**GAP-007**), while security and EHR logs exist but are fragmented and not continuously monitored (**GAP-011**). At the same time, unmanaged technology can enter production networks outside normal IT control (**GAP-012**), and endpoint/device-management coverage is incomplete (**GAP-013**). This combination is particularly dangerous in healthcare because employees often need legitimate access to sensitive patient information: MedDefense cannot rely only on blocking access at the perimeter, so it must be able to identify **who is using access, whether that use is appropriate, and when trusted users or devices depart from normal behavior**.
