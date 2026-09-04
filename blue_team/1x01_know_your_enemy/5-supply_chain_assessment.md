# MedDefense Health Systems — Supply Chain Risk Assessment

## Assessment Basis

This assessment uses the Project 1x00 onboarding environment, vendor dependencies, Asset Registry and Complete Control Matrix. Where the evidence does not document a vendor's exact protocol, account type or technical restriction, that limitation is stated rather than inferred.

---

## 1. MedTech Solutions

**Vendor:** MedTech Solutions

**Service:** EHR maintenance provider. The contract is valued at **$145,000 annually**, provides a **four-hour response SLA for critical issues**, and includes direct server access for maintenance and software updates.

**Access Type:** **Network / Application — direct maintenance access to the EHR server.**

**Access Scope:** The documented authorized scope is the EHR application environment, specifically `ehr-srv-01` (**A-001**) and the vendor-maintained EHR application (**A-036**). The evidence does **not** establish that MedTech is authorized for direct access to `ehr-db-01` (**A-002**). However, `ehr-srv-01` is part of the EHR service path to the PostgreSQL database, and Project 1x00 found that `ehr-db-01` is reachable from the wider Central internal network. A compromised maintenance session on `ehr-srv-01` could therefore create a route toward Restricted patient data and other reachable internal systems.

**Compromise Scenario:** If MedTech's maintenance credentials, engineer workstation or remote-access platform were compromised, an attacker could enter MedDefense through a trusted vendor path and obtain access to `ehr-srv-01`. From there, the attacker could tamper with the EHR application, steal data available to the application, plant persistence or attempt movement toward `ehr-db-01` and other Central systems. Because MedDefense lacks effective internal segmentation (**GAP-001**), a vendor compromise affecting one Critical server could become a wider internal compromise rather than remaining isolated to the EHR maintenance function.

**Existing Controls:** `ehr-srv-01` has several strong controls: **C-004** disables SSH root login, **C-005** enforces key-only SSH authentication, **C-006** limits authentication attempts and **C-007** disables SSH forwarding. **C-008** logs SSH authentication and **C-028** provides EHR application audit logging. These controls harden and record activity on the EHR environment, but the Control Matrix does not document a vendor-specific network allowlist, PAM workflow, session recording or time-limited MedTech access. The exact remote-maintenance method is also not documented.

**Risk Assessment:** **Critical.** MedTech has direct maintenance access to MedDefense's most critical clinical application. EHR confidentiality, integrity and availability are all Critical, and compromise could affect Restricted patient information and patient-care operations. The risk is amplified by weak internal segmentation and fragmented monitoring.

---

## 2. Microsoft

**Vendor:** Microsoft

**Service:** Microsoft O365 E3 providing organization-wide email, SharePoint, OneDrive and productivity services.

**Access Type:** **Application / Data / potentially Identity.**

**Access Scope:** Microsoft hosts MedDefense's organization-wide O365 environment (**A-039**), including workforce email and cloud-hosted collaboration data in SharePoint and OneDrive. This creates vendor dependency for Internal and Confidential business information and potentially sensitive information users place in those services. The task notes that Microsoft also manages identity **if Entra ID is used**; however, Project 1x00 documents Active Directory as MedDefense's confirmed identity platform and does not establish whether Entra ID is deployed or authoritative. Identity exposure through Entra must therefore be treated as **unverified** rather than assumed.

**Compromise Scenario:** If MedDefense's Microsoft tenant administration, a trusted Microsoft service component or Microsoft-issued authentication/session mechanisms were compromised, an attacker could potentially access mailboxes and cloud documents, alter sharing permissions, create malicious mailbox rules, or send convincing internal phishing from trusted accounts. Stolen cloud identities or tokens could also be used to target MedDefense users and administrative workflows. If later evidence confirms that Entra ID is integrated with or authoritative for MedDefense authentication, the same compromise could have a substantially wider identity impact.

**Existing Controls:** Project 1x00 documents password requirements, AD password enforcement and account lockout (**C-009 to C-012**) for accounts within their scope, but these controls cannot automatically be assumed to govern Microsoft's cloud administrative plane. **C-023** security-awareness training provides a general user safeguard against malicious messages. The Control Matrix does not document centralized monitoring of Microsoft 365 audit events, tenant-specific privileged-access controls or a verified Entra ID security configuration.

**Risk Assessment:** **High.** O365 is organization-wide, so a compromise could expose a large volume of email and business data and provide a highly trusted platform for follow-on phishing. The rating is kept below Critical because the evidence does not establish that Microsoft controls MedDefense's core on-premise clinical identity or EHR infrastructure. If Entra ID is later confirmed as a central authentication dependency, this rating should be reconsidered as **Critical**.

---

## 3. Sophos

**Vendor:** Sophos

**Service:** Endpoint protection and automated threat containment.

**Access Type:** **Application / Endpoint-management — privileged software agent and centralized update/configuration path.**

**Access Scope:** Sophos Endpoint Protection is recorded as **A-040**. Project 1x00 confirms **C-014** malware protection and **C-015** automated containment on **372 managed Windows 10/11 endpoints**. The wider documented endpoint population is larger, so the exact protected set is incomplete, but Sophos still has a broad trusted software presence across a large part of MedDefense's workstation estate.

**Compromise Scenario:** If Sophos's update infrastructure, management console or trusted software supply chain were compromised, an attacker could potentially distribute a malicious update or configuration through software that MedDefense endpoints already trust. Compromised agents could execute code on many covered endpoints, disable defenses, collect credentials or establish simultaneous footholds. At Central, **GAP-001** means a compromised workstation can have routes toward EHR, Active Directory and other Critical systems, while **GAP-011** means abnormal activity may not be centrally detected quickly.

**Existing Controls:** **C-014** and **C-015** are valuable endpoint controls during normal operation, but they are the vendor dependency being assessed and therefore are not independent protection against a Sophos supply-chain compromise. **C-002** provides a default-deny perimeter rule, while **C-003/C-024** and **C-025** provide firewall and Windows logging. However, MedDefense's monitoring is fragmented, and trusted vendor update traffic may not be blocked by perimeter controls.

**Risk Assessment:** **Critical.** Sophos has a trusted, privileged software channel to hundreds of endpoints. A malicious update or compromised management function could create simultaneous internal footholds at scale, and MedDefense's flat Central network could allow those footholds to become paths toward Critical clinical and identity systems.

---

## 4. Siemens

**Vendor:** Siemens

**Service:** Manufacturer and maintenance provider for the Siemens MAGNETOM MRI, including periodic servicing of the MRI environment and firmware/software updates.

**Access Type:** **Physical / Application / System maintenance.**

**Access Scope:** Siemens maintenance activity is associated with the Siemens MAGNETOM MRI (**A-029**) and the Windows XP SP3 MRI control workstation `WS-RAD-01` (**A-022**) in Radiology. The evidence does not document permanent Siemens remote access, so this assessment does not assume it exists. The main confirmed exposure is periodic vendor maintenance of a Critical clinical imaging environment.

**Compromise Scenario:** If a Siemens engineer's maintenance laptop, service media or update package were compromised, malicious code could be introduced to `WS-RAD-01` during legitimate servicing. Because the workstation runs unsupported Windows XP and remains on Central's broadly reachable internal environment (**GAP-006** and **GAP-001**), the attacker could disrupt MRI availability, alter or expose imaging-related data, or use the workstation as a foothold for reconnaissance and movement toward PACS or other internal systems.

**Existing Controls:** General facility controls include **C-019 — Visitor Registration and Badge Verification** and **C-033 — HID Badge Access Control**, although C-033 is rated Weak. Network perimeter protection (**C-002**) does not isolate the MRI workstation from other internal systems. Project 1x00 identified no MRI-specific detective or corrective control and explicitly recommended isolation as a compensating control for the unsupported platform.

**Risk Assessment:** **High.** The MRI is a Critical clinical service and its Windows XP control environment is unusually vulnerable. However, the documented Siemens access is periodic and narrower in scope than the persistent, organization-wide access associated with Sophos or the direct Critical-server access associated with MedTech.

---

## 5. Greenfield Building Management

**Vendor:** Greenfield Building Management

**Service:** Corporate HQ building network and Internet infrastructure, included with the office lease.

**Access Type:** **Network / Physical infrastructure management.**

**Access Scope:** Greenfield manages the underlying network and Internet service at Corporate HQ, where approximately 120 workstations and approximately 25–30 laptops operate. MedDefense has its own VLAN on the building-managed network, and HQ connects to Central through a site-to-site VPN. Project 1x00 does not document Greenfield as having authorized administrative access to Central systems. The exact VLAN configuration, underlying switching controls and landlord network-security controls are unknown.

**Compromise Scenario:** If Greenfield's building-network administration were compromised, an attacker could disrupt HQ connectivity, manipulate the network carrying the MedDefense VLAN, attempt attacks against HQ endpoints or observe traffic that is not otherwise encrypted. The site-to-site VPN should protect traffic between HQ and Central from simple interception, but a compromised HQ endpoint could still become a stepping stone toward Central through the VPN. The risk is increased because Marcus did not audit the HQ VPN ACLs, so the exact permitted path from HQ to Central is not confirmed.

**Existing Controls:** **C-031 — Site-to-Site VPN Protection** provides an important boundary by encrypting traffic between HQ and Central. MedDefense's dedicated VLAN also provides some logical separation at HQ, although its enforcement and configuration are landlord-managed and not independently verified. Covered HQ endpoints may also benefit from **C-014/C-015 Sophos protection**. There is no documented MedDefense control that independently validates Greenfield's switch/router configuration or continuously monitors the landlord-managed network.

**Risk Assessment:** **High.** Greenfield controls a network on which an entire MedDefense site depends, and a compromise could disrupt approximately 220 HQ staff or create an attack path toward MedDefense endpoints. The rating is limited to High because HQ has no documented on-premise servers and the site-to-site VPN provides a meaningful protective layer between the landlord network and Central.

---

# Supply Chain Risk Summary

The **Sophos** compromise has the greatest potential blast radius because Sophos has a trusted software agent and update/configuration path to **372 managed Windows endpoints**. A poisoned update could create many internal footholds at once, and MedDefense's lack of effective internal segmentation could allow those footholds to become routes toward Active Directory, EHR and other Critical systems. **MedTech Solutions is a very close second** because it has direct maintenance access to the EHR environment itself; compromise of that vendor path would place MedDefense's highest-criticality clinical service immediately at risk. The first organization-wide control MedDefense should implement is a **formal Third-Party Risk Management and Vendor Access Standard** requiring every vendor relationship to have a documented owner, exact system/data access scope, named least-privilege accounts, MFA where technically possible, time-limited or just-in-time access for maintenance, centralized logging of vendor activity, periodic access review, defined breach-notification requirements and immediate revocation when access is no longer required. The current evidence shows that MedDefense knows which vendors it depends on, but it does not yet have a consistently documented security boundary around what each vendor can reach.
