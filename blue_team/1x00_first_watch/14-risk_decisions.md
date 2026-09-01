# MedDefense Health Systems — Risk Treatment Decisions

This document applies risk treatment decisions to the seven highest-priority findings from the revised Gap Analysis. All seven are currently rated **Critical**.

The available annual security budget is **$120,000**. Cost figures below are planning estimates used for prioritization, not vendor quotations.

---

## GAP-001

**Gap ID:** GAP-001  
**Gap Title:** No effective internal segmentation between servers, workstations and medical devices  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** MedDefense cannot avoid use of its internal network because EHR, clinical endpoints, Active Directory and medical devices depend on it. Accepting the current flat-network exposure would leave multiple Critical systems reachable from a compromised endpoint, while transferring financial loss would not prevent clinical disruption or patient-safety consequences. Segmentation therefore provides the strongest practical reduction in risk within the current budget.

**If Mitigate:**

- **Proposed Control(s):**
  - **Technical / Preventive:** Create enforced VLAN/security zones for user workstations, servers, medical IoT, management interfaces and guest access.
  - **Technical / Preventive:** Apply firewall/ACL rules allowing only required communications between zones.
  - **Technical / Detective:** Enable logging and alerting for denied and abnormal east-west connections.
- **Estimated Cost:** **$10-50K** — planning allocation **$25,000**
- **Implementation Effort:** **Long-term > 1 month**
- **Expected Risk Reduction:** **High.** Segmentation does not eliminate endpoint compromise, but it substantially reduces lateral movement and prevents a single compromised system from automatically reaching multiple Critical clinical assets.

**Trade-offs:** Network changes can interrupt clinical workflows if rules are implemented incorrectly. MedDefense will need application-flow testing, staged deployment, rollback plans and coordination with clinical departments and vendors.

---

## GAP-003

**Gap ID:** GAP-003  
**Gap Title:** Medical IoT devices lack device-specific isolation and monitoring  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** Infusion pumps and patient monitors support direct patient care and cannot simply be disconnected or retired. Cyber insurance would not prevent unsafe readings, interrupted monitoring or disruption of medication delivery. MedDefense should therefore reduce exposure through device isolation and restricted communications while preserving clinical functionality.

**If Mitigate:**

- **Proposed Control(s):**
  - **Technical / Preventive:** Place medical IoT into dedicated clinical-device VLANs/security zones.
  - **Technical / Preventive:** Allow only required communication with approved clinical systems and management services.
  - **Technical / Detective:** Monitor medical-device network traffic for unexpected destinations, protocols or communication patterns.
  - **Administrative / Preventive:** Maintain an approved device inventory with owner, model, firmware and vendor-support status.
- **Estimated Cost:** **$10-50K** — planning allocation **$18,000**
- **Implementation Effort:** **Long-term > 1 month**
- **Expected Risk Reduction:** **High.** Isolation limits the ability to reach vulnerable devices and prevents a compromised device from freely communicating with the wider MedDefense network. Monitoring improves the likelihood that abnormal device behavior is detected.

**Trade-offs:** Medical devices may use vendor-specific protocols that are poorly documented. Overly restrictive rules could interrupt patient monitoring or dosage-update services, so clinical engineering and vendors must validate allowed traffic before enforcement.

---

## GAP-004

**Gap ID:** GAP-004  
**Gap Title:** Server-room access is not restricted to authorized personnel  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** The server room contains infrastructure supporting Critical clinical and recovery services. The existing HID badge system can be improved without major architectural change, making mitigation both inexpensive and operationally feasible. Accepting broad employee access would be difficult to justify when a relatively low-cost physical control change can materially reduce exposure.

**If Mitigate:**

- **Proposed Control(s):**
  - **Physical / Preventive:** Restrict server-room badge permissions to specifically authorized IT/security personnel.
  - **Physical / Detective:** Enable named entry/exit logging and periodic access review.
  - **Physical / Detective:** Add camera coverage of the server-room entrance.
  - **Administrative / Preventive:** Implement a visitor-access procedure requiring authorization and escort.
- **Estimated Cost:** **$1-10K** — planning allocation **$8,000**
- **Implementation Effort:** **Short-term < 1 month**
- **Expected Risk Reduction:** **High.** Restricting access removes the current ability for ordinary employee badges to enter the room, while logs and camera coverage create accountability and evidence for unauthorized-access attempts.

**Trade-offs:** Emergency or maintenance access may become less convenient. MedDefense must maintain an emergency-access process so stricter controls do not delay legitimate infrastructure work.

---

## GAP-005

**Gap ID:** GAP-005  
**Gap Title:** Network closet is unlocked and switch-management credentials are exposed  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** This gap can be reduced quickly and at low cost. The network closet exposes both physical infrastructure and valid administrative credentials, so accepting the risk would be unreasonable when basic physical protection and credential hygiene can remove the immediate exposure within days.

**If Mitigate:**

- **Proposed Control(s):**
  - **Physical / Preventive:** Lock the network closet and restrict key/badge access.
  - **Technical / Preventive:** Immediately rotate the exposed switch-management password.
  - **Administrative / Preventive:** Prohibit posting or storing administrative credentials in unsecured physical locations.
  - **Technical / Detective:** Enable switch administrative-login logging and review.
- **Estimated Cost:** **$1-10K** — planning allocation **$3,000**
- **Implementation Effort:** **Quick Win < 1 week**
- **Expected Risk Reduction:** **Very High for the specific exposure.** Locking the closet and invalidating the posted credentials immediately remove the simplest path to unauthorized switch administration.

**Trade-offs:** Minimal. IT staff must use an approved credential-management method and controlled physical-access process instead of the convenient posted password.

---

## GAP-006

**Gap ID:** GAP-006  
**Gap Title:** MRI control environment relies on an unsupported Windows XP platform  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** Avoidance would mean removing MRI capability from service, which is not operationally acceptable, and replacement is not feasible within the current budget cycle. The operating system cannot be brought back into vendor support through normal patching. MedDefense should therefore use a **compensating control** that limits the vulnerable workstation's exposure while preserving the required connection to PACS.

**If Mitigate:**

- **Proposed Control(s):**
  - **Technical / Compensating-Preventive:** Place `WS-RAD-01` on an isolated VLAN.
  - **Technical / Preventive:** Configure firewall rules so the MRI workstation can communicate only with the PACS server and explicitly required management services.
  - **Technical / Detective:** Log and alert on blocked or unexpected connections to/from the MRI VLAN.
  - **Administrative / Preventive:** Document the legacy-system exception, business justification, responsible owner and planned replacement/review date.
- **Estimated Cost:** **$1-10K** — planning allocation **$7,000**
- **Implementation Effort:** **Short-term < 1 month**
- **Expected Risk Reduction:** **High, but not complete.** Network isolation cannot remove vulnerabilities in Windows XP, but it sharply reduces the systems that can reach the workstation and limits where an attacker could move if the workstation were compromised.

**Trade-offs:** The underlying end-of-life platform remains vulnerable. Any PACS/vendor dependency omitted from the firewall allow-list could interrupt imaging workflows. This mitigation must therefore be treated as temporary risk reduction, with eventual vendor-supported replacement remaining the long-term objective.

---

## GAP-010

**Gap ID:** GAP-010  
**Gap Title:** Patient portal authorization failure has no documented remediation verification  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** MedDefense has already experienced unauthorized cross-patient access to laboratory results. Accepting this risk would expose Restricted patient information, while transferring financial consequences through insurance would not correct the privacy failure. Application-level authorization must be remediated and independently verified.

**If Mitigate:**

- **Proposed Control(s):**
  - **Technical / Preventive:** Enforce server-side object-level authorization so each authenticated patient can access only records they are authorized to view.
  - **Technical / Detective:** Add application logging/alerting for repeated unauthorized record-access attempts.
  - **Administrative/Technical / Preventive:** Perform targeted security testing and regression testing before closing the finding.
  - **Technical / Corrective:** Establish a defined remediation process for future authorization defects.
- **Estimated Cost:** **$10-50K** — planning allocation **$15,000**
- **Implementation Effort:** **Short-term < 1 month**
- **Expected Risk Reduction:** **Very High.** Correct authorization directly addresses the weakness that caused the February incident, while testing verifies that changing a URL or object identifier can no longer expose another patient's information.

**Trade-offs:** Development and testing may require vendor involvement and could temporarily delay other patient-portal enhancements. Poorly tested authorization changes could also interfere with legitimate access, so regression testing is essential.

---

## GAP-014

**Gap ID:** GAP-014  
**Gap Title:** Westside Clinic relies on a consumer router with no dedicated firewall  
**Risk Level:** Critical  

**Treatment Strategy:** Mitigate  

**Justification:** Westside must remain connected to Central for clinical and business operations, so avoiding the network connection is not feasible. The existing IPSec VPN protects traffic in transit but does not provide adequate enterprise perimeter security at the clinic. Replacing the consumer router is a proportionate mitigation for a site that handles Restricted clinical data and connects directly back to Central.

**If Mitigate:**

- **Proposed Control(s):**
  - **Technical / Preventive:** Replace the consumer Netgear router with an enterprise firewall/security gateway.
  - **Technical / Preventive:** Apply explicit inbound/outbound policies and restrict VPN access to required Central resources.
  - **Technical / Detective:** Enable firewall security-event logging and alerting.
  - **Administrative / Preventive:** Establish documented ownership, configuration review and firmware-update responsibility.
- **Estimated Cost:** **$10-50K** — planning allocation **$15,000**
- **Implementation Effort:** **Short-term < 1 month**
- **Expected Risk Reduction:** **High.** An enterprise firewall introduces enforceable site-perimeter controls and substantially reduces the chance that a compromise at Westside can freely reach Central through the VPN.

**Trade-offs:** Installation requires a planned network change and may cause temporary clinic connectivity disruption. Ongoing support/licensing and firewall-rule maintenance also add recurring operational cost.

---

# Budget Summary

## Recommended Current-Year Allocation

| Priority | Gap | Mitigation | Planning Allocation |
|---|---|---|---:|
| 1 | GAP-001 | Internal network segmentation | **$25,000** |
| 2 | GAP-003 | Medical IoT isolation and monitoring | **$18,000** |
| 3 | GAP-004 | Server-room access control and monitoring | **$8,000** |
| 4 | GAP-005 | Network-closet physical/credential security | **$3,000** |
| 5 | GAP-006 | MRI compensating isolation controls | **$7,000** |
| 6 | GAP-010 | Patient-portal authorization remediation/testing | **$15,000** |
| 7 | GAP-014 | Westside enterprise firewall | **$15,000** |
|  | **Total allocated to the seven highest-priority gaps** |  | **$91,000** |
|  | **Annual security budget** |  | **$120,000** |
|  | **Remaining budget** |  | **$29,000** |

The seven highest-priority mitigations therefore fit within the **$120,000** fiscal-year budget, using approximately **$91,000** and leaving approximately **$29,000** available.

The remaining amount should not be consumed simply to exhaust the budget. It should be retained for implementation contingency and, once the Critical treatments are underway, applied to the next High-rated risks—particularly isolated/offsite backup capability (GAP-008), centralized security monitoring (GAP-011), Shadow IT management (GAP-012), endpoint/mobile coverage (GAP-013) and incident-response/continuity planning (GAP-015).

## Implementation Sequence

**Quick Win — less than 1 week**
- GAP-005: lock the network closet, remove exposed credentials and rotate the switch-management password.
- Begin server-room badge restriction under GAP-004.
- Begin documenting and approving the MRI legacy-system exception under GAP-006.

**Short-term — less than 1 month**
- GAP-004: complete server-room access logging and camera coverage.
- GAP-006: isolate `WS-RAD-01` and restrict communication to PACS/required services.
- GAP-010: remediate and test patient-portal authorization.
- GAP-014: deploy the Westside enterprise firewall.

**Long-term — more than 1 month**
- GAP-001: complete staged internal network segmentation.
- GAP-003: complete medical-IoT isolation, permitted-flow validation and monitoring.
- Begin planning replacement or vendor-supported modernization of the Windows XP MRI control environment in a future capital cycle.

---

## Overall Treatment Position

MedDefense should **mitigate all seven Critical gaps**. Transfer is unsuitable as the primary strategy because insurance or outsourcing cannot prevent patient-safety, clinical-availability or privacy consequences. Acceptance is not proportionate given the severity of the affected assets and the availability of feasible controls. Avoidance is also operationally unrealistic for services such as MRI, patient access, medical IoT and site connectivity.

The treatment programme therefore concentrates the current-year budget on reducing the **likelihood and blast radius of compromise** while preserving necessary clinical services.
