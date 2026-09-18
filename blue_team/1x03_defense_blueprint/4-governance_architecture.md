# 4. The Governance Architecture

## Purpose

MedDefense needs a governance structure that clearly separates **security oversight**, **technical implementation**, **business ownership**, and **executive decision-making**.

The goal is to prevent security decisions from depending on informal influence or whoever happens to be most vocal. Security should define risk requirements and priorities, IT should implement the technical changes, business leaders should own the risks created by their operations and data, and executive leadership should approve major policy, budget, and risk decisions.

---

# Part 1 — RACI Matrix

## RACI Key

- **R — Responsible:** Performs or coordinates the work.
- **A — Accountable:** Owns the outcome and has final decision authority.
- **C — Consulted:** Provides expertise or input before the decision/action.
- **I — Informed:** Kept aware of the decision, progress, or outcome.

> Each activity has one primary **Accountable** role so ownership is clear.

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
|---|---|---|---|---|---|
| **Security budget approval** | **A** | **R** | C | C | C |
| **Vulnerability remediation** | I | C | **A/R** | C | **R** |
| **Incident response execution** | I | **A** | **R** | C | **R** |
| **Security policy approval** | **A** | **R** | C | C | C |
| **Risk acceptance decisions** | **A** | C | C | **R** | C |
| **Security awareness training** | I | **A** | C | **R** | **R** |
| **Vendor risk assessment** | I | **A** | C | C | **R** |
| **Audit coordination** | I | **A** | C | C | **R** |

---

## RACI Rationale

### Security Budget Approval

The **CEO is Accountable** because the security budget is a business decision and the current project has a hard **$120,000 limit**.

James is **Responsible** for preparing and defending the security investment plan. Sarah, Department Heads, and the Security Analyst are **Consulted** because they provide operational requirements, business impact, and technical evidence.

### Vulnerability Remediation

Sarah Park is **Accountable and Responsible** for technical remediation because IT manages the systems, patching processes, configuration changes, and operational deployment.

The Security Analyst is also **Responsible** for identifying findings, assigning priority, tracking remediation, and verifying that the vulnerability is actually closed.

James is **Consulted** when remediation decisions involve risk prioritization, exceptions, or conflicts between security and operations.

This separation resolves the current ownership problem: **Security determines what risk must be addressed and verifies the outcome; IT performs and owns the operational change.**

### Incident Response Execution

James is **Accountable** for the overall incident-response process because security incidents require security leadership, escalation, and risk decisions.

Sarah and the Security Analyst are **Responsible** for execution. IT performs containment and technical changes, while Security investigates alerts, gathers evidence, determines scope, and coordinates security actions.

Department Heads are **Consulted** when clinical or business operations are affected, and the CEO is **Informed** of significant incidents.

### Security Policy Approval

The **CEO is Accountable** for final approval because security policies apply across the organization and can impose requirements on clinical, administrative, and technical departments.

James is **Responsible** for developing and maintaining the security-policy framework. Sarah, Department Heads, and the Security Analyst are **Consulted** to confirm that requirements are technically realistic and operationally workable.

### Risk Acceptance Decisions

The **CEO is Accountable** for the final acceptance of significant cybersecurity risk because accepting risk means knowingly accepting possible financial, clinical, regulatory, or operational consequences.

Department Heads are **Responsible** for identifying and owning risks within their business areas. For example, a clinical leader cannot simply decide to ignore a security control because it is inconvenient; the risk must be documented and formally accepted through governance.

James, Sarah, and the Security Analyst are **Consulted** to explain the security exposure, technical options, and residual risk.

### Security Awareness Training

James is **Accountable** for ensuring the awareness programme addresses MedDefense's actual threat landscape.

The Security Analyst is **Responsible** for developing or coordinating training content, while Department Heads are also **Responsible** for ensuring staff in their departments complete required training.

Sarah is **Consulted** where training relates to technical systems or IT procedures.

### Vendor Risk Assessment

James is **Accountable** because third-party access can create organization-wide security risk.

The Security Analyst is **Responsible** for performing the assessment, documenting findings, reviewing access requirements, and tracking remediation.

Sarah and Department Heads are **Consulted** because they understand the technical integration and business dependency associated with each vendor.

This is particularly important for MedDefense because earlier projects identified vendor and maintenance pathways into Critical clinical environments.

### Audit Coordination

James is **Accountable** for security audit readiness and for ensuring findings are addressed.

The Security Analyst is **Responsible** for collecting evidence, maintaining documentation, tracking control status, and coordinating responses.

Sarah and Department Heads are **Consulted** when auditors require technical or departmental evidence.

---

# Part 2 — Role Definitions

## 1. Data Owner

**Assigned Role:** Department Heads / senior business leaders responsible for a specific data domain  
**Example:** Dr. Patel for Cardiology data

### What the Role Means

A **Data Owner** is the business person accountable for how a particular category of data should be used, protected, classified, retained, and accessed.

The Data Owner does not normally configure databases or firewalls. Instead, the owner makes business decisions such as:

- who should have access;
- what level of sensitivity the data has;
- how long it needs to be retained;
- what business or clinical purposes justify its use; and
- whether a proposed use of the data is acceptable.

### Why This Role Fits

Department Heads understand the operational and clinical meaning of the data used by their departments.

For example, Dr. Patel may understand who genuinely needs access to Cardiology data, but being Data Owner does **not** mean he can ignore security requirements. His decisions must still operate within MedDefense policy, regulatory requirements, and organizational risk controls.

---

## 2. Data Controller

**Assigned Role:** MedDefense Health Systems as the organization, with executive accountability represented by the CEO, Dr. Morales

### What the Role Means

The **Data Controller** determines **why** personal data is processed and the overall purposes and rules governing that processing.

For MedDefense, this includes decisions such as using patient information for diagnosis, treatment, billing, administration, and other approved healthcare operations.

### Why This Role Fits

The controller is fundamentally an organizational role rather than an individual technical role.

MedDefense decides why patient and employee information is collected and processed. The CEO therefore represents executive accountability for ensuring those decisions are governed appropriately.

Department Heads may make decisions within their areas, but they do not independently become separate controllers simply because they use the data.

---

## 3. Data Processor

**Assigned Role:** External service providers processing information on MedDefense's behalf

### What the Role Means

A **Data Processor** handles or processes information according to the instructions of the Data Controller rather than deciding independently why the information should be processed.

Examples may include third-party hosting, cloud, managed-service, billing, or technology providers where they process MedDefense information as part of an agreed service.

### Why This Role Fits

This role is different from an ordinary MedDefense employee.

MedDefense's internal IT staff may technically process data as part of their work, but they operate as part of MedDefense itself. A separate processor role is more accurately applied to an external organization processing MedDefense data on MedDefense's behalf.

Because MedDefense relies on vendors and technical partners, processor responsibilities should be defined through contracts, access limitations, security requirements, and vendor-risk assessments.

---

## 4. Data Custodian / Steward

**Assigned Role:** IT Director Sarah Park and the IT team

### What the Role Means

A **Data Custodian or Steward** is responsible for the day-to-day technical handling and protection of data according to requirements established by the Data Owner and MedDefense governance.

Typical responsibilities include:

- administering storage systems;
- implementing access controls;
- maintaining backups;
- applying configuration standards;
- supporting retention and deletion requirements;
- maintaining system availability; and
- implementing technical safeguards.

### Why This Role Fits

Sarah and the IT team manage the systems where MedDefense information is stored and processed.

They therefore act as custodians of the information, but they do not decide independently who should have access or what business use of the data is acceptable. Those decisions belong to the Data Owner and organizational governance.

---

## Role Relationship Summary

| Role | MedDefense Assignment | Primary Responsibility |
|---|---|---|
| **Data Owner** | Department Heads, e.g. Dr. Patel for Cardiology | Decides business/clinical access, classification, use, and requirements |
| **Data Controller** | MedDefense Health Systems, represented by CEO Dr. Morales | Determines why and under what organizational rules personal data is processed |
| **Data Processor** | External providers processing data for MedDefense | Processes data according to MedDefense's instructions |
| **Data Custodian / Steward** | Sarah Park / IT team | Implements the technical controls used to store, protect, back up, and administer the data |

---

# Part 3 — The CISO Question

## Current Governance Gap

MedDefense currently has no permanent CISO. James Chen is serving as Deputy CISO, but the senior security leadership position remains vacant.

This creates several problems:

- there is no permanent executive owner of the cybersecurity programme;
- security and IT responsibilities can overlap or conflict;
- security priorities may compete with operational priorities without clear escalation;
- Board reporting lacks a permanent security executive;
- risk acceptance and investment decisions may become inconsistent;
- audit and framework ownership can become fragmented; and
- James may be expected to perform CISO-level responsibilities without the authority or capacity of the actual role.

The disagreement between James and Sarah over ownership of endpoint security is an example of what happens when governance responsibilities are not formally defined.

---

## Recommendation — Use a vCISO in the Short Term

MedDefense should use a **virtual CISO (vCISO)** for the next six to twelve months rather than immediately hiring a full-time CISO.

The organization has a fixed security budget of **$120,000**, and that budget must also fund remediation of Critical vulnerabilities, monitoring, segmentation, identity controls, backup improvements, medical-device security, and other priorities identified in Projects 1x00–1x02. A full-time CISO would consume a large share of the available security budget before any technical risk was reduced. A vCISO provides senior governance, Board-level reporting, framework ownership, policy oversight, and independent risk guidance without committing the majority of the budget to one salary. James can remain the internal operational security lead, supported by the Security Analyst and Sarah's IT team, while the vCISO establishes the governance programme and helps develop James toward greater leadership responsibility. MedDefense should reassess the need for a permanent full-time CISO once the six-month security roadmap is established and the organization has the budget and maturity to sustain the position.

---

# Proposed Governance Structure

```text
Board / CEO — Dr. Morales
        |
        | Executive oversight, budget approval, major risk acceptance
        |
      vCISO
        |
        | Security strategy, governance, Board reporting,
        | policy oversight, risk programme
        |
Deputy CISO — James Chen
        |
        | Internal security programme ownership
        | incident response, risk coordination, control oversight
        |
        +-------------------------------+
        |                               |
Security Analyst                 IT Director — Sarah Park
        |                               |
Risk analysis                     IT operations
Monitoring                        Patching/remediation
Vendor assessment                 System administration
Control verification              Technical implementation
        |                               |
        +---------------+---------------+
                        |
                 Department Heads
                        |
              Business / clinical
                 Data Ownership
```

---

# Governance Principles for MedDefense

1. **Business leaders own business risk.** Security identifies and explains risk, but departments cannot independently bypass controls without formal risk acceptance.

2. **Security defines security requirements and verifies outcomes.** James and the Security Analyst determine risk priorities, control expectations, and whether remediation adequately addresses the exposure.

3. **IT owns technical implementation.** Sarah and the IT team are accountable for safely implementing changes to infrastructure, endpoints, servers, and applications.

4. **Executive leadership owns major decisions.** The CEO approves the security budget, organization-wide policies, and significant risk acceptance.

5. **Accountability must remain documented.** RACI assignments, risk owners, policy owners, control owners, and exceptions should be recorded so responsibilities do not depend on personalities or informal influence.

---

## Conclusion

MedDefense's governance problem is not simply the vacant CISO position. The deeper issue is that responsibility for security, IT operations, data ownership, and risk acceptance has not been formally separated.

The proposed structure gives MedDefense a clear chain of accountability:

**CEO → vCISO → Deputy CISO → Security / IT execution → Department ownership**

This structure supports the six-month move from a **Partial** to a **Managed** NIST CSF Govern function because security decisions become documented, repeatable, owned, and connected to business risk rather than being made informally.
