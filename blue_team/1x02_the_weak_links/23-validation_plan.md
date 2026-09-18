# 23. The Validation Plan

**Project:** `1x02_the_weak_links`  
**Task:** Advanced Task 23 — The Validation Plan  
**Repository path:** `blue_team/1x02_the_weak_links/23-validation_plan.md`  
**Purpose:** Define how MedDefense verifies remediation, validates compensating controls and operates a continuous vulnerability-management cycle.

---

# 1. Validation Principle

MedDefense should not close a vulnerability because a change ticket says **completed**.

A finding is closed only when the organization has evidence that:

1. the intended remediation or compensating control is actually active;
2. the vulnerable condition is no longer reachable or exploitable as expected;
3. the required clinical/business workflow still functions;
4. logging shows the control is operating;
5. a targeted rescan or retest confirms the result; and
6. the evidence is recorded against the original finding.

The operating rule is:

> **Remediate → Verify → Rescan → Close**

For the three highest-priority Immediate items from Task 20, validation should happen during the same 24–48 hour response window.

---

# 2. Post-Patch / Post-Remediation Verification

## Finding 004 — Windows XP MRI Workstation Isolation

### Remediation

`WS-RAD-01` is an unsupported Windows XP MRI control workstation with mature RDP/SMB exploitation paths. Because the operating system cannot be remediated through normal patching, Task 20 requires MedDefense to isolate it in a dedicated MRI/Radiology zone and block general-network RDP/SMB access.

### Validation Tests

**1. Confirm the network policy is installed**

Review the firewall/VLAN/ACL configuration and verify that:

- `WS-RAD-01` is in the intended MRI security zone;
- only documented PACS/vendor/management destinations are permitted;
- RDP (`3389/tcp`) and SMB (`445/tcp` / required legacy SMB traffic) are blocked from general workstation and server networks.

**2. Perform negative connectivity tests**

From a representative ordinary workstation/server network, attempt:

```bash
nc -vz 10.10.1.70 3389
nc -vz 10.10.1.70 445
```

or equivalent approved connection tests.

**Expected result:** the prohibited connections fail.

**3. Perform positive clinical tests**

From the systems that are supposed to communicate with the MRI workstation:

- confirm MRI-to-PACS image transfer;
- confirm modality worklist/required imaging workflow;
- confirm any approved vendor-management path.

**Expected result:** required clinical traffic continues to function normally.

**4. Confirm logging**

Generate a blocked test connection and confirm the denied event appears in firewall/security logs with:

- source;
- destination;
- port;
- timestamp;
- deny action.

### Closure Criterion

Finding 004 is **contained**, not eliminated, when required MRI/PACS workflows succeed and unrelated internal sources cannot initiate RDP/SMB access.

The residual Windows XP vulnerability remains open as a **legacy-system replacement risk** until the platform is replaced.

---

## Finding 003 — Restrict PostgreSQL Access to the EHR Database

### Remediation

Task 20 requires MedDefense to remove broad `10.10.0.0/16` PostgreSQL access and permit TCP/5432 only from `ehr-srv-01` and separately approved administration/monitoring sources.

### Validation Tests

**1. Review the configuration**

Confirm that `pg_hba.conf`, PostgreSQL listening settings and host/network firewall rules no longer permit the entire internal network.

Expected approved source example:

```text
ehr-srv-01 — 10.10.2.10
```

plus any separately validated administrative or monitoring hosts.

**2. Positive test**

From `ehr-srv-01`, connect to the EHR database using the normal application path.

**Expected result:** connection succeeds and the EHR can read/write the required records.

**3. Negative test**

From a representative workstation or unrelated server, test TCP/5432:

```bash
nc -vz 10.10.2.11 5432
```

**Expected result:** connection is denied or times out according to the intended firewall policy.

**4. Application test**

Confirm:

- patient lookup works;
- record updates work;
- application authentication succeeds;
- scheduled jobs/integrations still function.

**5. Targeted rescan**

Rescan `ehr-db-01` from an unauthorized network location.

**Expected result:** PostgreSQL is no longer reported as broadly reachable.

### Closure Criterion

Finding 003 can be closed when:

> **approved EHR/admin sources can connect + unauthorized internal sources cannot + the EHR workflow remains functional + the targeted rescan confirms restricted exposure.**

---

## Finding 001 — Apache `mod_lua` / CVE-2021-44790 on `billing-srv-01`

### Remediation

Task 20 requires MedDefense to upgrade Apache through a supported package path, confirm whether `mod_lua` is required, test the billing application and rescan.

The same tested Apache change package should also remediate Finding 002 where the upgraded package addresses that vulnerability.

### Validation Tests

**1. Verify the running package/version**

Check the installed and running Apache version using the appropriate package/service commands, for example:

```bash
apache2 -v
dpkg -l | grep apache2
```

**Expected result:** the running package is the approved remediated version, not merely a downloaded but inactive package.

**2. Verify `mod_lua` status**

If the billing application does not require `mod_lua`:

```bash
apache2ctl -M | grep lua
```

**Expected result:** the module is not loaded.

If it is required, confirm that the installed Apache version contains the vendor fix.

**3. Restart-state verification**

Confirm the Apache service was restarted after patching and that no old vulnerable binary remains active.

**4. Billing application regression test**

Confirm:

- billing portal/application loads;
- authentication succeeds;
- required billing transactions complete;
- integrations still function;
- relevant logs show no post-change errors.

**5. Targeted vulnerability rescan**

Rescan the Apache service and specifically verify that **CVE-2021-44790 is no longer detected**.

Where an approved safe verification method exists, confirm the previous exploit condition no longer succeeds without performing destructive exploitation against production.

### Closure Criterion

Finding 001 can be closed when the **running Apache version/module state is remediated**, the billing service works normally and a targeted rescan no longer reports CVE-2021-44790.

---

# 3. Compensating-Control Validation

## 3.1 MRI Compensating Control

The MRI control is successful only if it reduces **both reachability and blast radius** without breaking patient-care workflows.

### Validation Procedure

1. Document all required MRI/PACS/vendor flows before enforcement.
2. Confirm the MRI workstation is placed in the dedicated security zone.
3. From ordinary user/server networks, verify RDP/SMB and other unauthorized access paths fail.
4. From approved PACS/vendor/management systems, verify required connections succeed.
5. Attempt representative lateral-movement paths from the MRI zone toward:
   - Active Directory;
   - backup infrastructure;
   - unrelated servers;
   - user workstations;
   - medical-IoT networks.
6. Confirm those unauthorized paths are blocked.
7. Verify firewall logs record denied attempts.
8. Have Radiology/Clinical Engineering confirm normal MRI workflow.

### Success Criterion

> **Required clinical traffic works; unrelated internal systems cannot reach the MRI workstation; the MRI workstation cannot freely initiate connections into unrelated MedDefense zones; blocked attempts are visible in logs.**

Segmentation does **not** make Windows XP secure. It is successful when it contains the legacy risk until replacement.

---

## 3.2 Medical-IoT Compensating Controls

This applies primarily to the BD Alaris estate and Philips IntelliVue environment.

### Validation Procedure

**Network isolation**

From an ordinary user workstation:

- attempt to reach Alaris/Philips management interfaces;
- test representative device-management ports;
- verify direct access is denied unless explicitly required.

From approved Systems Manager/clinical-management hosts:

- confirm required device communications succeed.

**ACL / firewall validation**

Review rules and confirm:

- only documented endpoints can communicate with the device estate;
- only vendor-required ports are permitted;
- unrestricted `10.10.0.0/16` access is not allowed.

**Clinical workflow validation**

With Clinical Engineering and the vendor:

- confirm pumps communicate correctly with Systems Manager;
- confirm medication workflows remain functional;
- confirm monitor-to-EHR/HL7 flows operate normally;
- confirm alarms, observations and device-management functions required for care still operate.

**Monitoring validation**

Generate a test denied connection from a non-approved host.

**Expected result:** the attempt is blocked and visible in logs/monitoring.

**Version validation**

For Alaris, confirm:

- exact PC Unit version;
- exact Systems Manager / Guardrails component version;
- vendor-supported update status.

Finding 010 must not be closed merely because CVE-2020-25165 is version-inapplicable if the broader **GAP-003 medical-IoT isolation problem** remains.

### Success Criterion

> **Only approved clinical/management systems can reach the medical-device estate, required patient-care workflows remain functional and unauthorized access attempts are blocked and observable.**

---

# 4. Rescan Schedule

MedDefense should adopt a **risk-based scanning schedule**, not a single frequency for every asset.

| Scan / Review Type | Recommended Frequency | Scope |
|---|---|---|
| **Post-remediation targeted scan** | **Immediately after every change** | Changed host/service/finding |
| **Critical and Internet-facing systems** | **Weekly** | EHR, portal/web, AD, VPN/perimeter, Critical exposed services |
| **Authenticated internal server scan** | **Monthly** | Windows/Linux servers, databases, infrastructure |
| **Medical-IoT vulnerability/advisory review** | **Monthly + after vendor bulletin/change** | Alaris, Philips and other clinical devices |
| **Full enterprise vulnerability scan** | **Quarterly** | All approved reachable assets |
| **New asset / major change scan** | **Before production + after deployment** | New servers, major upgrades, network changes |
| **Exception / false-positive review** | **At least quarterly** | Suppressed/accepted findings |

## Why This Cadence Fits MedDefense

A **weekly** scan of Critical/exposed systems is justified because MedDefense has:

- legacy and EOL systems;
- flat-network exposure;
- public-facing services;
- Critical clinical assets;
- a history of compromise;
- a demonstrated need to verify that urgent changes actually remain in place.

A **monthly authenticated internal scan** is frequent enough to detect patch/configuration drift without making routine server scanning unnecessarily disruptive.

A **quarterly full scan** provides an organization-wide baseline and supports management reporting, while targeted scans after every remediation prevent findings from remaining falsely marked as closed.

Medical devices should not be aggressively scanned on a generic schedule without clinical/vendor approval. Their vulnerability-management cadence should combine **safe network validation + vendor advisory review + approved device testing**.

---

# 5. Continuous Intelligence

MedDefense should treat external vulnerability intelligence as an **input to the vulnerability-management queue**, not as a separate research activity.

## 5.1 CISA KEV

Security should review the **CISA Known Exploited Vulnerabilities Catalog** continuously through automated feed monitoring or at minimum every business day.

When a new KEV item appears:

1. compare the affected product/version with the Asset Registry;
2. determine whether MedDefense has the affected technology;
3. validate version/configuration applicability;
4. identify Internet/internal reachability;
5. map the vulnerability to asset criticality and relevant 1x01 threat paths;
6. create or reprioritize a remediation ticket;
7. require expedited remediation for confirmed Critical/High-risk matches.

A KEV match should raise urgency because it provides evidence of **real-world exploitation**, but it still requires MedDefense-specific applicability validation.

---

## 5.2 Vendor Advisories

Security and IT should subscribe to advisories for at least:

- Microsoft;
- Canonical/Ubuntu;
- Apache;
- Fortinet;
- Synology;
- BD Alaris;
- Philips;
- VMware/Veeam and other Critical infrastructure vendors.

For medical devices, **Clinical Engineering and the vendor** must participate before patches or firmware changes are approved.

Every relevant advisory should be checked against:

- Asset ID;
- product/model;
- software/firmware version;
- exposure;
- compensating controls;
- patient/business impact.

---

## 5.3 Threat Feeds and Threat-Landscape Updates

Threat-feed information should be used to detect changes in attacker behavior, such as:

- ransomware groups adopting a newly weaponized CVE;
- active exploitation of a technology MedDefense uses;
- new phishing/credential-abuse campaigns;
- attacks against healthcare or medical-device platforms.

Security should perform a **weekly threat-to-vulnerability correlation review**:

> **New threat intelligence → affected MedDefense asset? → matching open finding? → priority change required?**

If a vulnerability already in the backlog becomes actively exploited, its remediation timeline should be reassessed immediately rather than waiting for the next monthly scan cycle.

---

# 6. Continuous Vulnerability-Management Lifecycle

## Lifecycle Diagram

```text
        +---------+
        |  SCAN   |
        +----+----+
             |
             v
        +---------+
        | TRIAGE  |
        +----+----+
             |
             v
      +------------+
      | PRIORITIZE |
      +-----+------+
            |
            v
      +------------+
      | REMEDIATE  |
      +-----+------+
            |
            v
       +----------+
       | VALIDATE |
       +----+-----+
            |
            v
       +---------+
       | REPEAT  |
       +----+----+
            |
            +-----------------------> SCAN
```

---

## Step 1 — Scan

**Primary responsibility:** Security Analyst  
**Supporting:** IT Ops, Vendor / Clinical Engineering where required

### Activities

- run scheduled vulnerability scans;
- perform authenticated scanning where safe;
- collect OSINT/vendor advisories;
- identify exposed services and configuration issues;
- scan new assets after deployment.

### Output

**Raw findings with host, service, version and evidence.**

---

## Step 2 — Triage

**Primary responsibility:** Security Analyst  
**Supporting:** IT Ops, Vendor

### Activities

- validate whether the finding really applies;
- remove proven false positives;
- identify configuration vs CVE vs lifecycle findings;
- confirm exact product/version;
- document prerequisites and exposure.

### Output

**Validated finding: Actionable / Informational / False Positive.**

---

## Step 3 — Prioritize

**Primary responsibility:** Security Analyst  
**Supporting:** Management, IT Ops, Clinical/Vendor

### Activities

Combine:

- CVSS;
- asset criticality from 1x00;
- kill-chain/threat context from 1x01;
- exploit availability / KEV;
- existing controls;
- clinical/business impact;
- remediation feasibility.

### Management Role

Management approves:

- emergency prioritization;
- accepted exceptions;
- significant downtime;
- major budget/procurement decisions.

### Output

**Critical / High / Medium / Low remediation priority with owner and deadline.**

---

## Step 4 — Remediate

**Primary responsibility:** IT Ops  
**Supporting:** Vendor / Clinical Engineering / Security Analyst

### Activities

Depending on the finding:

- patch;
- upgrade;
- change configuration;
- restrict firewall/ACL rules;
- segment;
- replace EOL technology;
- implement compensating controls.

### Vendor Role

Vendor involvement is mandatory where changes affect:

- medical devices;
- certified clinical systems;
- vendor-supported application stacks;
- proprietary firmware.

### Output

**Implemented change with rollback evidence and change record.**

---

## Step 5 — Validate

**Primary responsibility:** Security Analyst  
**Supporting:** IT Ops, Vendor / Clinical Engineering, service owner

### Activities

- verify package/version/configuration;
- perform positive and negative tests;
- confirm business/clinical workflow;
- verify logging;
- perform targeted rescan;
- confirm exploit condition no longer exists;
- document residual risk.

### Closure Rule

> **A ticket is not closed until validation evidence exists.**

### Output

**Verified closed finding, documented exception or reopened remediation ticket.**

---

## Step 6 — Repeat / Monitor

**Primary responsibility:** Security Analyst  
**Supporting:** IT Ops and Management

### Activities

- run the next scheduled scan;
- review CISA KEV/vendor feeds;
- re-check exceptions;
- look for configuration drift;
- report overdue Critical/High findings;
- measure remediation/validation performance.

### Management Role

Management receives recurring metrics such as:

- open Critical/High findings;
- overdue remediation;
- unvalidated changes;
- mean time to remediate;
- exceptions nearing expiry;
- percentage of findings successfully verified after remediation.

### Output

**Updated vulnerability backlog and next remediation cycle.**

---

# 7. Roles and Accountability Summary

| Lifecycle Step | Security Analyst | IT Ops | Vendor / Clinical Engineering | Management |
|---|---|---|---|---|
| **Scan** | **Lead** | Provide access/credentials | Advise safe device testing | Oversight |
| **Triage** | **Lead** | Confirm configuration/version | Confirm vendor applicability | — |
| **Prioritize** | **Lead analysis** | Estimate operational impact | Explain clinical/vendor constraints | **Approve risk/budget decisions** |
| **Remediate** | Verify plan / monitor risk | **Lead implementation** | **Lead/support clinical/vendor changes** | Approve major outage/spend |
| **Validate** | **Lead security verification** | Confirm system functionality | Validate clinical/device workflow | Review unresolved residual risk |
| **Repeat / Monitor** | **Lead** | Maintain patch/config baseline | Supply advisories | Review metrics/exceptions |

---

# 8. Validation Evidence Standard

Every remediated finding should retain:

```text
Finding ID
Asset / hostname
Original evidence
Remediation date
Change ticket
Owner
Old version/configuration
New version/configuration
Positive test result
Negative test result
Targeted rescan result
Relevant logs/screenshots
Residual risk
Validator name
Closure date
```

For a false positive or accepted exception, also record:

- why the finding does not apply or cannot currently be fixed;
- supporting vendor/NVD evidence;
- compensating controls;
- review/expiry date;
- condition that triggers revalidation.

---

# 9. Final Validation Position

MedDefense's vulnerability-management programme should measure success by **verified risk reduction**, not by the number of patches deployed.

The three most urgent actions demonstrate the model:

- **MRI:** validate containment because the underlying XP weakness cannot be patched away;
- **EHR database:** prove that approved traffic succeeds while unauthorized TCP/5432 access fails;
- **billing Apache:** prove that the running vulnerable component/version is gone and the billing service still works.

The same principle then becomes continuous:

> **Scan → Triage → Prioritize → Remediate → Validate → Repeat**

Security owns discovery, triage and verification; IT Ops owns most technical remediation; vendors and Clinical Engineering protect clinical safety and supported configurations; Management owns risk acceptance, funding and accountability.

**Verification is the point at which remediation becomes evidence.**
