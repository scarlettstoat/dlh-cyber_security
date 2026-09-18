# 20. The Priority Matrix

**Project:** `1x02_the_weak_links`  
**Goal:** Provide the definitive remediation schedule for every Actionable finding from Task 16.  
**Repository path:** `blue_team/1x02_the_weak_links/20-priority_matrix.md`  
**Assessment date:** 16 September 2026

---

## 1. Scope and Budget Rule

Task 16 contains **26 Actionable findings**: **7 Actionable Critical** and **19 Actionable Standard**. Findings classified Informational or False Positive are not included in the remediation queue.

The four execution horizons are:

| Horizon | Timeline | Decision Rule |
|---|---|---|
| **Immediate** | **24–48 hours** | Weaponized/compound exposure, Critical asset, or a weakness that must be contained before the next normal change cycle |
| **Short-term** | **7 days** | High-risk vulnerability/configuration that can be corrected quickly after compatibility validation |
| **Medium-term** | **30 days** | Significant configuration, protocol, monitoring or device weakness requiring planned change coordination |
| **Long-term** | **90 days** | EOL migration, architecture replacement or systemic remediation requiring procurement/vendor/application testing |

**Cost note:** The figures below are **planning estimates, not vendor quotations**. Where two findings are closed by the same change package, the second finding is shown as **$0 incremental** so the budget is not counted twice.

---

# 2. Immediate — 24–48 Hours

| Priority | Finding | Description | Remediation Action | Owner | Estimated Cost |
|---:|---:|---|---|---|---:|
| **1** | **004** | Unsupported Windows XP MRI workstation with mature RDP/SMB remote exploits | Isolate `WS-RAD-01` in a dedicated MRI zone; block general-network RDP/SMB and allow only vendor-validated PACS/management flows | IT + Security + Clinical + Vendor | **$7,000** |
| **2** | **003** | PostgreSQL on `ehr-db-01` reachable from the wider internal network | Replace broad `/16` database access with explicit EHR/admin source rules and firewall TCP/5432 to approved hosts only | IT + Security | **$500** |
| **3** | **001** | CVE-2021-44790 Apache `mod_lua` memory-corruption/RCE weakness on `billing-srv-01` | Upgrade Apache through a supported package path, verify `mod_lua` necessity, test billing workflows and rescan | IT + Security | **$1,000** |
| **4** | **002** | CVE-2019-0211 local Apache privilege escalation that compounds Finding 001 | Close in the same tested Apache upgrade/change package as Finding 001 and verify the fixed version | IT + Security | **$0 incremental** |
| **5** | **009** | SSH password authentication enabled on the repeatedly compromised billing server | Deploy tested administrator/service SSH keys, set `PasswordAuthentication no`, and restrict SSH to approved management sources | IT + Security | **$500** |
| **6** | **012** | SMBv1 remains enabled on the unsupported MRI workstation | Block SMBv1 from general networks as part of Finding 004 containment; permit only a documented clinical dependency if one is proven necessary | IT + Security + Clinical + Vendor | **$0 incremental** |

**Immediate spend:** **$9,000**

The unsupported operating system in Finding 011 is not left exposed while its permanent migration is prepared: Findings **001, 002, 009, 006 and the network controls above provide immediate containment/hardening**, while the full supported-OS migration is completed under the Long-term horizon.

---

# 3. Short-term — 7 Days

| Priority | Finding | Description | Remediation Action | Owner | Estimated Cost |
|---:|---:|---|---|---|---:|
| **7** | **007** | LDAP signing is not enforced on `ad-dc-01` | Identify unsigned LDAP clients, remediate them, then enforce **Require signing** through controlled Group Policy across the domain controllers | IT + Security | **$1,000** |
| **8** | **010** | BD Alaris CVE mapping requires version validation; pump estate remains under-isolated | Verify exact PCU/Systems Manager versions with BD and enforce an Alaris-only VLAN/ACL policy with vendor-required flows only | Clinical + Vendor + IT + Security | **$6,000** |
| **9** | **005** | Missing security patches on `ad-dc-02` | Test and install current supported Windows Server security updates during a controlled AD maintenance window | IT | **$1,000** |
| **10** | **008** | PrintNightmare-class weakness on EOL `print-srv-01` | Apply the safest available vendor-supported mitigation/patch, restrict print service reachability and begin replacement planning | IT + Security | **$2,000** |
| **11** | **015** | `NAS-01` DSM management ports 5000/5001 reachable broadly | Restrict DSM management to approved admin hosts/management zone and verify backup operations still function | IT + Security | **$500** |
| **12** | **030** | NAS administrative login surface reachable broadly | Close with Finding 015 by source-restricting administrative access and reviewing administrator authentication | IT + Security | **$0 incremental** |
| **13** | **006** | MySQL 3306 on `billing-srv-01` unnecessarily reachable across the internal network | Firewall MySQL so only the billing application and approved administration sources can connect | IT + Security | **$500** |
| **14** | **028** | Undocumented Linux host `10.10.2.99` operating on the production network | Identify owner/purpose within 7 days; register and secure it or isolate/remove it if unauthorized | IT + Security | **$500** |

**Short-term spend:** **$11,500**

---

# 4. Medium-term — 30 Days

| Priority | Finding | Description | Remediation Action | Owner | Estimated Cost |
|---:|---:|---|---|---|---:|
| **15** | **016** | Unauthenticated Philips IntelliVue web-management exposure | Validate the interface, restrict management access to approved clinical/admin systems and remove unnecessary unauthenticated exposure | Clinical + Vendor + IT + Security | **$4,000** |
| **16** | **024** | Philips monitor-to-EHR / HL7 traffic insufficiently protected on the flat network | Validate message direction and required endpoints, then protect the interface with segmentation and vendor-supported secure transport/access controls | Clinical + Vendor + IT + Security | **$8,000** |
| **17** | **013** | SMBv1 enabled on Active Directory infrastructure | Confirm no required legacy clinical dependency, then disable SMBv1 or tightly restrict the remaining dependency until it is removed | IT + Security | **$1,000** |
| **18** | **019** | TLS 1.0 / weak ciphers enabled on `ehr-srv-01` | Disable TLS 1.0 and weak cipher suites after compatibility testing and enforce the approved TLS baseline | IT + Vendor + Security | **$1,000** |
| **19** | **017** | Tomcat product/version disclosure on the EHR server | Suppress unnecessary server/version disclosure and review exposed Tomcat connectors/services for business need | IT + Vendor | **$500** |
| **20** | **018** | HSTS missing on the EHR web stack | Enable HSTS after HTTPS-only validation and application regression testing | IT + Vendor | **$500** |
| **21** | **027** | Internet-facing web/patient-portal information disclosure and directory-listing behaviour | Disable directory listing and unnecessary product/version disclosure; retest the public service after the change | IT + Security | **$1,000** |
| **22** | **025** | DNS zone transfer permitted more broadly than required on `ad-dc-01` | Permit AXFR only to explicitly authorised secondary DNS systems and verify transfer functionality | IT + Security | **$500** |
| **23** | **021** | `ad-dc-02` security events are not centrally forwarded | Configure Windows Event Forwarding for priority AD/security events and assign Security review/alert ownership | IT + Security | **$1,000** |

**Medium-term spend:** **$17,500**

---

# 5. Long-term — 90 Days

| Priority | Finding | Description | Remediation Action | Owner | Estimated Cost |
|---:|---:|---|---|---|---:|
| **24** | **011** | `billing-srv-01` remains on Ubuntu 18.04 without an acceptable supported security-maintenance path | Build/test a supported Ubuntu LTS replacement, migrate the billing workload through a controlled parallel cutover and retire/isolate the old host | IT + Vendor | **$18,000** |
| **25** | **026** | Outdated 4.15 kernel on the billing server | Close through the Finding 011 supported-OS migration; verify the replacement host runs a currently supported kernel | IT + Vendor | **$0 incremental** |
| **26** | **014** | Westside Clinic relies on a consumer router for enterprise site/VPN connectivity | Replace the consumer router with an enterprise-managed firewall/security gateway, migrate the VPN and enforce least-privilege site rules | IT + Security + Vendor | **$15,000** |

**Long-term spend:** **$33,000**

---

# 6. Priority Matrix Summary

| Horizon | Findings | Count | Planned Cost |
|---|---|---:|---:|
| **Immediate — 24–48h** | 004, 003, 001, 002, 009, 012 | **6** | **$9,000** |
| **Short-term — 7d** | 007, 010, 005, 008, 015, 030, 006, 028 | **8** | **$11,500** |
| **Medium-term — 30d** | 016, 024, 013, 019, 017, 018, 027, 025, 021 | **9** | **$17,500** |
| **Long-term — 90d** | 011, 026, 014 | **3** | **$33,000** |
| **Total** | **All Actionable T16 findings** | **26** | **$71,000** |

---

# 7. Budget Summary

## 7.1 Task 20 Remediation Cost

The **gross planning cost of the complete Task 20 remediation matrix is $71,000**.

That amount by itself is below the **$120,000 annual security budget** established in Project 1x00. However, Task 20 is not a fresh budget operating in isolation. Project 1x00 already allocated **$91,000** to the seven Critical risk treatments, so the two plans must be reconciled instead of simply adding $71,000 and double-counting the same work.

## 7.2 Work Already Funded in the 1x00 Plan

The following Task 20 costs are implementation pieces of controls that already have a Project 1x00 planning allocation:

| Existing 1x00 Programme | Task 20 Findings Covered | Task 20 Cost Already Inside Existing Programme |
|---|---|---:|
| **GAP-006 — MRI compensating isolation** | 004, 012 | **$7,000** |
| **GAP-003 — Medical-IoT isolation/monitoring** | 010, 016, 024 | **$18,000** |
| **GAP-014 — Westside enterprise firewall** | 014 | **$15,000** |
| **GAP-001 — Internal segmentation / least network privilege** | 003, 006, 015, 030 | **$1,500** |
| **GAP-010 — Patient-portal remediation/testing programme** | 027 hardening work on the same public service | **$1,000** |
| **Total Task 20 overlap with existing 1x00 programme** |  | **$42,500** |

Therefore:

```text
Existing Project 1x00 annual allocation:          $91,000
Task 20 gross remediation programme:              $71,000
Less Task 20 work already funded in 1x00:        -$42,500
----------------------------------------------------------
Combined deduplicated annual requirement:         $119,500
Annual security budget:                           $120,000
Remaining headroom:                                   $500
```

The combined plan therefore **fits the $120,000 annual budget, but only narrowly**.

## 7.3 What Must Be Deferred?

**None of the 26 Actionable Task 16 findings is removed from the four-horizon remediation schedule.** The deduplicated plan fits within the annual security budget.

What **is deferred** is work beyond the finding-level remediation needed to close this queue:

- **Permanent replacement/modernisation of the Windows XP MRI control platform** is deferred to a future capital cycle. Finding 004 is treated now through the funded $7,000 isolation/compensating-control programme; replacing the certified clinical platform is a materially larger capital decision.
- **Broader monitoring expansion beyond the specific Finding 021 Windows Event Forwarding action** must wait for savings, contingency funding or the next budget cycle.
- **Additional modernization not required to close the 26 Actionable findings** must not consume the remaining **$500** contingency.

The reason is simple: after the previously approved Project 1x00 programme and the additional vulnerability-specific work are deduplicated, MedDefense has only **$500 of uncommitted annual security budget remaining**. The priority is therefore to complete the documented Critical/High-risk remediation safely rather than begin new projects that cannot be funded through completion.

---

# 8. Monday-Morning Execution Order

**Today / next 48 hours:** isolate the MRI workstation, restrict the EHR database, patch the billing Apache stack, remove SSH password authentication and contain SMBv1 on the MRI environment.

**By Friday / 7 days:** enforce LDAP signing after client discovery, validate/isolate Alaris, patch `ad-dc-02`, contain the print server, restrict NAS/MySQL administration paths and resolve the Shadow IT host.

**By month-end / 30 days:** finish Philips/HL7 controls, remove remaining SMBv1 dependency from AD, harden EHR TLS/Tomcat/HSTS, harden the Internet-facing web service, restrict DNS zone transfers and start central AD event forwarding.

**By quarter-end / 90 days:** complete the supported billing-server migration, which also closes the outdated-kernel finding, and replace the Westside consumer router with an enterprise security gateway.

---

# Sources

## Project 1x02

- `16-triage.md`
- `19-remediation_map.md`
- Supporting Tasks 1–15 used by the triage/remediation analyses

## Project 1x00

- `14-risk_decisions.md`
- `16-security_posture_assessment.md`
- Asset Registry, Criticality Assessment, Complete Control Matrix and Gap Analysis
