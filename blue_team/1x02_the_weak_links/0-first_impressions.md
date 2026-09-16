# MedDefense Health Systems — First Impressions Summary

## 1. Scan Metadata

The supplied vulnerability assessment was performed with **OpenVAS 22.x (Greenbone Community Edition)** against **`10.10.0.0/16`**, covering MedDefense's internal subnets. The report records **47 responsive hosts** and states that the scan used the **Full and Deep** policy, with authenticated checks where credentials were available.

| Item | Detail |
|---|---|
| Scanner | OpenVAS 22.x (Greenbone Community Edition) |
| Scan date | `[Current - 5 days]` — 11 September 2026 based on the project date |
| Target | `10.10.0.0/16` — all internal subnets |
| Responsive hosts scanned | 47 |
| Scan policy | Full and Deep |
| Authentication | Authenticated where credentials were available; Linux via SSH and Windows via domain credentials |
| Medical devices | Scanned unauthenticated because credentials were not provided |
| Requested by | James Chen, Deputy CISO |
| Executed by | SecurePoint Consulting (third party) |
| Scan window | 02:00–06:00, during off-peak hours |
| Active exploitation | Not performed |

The methodology notes explicitly exclude **Microsoft O365, iPads and any assets that were offline during the scan window**. Findings are based on version detection, configuration analysis and authenticated checks rather than active exploitation. SecurePoint also notes an expected OpenVAS false-positive rate of approximately **5–10%**, so significant findings still require validation before remediation decisions are made.

## 2. Finding Distribution

The report contains **31 findings** in total.

| Severity | Count | Share of Findings |
|---|---:|---:|
| Critical | 4 | 12.9% |
| High | 7 | 22.6% |
| Medium | 11 | 35.5% |
| Low | 5 | 16.1% |
| Informational | 4 | 12.9% |
| **Total** | **31** | **100%** |

**Medium** is the largest severity category, with **11 of 31 findings**. The four Critical findings are therefore important, but they represent only part of the overall exposure visible in the report.

## 3. Asset Heat Map

The counts below treat each numbered report finding as one finding against an affected host. A finding that contains several CVEs is still counted once for the purpose of this heat map.

| Position | Host | Finding Count | Asset Registry Cross-Reference | Role |
|---|---|---:|---|---|
| 1 | `billing-srv-01` (`10.10.2.15`) | **6** | **A-004** | Billing and insurance-claims server |
| 2= | `ehr-srv-01` (`10.10.2.10`) | **4** | **A-001** | EHR application server |
| 2= | `web-srv-01` (`10.10.2.50`) | **4** | **A-011** | Hosts the public website and patient portal |
| 4 | `ad-dc-01` (`10.10.2.20`) | **3** | **A-005** | Primary Active Directory domain controller; authentication and directory services |
| 5* | `ehr-db-01` (`10.10.2.11`) | **1** | **A-002** | EHR PostgreSQL database containing patient information |

\*There is **no unique fifth-place host**. After the four hosts above, several individually named systems appear in exactly one finding. `ehr-db-01` is shown as the fifth entry because it is the first of those tied hosts to appear in the report. This tie should not be interpreted as a higher priority than the other one-finding systems.

The most obvious concentration is `billing-srv-01`, which accounts for six separate findings across its web service, database exposure, SSH configuration, operating-system support status and kernel state. `ehr-srv-01` and `web-srv-01` also show clusters rather than isolated issues.

## 4. First Observations

The **four Critical findings are spread across three systems**, but they are not evenly distributed. Two of the four Critical findings are on `billing-srv-01`, while `ehr-db-01` and the MRI control workstation `WS-RAD-01` each have one. This means the Critical category is partly concentrated around one server rather than representing four unrelated systems.

Several findings also appear connected to each other without requiring deeper CVE research. On `billing-srv-01`, Findings 001 and 002 are explicitly described as a possible chain from remote code execution to local privilege escalation. The same host also has unrestricted MySQL exposure, password-based SSH authentication, unsupported Ubuntu status and an outdated kernel. These look less like six isolated problems and more like several weaknesses accumulating on the same asset.

A similar pattern appears on the EHR application server. Finding 017 identifies Tomcat information disclosure and recommends manual verification of the AJP connector; Finding 031 is the resulting manual follow-up and confirms that the connector is active. This is a useful example of why scanner output should lead to validation rather than immediate assumptions.

`web-srv-01` has four findings involving TLS, missing HTTP security headers, certificate renewal and the TRACE method. None of those should automatically be treated as equivalent in risk, but the cluster suggests general web-server configuration and maintenance issues rather than a single isolated defect.

The Active Directory environment also has findings across several services: LDAP signing, Kerberos encryption and DNS zone transfer. Because `ad-dc-01` is **A-005**, a shared authentication dependency, this concentration is worth noting even before prioritisation begins.

One of the clearest overall patterns is that **many findings are configuration or lifecycle problems rather than single CVEs**. The report includes unrestricted network bindings, weak authentication settings, missing security headers, end-of-life operating systems, default credentials, exposed management interfaces and shadow IT. This supports the wider vulnerability-management lesson that a system can be vulnerable without having a CVE identifier.

The report also demonstrates why **CVSS base score and scanner severity are not the same thing**. Finding 020 carries a CVSS base score of 9.8 but is rated Medium by the scanner because exploitation depends on specific environmental conditions and SecurePoint considers it a possible false positive. Conversely, Finding 002 is labelled Critical in the report despite a 7.8 base score because it is presented in the context of a potential attack chain. No priority decision should therefore be made from the base score alone.

The findings also reinforce weaknesses already documented in earlier MedDefense work. Broad internal reachability is consistent with **GAP-001 — no effective internal segmentation**; the unrestricted EHR database exposure maps directly to **GAP-002**; the medical-device findings are consistent with **GAP-003** and the later device-credential concern; and the amount of outdated or unsupported software reinforces **GAP-016 — no formal vulnerability and patch-management programme**. Project 1x01 already showed why ransomware operators and opportunistic attackers benefit from these conditions, particularly after an initial foothold. These are cross-references, not final vulnerability priorities.

Two additional points stand out on the first read. First, the scan identifies **two undocumented Linux systems**, showing that vulnerability scanning is also exposing asset-inventory problems. Second, at least one finding is explicitly marked as potentially false positive, reinforcing the need for verification before remediation effort is committed.

## 5. Scan Limitations

This report is useful, but it does not provide a complete picture of MedDefense's vulnerability exposure.

- **Cloud services are excluded.** Microsoft O365 was not assessed, so the report says nothing about cloud configuration, identities, SaaS permissions or cloud-specific vulnerabilities.
- **Mobile devices are excluded.** Physician iPads were outside the scan scope.
- **Offline assets are absent.** A system that was powered off, disconnected or otherwise unavailable during the scan window may not appear at all.
- **Medical-device visibility is shallower.** Those devices were scanned without credentials, so the scanner had less configuration visibility than it had on authenticated Linux and Windows systems.
- **No active exploitation was attempted.** The scan can identify versions and configurations associated with weaknesses, but it does not prove that every reported issue can be successfully exploited in MedDefense's environment.
- **False positives remain possible.** SecurePoint estimates a 5–10% false-positive rate and recommends manual verification for high-value findings.
- **The scan is from the internal network perspective.** It does not by itself prove which services are reachable from the public Internet or how external firewall rules affect them. This is particularly important for assets such as `web-srv-01`, whose exact DMZ/security-zone placement was already unresolved in the Asset Registry.
- **It is not an application security assessment.** The methodology does not describe source-code review, authenticated business-logic testing or a specialist web-application penetration test, so issues such as authorization flaws may exist without appearing here.
- **It does not test human or physical attack paths.** Phishing, social engineering, physical access, malicious insiders and supply-chain compromise are not evaluated by this network vulnerability scan.
- **It does not establish final risk priority.** The scanner provides technical findings and severity labels, but prioritisation still requires asset criticality, exploitability, threat relevance, existing controls, documented gaps and business/clinical impact.

Overall, the report should be treated as a **starting dataset for vulnerability analysis**, not as a remediation queue. The next stage should validate individual findings and enrich them with NVD/CVSS, exploit availability, CISA KEV status and MedDefense-specific asset and threat context before final priorities are assigned.
