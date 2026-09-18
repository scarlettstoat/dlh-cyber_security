# 13. The Web Exposure

**Project:** `1x02_the_weak_links`  
**Goal:** Analyse MedDefense's web-related scan findings according to where the affected service is exposed.  
**Repository path:** `blue_team/1x02_the_weak_links/13-web_exposure.md`  
**Assessment date:** 16 September 2026

---

## 1. Scope

The same technical weakness does not create the same risk on every host. For this task, the scan findings are grouped around the three web-exposure cases identified in the brief:

- `web-srv-01` — Internet-facing patient portal/public website;
- `NAS-01` — internal web management interface;
- `ehr-srv-01` — internal EHR application server, but reachable across MedDefense's effectively flat internal network.

The scan-derived project evidence preserves the exact IDs for **Finding 017** and **Finding 031** on `ehr-srv-01`. The exact numeric IDs for the four `web-srv-01` web-configuration findings and the NAS management-interface finding were not preserved in the retrieved project copy. I have therefore kept the scan finding descriptions without inventing IDs.

`billing-srv-01` also runs Apache and has separate CVE findings, but its direct Internet exposure has not been established. Those findings are already analysed in the CVE, exploit and Critical-CVE tasks and are not treated here as a fourth confirmed Internet-facing web host.

---

# 2. Host Analysis

## Host 1 — `web-srv-01` (`10.10.2.50`)

```text
Host: web-srv-01 — 10.10.2.50

Exposure:
Internet-facing.

The host provides the MedDefense public website and patient portal. Earlier
architecture material described it as a DMZ host, although the scan places
it in the 10.10.2.0/24 Central server addressing range. The exact VLAN /
firewall separation therefore still requires verification.

Findings:
- Obsolete TLS protocol support: TLS 1.0 remains enabled alongside TLS 1.2.
- Missing HTTP security headers.
- TLS certificate renewal / certificate-lifecycle issue.
- HTTP TRACE method enabled.

Combined Risk:
These are mostly configuration and hardening weaknesses rather than one
single Critical exploit, but their importance increases because they occur
together on an Internet-facing system that handles patient authentication
and Restricted health information.

TLS 1.0 weakens the transport-security baseline. Missing security headers
reduce browser-side defensive controls. TRACE provides an unnecessary HTTP
method that expands the exposed surface. The certificate issue creates a
separate trust and availability concern if renewal is not handled correctly.

The combined risk is therefore greater than treating each scanner line as
an isolated low- or medium-severity item. The same host is continuously
reachable by external scanners and has a documented history of a patient-
portal authorisation incident and public-website defacement. Those incidents
are contextual evidence rather than additional scan findings.

Attack Scenario:
An opportunistic attacker or hacktivist can enumerate the Internet-facing
service without first compromising another MedDefense host. The attacker
identifies the supported TLS versions, allowed HTTP methods, response
headers and application behaviour, then uses that information to focus
testing on the patient portal and public website.

The four scan findings do not themselves prove a direct compromise chain.
Their value to an attacker is that they reduce uncertainty and reveal a
weaker web-security baseline. If a separate application weakness such as
broken authorisation, an exposed administrative function or a vulnerable
component exists, the attacker already has a directly reachable route to it.

If web-srv-01 is not actually isolated in an enforced DMZ, a successful
web foothold could then become the initial-access stage of the lateral-
movement pattern described throughout Project 1x01: foothold -> discovery
-> credential access -> movement toward more valuable internal systems.
GAP-001 makes that possibility more serious, while GAP-010 and GAP-016
show that the patient portal and exposed-system vulnerability process
already require stronger control.

Relevant Threats / Gaps:
- Unskilled / Opportunistic Attackers — automated scanning and public
  exploit use.
- Hacktivists — public website / patient-portal disruption or defacement.
- Ransomware Groups / Organized Crime — exploitation of public-facing
  services as a possible initial-access vector.
- GAP-001 — no effective internal segmentation.
- GAP-010 — patient-portal authorisation weakness / remediation assurance.
- GAP-016 — vulnerability and patch-management weakness.
- GAP-019 — obsolete TLS support on the patient portal.

Priority:
1st of the three web hosts.

This host should be addressed first because it is directly Internet-facing,
continuously reachable without a prior internal foothold and processes
Restricted patient information. The immediate objective is to harden the
public service and also verify that the claimed DMZ separation is actually
enforced.
```

### Recommended remediation direction

Disable obsolete TLS versions and enforce the approved modern TLS baseline; add the required security headers; disable TRACE unless there is a documented requirement; fix the certificate-renewal process; verify the patient portal's application-level authorisation separately; and confirm that `web-srv-01` is genuinely isolated from the internal network by firewall policy rather than only by naming or addressing convention.

---

## Host 2 — `NAS-01` (`10.10.2.41`)

```text
Host: NAS-01 — 10.10.2.41

Exposure:
Internal-only management interface, but reachable from the wider internal
network.

Findings:
- Synology DSM web management interfaces on TCP/5000 and TCP/5001 are
  reachable network-wide instead of being restricted to authorised
  administration systems or a dedicated management segment.

Finding ID:
Exact numeric ID not preserved in the current retrieved scan evidence;
verify against the original scan before final submission if numeric
traceability is required.

Combined Risk:
The management interface is not proven Internet-facing, which lowers direct
external exposure. However, NAS-01 stores MedDefense's local Veeam backup
copies, so the impact of compromise is unusually high.

The main weakness is not simply that a web interface exists. It is that a
recovery-critical administrative interface is reachable by any attacker
who first obtains an internal foothold. In MedDefense's flat network, the
difference between "internal-only" and "well isolated" is substantial.

A compromised workstation, server or VPN session can directly reach the
NAS management plane. Stolen administrative credentials, credential reuse,
or a future/current DSM vulnerability could then be used to alter
configuration, delete backups or interfere with recovery.

Attack Scenario:
This maps directly to Project 1x01 Kill Chain #2 — VPN Entry to Backup
Neutralisation.

1. The attacker obtains an external foothold through a VPN/perimeter
   weakness or valid credentials.
2. The attacker performs internal discovery.
3. Because GAP-001 allows broad east-west reachability, the attacker
   discovers NAS-01 on TCP/5000 and TCP/5001.
4. The attacker obtains or reuses privileged credentials, or exploits an
   applicable weakness in the management plane.
5. The attacker changes, deletes or disables backup data before production
   ransomware is deployed.

The result is not merely compromise of one web interface. It can remove or
degrade MedDefense's recovery capability at the exact point it is needed.

Relevant Threats / Gaps:
- Ransomware Groups / Organized Crime — backup infrastructure is a deliberate
  target before encryption.
- GAP-001 — no effective internal segmentation.
- GAP-007 — incomplete privileged-access / MFA protection increases the
  value of stolen administrative credentials.
- GAP-008 — production and recovery infrastructure are concentrated in the
  same local environment.
- GAP-011 — fragmented monitoring can delay detection of administrative
  abuse.

Priority:
2nd of the three web hosts.

It is not exposed directly to the Internet, so an attacker generally needs
a prior foothold. Once that foothold exists, however, the broad internal
management exposure can convert an ordinary compromise into a much more
damaging ransomware event by attacking recovery itself.
```

### Recommended remediation direction

Restrict TCP/5000 and TCP/5001 to dedicated administration systems or a management segment; apply least-privilege firewall rules; require strong administrator authentication; verify the exact DSM build and patch status; monitor administrative changes; and separate or protect backup copies so compromise of the production network does not automatically expose the recovery plane.

---

## Host 3 — `ehr-srv-01` (`10.10.2.10`)

```text
Host: ehr-srv-01 — 10.10.2.10

Exposure:
Internal, but accessible within MedDefense's effectively flat internal
network.

Findings:
- Finding 017 — Apache Tomcat information / version disclosure.
- Finding 031 — CVE-2020-1938 (Ghostcat) reported after SecurePoint manually
  investigated the Tomcat / AJP exposure and confirmed the AJP connector on
  TCP/8009 was active.

Important validation note:
Finding 031 should not currently be treated as a confirmed Ghostcat
vulnerability. The scan reports Tomcat 9.0.31, while the current affected
Tomcat 9 range for CVE-2020-1938 ends before 9.0.31. The active AJP service
is still a real attack-surface and hardening concern, but the specific CVE
requires exact build/configuration validation.

Combined Risk:
The EHR server is not presented as a normal public Internet-facing web
server, but its internal exposure cannot be treated as low risk.

Finding 017 gives an attacker useful technology and version information.
The manual follow-up also revealed that an additional application connector
(AJP on TCP/8009) was active. Even if Finding 031 ultimately closes as a
false positive for Ghostcat, the investigation still discovered a service
that should be justified, restricted and monitored.

The importance of the host also changes the risk calculation. ehr-srv-01
supports MedDefense's EHR, where loss of Confidentiality, Integrity or
Availability can directly affect patient care. GAP-001 means that a
compromised internal endpoint is not strongly separated from this server.

Attack Scenario:
A realistic path starts with a separate initial foothold rather than a
direct Internet attack.

One example is the Project 1x01 trusted-vendor / supply-chain kill chain:

1. An attacker compromises a MedTech engineer, credential or maintenance
   system.
2. Legitimate-looking vendor access reaches ehr-srv-01.
3. The attacker enumerates the web application and Tomcat environment.
4. Finding 017 provides product/version information and the AJP follow-up
   reveals another listening application service.
5. The attacker checks those details against known vulnerabilities and
   attempts only weaknesses that actually match the installed build and
   configuration.
6. If server access is obtained, GAP-001 and GAP-002 make movement toward
   ehr-db-01 and other internal services easier.

The same internal targeting could follow an ordinary ransomware or phishing
foothold. The important point is that "internal" does not mean "isolated"
in MedDefense's current architecture.

Relevant Threats / Gaps:
- Ransomware Groups / Organized Crime — known-vulnerability exploitation
  after initial access.
- Unskilled / Opportunistic Attackers — relevant once internal reachability
  is obtained and version information identifies known attack options.
- Nation-State APT — the 1x01 vendor/supply-chain scenario provides a
  plausible route to the EHR environment.
- GAP-001 — no effective internal segmentation.
- GAP-002 — EHR database reachable more broadly than necessary.
- GAP-007 — vendor / privileged-access controls require improvement.
- GAP-011 — fragmented monitoring.
- GAP-016 — vulnerability and patch-management weakness.

Priority:
3rd of the three web hosts for remediation after immediate validation.

Finding 031 must be validated promptly because a genuine Ghostcat exposure
on the EHR would materially change this order. With the currently reported
Tomcat 9.0.31 build, however, Ghostcat appears inapplicable, so the present
work is to close or correct the false-positive CVE record, remove unnecessary
AJP exposure and reduce internal reachability rather than treating the host
as a confirmed 9.8 exploit.
```

### Recommended remediation direction

Confirm the exact Tomcat build and running instance; review `server.xml`; disable AJP if the EHR does not require it; otherwise bind/restrict it to only necessary systems and require the appropriate authentication/secret controls; suppress unnecessary version disclosure; and place the EHR application tier behind enforced segmentation rather than relying on internal addressing alone.

---

# 3. Relative Web-Exposure Priority

| Relative Priority | Host | Exposure | Why |
|---:|---|---|---|
| **1** | `web-srv-01` | Internet-facing | External attackers can reach it directly; it hosts the patient portal, handles Restricted data and has several web-hardening weaknesses. |
| **2** | `NAS-01` | Internal-only, broadly reachable | Requires a prior foothold, but exposes the management plane of recovery-critical backup storage and maps directly to the ransomware backup-neutralisation kill chain. |
| **3** | `ehr-srv-01` | Internal but flat-network accessible | Extremely important asset, but the most severe reported web CVE currently appears inapplicable to the reported Tomcat build. It still requires urgent validation and AJP hardening. |

This order is based on the **current validated evidence**, not on asset importance alone. If `ehr-srv-01` were found to be running a genuinely vulnerable Tomcat build, or if `NAS-01` were discovered to be Internet-reachable, the priority order would need to be reassessed immediately.

---

# 4. What Finding 017 Teaches About "Medium" Information-Disclosure Findings

Finding 017 is a good example of why a Medium finding should not automatically be treated as low-value work.

The first result was **information disclosure**: Tomcat exposed enough product/version detail to justify deeper investigation. SecurePoint did not stop at the severity label. They manually checked the application environment and discovered that the **AJP connector on TCP/8009 was active**, which generated Finding 031 for Ghostcat.

That investigation provides two important lessons.

First, **information is part of the attack chain**. Version numbers, frameworks, connectors, modules and server banners reduce uncertainty. Instead of blindly testing hundreds of attacks, an attacker can narrow the search to vulnerabilities that match the exposed technology. A finding that does not directly provide code execution may therefore increase the exploitability of another weakness.

Second, **Medium findings can be discovery pivots for defenders**. The value of Finding 017 was not only its standalone severity; it told the analyst what to investigate next. A version-disclosure result can reveal an unexpected service, vulnerable component, unsafe connector or configuration that the original automated check did not fully assess.

Finding 031 also shows why that deeper investigation must still end with **validation**. SecurePoint's AJP check was useful because it proved that the connector existed, but later version research showed that Tomcat 9.0.31 appears outside the affected Ghostcat range. The correct lesson is therefore not "every Medium finding hides a Critical vulnerability." It is:

**Medium findings that reveal technology or attack-surface information can justify deeper investigation, especially on Critical assets, because they may uncover a more serious exposure — but every resulting vulnerability must still be validated against the exact version and configuration.**

For MedDefense, severity should guide triage, not stop investigation.

---

# 5. Overall Conclusion

The three hosts demonstrate why **exposure changes risk**.

`web-srv-01` has the clearest external risk because the patient portal is reachable directly from the Internet. `NAS-01` is not Internet-facing, but its network-wide management interface gives any successful internal attacker a route to MedDefense's recovery infrastructure. `ehr-srv-01` is also internal, yet the flat network and the sensitivity of the EHR mean that a prior foothold can still place its Tomcat/AJP services within an attacker's reach.

The appropriate vulnerability-management question is therefore not only:

> "How severe is this finding?"

It is also:

> **"Who can reach it, what do they need first, what asset is behind it, and what can this finding help them reach next?"**

That is the difference between treating a vulnerability scan as a list of scores and using it as evidence for actual risk analysis.

---

# Sources

## MedDefense Project Evidence

- MedDefense vulnerability scan report supplied for Project 1x02
- `0-first_impressions.md`
- `1-cve_ecosystem.md`
- `4-exploit_hunt.md`
- `6-misconfiguration_analysis.md`
- `9-osint_hunt.md`
- `11-false_positives.md`
- Project 1x00 Asset Registry / Gap Analysis
- Project 1x01 Attack Surface Map / Threat Actor Matrix / Kill Chains
- Project 1x00 Advanced predecessor-review material for patient-portal TLS configuration

## Public Validation Sources Previously Used in Project 1x02

- NVD — CVE-2020-1938:  
  https://nvd.nist.gov/vuln/detail/CVE-2020-1938
- Apache Tomcat 9 Security Vulnerabilities:  
  https://tomcat.apache.org/security-9
