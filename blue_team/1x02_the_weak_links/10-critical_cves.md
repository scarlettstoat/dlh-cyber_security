# 10. The Critical CVEs

**Project:** `1x02_the_weak_links`  
**Goal:** Conduct a threat-informed deep analysis of the five scan findings that represent the greatest risk to MedDefense.  
**Repository path:** `blue_team/1x02_the_weak_links/10-critical_cves.md`  
**Assessment date:** 16 September 2026

---

## 1. Selection Method

The five findings were selected using more than CVSS. I considered:

- the scan severity and technical exploitability;
- public exploit maturity and CISA Known Exploited Vulnerabilities (KEV) status;
- the affected asset's CIA criticality from Project 1x00;
- MedDefense-specific network exposure;
- whether the weakness appears in a Project 1x01 kill chain;
- the threat actors most likely to use it; and
- whether the finding combines with another weakness to create a stronger attack path.

This produces a different result from simply sorting the scan by CVSS.

### Selected Findings

| Finding | Asset | Main Issue | Why It Makes the Top Five | Adjusted Priority |
|---|---|---|---|---|
| **004** | `WS-RAD-01` | Multiple mature RCE vulnerabilities on unsupported Windows XP MRI control workstation | Clinical imaging asset + flat network + weaponized KEV exploits | **Critical** |
| **003** | `ehr-db-01` | PostgreSQL reachable from the wider internal network | EHR CIA is Critical + directly appears in two kill chains | **Critical** |
| **010** | BD Alaris infusion-pump estate | CVE-2020-25165 network-session authentication weakness / DoS | Direct patient-care asset + ~120 pumps + no device isolation | **Critical** |
| **001** | `billing-srv-01` | CVE-2021-44790 Apache `mod_lua` memory corruption | Remote PoC + vulnerable component loaded + repeated compromise history + Finding 002 chain | **Critical** |
| **002** | `billing-srv-01` | CVE-2019-0211 Apache local privilege escalation | Public exploit + KEV + converts an initial foothold into root | **High** |

### Why Finding 020 and Finding 031 Were Not Selected

Two technically severe CVEs were deliberately left out of the top five after contextual validation.

- **Finding 020 / CVE-2023-38408** has an NVD CVSS score of 9.8, but exploitation depends on a forwarded `ssh-agent` reaching an attacker-controlled host. The scan itself rated the finding **Medium** and noted that the required condition may not exist at MedDefense.
- **Finding 031 / CVE-2020-1938 (Ghostcat)** is a known-exploited vulnerability, but the scan reports **Tomcat 9.0.31**, while current NVD data places affected Tomcat 9 releases below 9.0.31. The AJP service is active, but the CVE is not confirmed on the reported build.

This is why the final selection prioritizes findings with the strongest combination of **technical evidence + asset impact + MedDefense exposure**, rather than CVSS alone.

> **CWE note:** A separate Project 1x02 Task 3 CWE file is not present in the current repository snapshot. Where a CVE applies, the CWE values below use the current NVD/CISA mappings checked for this task. Finding 003 has no CVE/CWE because it is a deployment misconfiguration.

> **Exploit-score note:** Task 4 formally scored CVE-2021-44790, CVE-2008-4250 and CVE-2019-0708. Task 4 also identified public exploit material for CVE-2019-0211 but did not place it in the final five-CVE score table; the same Task 4 rubric is applied here. CVE-2020-25165 was not part of Task 4's selected set, so its score is explicitly marked as a new assessment using the same rubric.

---

# 2. Finding 004 — Unsupported Windows XP MRI Workstation

```yaml
Finding: "004"

CVE:
  - "CVE-2008-4250 — MS08-067 / Windows Server Service RCE"
  - "CVE-2019-0708 — BlueKeep / Remote Desktop Services RCE"
  - "CVE-2017-0144 — MS17-010 / SMBv1 RCE"

Host: "WS-RAD-01 — 10.10.1.70"

Asset Role: >
  A-022. Windows XP SP3 MRI control workstation used in the Radiology
  imaging workflow.

Asset Criticality:
  Category: "PACS and Medical Imaging"
  Confidentiality: "Critical"
  Integrity: "Critical"
  Availability: "High"
  Overall: "Critical"

Technical Analysis:
  Vulnerability Description: >
    Finding 004 places several remotely exploitable legacy Windows
    vulnerabilities on the same unsupported MRI control workstation.
    CVE-2008-4250 permits remote code execution through a crafted RPC
    request to the Windows Server service. CVE-2019-0708 targets Remote
    Desktop Services and can provide unauthenticated RCE through RDP.
    CVE-2017-0144 affects SMBv1 and permits remote code execution through
    specially crafted SMB traffic. The important MedDefense issue is not
    only that three old CVEs exist: mature exploitation techniques are
    available against a clinical workstation that cannot be treated like
    an ordinary supported endpoint.

  CVSS Base Score:
    CVE-2008-4250: >
      NVD has no NIST CVSS v3.x score; NVD CVSS v2 is 10.0.
      CISA-ADP now provides CVSS v3.1 9.8 Critical.
    CVE-2019-0708: "9.8 Critical — NVD CVSS v3.1"
    CVE-2017-0144: "8.8 High — current NVD CVSS v3.1"

  Exploit Availability: >
    5/5 overall. Task 4 scored CVE-2008-4250 and CVE-2019-0708 at 5/5:
    mature weaponized exploitation exists, Metasploit support is available
    and both are in CISA KEV. EternalBlue also has mature public
    exploitation history, although it was not separately scored in the
    final Task 4 table.

  CISA KEV Status:
    CVE-2008-4250: "Listed — added 20 May 2026"
    CVE-2019-0708: "Listed — added 3 November 2021"
    CVE-2017-0144: "Listed — added 10 February 2022"

  CWE:
    CVE-2008-4250: >
      CWE-94 — Improper Control of Generation of Code (NVD);
      CISA-ADP also maps CWE-119 — Improper Restriction of Operations
      within the Bounds of a Memory Buffer.
    CVE-2019-0708: "CWE-416 — Use After Free"
    CVE-2017-0144: "NVD-CWE-noinfo — current NVD does not assign a specific CWE"

Contextual Analysis:
  Network Exposure: >
    The workstation is internal, not confirmed Internet-facing. However,
    Central does not enforce security separation between its workstation,
    server and medical-device addressing ranges. RDP/3389 and SMB/445 are
    reachable services on the host, so any attacker who gains an internal
    foothold may be able to target the MRI workstation directly.

  Kill Chain Position: >
    Finding 004 is not explicitly named in any of the five Project 1x01
    Task 10 kill chains. Contextually it represents an alternative
    lateral-movement target after an attacker has entered the flat
    internal network, but that is an inference rather than a documented
    Task 10 step.

  Threat Actor: >
    Unskilled / Opportunistic Attackers are highly relevant because mature
    public exploits dramatically reduce the skill needed once network
    access exists. Ransomware Groups / Organized Crime are also relevant:
    exploitation of a legacy internal host can create persistence,
    lateral-movement opportunities or disruption of a clinical service.

  Related Findings: >
    Finding 004 is itself a compound finding containing multiple
    exploitable Windows weaknesses. Its risk is amplified by GAP-006
    (unsupported Windows XP MRI environment), GAP-001 (no effective
    internal segmentation) and GAP-011 (fragmented monitoring).

Adjusted Priority: "Critical"

Justification: >
  The technical evidence is unusually strong: multiple remotely
  exploitable legacy vulnerabilities, mature public exploitation and KEV
  confirmation exist on an unsupported Windows XP system. The affected
  asset is also part of a Critical imaging category where Confidentiality
  and Integrity are Critical. The host is not proven Internet-facing, but
  MedDefense's flat internal architecture means a single endpoint
  compromise elsewhere can create the network reachability needed to
  attack it. The combination of patient-care dependency, exploit maturity
  and lack of a modern patch path makes this an immediate containment and
  replacement problem, not simply an old-CVE cleanup task.
```

### SOC Decision

**Immediate action:** isolate `WS-RAD-01` into a tightly controlled clinical-device zone, restrict RDP/SMB to explicitly required management paths, increase monitoring and develop a supported replacement path. Normal patching alone is not an adequate long-term strategy for an unsupported Windows XP control environment.

---

# 3. Finding 003 — EHR PostgreSQL Exposed to the Wider Internal Network

```yaml
Finding: "003"

CVE: "N/A — configuration weakness"

Host: "ehr-db-01 — 10.10.2.11"

Asset Role: >
  A-002. PostgreSQL database supporting the Electronic Health Record,
  containing Restricted patient and clinical information.

Asset Criticality:
  Category: "EHR and Patient Record Systems"
  Confidentiality: "Critical"
  Integrity: "Critical"
  Availability: "Critical"
  Overall: "Critical"

Technical Analysis:
  Vulnerability Description: >
    PostgreSQL on TCP/5432 is reachable from the wider MedDefense internal
    network rather than being limited to ehr-srv-01 or a tightly defined
    application path. The scan evidence shows broad listening and access
    rules, including listen_addresses='*' and a pg_hba.conf rule covering
    the wider 10.10.0.0/16 environment. PostgreSQL is working as
    configured; the dangerous part is that the configuration exposes the
    EHR database to far more systems than necessary.

  CVSS Base Score: "N/A — no CVE, therefore no NVD CVSS Base score"

  Exploit Availability: >
    N/A. No software exploit is required for the exposure itself.
    An attacker with an internal foothold can reach the database service
    directly and then attempt stolen credentials, credential reuse,
    password attacks or other database-specific techniques.

  CISA KEV Status: "N/A — there is no CVE to list in KEV"

  CWE: "N/A — configuration/access-control exposure rather than a CVE weakness mapping"

Contextual Analysis:
  Network Exposure: >
    This is one of the clearest examples of why MedDefense's flat network
    matters. TCP/5432 is reachable from the wider internal environment
    instead of only from the EHR application tier. A compromised
    workstation, server or trusted access path can therefore attempt
    direct interaction with the database.

  Kill Chain Position: >
    Explicitly appears in two Task 10 kill chains.
    Kill Chain #1, Step 3: after phishing and credential compromise, the
    ransomware affiliate moves laterally toward the EHR and can attempt
    direct interaction with ehr-db-01 over PostgreSQL 5432.
    Kill Chain #3, Step 3: a compromised MedTech maintenance path on
    ehr-srv-01 can be used to enumerate and move toward ehr-db-01 because
    the database is reachable more broadly than required.

  Threat Actor: >
    Ransomware Groups / Organized Crime are the strongest fit. Their
    preferred vectors include phishing, stolen credentials, exploitation
    of public-facing services and trusted third-party access. Finding 003
    becomes valuable after any of those vectors produces an internal
    foothold. A malicious insider could also abuse legitimate internal
    access.

  Related Findings: >
    Finding 017 and Finding 031 concern the EHR application server's AJP
    exposure and demonstrate why application-server findings must be
    validated. Even if Finding 031 itself is not confirmed as Ghostcat,
    any successful foothold on ehr-srv-01 or another internal system is
    more dangerous because Finding 003 leaves the database broadly
    reachable. The finding maps directly to GAP-002 and is amplified by
    GAP-001 and GAP-011.

Adjusted Priority: "Critical"

Justification: >
  No CVE or CVSS score is needed to make this finding Critical. The asset
  has Critical Confidentiality, Integrity and Availability ratings, the
  service is unnecessarily reachable across a flat internal environment,
  and the exact weakness is already used as a lateral-movement step in
  two of MedDefense's five threat-informed kill chains. Direct database
  access can bypass the normal EHR application path and place Restricted
  patient information and clinical data integrity at risk. Restricting
  PostgreSQL reachability therefore breaks multiple attack paths at once.
```

### SOC Decision

**Immediate action:** restrict TCP/5432 so only explicitly required EHR application/database administration paths can reach `ehr-db-01`; enforce east-west segmentation and monitor rejected/abnormal database connection attempts.

---

# 4. Finding 010 — BD Alaris Network Session Authentication Weakness

```yaml
Finding: "010"

CVE: "CVE-2020-25165"

Host: >
  BD Alaris infusion-pump estate — A-032, approximately 120 networked
  devices in the Central medical-device environment.

Asset Role: >
  Network-connected infusion pumps supporting medication delivery and
  dosage updates during patient treatment.

Asset Criticality:
  Category: "Medication Management and Infusion Systems"
  Confidentiality: "High"
  Integrity: "Critical"
  Availability: "Critical"
  Overall: "Critical"

Technical Analysis:
  Vulnerability Description: >
    CVE-2020-25165 is an authentication weakness in communications
    between affected BD Alaris PC Units and Alaris Systems Manager.
    An unauthenticated network attacker can manipulate configuration
    headers in transit and cause the PC Unit's wireless capability to
    drop, forcing the unit into manual operation. The supplied CVSS vector
    represents an Availability-only impact, but in a hospital the loss of
    networked medication-management functionality can carry direct
    clinical consequences.

  CVSS Base Score: "7.5 High — NVD CVSS v3.1"

  Exploit Availability: >
    2/5 — newly assessed with the Task 4 rubric because Finding 010 was
    not one of Task 4's five selected CVEs. The vulnerability is
    confirmed and documented by NVD/CISA ICS material, but the earlier
    Task 4 research did not establish a verified Exploit-DB/Metasploit
    weaponized exploit or KEV listing for this CVE.

  CISA KEV Status: "Not currently listed in CISA KEV"

  CWE: "CWE-287 — Improper Authentication"

Contextual Analysis:
  Network Exposure: >
    The pump estate uses the 10.10.3.0/24 medical-device addressing
    range, but this is not an enforced security zone. Medical devices do
    not have effective device-specific isolation, so internal systems can
    reach the clinical-device environment more broadly than they should.

  Kill Chain Position: >
    Explicitly relevant to Kill Chain #5 — Insider Abuse of the Alaris
    Pump Environment. Step 3 describes an insider reaching the pump
    interfaces through the broader internal environment, while Step 4
    covers unauthorized device-management changes or disruption.
    CVE-2020-25165 provides a concrete technical Availability weakness
    within that same device environment.

  Threat Actor: >
    The clearest Task 10 actor is Insider — Malicious, using legitimate
    internal access to reach the pump environment. Opportunistic or
    ransomware actors become relevant after another compromise gives them
    internal network access, especially because the medical-device estate
    lacks effective isolation.

  Related Findings: >
    No second numbered scan finding is required for CVE-2020-25165 to
    matter. Its contextual risk is multiplied by GAP-003 (medical IoT
    isolation/monitoring), GAP-001 (flat internal network), GAP-018
    (device credential hardening not verified) and GAP-011 (fragmented
    monitoring).

Adjusted Priority: "Critical"

Justification: >
  A 7.5 CVSS score understates the organisational importance of the
  affected asset. The vulnerability is technically limited to
  Availability in its Base vector, but the affected estate supports
  medication delivery to patients at scale. Project 1x00 rates Integrity
  and Availability of medication/infusion systems as Critical, and
  Project 1x01 already places the Alaris environment inside a Critical
  attack path. Because the devices are not effectively isolated, a
  network foothold or malicious insider can reach an environment where
  service disruption may force clinical staff into manual operation.
```

### SOC Decision

**Immediate action:** validate the exact PC Unit / Systems Manager versions with Clinical Engineering, apply vendor-supported updates where required, and treat dedicated medical-IoT segmentation as part of remediation rather than relying on the software update alone.

---

# 5. Finding 001 — Apache `mod_lua` Buffer Overflow / Possible RCE

```yaml
Finding: "001"

CVE: "CVE-2021-44790"

Host: "billing-srv-01 — 10.10.2.15"

Asset Role: >
  A-004. Billing and insurance-claims server supporting Finance and
  revenue operations.

Asset Criticality:
  Category: "Administrative and Business Systems"
  Confidentiality: "High"
  Integrity: "High"
  Availability: "High"
  Overall: "High"

Technical Analysis:
  Vulnerability Description: >
    Apache HTTP Server's mod_lua multipart parser can write outside the
    intended memory buffer when it processes a specially crafted request.
    On affected Apache releases this can cause memory corruption, service
    failure and potentially arbitrary code execution. The MedDefense scan
    reports Apache 2.4.29 and confirms that mod_lua is loaded, so the
    vulnerable component is relevant rather than being inferred only from
    a version banner.

  CVSS Base Score: "9.8 Critical — NVD CVSS v3.1"

  Exploit Availability: >
    4/5 from Task 4. A verified public Exploit-DB PoC exists
    (EDB-ID 51193), but the Task 4 analysis did not treat it as a
    complete one-click weaponized shell exploit.

  CISA KEV Status: "Not currently listed in CISA KEV"

  CWE: "CWE-787 — Out-of-bounds Write"

Contextual Analysis:
  Network Exposure: >
    The vulnerability is network exploitable, but the available
    MedDefense evidence does not prove that billing-srv-01 is directly
    Internet-facing. It is reachable inside the broadly connected Central
    environment. The server also exposes other services internally, so an
    attacker who obtains any internal foothold can target it without
    crossing an enforced server-zone boundary.

  Kill Chain Position: >
    Finding 001 is not explicitly named in the five Task 10 kill chains.
    It can nevertheless serve as an alternative foothold before the
    lateral-movement stages described in those chains. That is a
    contextual inference, not a claim that Task 10 specifically used this
    CVE.

  Threat Actor: >
    Unskilled / Opportunistic Attackers are a strong fit because they use
    scanners and public exploits against known vulnerable services.
    Ransomware Groups / Organized Crime are also relevant because
    exploitation of vulnerable services is one of their preferred
    initial-access vectors.

  Related Findings: >
    Finding 001 combines directly with Finding 002 on the same host.
    Finding 001 can potentially provide execution in a low-privileged
    Apache process, while Finding 002 can elevate code already running in
    an Apache child process to the parent process's privileges, normally
    root. The server also has other configuration/lifecycle weaknesses,
    but only the verified Finding 001 -> Finding 002 relationship is used
    here as a numbered chain.

Adjusted Priority: "Critical"

Justification: >
  The asset itself is High rather than Critical, but several contextual
  factors raise the remediation priority. The vulnerability is remotely
  reachable over the network once the attacker can access the service, a
  public working PoC exists, mod_lua is confirmed loaded and a separate
  privilege-escalation vulnerability exists on the same host. Most
  importantly, billing-srv-01 has already suffered ransomware and a later
  crypto-miner compromise after rebuild. The evidence does not prove that
  CVE-2021-44790 caused either incident, but repeated compromise makes an
  unresolved Apache RCE-class weakness unacceptable.
```

### SOC Decision

**Immediate action:** patch/upgrade Apache to a supported fixed version, verify `mod_lua` necessity, validate that the vulnerable request path is removed and investigate the server's web layer as part of the recurring-compromise root-cause investigation.

---

# 6. Finding 002 — Apache Local Privilege Escalation

```yaml
Finding: "002"

CVE: "CVE-2019-0211"

Host: "billing-srv-01 — 10.10.2.15"

Asset Role: >
  A-004. Billing and insurance-claims server supporting Finance and
  revenue operations.

Asset Criticality:
  Category: "Administrative and Business Systems"
  Confidentiality: "High"
  Integrity: "High"
  Availability: "High"
  Overall: "High"

Technical Analysis:
  Vulnerability Description: >
    Apache HTTP Server 2.4.17 through 2.4.38 can allow code already
    executing in a lower-privileged Apache child process or thread to
    manipulate the shared scoreboard and execute code with the privileges
    of the parent process, commonly root. This is therefore not an
    initial remote entry vulnerability. Its value is in converting an
    existing Apache foothold into full operating-system control.

  CVSS Base Score: "7.8 High — NVD CVSS v3.1"

  Exploit Availability: >
    4/5 using the Task 4 rubric and the exploit evidence already collected
    there. Task 4 identified verified public exploit material
    (Exploit-DB EDB-ID 46676). The vulnerability is also in CISA KEV,
    but exploitation still requires prior local execution, so it is
    treated as a powerful privilege-escalation step rather than a
    standalone remote weapon.

  CISA KEV Status: >
    Listed — added 3 November 2021; federal remediation due 3 May 2022.

  CWE: "CWE-416 — Use After Free"

Contextual Analysis:
  Network Exposure: >
    The CVSS Attack Vector is Local. An attacker cannot normally exploit
    Finding 002 simply by reaching billing-srv-01 over the network. The
    attacker first needs code execution in a suitable Apache child
    process. This dependency makes the related Finding 001 particularly
    important.

  Kill Chain Position: >
    Finding 002 is not explicitly named in the five Task 10 kill chains.
    Functionally it fits between an initial server foothold and broader
    lateral movement: an attacker first compromises the web process, then
    escalates to root before harvesting credentials, altering the host or
    moving further through the flat network. This is contextual mapping,
    not a direct Task 10 reference.

  Threat Actor: >
    Ransomware Groups / Organized Crime are the strongest fit once an
    affiliate has initial code execution, because root privileges make
    credential access, persistence and lateral movement easier.
    Opportunistic attackers can also use the public exploit after gaining
    a low-privileged Apache foothold.

  Related Findings: >
    Directly related to Finding 001. The scan itself presents the two
    Apache weaknesses as a possible chain: Finding 001 can provide remote
    code execution and Finding 002 can then elevate the compromised
    Apache process to root. This relationship materially increases the
    importance of both findings.

Adjusted Priority: "High"

Justification: >
  CVE-2019-0211 is actively exploited according to KEV and public exploit
  material exists, but it requires prior code execution and therefore is
  not as urgent in isolation as the remote entry weakness in Finding 001.
  On billing-srv-01, however, the prerequisite is credible because a
  separate Apache RCE-class finding exists on the same host and the
  server has a documented history of repeated compromise. The correct SOC
  decision is therefore to remediate Findings 001 and 002 together rather
  than closing one ticket while leaving the other attack stage intact.
```

### SOC Decision

**Action:** remediate alongside Finding 001. Treat the Apache update as one change package that closes both the remote-entry and local-escalation weaknesses, then verify the resulting version/configuration rather than assuming the package installation succeeded.

---

# 7. Cross-Finding Analysis

## Attack Paths Created by the Five Findings

| Attack Path | Relevant Finding(s) | Why It Matters |
|---|---|---|
| **Internal foothold → EHR database** | **003** | Flat reachability provides direct access to the EHR database service and appears in Kill Chains #1 and #3 |
| **Legacy internal host → clinical imaging disruption** | **004** | Mature Windows exploits can turn internal reachability into compromise of a Critical imaging environment |
| **Internal/insider access → infusion-pump disruption** | **010** | Medical IoT lacks effective isolation and the asset's Availability is Critical |
| **Apache foothold → root on billing server** | **001 + 002** | Two separate findings combine into a stronger compromise chain on a repeatedly compromised host |

## Priority Summary

| Finding | CVSS Signal | Exploit Signal | Asset Criticality | Kill-Chain Relevance | Adjusted Priority |
|---|---|---|---|---|---|
| **004** | 10.0 v2 / 9.8 / 8.8 across included CVEs | **5/5; multiple KEV CVEs** | **Critical imaging** | Indirect / lateral-movement relevance | **Critical** |
| **003** | N/A | No exploit required | **Critical EHR** | **Direct: KC1 Step 3 + KC3 Step 3** | **Critical** |
| **010** | 7.5 High | **2/5 newly assessed** | **Critical medication/infusion** | **Direct: KC5 Steps 3-4** | **Critical** |
| **001** | 9.8 Critical | **4/5** | High business system | Indirect; pairs with F002 | **Critical** |
| **002** | 7.8 High | **4/5; KEV** | High business system | Post-foothold escalation; pairs with F001 | **High** |

---

# 8. SOC Manager Conclusion

The five findings show why patch decisions cannot be made from CVSS alone.

**Finding 004** deserves immediate containment because mature exploited vulnerabilities exist on an unsupported clinical imaging workstation. **Finding 003** has no CVE at all, yet it is Critical because it exposes the EHR database across the same flat network used in two documented kill chains. **Finding 010** has only a 7.5 Base score but affects medication delivery, where Availability is Critical to patient care. **Findings 001 and 002** demonstrate the value of analyzing vulnerabilities as a chain rather than independent tickets: a network-reachable Apache weakness can potentially provide a foothold and the second Apache weakness can turn that foothold into root access.

The patching decision should therefore follow this principle:

**technical severity + exploit evidence + exact exposure + asset criticality + threat path + related weaknesses = MedDefense priority**

The most urgent work is to isolate the unsupported MRI environment, restrict direct access to the EHR database, validate and remediate the Alaris estate, and patch the Apache weaknesses on `billing-srv-01` as one combined remediation package.

---

# Sources

## MedDefense Project Evidence

- Project 1x00 — `7-asset_registry.md`
- Project 1x00 — `8-criticality_assessment.md`
- Project 1x00 — `12-gap_analysis.md`
- Project 1x01 — `6-threat_actor_matrix.md`
- Project 1x01 — `10-kill_chains.md`
- Project 1x02 — `0-first_impressions.md`
- Project 1x02 — `1-cve_ecosystem.md`
- Project 1x02 — `2-cvss_analysis.md`
- Project 1x02 — `4-exploit_hunt.md`
- Project 1x02 — `6-misconfiguration_analysis.md`

## Public Vulnerability Sources

- NVD — CVE-2021-44790: https://nvd.nist.gov/vuln/detail/CVE-2021-44790
- NVD — CVE-2019-0211: https://nvd.nist.gov/vuln/detail/CVE-2019-0211
- NVD — CVE-2008-4250: https://nvd.nist.gov/vuln/detail/CVE-2008-4250
- NVD — CVE-2019-0708: https://nvd.nist.gov/vuln/detail/CVE-2019-0708
- NVD — CVE-2017-0144: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
- NVD — CVE-2020-25165: https://nvd.nist.gov/vuln/detail/CVE-2020-25165
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Exploit-DB EDB-ID 51193 — CVE-2021-44790
- Exploit-DB EDB-ID 46676 — CVE-2019-0211
- Exploit-DB / Metasploit material referenced in Task 4 for the Windows legacy vulnerabilities
