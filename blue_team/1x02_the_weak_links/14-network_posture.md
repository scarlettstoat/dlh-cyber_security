# 14. The Network Posture

**Project:** `1x02_the_weak_links`  
**Goal:** Quantify how MedDefense's flat network amplifies the effective risk of vulnerabilities identified in the scan.  
**Repository path:** `blue_team/1x02_the_weak_links/14-network_posture.md`  
**Assessment date:** 16 September 2026

---

## 1. Analysis Method

The scan and Asset Registry confirm that Central uses separate addressing ranges for workstations (`10.10.1.0/24`), servers (`10.10.2.0/24`) and medical devices (`10.10.3.0/24`), but these are **addressing conventions rather than enforced security zones**. There is no effective VLAN/firewall separation between them, and testing showed that an internal workstation could reach every internal subnet.

For this task, **Scenario A** therefore follows the project assumption that an attacker with an internal foothold can route broadly across the `10.10.0.0/16` environment, subject to any host-level or service-level controls that may still exist. **Scenario B** assumes those `/24` ranges are actually enforced as security VLANs with default-deny inter-VLAN firewall rules and only explicitly required traffic permitted.

A `/16` contains **65,536 IPv4 addresses**, while a `/24` contains **256**. At the address-space level, removing segmentation can therefore make the potentially reachable network **up to 256 times larger** than a single `/24`. This does **not** mean the probability of exploitation is literally 256 times higher: the scan saw 47 responsive hosts, and actual reachability depends on listening services, host firewalls and credentials. The figure is used here as a simple measure of how much the network boundary has expanded.

Three CVEs were selected because they affect three different MedDefense environments:

| CVE | Scan Finding | Affected System | Scan CVSS | Why Selected |
|---|---:|---|---:|---|
| **CVE-2021-44790** | 001 | `billing-srv-01` — A-004 | **9.8** | Server-side RCE-class weakness; compromise can become a general internal foothold |
| **CVE-2019-0708** | 004 | `WS-RAD-01` — A-022 | **9.8** | Weaponized RDP RCE on an unsupported MRI control workstation |
| **CVE-2020-25165** | 010 | BD Alaris infusion-pump estate — A-032 | **7.5** | Network-reachable availability weakness affecting a Critical clinical-device estate |

---

# 2. Segmentation Impact Analysis

## CVE-2021-44790 — Apache `mod_lua` Buffer Overflow

```text
CVE: CVE-2021-44790

Host:
billing-srv-01 — 10.10.2.15
Asset Registry: A-004
Role: Billing and insurance-claims server

CVSS Base Score from Scan:
9.8 — Critical


Scenario A: Current (flat network)

Who can reach this vulnerability:
At the network-architecture level, systems across MedDefense's internal
10.10.0.0/16 environment can route toward the Central server range because
there is no enforced VLAN/firewall boundary between workstation, server and
medical-device addressing ranges.

This means that an attacker does not have to compromise another server in
10.10.2.0/24 first. A foothold on a user workstation, another server, a
poorly isolated clinical system, or another trusted internal path can attempt
to reach billing-srv-01 directly if the Apache service accepts the traffic.

The flat design therefore turns many possible internal footholds into
potential source points for attacking this server.

What the attacker can reach AFTER exploitation:
Successful exploitation could provide code execution in the Apache process
on billing-srv-01. The scan also reports Finding 002 / CVE-2019-0211 on the
same host, which could potentially turn an Apache foothold into root-level
control.

Once the server is compromised, the attacker is still inside the same broadly
connected environment. From billing-srv-01 the attacker can perform discovery
and attempt lateral movement toward:

- ehr-srv-01 and ehr-db-01;
- ad-dc-01 / ad-dc-02;
- backup-srv-01 and NAS-01;
- PACS and other clinical servers;
- the workstation estate; and
- medical-device networks, including the Alaris and monitoring estates.

The vulnerability therefore creates more than a billing-server problem.
It can become an intermediate foothold in the same discovery -> credential
access -> lateral movement pattern used in the Project 1x01 ransomware
kill chains.

Effective Risk:
CRITICAL.

The CVSS score is already Critical, but the flat network increases the
organisational consequence because successful exploitation is not naturally
contained to Finance/Billing. A compromised business server can become a
stepping stone toward MedDefense's Critical clinical and identity systems.


Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the billing/server VLAN, plus any explicitly authorised
application or administration paths allowed through an inter-VLAN firewall.

Ordinary user workstations and medical devices would not be able to initiate
connections directly to the vulnerable Apache service unless there were a
documented business requirement.

What the attacker can reach AFTER exploitation:
The attacker could still compromise billing-srv-01 and any systems exposed
inside the same security zone. However, reaching the EHR, Active Directory,
backup infrastructure or medical-device networks would require a second
control failure:

- an allowed firewall path;
- compromised credentials for an authorised management route;
- exploitation of a firewall-exposed service; or
- another pivot host with access to the destination zone.

The attacker therefore has to defeat an additional security boundary before
the billing foothold becomes an enterprise-wide compromise.

Effective Risk:
HIGH.

The vulnerability itself remains serious and still needs patching. Segmentation
does not change its 9.8 CVSS Base score. What changes is the environmental
risk: the likely blast radius is reduced from the wider MedDefense network to
the billing/server security zone.


Risk Amplification Factor:
VERY HIGH.

At the simple address-space level, the reachable network expands from one
/24 (256 addresses) to the /16 (65,536 addresses): up to a 256x increase in
potential network scope.

More importantly, the flat network changes the post-exploitation role of the
vulnerability. Instead of "compromise billing-srv-01," the realistic outcome
becomes "compromise billing-srv-01 and attempt movement toward EHR, AD,
backups and clinical systems."

Related MedDefense gaps:
GAP-001, GAP-011, GAP-016.
```

### Segmentation effect

For CVE-2021-44790, segmentation does not make Apache safe. It makes the **failure containable**. This distinction is important because patching removes one known entry path, while segmentation limits the damage from this CVE, a future Apache vulnerability, stolen credentials, or another compromise of the same host.

---

## CVE-2019-0708 — BlueKeep RDP Remote Code Execution

```text
CVE: CVE-2019-0708

Host:
WS-RAD-01 — 10.10.1.70
Asset Registry: A-022
Role: Windows XP SP3 MRI control workstation

CVSS Base Score from Scan:
9.8 — Critical


Scenario A: Current (flat network)

Who can reach this vulnerability:
The scan reports RDP on TCP/3389 on WS-RAD-01. Because Central does not
enforce separation between its internal addressing ranges, an attacker with
a foothold elsewhere in 10.10.0.0/16 can potentially route toward the MRI
control workstation instead of first entering a dedicated Radiology security
zone.

The source of that foothold could be a compromised workstation, server,
remote-access session or another internal system. The workstation is therefore
exposed to a much larger internal attacker population than would be necessary
for normal MRI operation.

What the attacker can reach AFTER exploitation:
BlueKeep can provide remote code execution on the legacy Windows workstation.
Because WS-RAD-01 is not isolated from the rest of MedDefense, a successful
compromise can be followed by:

- reconnaissance of other workstation and server ranges;
- attempts to reach PACS and imaging systems;
- credential collection or reuse;
- attempts against Active Directory;
- scanning of other legacy or medical systems; and
- movement toward other reachable Central services.

The result can therefore progress from compromise of one MRI control endpoint
to a broader internal foothold. This is especially dangerous because the
workstation is an unsupported Windows XP system and mature public exploitation
tooling exists.

Effective Risk:
CRITICAL.

The immediate concern is patient-care and imaging availability, but the flat
network also makes the vulnerable MRI workstation useful as a lateral-movement
platform. The unsupported endpoint is therefore a risk to both Radiology and
the wider MedDefense environment.


Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the same MRI/Radiology VLAN, or preferably an even narrower
dedicated MRI security zone. The firewall would allow only the traffic needed
for clinical operation, such as explicitly required PACS communication and
approved management access.

Normal user workstations, unrelated servers and other medical-device zones
would not be permitted to initiate RDP or SMB connections to WS-RAD-01.

What the attacker can reach AFTER exploitation:
An attacker who compromises WS-RAD-01 can still affect the workstation and
the MRI workflow. They may also attempt attacks against any systems allowed
inside the same Radiology zone.

However, direct movement toward Active Directory, general servers, backups,
user workstations and unrelated medical-device networks would be blocked by
default. The attacker would need to exploit an explicitly allowed path or
compromise another system that legitimately crosses the boundary.

Effective Risk:
HIGH.

The Windows XP vulnerability remains severe, and segmentation cannot make an
unsupported operating system secure. It can, however, reduce the event from
a possible organisation-wide foothold to a much more constrained clinical
system incident.


Risk Amplification Factor:
VERY HIGH.

Using the /16 versus /24 comparison, the current architecture exposes the
workstation to a potential network scope up to 256x larger than one enforced
/24.

The practical amplification is even more important than the address count:
without segmentation, a weaponized RDP exploit on an unsupported clinical
endpoint can produce a foothold with routes toward PACS, AD and other hospital
systems. With segmentation, the same successful exploit is largely contained
to the MRI/Radiology zone.

Related MedDefense gaps:
GAP-001, GAP-006, GAP-011.
```

### Segmentation effect

This is the clearest example of segmentation acting as a **compensating control**. MedDefense may not be able to safely modernise the certified MRI environment immediately, but it can reduce who is able to attack the workstation and where an attacker can go after compromise. That does not remove the underlying CVE, but it sharply reduces both exposure and blast radius.

---

## CVE-2020-25165 — BD Alaris Network Session Authentication Weakness

```text
CVE: CVE-2020-25165

Host:
BD Alaris infusion-pump estate — A-032
Addressing range: 10.10.3.0/24
Approximately 120 documented network-connected infusion pumps

CVSS Base Score from Scan:
7.5 — High


Scenario A: Current (flat network)

Who can reach this vulnerability:
The Alaris estate uses the medical-device addressing range, but that range
is not an enforced security VLAN. Workstation and server networks can route
toward the medical-device environment without passing through a dedicated
device-security boundary.

An attacker who compromises an ordinary internal workstation or server can
therefore attempt to discover and interact with the infusion-pump environment.
The attacker does not first need to compromise a purpose-built clinical
management jump host.

What the attacker can reach AFTER exploitation:
CVE-2020-25165 is different from the two RCE vulnerabilities above. Its
documented effect is an Availability impact: an unauthenticated network
attacker can interfere with affected Alaris communications and cause the
PC Unit's wireless capability to drop, forcing manual operation.

Successful exploitation does not itself provide a general-purpose operating
system foothold for lateral movement. The flat network therefore amplifies
this CVE mainly by increasing WHO can reach the vulnerable device estate,
rather than by turning a compromised pump into the same kind of pivot host
as billing-srv-01 or WS-RAD-01.

Because the estate contains roughly 120 pumps supporting medication delivery,
broad internal reachability can allow one compromised endpoint to attempt the
same disruption against multiple clinical devices.

Effective Risk:
CRITICAL in the MedDefense environment.

The Base score is 7.5 High, but the affected asset category has Critical
Integrity and Availability requirements and the devices lack effective
network isolation. A vulnerability that causes loss of connectivity/manual
operation is more serious when the entire internal environment has unnecessary
routes toward the device estate.


Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the medical-device / infusion-pump VLAN, with firewall rules
allowing the Alaris Systems Manager and explicitly approved clinical or
management systems to communicate with the pumps.

User workstations, business servers and unrelated internal devices would not
have a direct route to the vulnerable pump services.

What the attacker can reach AFTER exploitation:
A successful attack could still disrupt a reachable pump or group of pumps,
so the clinical risk does not disappear.

However, the attacker would first need to compromise a system that is already
inside the medical-device zone or one of the small number of authorised
management systems. The attack could no longer originate from almost any
ordinary internal foothold.

Because CVE-2020-25165 is primarily an Availability weakness rather than an
RCE foothold, segmentation primarily reduces attack likelihood and accessible
device count rather than containing a powerful post-exploitation pivot.

Effective Risk:
HIGH.

The vulnerability remains clinically important, but enforced device isolation
removes a major environmental multiplier by restricting the attacker
population that can reach it.


Risk Amplification Factor:
HIGH.

At the broad addressing level, removing the /24 boundary again expands the
potential source network from 256 addresses to 65,536: up to 256x more
address-space scope.

For this CVE, however, the practical amplification is lower than for the two
RCE examples because successful exploitation does not itself create a strong
lateral-movement foothold. The flat network mainly amplifies the likelihood
and scale of disruption by allowing unrelated compromised systems to reach
the pump estate.

Related MedDefense gaps:
GAP-001, GAP-003, GAP-011, GAP-018.
```

### Segmentation effect

The Alaris example shows that segmentation is not only about containing compromised servers. It can also prevent ordinary compromised endpoints from **reaching specialised clinical technology in the first place**. That matters even when the vulnerability provides denial of service rather than code execution.

---

# 3. Cross-CVE Comparison

| CVE | System | Flat-Network Effect Before Exploitation | Flat-Network Effect After Exploitation | Effective Risk: Flat | Effective Risk: Segmented | Amplification |
|---|---|---|---|---|---|---|
| **CVE-2021-44790** | `billing-srv-01` | Many internal footholds can reach the server | RCE foothold can attempt movement toward EHR, AD, backups and clinical systems | **Critical** | **High** | **Very High** |
| **CVE-2019-0708** | `WS-RAD-01` | Unrelated internal systems can reach a legacy RDP target | Compromised MRI workstation can become a wider internal pivot | **Critical** | **High** | **Very High** |
| **CVE-2020-25165** | Alaris pump estate | Unrelated internal footholds can reach clinical-device environment | Main effect is scalable clinical disruption rather than a general RCE pivot | **Critical** | **High** | **High** |

**Address-space comparison used in all three cases:** `/16 = 65,536 addresses`; `/24 = 256 addresses`; theoretical network-scope expansion = **256x**. This is a reachability illustration, not a claim that exploitation probability or business loss is mathematically 256 times greater.

---

# 4. Network Posture Summary

Across the scan report, the flat network acts as a **systemic risk multiplier** because it removes a control that should exist both **before** and **after** exploitation: before exploitation, a foothold on one workstation or server can reach vulnerable services in server, identity, backup and medical-device environments that should belong to separate trust zones; after exploitation, a compromised host can immediately become a discovery and lateral-movement platform for reaching other Critical assets. The `/16` versus `/24` comparison illustrates the scale: an enforced `/24` boundary limits the immediate network scope to 256 addresses, whereas the current `10.10.0.0/16` architecture represents up to 65,536 addresses, a 256x increase in address space, although the real number of live and reachable services is smaller. This is why **segmentation is arguably more impactful than patching any single CVE**: patching CVE-2021-44790 removes one Apache weakness, while segmentation reduces the exploitability or blast radius of that CVE, BlueKeep, the Alaris weakness, stolen credentials, future zero-days, legacy systems and vulnerabilities that have not yet been discovered. Patching and segmentation are therefore complementary rather than alternatives, but segmentation provides a cross-cutting control that reduces the effective risk of many findings at once and prevents one successful compromise from automatically becoming an organisation-wide incident.

---

# 5. Key MedDefense Cross-References

- **GAP-001 — No effective internal segmentation:** the primary architectural multiplier across all three analyses.
- **GAP-003 — Medical IoT lacks device-specific isolation and monitoring:** directly increases Alaris exposure.
- **GAP-006 — Unsupported Windows XP MRI control environment:** makes segmentation an important compensating control for `WS-RAD-01`.
- **GAP-011 — Fragmented/manual monitoring:** weakens detection of reconnaissance and east-west movement after compromise.
- **GAP-016 — No formal vulnerability and patch-management programme:** increases the chance that exploitable server weaknesses remain available long enough to be used.
- **GAP-018 — Medical/embedded credential hardening not verified:** increases the value of network reachability into device environments.

Project 1x01 repeatedly shows the same attack pattern: **initial foothold -> discovery -> credential access / privilege escalation -> lateral movement -> objective / impact**. GAP-001 is the control failure that allows the lateral-movement stage to span otherwise unrelated MedDefense systems.

---

# Sources

## MedDefense Project Evidence

- MedDefense vulnerability scan report supplied for Project 1x02
- `1-cve_ecosystem.md`
- `2-cvss_analysis.md`
- `4-exploit_hunt.md`
- `10-critical_cves.md`
- Project 1x00 `7-asset_registry.md`
- Project 1x00 `14-risk_decisions.md`
- Project 1x00 Advanced `6-compensating_controls.md`
- Project 1x01 `8-technical_vectors.md`
- Project 1x01 `9-vector_asset_matrix.md`
- Project 1x01 `10-kill_chains.md`
