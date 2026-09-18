# 14. The Network Posture

**Project:** `1x02_the_weak_links`  
**Repository path:** `blue_team/1x02_the_weak_links/14-network_posture.md`

## Method

MedDefense uses `10.10.1.0/24`, `10.10.2.0/24`, and `10.10.3.0/24` as addressing ranges, but Project 1x00 established that they are not enforced security VLANs. An internal foothold can therefore route broadly across the `10.10.0.0/16` environment.

For the comparison below:

- `/16` = **65,536 addresses**
- `/24` = **256 addresses**
- theoretical address-space amplification = **65,536 / 256 = 256x**

The **256x figure describes network scope only**. It does not mean exploitation is 256 times more likely; actual risk also depends on live hosts, listening services, authentication, host firewalls, and exploit conditions.

---

## 1. CVE-2021-44790 — Apache `mod_lua` on `billing-srv-01`

```text
CVE:
CVE-2021-44790

Host:
billing-srv-01 — 10.10.2.15 — A-004

CVSS Base Score:
9.8 Critical

Scenario A: Current (flat network)

Who can reach this vulnerability:
All 10.10.0.0/16 — describe the scope:
Because MedDefense has no enforced internal segmentation, a compromised
workstation, server, clinical system, or other internal foothold can potentially
route toward billing-srv-01 if the Apache service accepts the connection.
The attacker does not first need to compromise another host in 10.10.2.0/24.

What the attacker can reach AFTER exploitation:
All other systems, describe the impact radius:
Successful exploitation can provide code execution in the Apache process.
Finding 002 / CVE-2019-0211 on the same host can then support privilege
escalation. From the compromised billing server, an attacker can perform
discovery and attempt movement toward EHR, Active Directory, backup,
workstation, PACS, and medical-device systems because the internal network
does not impose strong east-west boundaries.

Effective Risk:
Critical

Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the same VLAN:
Only systems in the billing/server VLAN and explicitly approved application or
management sources would be permitted to reach the Apache service. Ordinary
user workstations and medical-device networks would not have a direct path.

What the attacker can reach AFTER exploitation:
Only systems in the same VLAN, unless they can pivot through a firewall:
The attacker could still compromise billing-srv-01 and interact with systems
allowed inside that zone, but movement toward EHR, AD, backups, and medical
devices would require an explicitly allowed firewall path, stolen credentials,
or another pivot.

Effective Risk:
High

Risk Amplification Factor:
256x theoretical address-space scope (/16 versus /24), with Very High practical
amplification because a server RCE can become an enterprise lateral-movement
foothold on the current flat network.
```

---

## 2. CVE-2019-0708 — BlueKeep on `WS-RAD-01`

```text
CVE:
CVE-2019-0708

Host:
WS-RAD-01 — 10.10.1.70 — A-022 — Windows XP SP3 MRI control workstation

CVSS Base Score:
9.8 Critical

Scenario A: Current (flat network)

Who can reach this vulnerability:
All 10.10.0.0/16 — describe the scope:
RDP is exposed on the unsupported MRI workstation. Because Central does not
enforce VLAN/firewall separation, an attacker with a foothold elsewhere in the
internal /16 can potentially reach the RDP service instead of first entering a
dedicated Radiology security zone.

What the attacker can reach AFTER exploitation:
All other systems, describe the impact radius:
BlueKeep can provide remote code execution on the MRI workstation. From that
foothold, an attacker can perform reconnaissance, collect/reuse credentials,
attempt access to PACS and Active Directory, and scan other reachable servers,
workstations, and medical systems.

Effective Risk:
Critical

Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the same VLAN:
Only systems inside the MRI/Radiology security zone, plus explicitly approved
PACS or management paths, would be able to reach WS-RAD-01. General user and
server networks would not be able to initiate RDP/SMB connections.

What the attacker can reach AFTER exploitation:
Only systems in the same VLAN, unless they can pivot through a firewall:
A successful attacker could still disrupt the MRI workstation and interact
with systems explicitly allowed inside the Radiology zone, but direct movement
to AD, backups, unrelated servers, workstations, and medical-device networks
would be blocked by default.

Effective Risk:
High

Risk Amplification Factor:
256x theoretical address-space scope (/16 versus /24), with Very High practical
amplification because an unpatchable, weaponized RDP weakness can become a
lateral-movement platform when no internal boundary contains it.
```

---

## 3. CVE-2020-25165 — BD Alaris Network-Session Weakness

```text
CVE:
CVE-2020-25165

Host:
BD Alaris infusion-pump estate — A-032 — 10.10.3.0/24 addressing range

CVSS Base Score:
7.5 High

Applicability Note:
The scan mapped CVE-2020-25165 to the Alaris estate, but MedDefense records
software/firmware 12.1.2 and BD states that PC Unit software 12.1.1 and newer
addresses this CVE. The exact affected component/version must therefore be
validated. The network-posture comparison below describes the risk if an
affected component is present and, separately, the broader benefit of device
segmentation.

Scenario A: Current (flat network)

Who can reach this vulnerability:
All 10.10.0.0/16 — describe the scope:
The medical-device /24 is only an addressing convention, not an enforced
security VLAN. A compromised workstation or server elsewhere in MedDefense can
therefore potentially route toward the pump environment.

What the attacker can reach AFTER exploitation:
All other systems, describe the impact radius:
For CVE-2020-25165 itself, the primary effect is availability disruption rather
than a general-purpose RCE foothold. An attacker could interfere with affected
Alaris communications and force manual workflows. Because many pumps are
reachable from the broader environment, one internal foothold could attempt the
same disruption against multiple clinical devices.

Effective Risk:
Critical in MedDefense if the vulnerable condition is confirmed, because the
pump estate has Critical Availability requirements and lacks effective device
isolation.

Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability:
Only systems in the same VLAN:
Only the Alaris medical-device VLAN, Systems Manager, and explicitly approved
clinical/management systems would be allowed to communicate with the pumps.

What the attacker can reach AFTER exploitation:
Only systems in the same VLAN, unless they can pivot through a firewall:
The clinical availability risk would still exist for an affected reachable
pump, but an attacker would first need control of a system inside the device
zone or an approved management path. Ordinary user or business-server
footholds would no longer have direct reachability.

Effective Risk:
High

Risk Amplification Factor:
256x theoretical address-space scope (/16 versus /24). Practical amplification
is High rather than Very High because this CVE mainly increases the scale and
likelihood of device disruption rather than creating a powerful RCE pivot.
```

---

## Network Posture Summary

Across the entire MedDefense scan, the flat network amplifies risk both before and after exploitation: before exploitation, a foothold on one internal system can reach vulnerable services in server, clinical, identity, backup, and medical-device environments that should sit in separate trust zones; after exploitation, a compromised host can immediately become a discovery and lateral-movement platform instead of being contained. The `/16` versus `/24` comparison gives a theoretical **256x increase in address-space scope**, although that is not a 256x probability claim because only a subset of addresses are live and reachable. This is why **segmentation is arguably more impactful than patching any single CVE**: patching removes one known weakness, while segmentation reduces the reachability and blast radius of CVE-2021-44790, BlueKeep, medical-device weaknesses, stolen credentials, future zero-days, and vulnerabilities not yet discovered. Patching and segmentation remain complementary, but segmentation provides a cross-cutting control that prevents one successful compromise from automatically becoming an organization-wide incident.
