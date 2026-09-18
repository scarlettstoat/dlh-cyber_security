# 12. The Legacy Systems

**Project:** `1x02_the_weak_links`  
**Repository:** `dlh-cyber_security`  
**Path:** `blue_team/1x02_the_weak_links/12-legacy_systems.md`  
**Research date:** 18 September 2026

---

## Research Method

The vulnerability scan identifies three MedDefense systems operating outside their normal supported lifecycle:

| System | IP | Role |
|---|---|---|
| Windows XP SP3 | `10.10.1.70` | MRI Workstation (`WS-RAD-01`) |
| Windows Server 2012 R2 | `10.10.2.31` | Print Server (`print-srv-01`) |
| Ubuntu 18.04 LTS without ESM | `10.10.2.15` | Billing Server (`billing-srv-01`) |

For the NVD research I used the publication window **18 September 2024 – 18 September 2026**, searched for the relevant OS/version, restricted the result to **Critical** CVEs and checked the affected-product information rather than relying only on keywords.

A CVE modified during the last two years but originally published earlier was **not** counted as a new result.

---

# System 1 — Windows XP SP3

**Host:** `WS-RAD-01`  
**IP:** `10.10.1.70`  
**Function:** MRI control workstation

## 1. EOL Research

Windows XP SP3 reached the end of Microsoft support in **April 2014**. Microsoft no longer provides a normal security-update path for the operating system.

### NVD result

**Critical CVEs published in the last two years specifically mapped to Windows XP SP3: 0**

This does not mean Windows XP is safe. It means an operating system that has been unsupported for more than a decade is no longer receiving the same level of current vendor vulnerability research and patching as supported Windows releases.

Because the result count is zero, there are no two recent Critical CVEs to list without inventing results.

Two older Critical vulnerabilities that are already directly relevant to the MedDefense scan are:

| CVE | Issue | Relevance |
|---|---|---|
| CVE-2019-0708 | BlueKeep / RDP remote code execution | Mature remote-exploitation path against the legacy Windows workstation |
| CVE-2017-0144 | EternalBlue / SMB remote code execution | Exploits the old SMB stack exposed on the workstation |

These are **not included in the two-year NVD count**.

## 2. Permanent Exposure

An unpatched supported system is temporarily behind: a vendor patch either exists or can still be released, so the system can be brought back to a supported baseline. Windows XP is different because normal vendor security support has ended permanently.

MedDefense therefore cannot eliminate the operating-system risk through routine patching. It can only reduce the likelihood and blast radius through compensating controls until the MRI control platform is replaced.

## 3. Scan Findings

The scan identifies two findings affecting `WS-RAD-01`:

| Finding | Issue | EOL relationship |
|---|---|---|
| **004** | Multiple legacy Windows remote-exploitation paths, including mature RDP/SMB vulnerabilities | **Directly amplified by EOL.** The underlying vulnerabilities remain useful to attackers because the platform cannot be brought to a modern supported baseline. |
| **012** | SMBv1 enabled | **Closely linked to the legacy environment.** The MRI workflow may still depend on functionality that modern Windows systems have removed or disabled. |

Finding 004 is particularly serious because the attacker has several possible routes rather than a single theoretical weakness.

The vulnerabilities themselves were not *created* by EOL. EOL makes the exposure persistent because MedDefense has lost its normal remediation path.

## 4. Compensating Controls

### Controls already proposed in 1x00

The MRI scenario in 1x00 proposed:

- moving `WS-RAD-01` into a dedicated MRI/Radiology security zone;
- allowing only required PACS communication;
- allowing only explicitly approved management sources;
- blocking unrelated systems from initiating RDP or SMB connections to the MRI workstation;
- documenting the legacy-system exception, system owner and review date;
- creating a supported replacement/upgrade plan.

### Are these adequate?

**Partially.**

Isolation substantially reduces the number of systems able to exploit the workstation and limits lateral movement after compromise. However, it does not remove BlueKeep, SMBv1, EternalBlue or the unsupported Windows code itself.

I would therefore add:

- block RDP completely unless there is a confirmed operational requirement;
- restrict SMB to only the exact systems that require it;
- prevent direct Internet access;
- use a controlled management/jump host rather than normal administrator workstations;
- monitor the MRI segment for abnormal SMB/RDP activity;
- rotate legacy administrative credentials and remove unused accounts;
- maintain a tested workstation/configuration recovery method;
- establish a funded replacement project with the MRI vendor.

**Residual risk:** High until the legacy workstation is replaced.

---

# System 2 — Windows Server 2012 R2

**Host:** `print-srv-01`  
**IP:** `10.10.2.31`  
**Function:** Print server

## 1. EOL Research

Windows Server 2012 R2 left normal extended support in **October 2023**.

There is an important qualification: Microsoft still offers **Extended Security Updates (ESU)** for Windows Server 2012 R2 until **13 October 2026**. There is no evidence in the MedDefense material that `print-srv-01` is enrolled in ESU, so I treat its current state as unsupported rather than assuming it receives those patches.

### NVD result

Using the Windows Server 2012 R2 affected-product search with the two-year publication window, I identified:

**4 Critical results**

They are:

- CVE-2024-49112
- CVE-2025-47981
- CVE-2025-55234
- CVE-2026-41089

### Two most critical examples

#### CVE-2026-41089 — Windows Netlogon RCE

- **CVSS:** 9.8 Critical
- **Attack vector:** Network
- **Privileges required:** None
- **User interaction:** None

The vulnerability is a stack-based buffer overflow in Windows Netlogon that can allow an unauthenticated attacker to execute code over the network. NVD lists Windows Server 2012 R2 among the affected products.

#### CVE-2025-47981 — Windows SPNEGO Extended Negotiation RCE

- **CVSS:** 9.8 Critical
- **Attack vector:** Network
- **Privileges required:** None
- **User interaction:** None

This vulnerability is a heap-based buffer overflow in Windows SPNEGO Extended Negotiation. NVD also lists Windows Server 2012 R2 as affected.

Both are particularly important because they involve **network-based remote code execution without requiring existing privileges**.

## 2. Permanent Exposure

A supported but unpatched Windows server can normally be returned to a secure baseline by installing Microsoft's security updates. Windows Server 2012 R2 has already left normal support, so that ordinary lifecycle has ended.

Unlike Windows XP, it still has a short ESU bridge. However, ESU itself ends in October 2026, so patching is only a temporary treatment. The sustainable solution is migration to a supported server platform.

## 3. Scan Findings

| Finding | Issue | EOL relationship |
|---|---|---|
| **008** | PrintNightmare-class vulnerability on Windows Server 2012 R2 | The vulnerability itself is not caused by EOL, but an unsupported OS makes future remediation progressively harder and eventually removes the security-update path entirely. |

Finding 008 is therefore exploitable because of the vulnerable Windows printing environment, while EOL increases the likelihood that vulnerable components remain in service.

## 4. Compensating Controls

1x00 did not contain a print-server-specific compensating-control plan equivalent to the MRI treatment.

Until migration I would:

- verify whether all Print Spooler functionality is required;
- disable unnecessary spooler functionality;
- restrict print access to approved users/subnets;
- restrict management access to approved administrator systems;
- use host firewall rules to allow only required print services;
- prevent the print server from initiating unnecessary connections to critical systems;
- segment it from clinical and high-value server networks;
- monitor spooler/service creation and abnormal privileged processes;
- determine whether MedDefense is entitled to ESU and apply available security updates if it is;
- plan migration to a supported Windows Server release or managed print platform.

These measures can reduce exploitation and lateral movement, but they do not provide a long-term solution to the lifecycle problem.

---

# System 3 — Ubuntu 18.04 LTS Without ESM

**Host:** `billing-srv-01`  
**IP:** `10.10.2.15`  
**Function:** Billing and insurance claims

## 1. EOL Research

Ubuntu 18.04 LTS reached the end of its standard five-year security-maintenance period on **31 May 2023**.

### NVD result

Using the Ubuntu 18.04 operating-system CPE and the same two-year Critical/date filter:

**Critical OS-level results: 0**

That result should not be interpreted as Ubuntu 18.04 having no vulnerabilities. Linux vulnerabilities are frequently assigned to individual components such as the kernel, Apache, OpenSSH or other packages rather than directly to the Ubuntu release CPE.

Because the exact OS-CPE result is zero, there are no two Critical CVEs from this two-year result set to list.

However, the MedDefense scan already shows serious component-level vulnerabilities on this host:

| CVE | Component | Severity | Relevance |
|---|---|---:|---|
| CVE-2021-44790 | Apache `mod_lua` | 9.8 Critical | Remote code execution exposure in Finding 001 |
| CVE-2019-0211 | Apache HTTP Server | 7.8 High | Local privilege escalation in Finding 002 |

These are shown for context and **are not being counted as recent two-year Ubuntu OS-CPE results**.

## 2. Permanent Exposure

Ubuntu 18.04 without ESM no longer receives normal standard security updates, so MedDefense cannot treat it like an ordinary supported Ubuntu installation.

There is, however, still an extended-support route: Canonical provides Ubuntu Pro/ESM for Ubuntu 18.04. Enabling ESM could therefore reduce immediate exposure, but it is a temporary bridge rather than a reason to keep the server indefinitely. Migration to a supported LTS remains the durable solution.

## 3. Scan Findings

The billing server has six scan findings:

| Finding | Issue | Relationship to EOL |
|---|---|---|
| **001** | Apache `mod_lua` / CVE-2021-44790 | Application vulnerability; not caused by EOL |
| **002** | Apache privilege escalation / CVE-2019-0211 | Application vulnerability; not caused by EOL |
| **006** | MySQL TCP/3306 exposed too broadly | Configuration issue |
| **009** | SSH password authentication enabled | Configuration issue |
| **011** | Ubuntu 18.04 without ESM | **Direct lifecycle/EOL finding** |
| **026** | Linux 4.15 kernel with known vulnerabilities | **Directly connected to the outdated support/patching state** |

Not every billing vulnerability exists because the OS is EOL.

Findings 001, 002, 006 and 009 still require application or configuration remediation even after migration. Findings 011 and 026 are the findings most directly tied to the lifecycle problem.

## 4. Compensating Controls

1x00 did not contain a billing-specific legacy-system treatment equivalent to the MRI T6 plan.

While migration is prepared, MedDefense should:

- patch/upgrade Apache and verify whether `mod_lua` is required;
- disable SSH password authentication;
- restrict SSH to approved management hosts;
- restrict MySQL/3306 to systems that genuinely require access;
- activate Ubuntu Pro/ESM if immediate migration is not possible;
- apply a least-privilege host firewall policy;
- isolate the billing server from unrelated workstation and medical-device networks;
- centralize authentication, Apache and system logging;
- investigate the server for persistence because it has already shown compromise indicators;
- rebuild/migrate the workload onto a supported Ubuntu LTS.

These controls address several immediate vulnerabilities, but migration is still required to eliminate the underlying lifecycle risk.

---

# 5. Business Decision

## System to migrate first: Windows XP MRI Workstation

If MedDefense can migrate only one of the three systems next quarter, I would migrate **`WS-RAD-01`, the Windows XP MRI control environment**.

### Asset criticality

The 1x00 assessment places the PACS/Medical Imaging environment at **Critical overall criticality**, while the billing system is High and the print server is a lower-impact operational service.

The MRI platform directly supports patient imaging, so loss of integrity or availability can affect clinical operations rather than only administrative work.

### Threat exposure

The Windows XP workstation also has the strongest combination of exploitable legacy services and potential impact.

The MedDefense threat analysis identified vulnerable software, unsupported systems and internal lateral movement as realistic attack paths. An attacker who already gains a foothold elsewhere in the flat MedDefense network could attempt to reach the MRI workstation through its legacy RDP/SMB exposure.

The existing BlueKeep/EternalBlue-class attack paths also have mature public exploitation techniques, meaning the risk is operational rather than theoretical.

### Ability to buy time

This is the biggest difference between the three systems:

| System | Temporary security-support option |
|---|---|
| Windows XP SP3 | **None through the normal vendor lifecycle** |
| Windows Server 2012 R2 | ESU available until October 2026 |
| Ubuntu 18.04 | Ubuntu Pro/ESM available |

The print and billing servers therefore still have temporary mechanisms that can buy MedDefense time while migration is prepared.

Windows XP does not.

### Decision

For that reason, the MRI workstation combines:

- **Critical clinical importance**;
- mature remote-exploitation paths;
- exposure to lateral movement on the MedDefense network;
- direct patient-care consequences;
- and no sustainable vendor patch path.

The 1x00 segmentation controls should still be implemented immediately, but they **contain** the risk rather than eliminate it.

**The only durable treatment is replacement of the Windows XP MRI control environment.**

The billing server should follow quickly afterwards, using ESM and immediate Apache/SSH/MySQL remediation as temporary protection. The print server can be restricted, patched through ESU where available and migrated after the higher-impact systems.

---

# Conclusion

The scan shows why EOL should not be treated as just another vulnerability.

A normal vulnerability can potentially be removed with a patch. A lifecycle problem means the organisation is increasingly dependent on compensating controls, extended-support programmes or replacement.

For MedDefense:

- **Windows XP** is the most severe lifecycle case because no normal security-maintenance route remains.
- **Windows Server 2012 R2** is beyond normal support but still has a very short ESU bridge.
- **Ubuntu 18.04 without ESM** is outside standard support but can temporarily regain security maintenance through Ubuntu Pro.

This makes the Windows XP MRI workstation the strongest migration candidate for the next-quarter budget, while the other two systems should receive immediate compensating controls until they can also be moved to supported platforms.

---

# Sources

## NVD

- https://nvd.nist.gov/vuln/detail/CVE-2026-41089
- https://nvd.nist.gov/vuln/detail/CVE-2025-47981
- https://nvd.nist.gov/vuln/detail/CVE-2025-55234
- https://nvd.nist.gov/vuln/detail/CVE-2024-49112
- https://nvd.nist.gov/vuln/detail/CVE-2019-0708
- https://nvd.nist.gov/vuln/detail/CVE-2017-0144
- https://nvd.nist.gov/vuln/detail/CVE-2021-44790
- https://nvd.nist.gov/vuln/detail/CVE-2019-0211

## Vendor Lifecycle References

- Microsoft — Windows XP lifecycle: https://learn.microsoft.com/en-us/lifecycle/products/windows-xp
- Microsoft — Windows Server 2012/R2 end of support: https://learn.microsoft.com/en-us/lifecycle/announcements/windows-server-2012-r2-end-of-support
- Microsoft — Extended Security Updates: https://learn.microsoft.com/en-us/windows-server/get-started/extended-security-updates-overview
- Canonical — Ubuntu 18.04 end of standard support: https://ubuntu.com/blog/18-04-end-of-standard-support
- Canonical — Ubuntu Pro / ESM: https://ubuntu.com/security/esm
