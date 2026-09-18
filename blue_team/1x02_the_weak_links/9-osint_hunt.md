# 9. The OSINT Hunt

**Project:** `1x02_the_weak_links`  
**Goal:** Use open-source intelligence (OSINT) to identify vulnerabilities and attack techniques relevant to MedDefense that were not identified in the automated vulnerability scan.  
**Repository path:** `blue_team/1x02_the_weak_links/9-osint_hunt.md`  
**Research date:** 16 September 2026

---

## 1. Scope and Method

The automated OpenVAS scan is useful, but it does not cover every part of the MedDefense environment. For this task, I compared the MedDefense technology stack with current public information from vendor security advisories, the National Vulnerability Database (NVD), CISA and Microsoft Threat Intelligence.

The research focused on three areas that were either outside the original scan scope or not fully fingerprinted:

- **Fortinet FortiGate 100F — A-016**
- **Microsoft O365 E3 — A-039**
- **Synology DSM 7 on `NAS-01` — A-010**

The aim is not to claim that every vulnerability below is definitely exploitable at MedDefense. Where the exact firmware, build or cloud configuration is unknown, the finding is marked as requiring validation.

---

## 2. Finding 1 — FortiGate Authentication Bypass

### CVE-2024-55591

```yaml
Source:
  - Fortinet PSIRT: https://fortiguard.fortinet.com/psirt/FG-IR-24-535
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-55591
  - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CVE: CVE-2024-55591

Affected Product:
  MedDefense Fortinet FortiGate 100F (A-016) if it is running
  FortiOS 7.0.0 through 7.0.16.

Why the Scan Missed It:
  The internal scan did not identify a management IP or exact FortiOS
  firmware version for the FortiGate. The firewall therefore was not
  assessed in the same way as the internal servers, and the scan report
  contains no finding for this CVE.

CVSS / Severity:
  Critical.
  NVD base score: 9.8.
  Fortinet advisory score: 9.6.
  CISA lists the vulnerability in the Known Exploited Vulnerabilities
  catalog.

MedDefense Impact:
  Successful exploitation can allow a remote attacker to obtain
  super-admin privileges on the FortiGate. For MedDefense, compromise of
  the Internet-edge firewall could allow an attacker to alter firewall
  policy, create or modify accounts, interfere with VPN access and gain a
  much stronger position for reaching the internal network.

Recommendation:
  Confirm the exact FortiOS version immediately. If the device is running
  FortiOS 7.0.0-7.0.16, upgrade to 7.0.17 or later using Fortinet's
  supported upgrade path. Review FortiGate administrator accounts and
  logs for indicators of compromise, restrict management access and apply
  Fortinet's documented mitigations if patching cannot be completed
  immediately.
```

### MedDefense Relevance

This is especially important because the FortiGate is **A-016**, MedDefense's Internet-edge firewall and VPN termination point. Project 1x00 already identified **GAP-016 — no formal vulnerability and patch-management programme for exposed and Critical systems**. Project 1x01 also showed that ransomware groups and opportunistic attackers actively look for vulnerable public-facing infrastructure.

This finding is **potentially applicable, not confirmed**. The hardware model alone does not prove that MedDefense is running a vulnerable FortiOS release. If the appliance is already running a non-affected branch such as FortiOS 7.2, 7.4 or 7.6, this CVE would not apply.

---

## 3. Finding 2 — Microsoft 365 Device Code Phishing

### Storm-2372 Device Code Phishing Technique

```yaml
Source:
  - Microsoft Threat Intelligence:
    https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

CVE: N/A — this is an attack technique, not a software vulnerability.

Affected Product:
  Microsoft O365 E3 / Microsoft cloud identities used by MedDefense
  (A-039). Exact MedDefense Entra ID configuration is not documented.

Why the Scan Missed It:
  Microsoft O365 was explicitly outside the scope of the internal
  OpenVAS scan. Device code phishing also targets the authentication and
  user workflow rather than a vulnerable service running on an internal
  host, so a normal infrastructure CVE scan would not identify it.

CVSS / Severity:
  CVSS: N/A.
  MedDefense assessment: High if device code authentication is enabled
  without adequate Conditional Access restrictions and monitoring.

MedDefense Impact:
  A user can be tricked into entering an attacker-generated device code
  into a legitimate Microsoft sign-in page. The attacker can then obtain
  valid authentication tokens and access resources available to the
  compromised account, including email or cloud storage. A compromised
  MedDefense mailbox could also be used for convincing internal phishing
  and further account compromise.

Recommendation:
  Block device code flow wherever it is not required. Where it is
  required, control it with Conditional Access. Require strong MFA,
  preferably phishing-resistant methods, monitor risky sign-ins and new
  device registrations, and revoke refresh tokens if compromise is
  suspected. MedDefense should also confirm how O365 identities are
  integrated with its on-premises Active Directory environment.
```

### MedDefense Relevance

Microsoft reported that device code phishing has been used successfully to steal authentication tokens and access Microsoft cloud accounts. The same campaign included **health-sector targets**, and Microsoft observed attackers using compromised accounts to search and exfiltrate email through Microsoft Graph.

For MedDefense, the key connection is **A-039 — Microsoft O365 E3**, which provides organisation-wide email, SharePoint and OneDrive. Project 1x00 already identified **GAP-007 — MFA and privileged-access controls are not broadly documented** and **GAP-011 — monitoring is fragmented**. Those gaps make cloud identity attacks more difficult to detect and contain.

This is also an important OSINT lesson: there is **no CVE to search for** because Microsoft states that the campaign abuses a legitimate authentication flow rather than exploiting a vulnerability in Microsoft's code.

---

## 4. Finding 3 — Synology DSM WebAPI Remote Code Execution

### CVE-2024-45538

```yaml
Source:
  - Synology Security Advisory:
    https://www.synology.com/en-global/security/advisory/Synology_SA_24_27
  - NVD:
    https://nvd.nist.gov/vuln/detail/CVE-2024-45538

CVE: CVE-2024-45538

Affected Product:
  Synology DiskStation Manager (DSM) used by NAS-01 (A-010).
  The vulnerability affects DSM before 7.2.1-69057-2 and
  7.2.2-72806.

Why the Scan Missed It:
  The scan identified NAS-01 as running Synology DSM 7 and found its
  management ports, but the project evidence does not record a precise
  DSM build. Without an exact build match, an automated scanner may not
  be able to determine whether this specific WebAPI vulnerability is
  applicable.

CVSS / Severity:
  9.6 — Critical.
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

MedDefense Impact:
  The vulnerability can allow remote attackers to execute arbitrary code
  through the DSM WebAPI under the vulnerable conditions. NAS-01 stores
  MedDefense's Veeam backup copies, so compromise could expose or alter
  backup data, interfere with recovery operations or allow an attacker
  to damage backup availability before a ransomware deployment.

Recommendation:
  Confirm the exact DSM build on NAS-01. If it is within an affected
  release, update to at least DSM 7.2.1-69057-2 or 7.2.2-72806 as
  appropriate. Restrict DSM management access on TCP/5000 and 5001 to
  authorised administration systems or a dedicated management segment,
  review administrator accounts and logs, and verify that backup data
  remains intact and recoverable.
```

### MedDefense Relevance

`NAS-01` is **A-010** and stores the local Veeam backup copies. Project 1x00 already recorded that its management ports **5000/5001 are reachable from the entire internal network** and that the NAS is located in the same network and physical environment as other backup infrastructure.

This ties directly to **GAP-008 — backup infrastructure concentration** and **GAP-001 — no effective internal segmentation**. Project 1x01 also identified backup systems as a deliberate ransomware target because attackers may try to damage recovery capability before encrypting production systems.

Again, applicability must be validated. "DSM 7" is not precise enough to prove that `NAS-01` is running an affected build.

---

## 5. OSINT Findings Summary

| Area | OSINT Finding | Severity | Why It Was Not in the Scan | MedDefense Validation Needed |
|---|---|---|---|---|
| FortiGate 100F | CVE-2024-55591 authentication bypass | Critical | Firewall firmware / management plane not identified in scan | Confirm FortiOS version |
| Microsoft O365 | Device code phishing / token theft | No CVSS; High MedDefense relevance | O365 was out of scope and technique targets identity/user workflow | Confirm device code policy, MFA and Conditional Access |
| Synology DSM 7 | CVE-2024-45538 WebAPI RCE | 9.6 Critical | Exact DSM build not established by scan | Confirm DSM build and patch level |

---

## 6. What the OSINT Hunt Adds to the Automated Scan

The OSINT review found three different reasons why a vulnerability assessment can be incomplete even when an automated scan is technically successful.

First, an appliance such as the **FortiGate** may be part of the environment but not have its management plane or exact firmware fingerprinted by the internal scan. Second, a cloud service such as **Microsoft O365** may be deliberately excluded from scan scope, even though identity attacks against it can still provide an attacker with access to organisational data. Third, a scanner may identify a product family such as **Synology DSM 7** without identifying the exact build needed to match a newer vendor advisory.

The important lesson is that a scanner result should be treated as **one evidence source, not a complete vulnerability inventory**. MedDefense's vulnerability-management process should combine automated scanning with vendor-advisory monitoring, NVD/CISA research, cloud and identity review, asset/version verification and manual validation of findings.

---

## Sources

- Fortinet PSIRT — FG-IR-24-535:  
  https://fortiguard.fortinet.com/psirt/FG-IR-24-535
- NVD — CVE-2024-55591:  
  https://nvd.nist.gov/vuln/detail/CVE-2024-55591
- CISA Known Exploited Vulnerabilities Catalog:  
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Microsoft Threat Intelligence — Storm-2372 device code phishing:  
  https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Synology Security Advisory — Synology-SA-24:27:  
  https://www.synology.com/en-global/security/advisory/Synology_SA_24_27
- NVD — CVE-2024-45538:  
  https://nvd.nist.gov/vuln/detail/CVE-2024-45538
