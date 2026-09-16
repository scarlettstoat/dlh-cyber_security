# 16. The Noise Filter

**Project:** `1x02_the_weak_links`  
**Goal:** Triage all 31 scan findings into action categories so that confirmed risk is separated from low-value noise and false positives.  
**Repository path:** `blue_team/1x02_the_weak_links/16-triage.md`  
**Assessment date:** 16 September 2026

---

## 1. Triage Method

This triage uses the four categories required by the assignment:

| Category | Code | Meaning | Required Action |
|---|---|---|---|
| **Actionable Critical** | **AC** | Exploitable or high-impact weakness on a critical/high-value asset where delay materially increases risk | Immediate remediation / containment within **24–48 hours** |
| **Actionable Standard** | **AS** | Real weakness requiring remediation, but not an emergency change | Planned remediation within **7–30 days** |
| **Informational** | **I** | Real observation with low direct risk or primarily monitoring/documentation value | Document, monitor, and fold into related remediation |
| **False Positive** | **FP** | The scanner's specific vulnerability conclusion does not apply in MedDefense's context | Document validation evidence and dismiss the specific finding |

The classification does **not** simply copy the scanner's severity. It incorporates the work completed in Tasks 1–15: CVSS, exploit maturity, KEV status, asset criticality, network exposure, kill-chain relevance, medical-device context and false-positive validation.

### Important validation updates applied in this triage

- **Finding 020** is treated as a **provisional FP** because CVE-2023-38408 requires a forwarded `ssh-agent`; it should only be formally closed after confirming that this workflow is not used.
- **Finding 031** is treated as an **FP for Ghostcat specifically** because the scan reports Tomcat **9.0.31**, while the affected Tomcat 9 range ends at 9.0.30. The exposed AJP service still requires hardening.
- **Finding 010** remains **Actionable Standard pending exact Alaris component/version validation**. The scan maps CVE-2020-25165 to the Alaris estate, but BD states that PC Unit software 12.1.1+ addresses that CVE, while MedDefense records 12.1.2. The broader Alaris environment still requires vendor-supported updating and segmentation.
- **Finding 025** is **not** a false positive. DNS zone transfer is a genuine configuration weakness even if other reconnaissance methods are also available.
- **Finding 023** is treated as **Informational rather than FP** because an intentionally permitted USB workflow is still a real control observation; business justification does not make the scanner observation false.

---

# 2. Complete Finding Triage

```text
Finding 001 | 9.8 / Critical | billing-srv-01 | Category: AC | Reason: Apache mod_lua memory-corruption/RCE-class weakness has a working public PoC, the vulnerable module is loaded, and the repeatedly compromised billing server sits on the flat internal network.

Finding 002 | 7.8 / Critical (scan) | billing-srv-01 | Category: AC | Reason: CVE-2019-0211 is KEV-listed and can turn an Apache-process foothold into root, directly strengthening the attack chain created by Finding 001.

Finding 003 | N/A / Critical Misconfiguration | ehr-db-01 | Category: AC | Reason: PostgreSQL is reachable from the wider internal network, exposing the Critical EHR database directly to any successful internal foothold.

Finding 004 | 10.0 / 9.8 / 8.1 / Critical | WS-RAD-01 | Category: AC | Reason: The unsupported Windows XP MRI workstation contains multiple mature remotely exploitable Windows vulnerabilities with public weaponized exploits and direct clinical-service impact.

Finding 005 | High | ad-dc-02 | Category: AS | Reason: Missing security patches on a domain controller are a genuine identity-infrastructure risk but require controlled testing and scheduled remediation rather than an unplanned emergency change.

Finding 006 | High / Misconfiguration | billing-srv-01 | Category: AS | Reason: MySQL is unnecessarily reachable across the internal network, increasing financial-data and lateral-movement exposure after any internal foothold.

Finding 007 | High / Misconfiguration | ad-dc-01 | Category: AC | Reason: LDAP signing is not enforced on the primary domain controller, creating an identity-layer relay/manipulation risk that can affect authentication across the organisation.

Finding 008 | 8.8 / High | print-srv-01 | Category: AS | Reason: The PrintNightmare-class weakness is exploitable on an EOL Windows Server 2012 R2 host, but the print server is lower impact than the EHR, AD and clinical-device assets requiring immediate containment.

Finding 009 | High / Misconfiguration | billing-srv-01 | Category: AC | Reason: Password-based SSH remains enabled on a repeatedly compromised server, providing a practical stolen-credential persistence/access path that should be closed with the emergency billing-server remediation.

Finding 010 | 7.5 / High | BD Alaris infusion-pump estate | Category: AS | Reason: The scanner's CVE-2020-25165 match needs exact version validation because MedDefense records 12.1.2, but the clinically critical Alaris estate still requires vendor-supported patch review and enforced device isolation.

Finding 011 | Medium / Lifecycle | billing-srv-01 | Category: AC | Reason: Ubuntu 18.04 without an active supported security-maintenance path leaves a repeatedly compromised server exposed to accumulating OS vulnerabilities and should be addressed with the same 24-48h containment plan.

Finding 012 | Medium | WS-RAD-01 | Category: AS | Reason: SMBv1 on the unsupported MRI workstation is a real legacy-protocol risk and requires immediate containment planning even if the device cannot be conventionally upgraded.

Finding 013 | Medium | ad-dc-01 | Category: AS | Reason: SMBv1 on identity infrastructure expands the attack surface and should be removed or tightly restricted after validating any remaining clinical dependency.

Finding 014 | Medium / Architecture | Westside router | Category: AS | Reason: A consumer-grade router performing enterprise VPN/perimeter functions is a real architecture weakness that should be replaced through planned remediation.

Finding 015 | Medium | NAS-01 | Category: AS | Reason: Synology management ports 5000/5001 are reachable broadly from the internal network, exposing ransomware-relevant backup infrastructure to any successful internal foothold.

Finding 016 | Medium | Philips IntelliVue monitors | Category: AS | Reason: Unauthenticated web access exposes medical-device information and potentially patient-monitoring data on a flat network; exact control capabilities must be validated and access restricted.

Finding 017 | Medium | ehr-srv-01 | Category: AS | Reason: Tomcat product/version disclosure is a genuine reconnaissance weakness and directly justified the deeper AJP investigation that produced Finding 031.

Finding 018 | Medium | ehr-srv-01 | Category: AS | Reason: Missing HSTS weakens browser-side transport enforcement on a Critical EHR application and should be corrected as part of web-stack hardening.

Finding 019 | Medium | ehr-srv-01 | Category: AS | Reason: TLS 1.0 / weak-cipher support unnecessarily lowers transport security on the internal EHR service and is more serious because internal traffic is not strongly segmented.

Finding 020 | 9.8 CVSS / Medium scan severity | backup-srv-01 | Category: FP | Reason: CVE-2023-38408 requires a forwarded ssh-agent workflow that the scanner did not establish; close as FP only after confirming agent forwarding is not used.

Finding 021 | Medium | ad-dc-02 | Category: AS | Reason: Missing central Windows Event Log forwarding weakens detection and incident response on identity infrastructure and should be corrected through scheduled logging improvements.

Finding 022 | Low | ad-dc-01 | Category: I | Reason: The administrator-account naming/hardening observation has limited standalone security value compared with authentication, signing and patching controls already prioritised on AD.

Finding 023 | Low | Clinical workstation estate | Category: I | Reason: USB mass-storage policy is a real control observation but requires workflow and Sophos-policy validation before deciding whether restriction is appropriate for clinical operations.

Finding 024 | Low / Medical-IoT exposure | Philips monitor-to-EHR pipeline | Category: AS | Reason: Cleartext or insufficiently protected HL7 traffic can expose patient identifiers and physiological observations on the flat network and requires interface/transport hardening.

Finding 025 | Low / Misconfiguration | ad-dc-01 | Category: AS | Reason: DNS zone transfer is a genuine unnecessary reconnaissance exposure; the existence of other enumeration methods does not make the configuration safe or false.

Finding 026 | Low / Lifecycle | billing-srv-01 | Category: AS | Reason: The outdated 4.15 kernel adds known-vulnerability exposure and should be remediated through the same OS-support/upgrade work as Finding 011.

Finding 027 | Informational | web-srv-01 / patient portal | Category: AS | Reason: Internet-facing web information disclosure and directory-listing behaviour materially assists external reconnaissance and should be corrected despite the scanner's low technical severity.

Finding 028 | Informational | 10.10.2.99 / Shadow IT Linux host | Category: AS | Reason: An undocumented Linux system on the production network is an asset-governance failure that must be identified, authorised and secured or removed.

Finding 029 | Informational | NAS-01 | Category: I | Reason: DSM version disclosure is low risk by itself; document it and remove unnecessary disclosure while the broader NAS management exposure is remediated under Findings 015/030.

Finding 030 | Informational | NAS-01 | Category: AS | Reason: A broadly reachable NAS administrative login surface increases the attackability of recovery-critical infrastructure and should be source-restricted even without a confirmed software exploit.

Finding 031 | 9.8 CVSS / High scan severity | ehr-srv-01 | Category: FP | Reason: The reported Tomcat 9.0.31 build is outside the vulnerable Tomcat 9 range for CVE-2020-1938, so Ghostcat is inapplicable if that build is confirmed; AJP exposure remains a separate hardening issue.
```

---

# 3. Triage Summary

| Category | Code | Count | Percentage |
|---|---|---:|---:|
| **Actionable Critical** | **AC** | **7** | **22.6%** |
| **Actionable Standard** | **AS** | **19** | **61.3%** |
| **Informational** | **I** | **3** | **9.7%** |
| **False Positive** | **FP** | **2** | **6.5%** |
| **Total** |  | **31** | **100%** |

### Category Membership

- **AC:** 001, 002, 003, 004, 007, 009, 011
- **AS:** 005, 006, 008, 010, 012, 013, 014, 015, 016, 017, 018, 019, 021, 024, 025, 026, 027, 028, 030
- **I:** 022, 023, 029
- **FP:** 020, 031

The relatively small FP category is deliberate. The scanner's expected 5–10% false-positive rate is **not a quota**, and findings should not be dismissed merely to reach a statistical target. Finding 020 still needs workflow confirmation before final closure, while Finding 031 has a much stronger version-applicability basis for dismissal.

---

# 4. Actionable Findings List

## Actionable Critical — Immediate Remediation / Containment (24–48 Hours)

| Priority | Finding | Host | Why It Is First-Line Work |
|---:|---:|---|---|
| **1** | **004** | `WS-RAD-01` | Unsupported clinical workstation with multiple mature remote exploits; isolate immediately because normal patching is constrained. |
| **2** | **003** | `ehr-db-01` | Critical EHR database is reachable from the wider flat network; segmentation can immediately break multiple attack paths. |
| **3** | **007** | `ad-dc-01` | Identity-layer weakness on the primary domain controller can support credential abuse and organisation-wide lateral movement. |
| **4** | **001** | `billing-srv-01` | Network-reachable Apache RCE-class weakness with public PoC on a repeatedly compromised host. |
| **5** | **002** | `billing-srv-01` | KEV-listed local privilege escalation directly compounds Finding 001 and should be patched in the same change package. |
| **6** | **011** | `billing-srv-01` | Unsupported/insufficiently maintained operating system means the host remains structurally difficult to secure even after individual CVEs are patched. |
| **7** | **009** | `billing-srv-01` | Password-based SSH provides a credential-based access/persistence path and should be removed during the emergency billing-server hardening window. |

### Immediate Work Packages

Rather than treating the AC findings as seven unrelated tickets, MedDefense should group them into three emergency work packages:

1. **MRI containment:** Findings **004 + 012** — isolate the unsupported Windows XP MRI environment and restrict RDP/SMB.
2. **EHR/identity containment:** Findings **003 + 007** — restrict database reachability and harden the identity layer.
3. **Billing rebuild/hardening:** Findings **001 + 002 + 009 + 011 + 026** — patch Apache, remove the privilege-escalation path, move away from password SSH and restore the operating system to a supported maintenance state.

---

## Actionable Standard — Scheduled Remediation (7–30 Days)

| Priority | Finding | Host / Scope | Planned Action |
|---:|---:|---|---|
| **1** | **015** | `NAS-01` | Restrict DSM management ports to authorised admin systems / management VLAN. |
| **2** | **030** | `NAS-01` | Restrict administrative login surface and strengthen backup-management access controls. |
| **3** | **010** | BD Alaris estate | Validate exact PCU/Systems Manager versions with Clinical Engineering; apply BD-approved updates and isolation controls. |
| **4** | **016** | Philips IntelliVue | Validate the unauthenticated web interface and restrict medical-monitor management access. |
| **5** | **024** | Philips / HL7 pipeline | Validate message direction/authentication and protect clinical-data transport. |
| **6** | **008** | `print-srv-01` | Patch/replace the EOL print server and restrict print-service exposure. |
| **7** | **005** | `ad-dc-02` | Apply missing domain-controller updates after compatibility/change testing. |
| **8** | **006** | `billing-srv-01` | Restrict MySQL 3306 to required application/admin sources only. |
| **9** | **012** | `WS-RAD-01` | Disable or firewall SMBv1 where possible; otherwise enforce MRI-zone containment. |
| **10** | **013** | `ad-dc-01` | Remove SMBv1 after confirming that no required clinical workflow depends on it. |
| **11** | **019** | `ehr-srv-01` | Disable TLS 1.0/weak ciphers and enforce the approved TLS baseline. |
| **12** | **017** | `ehr-srv-01` | Suppress unnecessary Tomcat/version disclosure and review exposed connectors. |
| **13** | **018** | `ehr-srv-01` | Add HSTS where technically appropriate and confirm HTTPS-only access. |
| **14** | **026** | `billing-srv-01` | Resolve outdated kernel through supported OS maintenance/upgrade. |
| **15** | **014** | Westside router | Replace consumer-grade VPN/perimeter equipment with an enterprise-managed device. |
| **16** | **027** | `web-srv-01` / patient portal | Remove unnecessary disclosure/directory listing on the Internet-facing portal. |
| **17** | **028** | `10.10.2.99` | Identify owner/purpose; register and secure the device or remove it from the network. |
| **18** | **025** | `ad-dc-01` | Restrict DNS zone transfers to explicitly authorised secondary DNS systems. |
| **19** | **021** | `ad-dc-02` | Implement central event forwarding/monitoring for identity infrastructure. |

---

# 5. Noise-Filter Conclusions

The final triage shows that the majority of the scan is **signal rather than noise**. Twenty-six of the 31 findings require some form of remediation, but only seven justify immediate 24–48 hour action. That distinction matters: treating every scanner result as an emergency would overload engineering teams, while treating all Medium/Low findings as harmless would miss attack enablers such as Tomcat disclosure, broad NAS management access, cleartext clinical interfaces and DNS zone transfer.

The false-positive analysis also changes the queue materially. **Finding 031 looks severe on paper because Ghostcat has a 9.8 CVSS score and public exploitation tooling, but the reported Tomcat 9.0.31 build falls outside the affected range.** Conversely, **Finding 003 has no CVE or CVSS at all yet remains Actionable Critical** because the EHR database is broadly reachable across the flat network. This is the core vulnerability-management lesson from the MedDefense scan: remediation priority must be based on **applicability, exposure, asset impact and attack path**, not scanner severity alone.

---

# Sources

## MedDefense Project Evidence

- MedDefense OpenVAS/SecurePoint vulnerability scan report
- `0-first_impressions.md`
- `1-cve_ecosystem.md`
- `2-cvss_analysis.md`
- `4-exploit_hunt.md`
- `6-misconfiguration_analysis.md`
- `9-osint_hunt.md`
- `10-critical_cves.md`
- `11-false_positives.md`
- `13-web_exposure.md`
- `14-network_posture.md`
- `15-medical_iot.md`
- Project 1x00 Asset Registry / Criticality / Gap Analysis
- Project 1x01 Threat Actor Matrix / Kill Chains
