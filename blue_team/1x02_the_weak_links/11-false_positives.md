# 11. The False Positives

**Project:** `1x02_the_weak_links`  
**Goal:** Identify scan findings that do not represent an exploitable vulnerability in MedDefense's actual environment and show why validation must come before remediation.  
**Repository path:** `blue_team/1x02_the_weak_links/11-false_positives.md`  
**Assessment date:** 16 September 2026

---

## 1. Validation Approach

An automated scanner can correctly identify a product or version and still reach the wrong conclusion about whether a vulnerability is actually exploitable on that host. A finding should therefore be validated against:

1. the exact installed version/build;
2. the vulnerable component or feature;
3. the configuration required for exploitation; and
4. the way the system is actually used at MedDefense.

For this scan, two findings have strong false-positive indicators:

- **Finding 020 — CVE-2023-38408 on `backup-srv-01`**, which SecurePoint explicitly flagged for investigation because the exploit requires `ssh-agent` forwarding; and
- **Finding 031 — CVE-2020-1938 (Ghostcat) on `ehr-srv-01`**, where the detected Tomcat version is outside the current affected range.

I have not labelled a third finding as a false positive without enough evidence to prove it. A low-risk or configuration-dependent finding is not automatically a false positive.

---

# 2. False Positive Analysis

## Finding 020 — OpenSSH `ssh-agent` Remote Code Execution

```text
Finding ID: 020

Reported Vulnerability:
CVE-2023-38408 — OpenSSH forwarded ssh-agent remote code execution on
backup-srv-01. The scan detected OpenSSH 8.9p1 and associated the host
with a CVE that has an NVD CVSS v3.1 Base Score of 9.8.

Why It Is a False Positive:
The vulnerable path is not the normal SSH daemon simply listening on
TCP/22. CVE-2023-38408 affects the PKCS#11 handling performed by
ssh-agent. NVD states that exploitation requires an SSH agent to be
forwarded to a system controlled by the attacker.

That means a version match alone is not enough. An attacker cannot exploit
backup-srv-01 merely because it runs OpenSSH 8.9p1 and accepts SSH
connections. The vulnerable workflow must actually exist: a user or
automation must forward an ssh-agent to an attacker-controlled or
compromised host.

SecurePoint already treated this as a possible false positive and rated it
Medium despite the 9.8 Base score because the required operating condition
may not exist in the MedDefense environment.

The finding should therefore be closed as a false positive only after the
validation below confirms that agent forwarding is not used in the relevant
backup-administration workflow. If agent forwarding is found, the finding
must immediately be reclassified as a true positive.

Validation Method:
1. Review system-wide and administrator SSH client configuration:
   - /etc/ssh/ssh_config
   - /etc/ssh/ssh_config.d/*
   - ~/.ssh/config for backup/IT administrator accounts
2. Search specifically for:
   - ForwardAgent yes
   - host-specific forwarding rules
3. Review administrator shell history and automation for use of:
   - ssh -A
4. Check whether SSH_AUTH_SOCK is present during relevant administrative
   sessions and whether ssh-agent processes are in use.
5. Review backup scripts, scheduled jobs and documented Veeam/administrative
   workflows for outbound SSH connections using forwarded credentials.
6. Confirm the workflow with the administrators responsible for
   backup-srv-01.
7. Where logging permits, review outbound SSH activity to determine whether
   the server or its administrators actually use agent forwarding.

Important validation detail:
Checking only sshd_config is not sufficient. AllowAgentForwarding controls
whether the server permits agent forwarding into a session; the CVE is in
the forwarded ssh-agent path, so the analyst must establish whether agent
forwarding is actually used by the client/user workflow.

Risk of Acting on This FP:
Treating the version match as a confirmed Critical RCE could trigger an
emergency OpenSSH upgrade, service restart, change-management work,
backup-job testing and administrator downtime even though the vulnerable
workflow is not used. Because backup-srv-01 supports recovery operations,
an unnecessary emergency change also introduces avoidable availability
risk to an important recovery system.

Risk of Not Validating:
The opposite mistake is more dangerous. If backup administrators do use
agent forwarding and the finding is dismissed only because exploitation
looks unusual, a real remote-code-execution path could remain on a Critical
backup/recovery asset. Ransomware operators deliberately target recovery
infrastructure, so the correct response is validation rather than automatic
remediation or automatic dismissal.
```

### Assessment

**Classification: Probable / environment-dependent false positive, pending confirmation that `ssh-agent` forwarding is not used.**

The important distinction is that **the CVE is real and the detected OpenSSH version is within the affected range; what may be false is the scanner's assumption that the required vulnerable workflow exists on this MedDefense host.**

---

## Finding 031 — Apache Tomcat Ghostcat

```text
Finding ID: 031

Reported Vulnerability:
CVE-2020-1938 — Apache Tomcat AJP "Ghostcat" vulnerability on
ehr-srv-01. The manual follow-up confirmed that the AJP connector is
listening on TCP/8009, and the scanner associated the service with
Ghostcat.

Why It Is a False Positive:
The scan reports Apache Tomcat 9.0.31.

Current NVD and Apache Tomcat security information identify the affected
Tomcat 9 range as versions before 9.0.31. Apache states that CVE-2020-1938
was fixed in Tomcat 9.0.31, and NVD's affected CPE range ends at
9.0.31 exclusive.

Therefore, an active AJP listener on Tomcat 9.0.31 does not by itself prove
that CVE-2020-1938 is present. The scanner appears to have treated the
presence of AJP, together with a close version match, as evidence of the
CVE even though the reported build is at the fixed-version boundary.

This is a strong false-positive case for the specific CVE. AJP on
TCP/8009 may still be an unnecessary or overly exposed service and should
be reviewed as a hardening issue, but that is not the same as proving
Ghostcat on Tomcat 9.0.31.

Validation Method:
1. Confirm the exact Tomcat build directly on ehr-srv-01 rather than
   relying only on service fingerprinting:
   - run the Tomcat version script, for example `catalina.sh version`;
   - check the installed package/build through the package manager; and
   - compare the build with vendor documentation.
2. Inspect `server.xml` and confirm the AJP Connector configuration,
   including:
   - listening address;
   - whether a shared secret is required; and
   - whether the connector is actually required by the EHR architecture.
3. Confirm that the running Tomcat binaries match the reported 9.0.31
   installation and that there is not an older parallel instance.
4. If authorised and operationally safe, perform a non-destructive
   Ghostcat validation test during an approved maintenance window rather
   than attempting active exploitation in production.
5. Rescan after validation so the scanner record can be documented as a
   false positive or converted to a separate AJP-hardening finding.

Risk of Acting on This FP:
ehr-srv-01 hosts MedDefense's most critical clinical application. Treating
Ghostcat as a confirmed Critical CVE could create an unnecessary emergency
patch or Tomcat change, vendor-maintenance work, application testing,
rollback planning and potentially EHR downtime. It would also consume SOC,
infrastructure and vendor resources that should be directed toward
confirmed exposures.

Risk of Not Validating:
Ghostcat is a known-exploited vulnerability and public exploitation
tooling exists. If the detected version were wrong, an older Tomcat
instance were actually running, or the EHR used an unexpectedly vulnerable
build, dismissing the alert without validation could leave an AJP file-read
or code-execution path on MedDefense's EHR server. Because the consequence
would be severe, the correct conclusion is "verify and close as FP," not
"ignore."
```

### Assessment

**Classification: False positive for CVE-2020-1938 if the reported Tomcat 9.0.31 build is confirmed.**

The AJP connector itself still deserves review. **False positive for one CVE does not mean the surrounding configuration is automatically secure.**

---

# 3. False-Positive Rate for This Scan

SecurePoint states that an automated OpenVAS scan can be expected to produce approximately a **5–10% false-positive rate**.

For **31 findings**:

- `31 × 5% = 1.55`
- `31 × 10% = 3.10`

A reasonable expectation is therefore approximately **2–3 false positives** in this report.

That number should not be treated as a quota. It does **not** mean analysts should force two or three findings into a false-positive category. It means that with this scanner and this dataset, seeing a small number of incorrect or contextually inapplicable results would be normal and every important finding should be validated on its own evidence.

---

# 4. Why Manual Validation Is Essential

Automated scanners are very good at identifying patterns at scale, but they do not always understand the exact way a system is built or used.

The two findings above demonstrate two different failure modes:

| Failure Mode | Example | What the Scanner Saw | What Validation Adds |
|---|---|---|---|
| **Required condition not established** | Finding 020 | OpenSSH 8.9p1 matches an affected version | Determines whether `ssh-agent` forwarding is actually used |
| **Version-boundary / applicability error** | Finding 031 | Tomcat + active AJP connector | Confirms that Tomcat 9.0.31 is outside the Ghostcat-affected range |

Without validation, MedDefense can make errors in both directions.

### Acting Too Quickly on a False Positive

Unnecessary remediation can consume:

- administrator and SOC time;
- vendor support hours;
- emergency change windows;
- testing and rollback effort;
- clinical/business downtime; and
- attention that could have been spent on confirmed Critical findings.

In a hospital, the remediation itself can also carry operational risk. Restarting or modifying a Critical service without a real need is not harmless just because the change is security-related.

### Dismissing Too Quickly

Validation is equally important before **closing** a suspected false positive. If the assumption is wrong, the organisation may leave a real vulnerability exposed while creating a documented but false sense of safety.

The proper vulnerability-management flow is therefore:

**Detect → research → validate applicability → classify → remediate or close → verify**

A scanner result is evidence that something needs investigation. It is not, by itself, proof that the vulnerability is exploitable on that specific asset.

---

# 5. Conclusion

The strongest false-positive cases in the MedDefense scan are **Finding 020** and **Finding 031**, but for different reasons.

**Finding 020** is a contextual false-positive candidate: the software version matches, but exploitation requires an `ssh-agent` forwarding workflow that the scan has not proved exists. It should be closed as a false positive only after configuration and workflow checks confirm that forwarding is not used.

**Finding 031** is a stronger version-applicability false positive: the scan reports Tomcat 9.0.31, while both NVD and Apache place the affected Ghostcat range below that release. The active AJP connector should still be reviewed as a configuration issue, but it does not establish CVE-2020-1938 on the reported build.

With a stated scanner false-positive rate of **5–10%**, approximately **2–3 false positives among 31 findings** is a reasonable expectation. The analyst's job is not to reach that number; it is to prove each classification with host-specific evidence before MedDefense spends remediation resources or accepts residual risk.

---

# Sources

## MedDefense Project Evidence

- MedDefense vulnerability scan report supplied for Project 1x02
- `0-first_impressions.md`
- `1-cve_ecosystem.md`
- `4-exploit_hunt.md`
- Project 1x00 Asset Registry / Criticality Assessment
- Project 1x01 Threat Actor Matrix

## Public Technical References

- NVD — CVE-2023-38408:  
  https://nvd.nist.gov/vuln/detail/CVE-2023-38408
- OpenSSH 9.3p2 release notes:  
  https://www.openssh.com/txt/release-9.3p2
- NVD — CVE-2020-1938:  
  https://nvd.nist.gov/vuln/detail/CVE-2020-1938
- Apache Tomcat 9 Security Vulnerabilities:  
  https://tomcat.apache.org/security-9
