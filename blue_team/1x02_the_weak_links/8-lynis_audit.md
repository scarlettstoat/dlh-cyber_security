# 8. The Self-Audit

**Project:** `1x02_the_weak_links`  
**Task:** Advanced Task 8 — The Self-Audit  
**Repository path:** `blue_team/1x02_the_weak_links/8-lynis_audit.md`  
**Audit evidence used:** Lynis run supplied for this task

> **Evidence note:** The Lynis results below come from the supplied audit run. Lynis itself reported **0 formal warnings** and **28 suggestions**. To satisfy the task's request for the “Top 5 Warnings,” I distinguish between **formal Lynis warnings** and the five most security-relevant negative audit results observed in the output.

---

# Part 1 — Install and Run

The audit was performed with Lynis using the standard full-system audit command:

```bash
sudo lynis audit system
```

For Debian/Ubuntu-based systems, Lynis can be installed with:

```bash
sudo apt update
sudo apt install lynis -y
```

The supplied audit run produced the following system information:

| Parameter | Result |
|---|---|
| **Lynis Version** | 3.1.7 |
| **Operating System** | CachyOS, rolling release |
| **Kernel Version** | 7.1.4 |
| **Hostname** | `chloeravenloft` |
| **Hardware Platform** | x86_64 |
| **Tests Performed** | 248 |
| **Plugins Enabled** | 0 |
| **Hardening Index** | **70 / 100** |
| **Formal Warnings** | **0** |
| **Suggestions** | **28** |

---

# Part 2 — Analyze Results

## 2.1 Hardening Index

**Hardening Index: 70 / 100**

A score of 70 suggests that the machine has a reasonable security baseline, but there is still substantial room for hardening. The system already has some good preventive controls, such as an active firewall and disk encryption, but the audit also shows weaker detective and containment controls.

The score should not be treated as a simple pass/fail grade. The more useful interpretation comes from examining which controls are present and which important security capabilities are missing.

---

## 2.2 Top 5 Security-Relevant Audit Findings

Lynis formally reported **0 warnings**. However, the audit output still contained several negative statuses such as `NOT FOUND`, `DISABLED`, `FILES FOUND` and `NONE`.

The five most important negative results are listed below. These are **not formal Lynis warnings**; they are the most significant security weaknesses observed in the audit output.

### 1. No Mandatory Access Control Framework

**Lynis result:** AppArmor not found, SELinux not found, TOMOYO not found, grsecurity not found, MAC framework none.

**What Lynis checks:**  
Whether the system uses a Mandatory Access Control framework such as AppArmor or SELinux to restrict what processes are allowed to access.

**Why it matters:**  
Traditional Unix permissions control what a user or process can access, but a MAC framework adds an additional policy layer. If an application is compromised, MAC can limit the attacker's ability to access files, execute tools or move beyond the compromised process.

**Remediation:**  
Deploy and enforce an appropriate MAC framework. On a compatible Linux system this could include enabling and configuring **AppArmor** or **SELinux**, then verifying that important services are covered by active policies.

---

### 2. Deleted Files Still in Use

**Lynis result:** `FILES FOUND`

**What Lynis checks:**  
Whether running processes still have file handles open to files that have already been deleted.

**Why it matters:**  
This can occur normally after package updates, but it may mean that a service is still running an old binary in memory. It can also be relevant during incident investigation because suspicious processes may continue using deleted executable or library files.

**Remediation:**  
Identify the affected processes:

```bash
lsof +L1
```

If the files are related to legitimate updates, restart the affected services or reboot when appropriate. If the process is unexpected, investigate it before restarting or deleting evidence.

---

### 3. Failed Login Attempt Logging Disabled

**Lynis result:** Failed login logging `DISABLED`.

**What Lynis checks:**  
Whether authentication failures are recorded.

**Why it matters:**  
Failed-login events are important for identifying password guessing, brute-force activity and account misuse. Without them, repeated authentication attempts may be much harder to detect or investigate.

**Remediation:**  
Enable authentication-failure logging through the system's PAM and logging configuration, confirm that the events are written to the appropriate log source and consider tools such as **fail2ban** where suitable.

---

### 4. Secure Boot Disabled

**Lynis result:** Secure Boot `DISABLED`.

**What Lynis checks:**  
Whether the system uses UEFI Secure Boot to validate trusted boot components.

**Why it matters:**  
Secure Boot helps prevent unauthorized or modified bootloaders and kernel components from loading before the operating system starts.

**Remediation:**  
If the hardware and operating system support it, enable Secure Boot in UEFI/BIOS and ensure the bootloader and required kernel modules are correctly signed.

---

### 5. No File Integrity Monitoring Tool

**Lynis result:** integrity tool `NOT FOUND`; `dm-integrity` and `dm-verity` disabled.

**What Lynis checks:**  
Whether the system has tooling that can detect unauthorized changes to important system files.

**Why it matters:**  
After a compromise, an attacker may modify binaries, startup files, scheduled tasks or configuration files. File Integrity Monitoring helps identify these unexpected changes.

**Remediation:**  
Deploy a tool such as **AIDE** or another suitable file-integrity solution, establish a trusted baseline and schedule recurring checks with appropriate alerting.

---

## 2.3 Top 5 Suggestions

The audit reported **28 suggestions**. The five most relevant from the supplied result are:

| Rank | Suggestion ID | Recommendation | Security Improvement |
|---:|---|---|---|
| **1** | **AUTH-9230** | Configure password hashing rounds in `/etc/login.defs` | Increases the computational cost of offline password cracking |
| **2** | **AUTH-9262** | Install a PAM password-strength module | Helps prevent users from choosing weak and easily guessed passwords |
| **3** | **LOGG-2154** | Configure logging to an external host | Protects log evidence from local tampering and supports centralized analysis |
| **4** | **FINT-4350** | Install a file-integrity monitoring tool | Detects unexpected changes to important system files and configurations |
| **5** | **KRNL-6000** | Harden recommended `sysctl` values | Reduces exposure to unsafe kernel, BPF and network behaviours |

### Why These Suggestions Matter

The suggestions are significant because they focus on **defense in depth**. The machine already has some preventive protections, but these recommendations improve password resilience, logging, integrity monitoring and kernel hardening.

---

## 2.4 Category Breakdown

Lynis performs checks across many security categories. The supplied audit did not provide a simple numeric score for each category, so the classification below is an interpretation of the actual statuses observed.

| Category | Relative Posture | Evidence / Interpretation |
|---|---|---|
| **Networking / Firewall** | **Strong** | Firewall active, no major interface concerns reported |
| **Cryptography** | **Moderate to Strong** | Disk encryption and sufficient entropy present, but certificate-management issues remain |
| **Boot and Services** | **Moderate** | Secure Boot disabled and some service-hardening concerns identified |
| **Authentication** | **Moderate** | Core authentication works, but password-strength and failed-login controls need improvement |
| **Kernel Hardening** | **Moderate** | Multiple `sysctl` values differ from the recommended hardening profile |
| **Malware Detection** | **Moderate** | Some scanning capability exists but stronger active monitoring would improve protection |
| **Logging / Auditing** | **Weak** | Remote logging not enabled and stronger audit capability is needed |
| **File Integrity** | **Weak** | No dedicated integrity-monitoring tool was found |
| **Security Frameworks** | **Weak** | No active AppArmor, SELinux, TOMOYO or comparable MAC framework was found |
| **USB / Removable Media** | **Moderate** | USB storage controls were not strongly restricted |

### Highest-Performing Areas

The strongest areas are **Networking / Firewall** and parts of **Cryptography**. The machine already has useful preventive controls such as an active firewall and disk encryption.

### Lowest-Performing Areas

The weakest areas are **Logging / Auditing**, **File Integrity** and **Security Frameworks**.

This suggests that the machine is better at **preventing some initial attacks** than it is at **detecting and containing an attacker after compromise**. That distinction is important: a system can have good firewalling while still lacking strong visibility, integrity monitoring and process confinement.

---

# Part 3 — MedDefense Projection

The Lynis run above was performed on a different Linux system. The following section therefore does **not** claim that Lynis was run on `billing-srv-01`.

Instead, it projects what Lynis would likely identify based on the MedDefense evidence already collected.

## 3.1 `billing-srv-01` Context

`billing-srv-01` is MedDefense asset **A-004** and supports billing and insurance claims.

Known characteristics include:

- **Ubuntu 18.04**
- **Apache 2.4.29**
- **MySQL**
- **SSH password authentication enabled**
- outdated **Linux 4.15 kernel**
- previous compromise history
- broad internal reachability because MedDefense lacks effective network segmentation

The most relevant vulnerability findings are:

- **Finding 001:** Apache CVE-2021-44790
- **Finding 002:** Apache CVE-2019-0211
- **Finding 006:** MySQL reachable more broadly than necessary
- **Finding 009:** SSH password authentication enabled
- **Finding 011:** unsupported / unacceptable Ubuntu lifecycle state
- **Finding 026:** outdated Linux kernel

---

## 3.2 Five Expected Lynis Findings on `billing-srv-01`

### 1. Operating-System and Package Maintenance Concerns

**Expected issue:**  
Lynis would likely identify outdated package or operating-system maintenance concerns.

**Reasoning:**  
The server is still using Ubuntu 18.04 and an old 4.15 kernel. Findings 011 and 026 already establish the lifecycle and kernel concerns.

**Why it matters:**  
Unsupported or inadequately maintained systems accumulate vulnerabilities over time and become increasingly difficult to secure.

**Likely remediation:**  
Migrate the billing workload to a supported Ubuntu LTS release, fully patch the new server, validate the application and retire the old host.

---

### 2. SSH Password Authentication

**Expected issue:**  
Lynis would likely recommend stronger SSH configuration.

**Reasoning:**  
Finding 009 confirms that password-based SSH authentication is enabled on `billing-srv-01`.

**Why it matters:**  
Passwords can be guessed, reused or stolen. On MedDefense's flat internal network, a compromised workstation could attempt authentication against the server.

**Likely remediation:**  
Use SSH keys and restrict management access:

```text
PasswordAuthentication no
PubkeyAuthentication yes
```

Only authorized administration sources should be allowed to reach SSH.

---

### 3. Local Firewall / Network-Service Hardening

**Expected issue:**  
Lynis would likely identify network or firewall hardening opportunities.

**Reasoning:**  
Finding 006 shows that MySQL TCP/3306 is reachable from a broader internal scope than required.

**Why it matters:**  
Unnecessary service exposure increases attack surface. Once an attacker gains an internal foothold, broad reachability makes lateral movement easier.

**Likely remediation:**  
Restrict MySQL to the billing application and specifically approved administration sources using host and network firewall rules.

---

### 4. Apache and Web-Service Hardening

**Expected issue:**  
Lynis would likely identify package and service-hardening opportunities around Apache.

**Reasoning:**  
The server runs Apache 2.4.29 and Project 1x02 identified both:

- **CVE-2021-44790** — Finding 001
- **CVE-2019-0211** — Finding 002

These two vulnerabilities are particularly dangerous together because one can provide code execution while the other can support privilege escalation.

**Why it matters:**  
A compromised public or internal web service can become a foothold for broader system compromise.

**Likely remediation:**  
Upgrade Apache through a supported package path, remove unnecessary modules such as `mod_lua` if they are not required, review configuration and rescan after remediation.

---

### 5. Logging and Monitoring Hardening

**Expected issue:**  
Lynis would likely recommend stronger auditing, logging or remote-log protection.

**Reasoning:**  
Project 1x00 identified **GAP-011 — fragmented/manual logging and monitoring**. `billing-srv-01` has also previously been compromised, making reliable forensic visibility especially important.

**Why it matters:**  
If logs remain only on the local server, an attacker with sufficient privileges may modify or remove evidence. Central logging also makes it easier to detect suspicious activity across multiple systems.

**Likely remediation:**  
Forward authentication, system, Apache and security-relevant events to a centralized logging or SIEM platform and create alerts for suspicious authentication, privileged activity and process behaviour.

---

## 3.3 Findings That Cannot Be Predicted Reliably

The supplied personal audit identified weaknesses such as:

- no MAC framework;
- no file-integrity monitor;
- Secure Boot disabled;
- failed-login logging disabled.

Those findings should **not automatically be copied to `billing-srv-01`**.

They would be reasonable checks to perform, but the MedDefense scan does not prove that these controls are absent on the billing server.

This is an important vulnerability-management principle:

> **A plausible weakness is not the same as a validated finding.**

---

# 4. Comparison

| Area | Supplied Lynis Audit Machine | MedDefense `billing-srv-01` |
|---|---|---|
| **Hardening Index** | **70 / 100** | Not known — Lynis has not been run on it |
| **OS status** | Current rolling release | Ubuntu 18.04 lifecycle concern |
| **Firewall / Networking** | Active firewall | Broad internal service reachability |
| **SSH** | Not identified as a major audit weakness | Password authentication confirmed |
| **Logging** | Remote logging needs improvement | Project-level logging/monitoring gap |
| **File Integrity** | No tool found | Unknown on billing server |
| **MAC framework** | None found | Unknown on billing server |
| **Known vulnerable services** | Not established by this Lynis output | Apache vulnerabilities confirmed |

The supplied Linux machine and the MedDefense billing server therefore have different risk profiles.

The audit machine's largest weaknesses are mainly **hardening and detective-control gaps**. `billing-srv-01`, by contrast, has confirmed **software, lifecycle, authentication and network-exposure weaknesses** on top of a previous compromise history.

---

# Conclusion

The Lynis audit produced a **Hardening Index of 70/100**, with **0 formal warnings** and **28 suggestions**. Its strongest areas were networking/firewalling and basic cryptographic protection, while its weakest areas were logging, file integrity and Mandatory Access Control.

The exercise also demonstrates an important difference between **audit output** and **vulnerability interpretation**. Lynis can identify weak system-hardening practices, but those results still need context.

For MedDefense, the strongest projected concerns on `billing-srv-01` are:

1. operating-system and package lifecycle,
2. SSH password authentication,
3. broad network/service exposure,
4. Apache service hardening and patching,
5. logging and monitoring.

These predictions are based on validated MedDefense evidence. Other weaknesses seen in the supplied Lynis run, such as missing AppArmor or file-integrity tooling, would need to be checked directly before being recorded as findings on the billing server.

---

# Evidence Used

## Supplied Lynis Run
- Lynis 3.1.7
- CachyOS / kernel 7.1.4
- 248 tests
- Hardening Index 70
- 0 formal warnings
- 28 suggestions

## MedDefense Project Evidence
- Project 1x00 Asset Registry, Control Matrix and Gap Analysis
- Project 1x01 threat and kill-chain analysis
- Project 1x02 scan findings
- `6-misconfiguration_analysis.md`
- `16-triage.md`
- `19-remediation_map.md`
- `21-vulnerability_assessment.md`
