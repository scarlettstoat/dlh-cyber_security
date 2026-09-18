# 8. The Self-Audit

**Project:** `1x02_the_weak_links`  
**Repository path:** `blue_team/1x02_the_weak_links/8-lynis_audit.md`

> **Evidence note:** The audit evidence supplied for this task reports **Lynis 3.1.7**, **Hardening Index 70/100**, **0 formal warnings**, and **28 suggestions**. The task still requires a “Top 5 Warnings” section, so the five entries below are the five most serious negative audit results visible in the supplied run. They are not falsely presented as formal Lynis warnings.

---

## Part 1: Install and Run

### Install Lynis

```bash
sudo apt update && sudo apt install lynis -y
```

Alternative installation:

```bash
git clone https://github.com/CISOfy/lynis && cd lynis
```

### Run a Full System Audit

```bash
sudo lynis audit system
```

### Audit Summary

| Item | Result |
|---|---|
| Lynis Version | **3.1.7** |
| Operating System | **CachyOS (rolling release)** |
| Kernel Version | **7.1.4** |
| Hostname | **chloeravenloft** |
| Hardware Platform | **x86_64** |
| Tests Performed | **248** |
| Plugins Enabled | **0** |
| **Hardening Index** | **70 / 100** |
| **Formal Warnings** | **0** |
| **Suggestions** | **28** |

---

## Part 2: Analyze Results

### Hardening Index

**Hardening Index: 70 / 100**

The system has a reasonable security baseline, but the result also shows room for improvement. Preventive controls such as the firewall and disk encryption are stronger than the detective and containment controls identified in the audit.

The Hardening Index should not be treated as a pass/fail score. The individual checks are more useful because they identify the exact controls that are missing or need hardening.

---

### Top 5 Warnings

**Formal Lynis warnings reported: 0.**

For the purpose of the task, these are the **five most critical negative audit results** found in the supplied Lynis output.

#### Warning 1: No Mandatory Access Control Framework

**Lynis Check:** AppArmor `NOT FOUND`, SELinux `NOT FOUND`, TOMOYO `NOT FOUND`, grsecurity `NOT FOUND`, MAC framework `NONE`.

**What Lynis checks:** Whether a Mandatory Access Control framework is installed and enforcing policies that restrict what processes can access.

**Why it matters:** If an application is compromised, a MAC framework can limit what the compromised process is allowed to read, write or execute. Without one, the attacker is constrained mainly by normal Unix permissions.

**Remediation:** Deploy and enforce an appropriate framework such as AppArmor or SELinux and apply policies to important services.

---

#### Warning 2: Deleted Files Still in Use

**Lynis Check:** Deleted files in use — `FILES FOUND`.

**What Lynis checks:** Whether running processes still hold open file handles to files that have been deleted.

**Why it matters:** This can happen after legitimate updates, but it can also indicate that an old or suspicious executable/library remains active in memory.

**Remediation:** Identify affected processes with:

```bash
lsof +L1
```

Restart legitimate services after updates. Investigate unexpected processes before removing evidence.

---

#### Warning 3: Failed Login Attempt Logging Disabled

**Lynis Check:** Failed-login logging — `DISABLED`.

**What Lynis checks:** Whether authentication failures are recorded.

**Why it matters:** Without failed-login records, password guessing and brute-force attempts are harder to detect and investigate.

**Remediation:** Enable authentication-failure logging through PAM and the system logging stack, verify that failures are recorded, and consider a control such as fail2ban where appropriate.

---

#### Warning 4: Secure Boot Disabled

**Lynis Check:** Secure Boot — `DISABLED`.

**What Lynis checks:** Whether UEFI Secure Boot verifies trusted boot components.

**Why it matters:** Secure Boot helps prevent unauthorized or modified bootloaders and kernel components from loading before the operating system starts.

**Remediation:** If supported by the hardware and operating system, enable Secure Boot and ensure required boot components and kernel modules are correctly signed.

---

#### Warning 5: No File Integrity Monitoring Tool

**Lynis Check:** Integrity tool — `NOT FOUND`; `dm-integrity` and `dm-verity` disabled.

**What Lynis checks:** Whether the system can detect unexpected changes to important files.

**Why it matters:** An attacker may modify binaries, startup files, configuration files or scheduled tasks after compromise. File-integrity monitoring provides evidence of those changes.

**Remediation:** Install and configure a tool such as AIDE, establish a trusted baseline, and schedule recurring integrity checks with alerting.

---

### Top 5 Suggestions

| Rank | Suggestion ID | Suggestion | Security Improvement |
|---:|---|---|---|
| **1** | **AUTH-9230** | Configure password hashing rounds in `/etc/login.defs` | Makes offline password cracking more expensive by increasing the work needed for each guess |
| **2** | **AUTH-9262** | Install a PAM password-strength module | Helps prevent users from selecting weak and easily guessed passwords |
| **3** | **LOGG-2154** | Enable logging to an external logging host | Protects log evidence from local tampering and supports centralized investigation |
| **4** | **FINT-4350** | Install a file-integrity monitoring tool | Detects unauthorized or unexpected modification of important files |
| **5** | **KRNL-6000** | Harden recommended `sysctl` values | Reduces exposure from weak kernel and network security settings |

---

### Category Breakdown

| Category | Score / Status | Findings | Interpretation |
|---|---|---|---|
| **Networking** | **Good / High** | Firewall active; no major network-interface weakness dominated the audit | Strong preventive network baseline |
| **Software: Firewalls** | **Good / High** | Host firewall active | Useful local protection is already present |
| **Cryptography** | **Medium to Good** | Disk encryption and sufficient entropy present; certificate hardening can improve | Strong basic protection with some remaining hardening |
| **Boot and Services** | **Medium** | Secure Boot disabled; service hardening opportunities remain | Boot/service controls need improvement |
| **Users, Groups and Authentication** | **Medium** | Password-strength and failed-login controls need improvement | Authentication works but should be hardened |
| **Kernel Hardening** | **Medium** | Several `sysctl` values differ from the hardened profile | Kernel/network tuning is incomplete |
| **Malware Detection** | **Medium** | Some scanning capability, but stronger active monitoring would help | Detection is present but limited |
| **USB Devices** | **Medium** | USB storage controls are not strongly restricted | Removable-media exposure remains |
| **Logging / Auditing** | **Weak / Low** | External logging not enabled; stronger auditing recommended | Weak forensic and detection capability |
| **File Integrity** | **Weak / Low** | No integrity-monitoring tool found | Unauthorized file changes may go undetected |
| **Security Frameworks** | **Weak / Low** | No AppArmor, SELinux, TOMOYO or comparable MAC framework active | Weak process-level containment |

**Highest-scoring categories:** **Networking** and **Software: Firewalls**, with **Cryptography** also relatively strong.

**Lowest-scoring categories:** **Logging / Auditing**, **File Integrity**, and **Security Frameworks**.

**Security posture interpretation:** The system has a reasonable preventive baseline, but weaker detective and containment controls. It is better prepared to block some initial attacks than to detect unauthorized changes, preserve evidence or constrain an attacker after compromise.

---

## Part 3: MedDefense Projection

### `billing-srv-01` Context

| Item | MedDefense Evidence |
|---|---|
| Host | `billing-srv-01` — `10.10.2.15` |
| Operating System | **Ubuntu 18.04** |
| Web Server | **Apache 2.4.29** |
| Database | **MySQL** |
| SSH | **Password authentication enabled** |
| Kernel | **Linux 4.15** |
| History | **Crypto-miner compromise history** |
| Network | Broad internal reachability / no effective segmentation |

Without direct access to the server, the following are **projected Lynis findings**, not claims that Lynis has actually been run on `billing-srv-01`.

### Projected Lynis Finding 1: Operating-System and Package Maintenance

**Expected finding:** Outdated / unsupported operating-system and package maintenance state.

**Reasoning:** Ubuntu 18.04 is outside standard support for MedDefense and the server uses an old Linux 4.15 kernel. Findings 011 and 026 already establish the lifecycle and kernel concerns.

**Expected remediation:** Migrate the billing workload to a supported Ubuntu LTS release, fully patch it and retire/isolate the old host.

---

### Projected Lynis Finding 2: File Integrity Monitoring

**Expected finding:** Lynis may recommend a file-integrity monitoring capability.

**Reasoning:** The server has a **crypto-miner compromise history**, so the ability to detect unexpected changes to binaries, configuration files, cron jobs and startup mechanisms is particularly valuable. The MedDefense evidence does not prove that FIM is absent, so this remains a projection to validate.

**Expected remediation:** Verify whether AIDE/Tripwire or equivalent FIM exists; if not, deploy it, establish a trusted baseline and send alerts to central monitoring.

---

### Projected Lynis Finding 3: Remote / Centralized Logging

**Expected finding:** Lynis may recommend stronger external logging and auditing.

**Reasoning:** Project 1x00 identified **GAP-011 — fragmented/manual logging and monitoring**. A previously compromised server should not rely only on local logs that may be lost or altered after an attack.

**Expected remediation:** Forward Linux authentication, system, Apache and security-relevant events to centralized logging/SIEM and create useful alerts.

---

### Projected Lynis Finding 4: SSH Password Authentication

**Expected finding:** SSH configuration does not meet a stronger hardening baseline.

**Reasoning:** Finding 009 explicitly confirms that password-based SSH authentication is enabled.

**Expected remediation:**

```text
PasswordAuthentication no
PubkeyAuthentication yes
```

Restrict SSH to approved administration sources.

---

### Projected Lynis Finding 5: Mandatory Access Control / Service Confinement

**Expected finding:** Lynis may recommend stronger process confinement, including verifying AppArmor/SELinux status.

**Reasoning:** Apache on the billing server has confirmed vulnerable application components. A MAC framework would provide defense in depth by limiting what a compromised web-service process can access. The current project evidence does **not** prove that AppArmor is absent, so this must be checked rather than assumed.

**Expected remediation:** Verify the current MAC state. If no effective framework/profile protects Apache and other important services, enable and configure an appropriate supported policy.

---

## Conclusion

The supplied Lynis audit recorded:

- **Hardening Index: 70 / 100**
- **Formal Warnings: 0**
- **Suggestions: 28**
- strongest categories: **Networking / Firewalls**
- weakest categories: **Logging / Auditing, File Integrity, Security Frameworks**

For `billing-srv-01`, the five projected areas are:

1. operating-system/package maintenance;
2. file-integrity monitoring;
3. centralized logging/auditing;
4. SSH password authentication;
5. Mandatory Access Control/service confinement.

These are projections based on the known MedDefense server context and should be validated directly before being recorded as confirmed host findings.
