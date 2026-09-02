# MedDefense Health Systems — Root Cause Analysis: `billing-srv-01`

## 1. Identify the Process

The process named `kworker` is not a legitimate Linux kernel worker. Genuine `kworker` processes are kernel threads, normally appear in brackets such as `[kworker]`, and run as part of the kernel rather than as the web-service account. In this case, the process:

- runs as `www-data`;
- is located at `/var/www/html/.cache/kworker`;
- consumes approximately 94% of the CPU;
- connects to external hosts on ports commonly associated with cryptocurrency mining; and
- starts with the argument `-o stratum+tcp://pool.monero.org:4443`.

The `stratum+tcp://` connection is the strongest indicator of the process's purpose. **Stratum is a protocol used by cryptocurrency miners to communicate with mining pools**, and `pool.monero.org` identifies a Monero mining pool. The accompanying configuration file also contains a mining wallet identifier, multiple pool addresses, four CPU threads and background execution.

The process is therefore a **malicious cryptocurrency miner**, most likely installed by an attacker to use MedDefense's computing resources to mine Monero for the attacker's benefit. The high CPU usage is a consequence of the miner performing computationally intensive mining work; it is not evidence that the legitimate billing workload has exceeded the server's capacity.

---

## 2. Classify the Real Compromise

The visible symptom is an **Availability** problem because the miner consumes CPU resources and causes the billing application to become slow. However, Availability is not the first security failure. **Integrity and Confidentiality have already been compromised before the performance problem becomes visible.**

### Integrity

**Integrity is compromised because unauthorized code has been introduced and executed on the server.**

The attacker-controlled `kworker` executable and its configuration file were placed inside `/var/www/html/.cache`, and the process is running under the `www-data` account. This means the server's filesystem and running state have been modified without authorization. The system is no longer operating only the software and processes that MedDefense intended.

The fact that the miner is disguised with the name `kworker` also suggests an attempt to make the malicious process resemble a legitimate system component.

### Confidentiality

**Confidentiality is compromised because an unauthorized party has obtained access to the server environment and established communication with external systems.**

The miner is making outbound connections to external mining-pool infrastructure, demonstrating that attacker-controlled code can communicate outside MedDefense. An attacker capable of placing and executing code as `www-data` has gained access that should not exist.

This does **not** prove that billing or patient data was exfiltrated, so the evidence should not be overstated. However, the unauthorized access itself represents a confidentiality failure and creates the opportunity for information accessible to the compromised account or application to be viewed or transmitted.

### Availability

Availability is the later and most visible symptom. The malicious process is consuming approximately 94% of CPU resources, leaving the legitimate Apache and MySQL services competing for capacity. Finance therefore experiences a slow billing application.

The security sequence is:

**Unauthorized access (Confidentiality) → unauthorized system modification/execution (Integrity) → resource exhaustion and degraded service (Availability).**

---

## 3. Why the Sysadmin's Proposed Solution Fails

Upgrading `billing-srv-01` to a larger VM would **not solve the security problem**.

The sysadmin has correctly observed CPU saturation but has attributed it to legitimate billing demand. The diagnostics show that the dominant CPU consumer is the malicious miner, not Apache or MySQL. At the time of the snapshot:

- the miner uses approximately **94.2% CPU**;
- Apache uses approximately **2.1%**; and
- MySQL uses approximately **1.3%**.

Adding more CPU and memory may temporarily make the billing application appear faster, but the attacker-controlled process would still be present. In effect, MedDefense could spend money increasing the resources available to the crypto-miner while leaving the compromise unresolved.

The repeated restarts have the same weakness: they treat the symptom rather than the cause. Restarting services temporarily improves performance, but the malicious activity returns because the underlying compromise has not been investigated and remediated.

A migration would only help if MedDefense also addresses the **entry point and security weakness that allowed the compromise**. Moving the same vulnerable application or configuration to a more powerful VM without correcting the underlying vulnerability risks recreating the problem on the new system.

The immediate priority should therefore be incident investigation and containment, followed by remediation of the entry point—not a capacity upgrade.

---

## 4. Connection to the January Ransomware Incident

The January ransomware incident and the current crypto-miner affected the **same server**, even though `billing-srv-01` was rebuilt after the ransomware event. This strongly suggests that the January response removed the payload and restored service without fully eliminating the underlying condition that allowed the server to be compromised.

The current evidence also points toward the web-service layer as a likely area for investigation:

- the malicious binary is stored beneath `/var/www/html`;
- it executes as `www-data`;
- Marcus specifically noted that this suggests something entered through Apache; and
- the server is running Apache 2.4.29, which Marcus had already flagged for known remote-code-execution vulnerabilities.

This evidence makes Apache or the billing web application a **credible suspected entry point**, but the exact initial-access vulnerability has not yet been proven. It should therefore be investigated rather than stated as confirmed fact.

The most important question is:

> **What underlying vulnerability or exposed service allowed an attacker to execute code on `billing-srv-01`, and was that entry point actually remediated when the server was rebuilt after the January ransomware incident?**

Two different payloads—ransomware and a cryptocurrency miner—appearing on the same rebuilt server indicate a broader security-posture problem. The focus should not be only on removing whichever malware is currently visible. MedDefense needs to identify and close the common path that makes repeated compromise possible.

---

## Root Cause Conclusion

The recurring performance degradation on `billing-srv-01` is **not a hardware-capacity problem**. It is the operational symptom of an active security compromise.

A malicious process masquerading as `kworker` is using the server to mine Monero, demonstrating unauthorized access and modification before its CPU consumption causes an Availability impact. The recurrence after the January ransomware rebuild indicates that MedDefense must investigate the server's underlying exposure—particularly the Apache/web application attack surface—and verify that the original entry point is removed before treating the server as clean.
