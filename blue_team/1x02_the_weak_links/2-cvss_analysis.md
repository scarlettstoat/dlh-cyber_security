# MedDefense Health Systems — CVSS Deconstruction

**Project:** `1x02_the_weak_links`  
**Task:** 2 — The CVSS Deconstruction  
**Calculator:** NIST CVSS v3.1 Calculator  
**Standard:** CVSS v3.1

> CVSS measures the technical severity of a vulnerability. It is not, by itself, a complete risk score for MedDefense. Asset criticality, exploit availability, threat relevance, exposure and existing controls still need to be considered during prioritization.

---

## Exercise 1 — Deconstruction

### Starting Vector

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

This is the vector supplied for **Finding 001 — CVE-2021-44790**, affecting Apache HTTP Server on `billing-srv-01`.

**Original Base Score:** **9.8 — Critical**

### Component-by-Component Breakdown

| Component | Selected Value | What It Means | Other Possible Values and Effect on Score | Why It Fits CVE-2021-44790 |
|---|---|---|---|---|
| **AV — Attack Vector** | **N — Network** | The vulnerability can be exploited through a network connection without the attacker needing local or physical access to the target. | **A — Adjacent** limits exploitation to a logically/physically adjacent network; **L — Local** requires local access; **P — Physical** requires physical interaction. Moving from N toward A/L/P lowers the exploitability portion of the score. | The scan describes exploitation through a specially crafted HTTP request sent to Apache. The attacker does not need an existing local session on the server. |
| **AC — Attack Complexity** | **L — Low** | No unusual conditions outside the attacker's control are required and exploitation is expected to be repeatable when the vulnerable condition is present. | **H — High** means exploitation depends on additional conditions, preparation or circumstances outside the attacker's control. High complexity lowers the score. | The vulnerability is triggered by a crafted request body when the vulnerable `mod_lua` code path is present; the scan does not describe a race condition or other special prerequisite. |
| **PR — Privileges Required** | **N — None** | The attacker does not need to authenticate or already hold privileges on the vulnerable system. | **L — Low** requires ordinary/basic privileges; **H — High** requires significant administrative privileges. Requiring privileges lowers the exploitability score. | Finding 001 describes potential remote exploitation without authentication. |
| **UI — User Interaction** | **N — None** | No separate user needs to click, open, approve or otherwise participate in the attack. | **R — Required** means another user must perform an action before exploitation succeeds. Requiring interaction lowers the score. | The attacker sends the malicious request directly to Apache; no victim action is part of the exploit path described in the scan. |
| **S — Scope** | **U — Unchanged** | The vulnerable component and the directly impacted resources remain under the same security authority. | **C — Changed** means exploitation crosses a security/trust boundary and affects a component controlled by a different security authority. Changed Scope uses a different CVSS impact formula and can increase severity. | The vulnerability is scored as compromise of the Apache/server environment itself rather than an intrinsic cross-boundary compromise of a separate security authority. |
| **C — Confidentiality** | **H — High** | Successful exploitation can cause a complete or serious loss of confidentiality. | **L — Low** means limited information exposure; **N — None** means no confidentiality impact. Lower values reduce the impact score. | Potential remote code execution can give an attacker serious access to information available to the compromised server process/system. |
| **I — Integrity** | **H — High** | Successful exploitation can allow serious or complete unauthorized modification of protected data or resources. | **L — Low** means limited modification; **N — None** means no integrity impact. Lower values reduce the impact score. | Code execution can permit alteration of files, application content or system resources. |
| **A — Availability** | **H — High** | Successful exploitation can seriously or completely disrupt availability of the affected component. | **L — Low** means partial/reduced availability; **N — None** means no availability impact. Lower values reduce the impact score. | A memory-corruption flaw can crash the service and, if code execution is achieved, an attacker can also deliberately disrupt the server. |

### What Happens if Attack Vector Changes from Network to Local?

Changed vector:

`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**NIST Calculator result:** **8.4 — High**

The score falls from **9.8 (Critical)** to **8.4 (High)**.

The impact does not change: Confidentiality, Integrity and Availability are still all High. What changes is **exploitability**. In CVSS v3.1, Network has a higher Attack Vector weight than Local because a remotely reachable vulnerability exposes the target to a much larger set of possible attackers.

Approximate calculator sub-scores:

- Original AV:N — Impact **5.9**, Exploitability **3.9**
- Changed AV:L — Impact **5.9**, Exploitability **2.5**

So the vulnerability is still technically severe if exploited, but requiring local access makes exploitation substantially less accessible.

**NIST calculator deep link:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AL%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AH&version=3.1

---

## Exercise 2 — Construction

### Given Characteristics

The vulnerability:

- can only be exploited from the local network;
- requires specific conditions and is complex to exploit;
- requires low-level privileges;
- requires no user interaction;
- does not cross a security boundary;
- causes complete loss of confidentiality;
- causes no integrity impact; and
- causes no availability impact.

### Building the Vector

| Characteristic | CVSS Metric | Selected Value | Reason |
|---|---|---|---|
| Local/adjacent network only | AV | **A — Adjacent** | For this exercise, "local network" is interpreted as requiring access to the same local/adjacent network environment rather than being reachable over a general network path. |
| Specific conditions required | AC | **H — High** | Exploitation depends on conditions beyond simply sending an attack at will. |
| Low-level privileges required | PR | **L — Low** | The attacker must already possess ordinary/basic privileges. |
| No user action required | UI | **N — None** | Exploitation does not depend on another person taking an action. |
| Only targeted system affected | S | **U — Unchanged** | The vulnerability does not cross into another security authority. |
| Complete confidentiality compromise | C | **H — High** | Successful exploitation produces a serious/complete confidentiality loss. |
| No integrity impact | I | **N — None** | Data or system integrity is not changed. |
| No availability impact | A | **N — None** | The service remains available. |

### Constructed Vector

`CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

### Calculator Result

**CVSS Base Score:** **4.8**  
**Severity:** **Medium**

The confidentiality impact is serious, but the overall score is reduced because exploitation is restricted to an adjacent network, has High attack complexity and requires existing Low privileges. There is also no Integrity or Availability impact.

**NIST calculator deep link:**  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AA%2FAC%3AH%2FPR%3AL%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AN%2FA%3AN&version=3.1

> **Scoring note:** CVSS v3.1 uses **Adjacent (A)** more narrowly than the everyday phrase "internal network." If an attack can travel across a routed corporate intranet rather than requiring the same logically or physically adjacent network, FIRST guidance says **Network (N)** may be more appropriate. The exercise wording is treated here as meaning an adjacent/local network segment.

---

## Exercise 3 — Comparison

### Evidence Note

The instruction asks for one finding above 9.0 and one finding with a CVSS score between 5.0 and 7.0. The supplied MedDefense scan does **not** contain a numeric CVSS Base score in the 5.0–7.0 range.

The explicit numeric CVSS scores appearing in the report are **7.5, 7.8, 8.1, 8.8, 9.8 and 10.0**; many configuration findings have **N/A** instead of a CVSS Base score.

To avoid inventing a finding, this comparison uses the closest lower-scoring finding with a complete v3.1 vector: **Finding 010 at 7.5**.

### Findings Selected

#### Finding 001 — CVE-2021-44790

**Asset:** `billing-srv-01`  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**Base Score:** **9.8 — Critical**

#### Finding 010 — CVE-2020-25165

**Asset:** BD Alaris infusion pumps  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`  
**Base Score:** **7.5 — High**

### Side-by-Side Metric Comparison

| Metric | Finding 001 | Finding 010 | Effect on Difference |
|---|---|---|---|
| Attack Vector | N | N | Same |
| Attack Complexity | L | L | Same |
| Privileges Required | N | N | Same |
| User Interaction | N | N | Same |
| Scope | U | U | Same |
| Confidentiality | **H** | **N** | Major difference |
| Integrity | **H** | **N** | Major difference |
| Availability | H | H | Same |

Both findings are equally easy to reach according to their supplied Base vectors: Network attack, Low complexity, no privileges, no user interaction and unchanged scope. Their **Exploitability sub-score is therefore the same, approximately 3.9**.

The score difference comes from the **Impact metrics**:

- Finding 001 has **C:H / I:H / A:H** — all three impact dimensions are High.
- Finding 010 has **C:N / I:N / A:H** — only Availability is High.

Approximate calculator sub-scores:

| Finding | Impact | Exploitability | Base Score |
|---|---:|---:|---:|
| Finding 001 | 5.9 | 3.9 | **9.8** |
| Finding 010 | 3.6 | 3.9 | **7.5** |

### Which Components Have the Biggest Impact?

For **this specific pair**, **Confidentiality and Integrity** explain the entire difference. Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope and Availability are identical.

This is an important CVSS lesson: a vulnerability can be very easy to exploit but still score lower if the successful outcome affects only one part of the CIA triad. Finding 010 is remotely exploitable with few barriers, but its supplied vector represents a denial-of-service impact only. Finding 001 combines the same exploitability with complete Confidentiality, Integrity and Availability impact.

Scope can also have a major effect in other comparisons because a Scope change uses a different CVSS formula, while AV, AC, PR and UI multiply together to form the Exploitability sub-score. The "biggest" component therefore depends on which metrics differ between the vulnerabilities being compared.

### MedDefense Cross-Reference

**Finding 001 — `billing-srv-01`:**  
The host is **A-004** in the 1x00 Asset Registry and supports billing and insurance claims. Project 1x01 identifies opportunistic attackers as highly exposed to known-vulnerability exploitation and identifies ransomware groups as a major external threat. This finding maps directly to **GAP-016 — no formal vulnerability/patch-management programme**, while **GAP-001 — no effective internal segmentation** can increase the blast radius after a foothold.

**Finding 010 — BD Alaris infusion pumps:**  
The pump estate is **A-032** and supports medication infusion and dosage updates, making Availability particularly important in MedDefense's clinical context. Project 1x01 identifies vulnerable medical software and reachable medical IoT as realistic attack paths for opportunistic and ransomware actors. The finding is especially relevant to **GAP-003 — medical IoT lacks device-specific isolation and monitoring** and **GAP-016 — vulnerability/patch management**.

These cross-references do not change the **Base CVSS scores**. They explain why the same technical score can have different operational significance once MedDefense-specific asset and threat context is added.

---

## Key Takeaways

1. **CVSS is transparent because the vector explains the score.** A number such as 9.8 is meaningful only when the analyst can explain which exploitability and impact metrics produced it.
2. **Restrictions on exploitation lower the score.** Local/adjacent access, High complexity, required privileges and required user interaction reduce exploitability.
3. **Impact is cumulative across Confidentiality, Integrity and Availability.** A vulnerability affecting all three severely will normally score higher than one with the same exploitability but only one High impact.
4. **CVSS Base Score is not complete organizational risk.** MedDefense must still combine CVSS with asset criticality, exploit availability, threat actors, existing gaps and clinical/business impact.

---

## Sources

- NIST CVSS v3.1 Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- FIRST CVSS v3.1 Specification: https://www.first.org/cvss/v3-1/specification-document
- MedDefense Vulnerability Scan Report: supplied project evidence
- Project 1x00 Asset Registry and Gap Analysis
- Project 1x01 Threat Actor Matrix and Threat Landscape Report
