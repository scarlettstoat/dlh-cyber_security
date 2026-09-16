# MedDefense Health Systems - Considering the how

We're back to MedDefense Health Systems. Now that we understand the internal and external threats, and have a clear overview of the security posture, we need to consider the attack vectors. The Emmy-award wining series The Pitt is still helping me a lot with visualisation. Imagining Dr. Robinavitch getting upset over the availability issues help with motivation. In anycase, here's the instructions from the Project.

# Project 1x02 Introduction

A vulnerability scanner does not think. It compares version numbers against databases. It checks configurations against templates. It produces a report with 31 findings, four of which say "Critical" in red, and hands it to you. What it cannot do is tell you which of those 31 findings actually matters in your environment, which ones are noise, which ones the ransomware group you profiled in the last project would actually use, and which one you need to fix before lunch.

That is your job. And it is harder than it sounds.

The 2024 Qualys TruRisk report found that the average enterprise has over 30,000 vulnerabilities at any given time. Fewer than 3% have a known exploit in the wild. Fewer than 1% are actively exploited. Organizations that prioritize by CVSS score alone spend 80% of their patching effort on vulnerabilities that no attacker will ever touch, while the ones that matter sit open.

The skill this project develops is not "reading a scan report." It is the analytical judgment that transforms 31 raw findings into a prioritized, threat-informed, business-contextualized action plan that tells MedDefense exactly what to fix, in what order, and why. You will learn the global vulnerability ecosystem (CVE, CVSS, CWE, NVD, Exploit-DB, CISA KEV) not from a textbook but by using each one to investigate real findings. You will run a security audit tool on your own machine. You will write scripts that automate exploit research. And you will connect every finding back to the threats you identified and the assets you mapped.

# Why It Matters
Vulnerability management is the most operationally demanding discipline in defensive security. New CVEs are published at a rate of approximately 80 per day. Every scan produces more findings than any team can address. The analyst who can separate the 3% that matter from the 97% that do not is the analyst every SOC wants to hire.

The Vulnerability Assessment Summary you produce here will directly feed the Defense Blueprint in the next project, where you will design the controls and calculate the cost-benefit of each remediation. Every recommendation you make from this point forward must be grounded in evidence: this vulnerability, on this asset, exploitable by this actor, via this kill chain, with this impact.

# Context
Week three at MedDefense Health Systems.

The Board meeting went well. Better than James Chen expected. Dr. Morales read both reports cover to cover. She called James the next morning with a single question: "You told me ransomware groups exploit software vulnerabilities to get in. Do we have those vulnerabilities ? Which ones ?"

James had already anticipated this. Two weeks ago, he engaged SecurePoint Consulting, a third-party firm, to run a vulnerability scan of the MedDefense infrastructure. The results arrived yesterday. Thirty-one findings. Four marked Critical.

James drops the report on your desk. It is 15 pages of technical output: CVE identifiers, CVSS scores, port numbers, version strings.

"This is the raw scan. SecurePoint did their job, they scanned and reported. But their report is just data. Data is not intelligence. I need you to turn this into something actionable."

He taps the report.

"Thirty-one findings sounds scary, but I guarantee you that not all of them are real problems. Some are false positives. Some are low-risk noise. Some are devastating. Your job is to figure out which is which. And for the ones that matter, I need to know: which threat actors would exploit them, which of our assets are at risk, and what we should fix first."

"One more thing. The scan is a snapshot. It tells us what the scanner found on one night last week. It does not tell us about vulnerabilities the scanner missed, or vulnerabilities that were disclosed yesterday, or misconfigurations that do not have CVE numbers. I need the full picture, not just the scan output."

"You have the posture assessment, the threat landscape, and now the scan data. Connect them. Make it mean something."

