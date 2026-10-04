# The Board Briefing - Culmination

## Introduction
"Everyone has a plan until they get punched in the mouth." - Mike Tyson

Five weeks. Five projects. You have mapped every asset MedDefense owns, profiled every adversary that threatens it, triaged every vulnerability in its infrastructure, built a strategy with quantitative risk analysis and cost-justified controls, and designed the cryptographic foundation to protect its data. You have produced five professional reports. You have a roadmap. You have a budget.

And then, 48 hours before the Board meeting, the world changes.

CISA publishes an emergency advisory. A ransomware campaign called "Crimson Tide" has hit 5 regional hospitals in 10 days, 3 of them within 50 miles of MedDefense. The attack chain reads like a checklist of MedDefense weaknesses: FortiGate exploitation, flat network traversal, Kerberoasting, unencrypted database exfiltration, backup destruction on the shared network. Hospital C, 45 miles away, is still in active containment. FBI is on site. Ambulances are being diverted.

The Board meeting was next week. Dr. Morales moved it to tomorrow morning. 9:00 AM.

James Chen is standing in your office. His voice is steady, but his jaw is tight.

"Everything we built in five weeks is about to be tested. Not by an attacker. By reality. The Board is going to ask one question: Are we safe ? And the answer is going to be nuanced, because we have done a lot of work but we have not implemented everything yet. Some controls are funded but not deployed. Some vulnerabilities are identified but not patched. Some recommendations exist on paper but not in production."

"You have tonight. Give me two things by 8:00 AM: the complete security assessment that synthesizes everything we have built, and the emergency response to THIS specific threat. The Board needs to understand where we stand AND what we do in the next 72 hours."

This is the capstone. Not because it is the last project, but because it is the project where you prove that everything you learned connects into something operational. This is not a report-writing exercise. It is a demonstration that you can analyze a live threat, synthesize 5 weeks of work, make decisions under pressure, defend those decisions to non-technical stakeholders and produce deliverables that a real CISO would present to a real Board.

What Makes This Different
In the previous five projects, you learned one discipline at a time. Here, you use all of them simultaneously. The CISA advisory does not care which project you learned CVSS in. It requires you to know CVSS, threat actor profiling, kill chain analysis, risk quantification, framework mapping, cryptographic assessment and executive communication all at once.

The review section at the end is the most comprehensive assessment in the module: 8 Security+ style questions spanning every domain you have covered, plus 2 open-ended synthesis questions that require deep cross-domain reasoning. This is your Security+ readiness checkpoint.

## Context
Week six at MedDefense Health Systems. Tuesday, 6:47 PM.

The CISA advisory landed in James Chen's inbox 4 hours ago. He has already verified: MedDefense's FortiGate 100F is running FortiOS 7.0.9. The advisory says 7.0.0 through 7.0.11 are vulnerable. MedDefense is in the blast radius.

James has made two calls. The first to Sarah Park: "Cancel all non-essential IT changes tonight. Nobody touches production until I say so. And find out if we have the latest FortiGate firmware downloaded and ready to apply."

The second to Dr. Morales: "We need an emergency Board session. Tomorrow morning. I will have the full briefing ready."

Sarah Park's response came 20 minutes later: "FortiGate firmware 7.0.14 is available but not downloaded. Our FortiGate support contract expired 3 months ago. We cannot download the firmware without renewing the contract ($2,400/year) or finding an alternative. I am working on it."

The Board members you will face tomorrow:

Dr. Patricia Morales (CEO): Wants to know if patients are safe

Robert Kim (CFO): Wants to know what this costs

Dr. Angela Reeves (Board Chair, retired surgeon): Wants to know what you recommend and why she should trust it

Thomas Wright (Board Member, former bank executive): Wants to know how this compares to financial sector standards

Maria Santos (General Counsel): Wants to know the liability exposure

## Learning Objectives
By the end of this project, you are expected to be able to demonstrate:

Integration and Synthesis

The ability to connect asset management, threat intelligence, vulnerability analysis, risk quantification, control strategy and cryptographic protection into a single coherent assessment

The ability to apply existing analysis to a new, specific, emerging threat

The ability to make prioritized recommendations under time pressure with incomplete information

Emergency Response

How to translate a CISA advisory into an organization-specific impact assessment

How to design a 72-hour emergency response plan that addresses the most critical gaps first

How to communicate urgency to non-technical stakeholders without causing panic

Professional Mastery

How to produce a comprehensive Board-ready security package

How to present complex technical concepts to diverse audiences (CEO, CFO, legal counsel, Board members)

How to defend technical decisions against financial and legal scrutiny

## Resources
All resources from Projects 1x00 through 1x04 remain applicable.

Additional resources for this project:

CISA Cybersecurity Advisories -- How real advisories are structured

SANS Emergency Response Checklists -- Professional response frameworks

Your complete set of deliverables from all 5 prior projects

Man or Help:

All tools from prior projects remain applicable (OpenSSL, searchsploit, Lynis, NIST CVSS Calculator, SSL Labs).

## Requirements
General
All deliverables must be written in professional English.

A README.md file, at the root of the folder of the project, is mandatory.

All your files should end with a new line.

Bash Scripting
All your scripts must be executable.

The first line of all your scripts should be exactly #!/bin/bash.

All your files should end with a new line.

## Capstone-Specific Rules

This is a synthesis, not a copy. You may reference your prior deliverables, but you may not copy-paste sections from them. The Board package must be a new document that synthesizes, not a compilation.

The advisory is real-time. Treat the CISA advisory as an event that happened 4 hours ago. Your response must reflect urgency and prioritization.

Every recommendation must be traceable. Each action item must connect to: the specific threat (from the advisory), the specific vulnerability (from 1x02), the specific gap (from 1x00), the control (from 1x03), and the cost (from the budget analysis).

Incomplete information is realistic. The advisory does not tell you everything. Some details are unknown. State your assumptions explicitly. Do not pretend to know more than you do.
