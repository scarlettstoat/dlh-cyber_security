Project 1x01 — Know Your Enemy

Hello! The title of this project is quite intense, as it should be. I am still not a fan of taking myself too seriously, so am adding this cute note for a slight tonal shift. :) Also note that I've been enjoying the MedDefense project so far because I'm imagining myself doing all this work as part of The Pitt's crew. Okay, back to our regular programming:

MedDefense Health Systems Threat Landscape Project

This project extends the internal Security Posture Assessment completed in Project 1x00 by examining the external threat landscape relevant to MedDefense Health Systems.

The central analytical question is:

Given MedDefense's assets, data, controls and known security gaps, which threat actors are most relevant, why would they target MedDefense, and which attack paths are most credible?

Project Approach

Deliverables in this project follow four principles:

MedDefense-specific analysis — generic statements such as "ransomware is a threat to healthcare" are insufficient. Threats must be connected to specific MedDefense assets, data, control gaps or attack paths.

Evidence-based judgments — likelihood and priority assessments must be supported by threat-intelligence evidence, healthcare-sector data and MedDefense-specific findings.

Cross-reference Project 1x00 — the Asset Registry, Asset Criticality Assessment, Gap Analysis and Data Map are direct inputs to this project.

Evidence before attribution — observed behavior may support an actor profile or likely technique without proving attribution to a named threat group.

Project 1x00 Baseline Inputs

7-asset_registry.md
8-criticality_assessment.md
12-gap_analysis.md
9-data_map.md

Key inherited findings include:

Critical EHR, medication/infusion, patient-monitoring, identity, network and recovery systems
Restricted patient, imaging, medication, monitoring, credential and backup data
No effective internal segmentation at MedDefense Central
Limited medical-IoT isolation and monitoring
Incomplete MFA and privileged-access controls
Locally concentrated backup infrastructure
Fragmented security monitoring
Legacy and unsupported systems
Incomplete endpoint/device-management coverage
Internet-facing patient services and a weak Westside perimeter

Evidence Sources:

Primary threat-intelligence evidence for Task 0 is the supplied marcus-intelligence-dossier.txt, containing condensed CISA and HC3 material, HHS breach statistics, a regional-hospital ransomware case, healthcare ransomware economics and Marcus Webb's unfinished MedDefense analysis.

Framework and sector references supplied for the wider project include CISA, HC3/HHS, ENISA, NIST, Microsoft STRIDE, MITRE ATT&CK and HHS 405(d).

