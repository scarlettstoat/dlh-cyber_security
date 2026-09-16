# 15. The Medical IoT

**Project:** `1x02_the_weak_links`  
**Goal:** Assess vulnerabilities in connected medical devices with specific attention to patient-safety consequences.  
**Repository path:** `blue_team/1x02_the_weak_links/15-medical_iot.md`  
**Assessment date:** 16 September 2026

---

## 1. Scope

This assessment focuses on the medical-IoT findings identified in the MedDefense vulnerability scan and the supporting Asset Registry:

- **Finding 010** — BD Alaris infusion-pump vulnerability;
- **Finding 016** — Philips IntelliVue unauthenticated web-interface exposure;
- **Finding 024** — Philips IntelliVue / clinical-monitoring HL7 service exposure; and
- related medical-IoT exposure, including the broader lack of device-specific segmentation and the HTTP service observed on `MON-VITALS-3F-01`.

The MedDefense Asset Registry identifies:

- **A-032 — BD Alaris infusion-pump estate**, approximately 120 devices, firmware/software noted as **12.1.2**, supporting medication infusion and dosage updates; and
- **A-031 — Philips IntelliVue monitor estate**, approximately 80 patient monitors, with management interfaces reachable across the internal network.

The scan was unauthenticated for medical devices, so the findings provide useful network and version evidence but do not prove every configuration or administrative capability.

---

# 2. Medical-IoT Finding Summary

| Finding | Device / Estate | Scan Concern | Primary Security Effect | Patient-Safety Relevance |
|---|---|---|---|---|
| **010** | BD Alaris infusion pumps — A-032 | Alaris network-session / firmware vulnerability | Availability / device-management risk | Can interrupt networked pump operation and force manual workflows |
| **016** | Philips IntelliVue monitors — A-031 | Unauthenticated web interface | Confidentiality / device reconnaissance | Exposes live patient-monitoring information and device details |
| **024** | Philips IntelliVue monitors — A-031 | HL7 / monitoring service exposed on flat network | Confidentiality; potentially integrity depending on interface direction and permissions | Clinical observations and patient-identification data move through the monitoring environment |
| **Related** | `MON-VITALS-3F-01` — A-033 | HTTP/80 reachable; firmware noted as old | Reconnaissance / weak management exposure | Another bedside-monitoring interface reachable from the same flat environment |

The common multiplier across the findings is **GAP-003 — medical IoT lacks device-specific isolation and monitoring**, combined with **GAP-001 — no effective internal segmentation**.

---

# 3. BD Alaris Assessment

## Finding 010 — BD Alaris Infusion-Pump Environment

### MedDefense Context

```yaml
Asset:
  A-032 — BD Alaris infusion-pump estate

Function:
  Medication infusion and dosage updates

Scale:
  Approximately 120 pumps documented by MedDefense.
  The scan identified seven named devices plus approximately 110 additional
  devices.

Software/Firmware:
  12.1.2 recorded in the Asset Registry

Network:
  10.10.3.0/24 addressing range, but this is not an enforced security VLAN.

Criticality:
  Confidentiality: High
  Integrity: Critical
  Availability: Critical
  Overall: Critical
```

## 3.1 What the Vendor Bulletins Actually Say

There are **two relevant BD security stories that must not be mixed together**.

### A. CVE-2020-25165 — Network Session Authentication Vulnerability

The original scan work associated Finding 010 with **CVE-2020-25165**. The vulnerability affects the authentication process between older BD Alaris PC Units and Alaris Systems Manager. An attacker able to manipulate traffic in the vulnerable session can cause the PC Unit's wireless capability to drop, forcing the device into manual operation.

NVD gives this vulnerability a **CVSS v3.1 score of 7.5 High**:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```

However, current BD vendor information is important: BD states that **Alaris PC Unit software 12.1.1 and newer addresses CVE-2020-25165**.

MedDefense's Asset Registry records **12.1.2**, which is newer than the vendor's fixed 12.1.1 release.

### Finding 010 Validation Conclusion

**CVE-2020-25165 should not be treated as confirmed on a genuinely updated 12.1.2 PC Unit.**

The correct next step is to verify the exact software component and version on the affected Alaris devices and Systems Manager. If the PC Units are truly running 12.1.2, the scanner's CVE-2020-25165 mapping is likely stale or version-inapplicable.

That does **not** mean the Alaris estate is secure.

---

### B. BD Alaris 12.1.2 / 12.1.3 Security Bulletin

BD published a separate security bulletin covering the **BD Alaris System with Guardrails Suite MX 12.1.3 and earlier**. This is directly relevant to MedDefense's recorded 12.1.2 environment.

One particularly relevant issue is:

```yaml
CVE: CVE-2023-30562

Component:
  BD Alaris Guardrails Editor 12.1.2 and earlier

Weakness:
  Lack of dataset integrity checking

CVSS:
  6.7 Medium for the 12.1.3 / Guardrails Editor 12.1.2 and earlier branch

Technical Risk:
  A threat actor with the required adjacent-network access and privileges
  can tamper with a Guardrails dataset within Systems Manager and have the
  altered dataset distributed toward PCUs.

Clinical Significance:
  An undesired or manipulated dataset can affect the safety limits and
  configuration clinicians rely on when programming infusions.
```

BD explicitly states that this vulnerability has the **possibility to affect patient safety**, although the product contains controls intended to detect integrity problems and users are required to confirm datasets before activation.

The same BD bulletin also documents additional vulnerabilities affecting Alaris components, including PCU configuration weaknesses, insecure device-bus communications and Systems Manager web vulnerabilities. The key lesson is that **being on 12.1.2 may fix the older 2020 network-session CVE while still leaving the broader 12.1.x platform within scope of later security advisories**.

---

## 3.2 Vendor-Recommended Mitigations

BD's 2023 bulletin recommends a combination of software remediation and network compensating controls.

### Software

BD recommends updating to supported Alaris releases where available under the applicable regulatory authorization. The bulletin identifies the later **BD Alaris System v12.3** release and associated component updates as remediation for several of the disclosed vulnerabilities.

### Network Security

BD specifically recommends:

- placing Alaris PCUs on their **own VLAN**;
- using firewalls or Access Control Lists to permit only required endpoints and ports;
- restricting access to the Systems Manager server;
- using valid SSL certificates;
- enabling the authentication challenge password for network-configuration changes;
- rotating Wi-Fi credentials according to security policy;
- monitoring for unusual or unexpected traffic; and
- using allow-listing / MAC filtering where appropriate.

BD notes that the PCU needs only defined infrastructure and Systems Manager communication, rather than unrestricted access to the wider hospital network.

---

## 3.3 Has MedDefense Implemented the Recommendation?

**No — not fully.**

MedDefense has placed the devices in the `10.10.3.0/24` medical-device **address range**, but the Asset Registry and network review establish that this is only an addressing convention. It is **not an enforced medical-device VLAN or firewall security zone**.

Therefore, the most important vendor compensating control — **isolating the Alaris devices from unrelated internal systems** — has not been implemented.

MedDefense also has **GAP-018**, because there is no verified medical-device credential-hardening standard and no evidence that device-management credentials have been systematically reviewed across the Alaris and Philips estates.

### BD Alaris Assessment

**Current MedDefense risk: Critical operational/clinical priority.**

The exact CVE-2020-25165 scanner match requires correction if the PCUs are truly on 12.1.2, but the vendor's later 12.1.x bulletin confirms that the Alaris platform still requires active vulnerability management, version validation, vendor coordination and network isolation.

The strongest remediation action is therefore not "patch one CVE and close the ticket." It is:

**verify exact Alaris component versions → apply BD-authorized software updates → isolate the pump estate → restrict Systems Manager access → monitor device traffic → verify dataset and credential controls.**

---

# 4. Philips IntelliVue Assessment

## Findings 016 and 024 — Web and HL7 Exposure

### MedDefense Context

```yaml
Asset:
  A-031 — Philips IntelliVue patient-monitor estate

Scale:
  Approximately 80 monitors documented.
  The scan identified 13 named monitors plus approximately 65 additional
  devices.

Purpose:
  Continuous bedside patient monitoring

Network:
  10.10.3.0/24 addressing range, but reachable from the wider flat
  MedDefense network.

Scan Findings:
  Finding 016 — unauthenticated web-interface exposure
  Finding 024 — HL7 / clinical-monitoring service exposure
```

## 4.1 What Data Flows Through IntelliVue Systems?

Philips documentation shows that IntelliVue monitoring environments can handle far more than a simple "device status" page.

Depending on the exact IntelliVue / PIC iX configuration, the monitoring environment can contain or transfer:

- real-time physiological **waveforms**, including ECG and other monitored signals;
- numeric vital-sign measurements;
- trends over time;
- alarms and alarm events;
- patient demographic information;
- admit / discharge / transfer (**ADT**) information;
- patient identifiers such as name, encounter ID and lifetime ID;
- waveform strips and retrospective monitoring data;
- clinical measurements exported through **HL7**;
- data forwarded to electronic medical record / hospital information systems; and
- in some configurations, externally connected device measurements that are incorporated into the IntelliVue monitoring environment.

Philips documentation specifically describes IntelliVue/PIC iX as capturing waveforms, trends, alarms and numerics from networked monitors and exporting clinical information through HL7 to other hospital systems.

This means the interfaces sit on a **Restricted clinical-data flow**, not a generic appliance-management network.

---

## 4.2 Finding 016 — Unauthenticated Web Interface

### What an Attacker Could See

If the web interface exposed by the scan is genuinely accessible without authentication, an attacker with internal network access could potentially obtain:

- device identity and model information;
- software/firmware information;
- network or configuration details exposed by the interface;
- current monitoring status; and
- any patient-monitoring or patient-identification information presented by that particular interface.

The exact content must be validated directly because different IntelliVue generations and deployments expose different web features.

### What an Attacker Could Do

The scan evidence establishes **unauthenticated web access**, but it does not by itself prove that the same interface permits unauthenticated control of monitor settings.

Therefore, the defensible conclusion is:

**Confirmed concern:** information disclosure and attack-surface reconnaissance.

**Requires validation:** whether the interface permits state-changing operations such as configuration changes, alarm-related actions, remote control or device administration.

That distinction matters because Philips platforms can support remote monitoring and control capabilities in authorised configurations, but the scan alone does not prove that those functions are exposed through MedDefense's unauthenticated interface.

---

## 4.3 Finding 024 — HL7 / Clinical Data Interface Exposure

HL7 is used to move clinical and patient information between systems. In the IntelliVue environment, Philips documentation shows that HL7 workflows can include physiological numerics, monitoring observations, ADT information and other patient-monitoring data.

### What an Attacker With Network Access Could See

If an attacker can observe or query an inadequately protected HL7 feed, the data may reveal:

- patient names or identifiers;
- bed / encounter information;
- physiological measurements;
- ECG and other clinical observations;
- trends and monitoring events;
- alarms; and
- admit/discharge/transfer context.

That creates a **Confidentiality risk to Restricted clinical data**.

### What Could They Do?

The answer depends on whether the exposed port is:

- an outbound-only data export;
- a bidirectional integration service; or
- an interface accepting inbound HL7 messages.

The scan does not establish that an attacker can inject arbitrary HL7 messages or directly alter a bedside monitor. That should therefore **not** be claimed without validation.

However, Philips documentation confirms that IntelliVue environments can accept inbound ADT information and can export monitoring data to hospital systems. If a MedDefense interface accepts unauthenticated inbound messages, a successful manipulation could create an **Integrity problem** in patient identity, workflow or associated clinical data.

The safe assessment is therefore:

**Confirmed:** unnecessary flat-network reachability creates data-disclosure and reconnaissance exposure.

**Potential, requiring testing:** message injection, patient-association errors, workflow manipulation or unauthorised control.

---

## 4.4 Flat-Network Effect

These findings would be less serious if only a dedicated monitoring server and approved clinical-management systems could reach the monitors.

Instead, MedDefense's `10.10.3.0/24` medical-device range is not an enforced security boundary. A compromised workstation elsewhere in Central can potentially discover the same web and HL7 services.

This directly reinforces:

- **GAP-001 — no effective internal segmentation**;
- **GAP-003 — medical IoT lacks device-specific isolation and monitoring**;
- **GAP-011 — fragmented/manual monitoring**; and
- **GAP-018 — device credential hardening has not been verified**.

### Philips IntelliVue Assessment

**Priority: High, with Critical escalation if unauthenticated control or writable clinical interfaces are confirmed.**

The immediate requirement is to establish exactly which services are exposed, which are read-only, which accept commands/messages, and which systems actually need access.

---

# 5. Patient Safety Dimension

Medical-device vulnerabilities belong to a different risk category because **cybersecurity failure can become a direct clinical-safety event rather than only a data or business-system incident**. A compromised workstation may expose records, credentials or business operations; a compromised infusion-pump environment can delay therapy, disrupt medication delivery or affect the safety limits clinicians use when programming doses. In the worst case, workstation compromise causes data theft or lateral movement, while malicious or incorrect pump configuration could contribute to an underdose, overdose or interruption of a time-critical infusion. Patient-safety impact therefore has to be considered alongside Confidentiality, Integrity and Availability when medical IoT is prioritised.

---

# 6. Why Medical-Device Patching Is Harder Than Normal IT Patching

Medical devices cannot always be treated like ordinary laptops or servers. At least four constraints apply at MedDefense.

## 6.1 Regulatory and Safety Validation

Medical devices perform safety-critical functions and operate within a regulated product lifecycle. Firmware and software changes may need manufacturer validation, documented risk assessment and, depending on the type of change and jurisdiction, regulatory review or authorization.

BD's own remediation language reflects this: customers are told to update **where available based on regulatory authorization** and to coordinate remediation through BD.

An IT administrator therefore cannot safely treat an infusion pump like a normal Linux or Windows endpoint and install an arbitrary patch found online.

---

## 6.2 Operational Availability and Patient Care

A server can often be rebooted during a maintenance window. A bedside monitor or infusion pump may be actively supporting a patient.

Patching can require:

- removing the device from clinical use;
- replacing it temporarily with another device;
- coordinating with nursing, pharmacy, Clinical Engineering and IT;
- testing that networking and clinical functions still work; and
- confirming that the device returns safely to service.

At a scale of approximately 120 Alaris pumps and around 80 IntelliVue monitors, even a short per-device maintenance process becomes a significant operational project.

---

## 6.3 Vendor Dependency

Hospitals often depend on the manufacturer for:

- approved firmware images;
- vulnerability interpretation;
- installation procedures;
- compatibility information;
- service tooling;
- validation testing; and
- sometimes the installation itself.

The FDA advises users to keep medical devices updated using manufacturer-supplied patches and warns against applying unsupported fixes because they can make the device less safe.

For MedDefense, remediation therefore requires cooperation with **BD, Philips and Clinical Engineering**, not only the Security team.

---

## 6.4 Long Device Lifecycles and Legacy Technology

Medical equipment often remains in clinical service far longer than ordinary office IT. Hardware may still perform its medical function safely even when the embedded operating system, network stack or management software has become outdated.

Replacement can also be expensive and disruptive, especially when the device is part of a larger certified ecosystem.

This makes **compensating controls** essential:

- dedicated medical-device VLANs;
- default-deny ACLs;
- allow-listed management systems;
- passive network monitoring;
- strong device-management credentials;
- restricted vendor access; and
- accurate asset/firmware inventory.

These controls do not remove the vulnerability, but they reduce the number of systems that can reach it and the consequences if a vulnerable device cannot be patched immediately.

---

# 7. Recommended MedDefense Actions

| Priority | Action | Why |
|---:|---|---|
| **1** | Verify the exact Alaris PCU, Guardrails Editor and Systems Manager versions | The scanner's CVE-2020-25165 mapping conflicts with BD's statement that 12.1.1+ fixes that CVE |
| **2** | Engage BD / Clinical Engineering for the supported Alaris remediation path | 12.1.x remains within scope of later BD security advisories |
| **3** | Create an enforced medical-IoT VLAN / security zone | This is explicitly recommended by BD and directly addresses GAP-003 |
| **4** | Allow only required Alaris and IntelliVue communications | Prevent unrelated workstations and servers from reaching clinical-device interfaces |
| **5** | Validate Findings 016 and 024 manually | Determine whether Philips web/HL7 interfaces are read-only, authenticated and/or writable |
| **6** | Review medical-device credentials | GAP-018 confirms that credential hardening has not been verified |
| **7** | Monitor east-west medical-IoT traffic | Detect scanning, unusual connections, unexpected HL7 traffic and access outside normal clinical patterns |
| **8** | Build a vendor-aware patch register | Track model, firmware, vendor bulletin, approved fix, maintenance window, clinical owner and validation status for every medical-device family |

---

# 8. Overall Assessment

The medical-IoT findings show why vulnerability management in healthcare cannot stop at CVSS.

Finding 010 initially appears to be a normal High-severity CVE, but vendor research changes the interpretation: **BD states that PCU 12.1.1 and newer address CVE-2020-25165, while MedDefense records 12.1.2**. That specific scanner match must therefore be validated rather than accepted automatically. At the same time, BD's later Alaris bulletin confirms that the 12.1.x ecosystem still contains security weaknesses, including a Guardrails dataset-integrity vulnerability that can affect downstream PCUs.

The Philips findings create a different problem. Their unauthenticated web and HL7 exposure places patient-monitoring information and device interfaces within reach of the same flat network used by ordinary MedDefense systems. The correct remediation is therefore a combination of **vendor-approved patching, service validation, strict medical-device segmentation, credential hardening and continuous monitoring**.

For medical IoT, the question is not only:

> "Can this vulnerability compromise the device?"

It is also:

> **"Could compromise of this device change, delay or remove information or therapy that clinicians depend on to keep a patient safe?"**

That patient-safety dimension is what makes medical-device vulnerability management materially different from ordinary IT patching.

---

# Sources

## MedDefense Project Evidence

- MedDefense vulnerability scan report supplied for Project 1x02
- Project 1x00 `7-asset_registry.md`
- Project 1x00 `12-gap_analysis.md`
- Project 1x00 `13-reality_check.md`
- Project 1x01 `8-technical_vectors.md`
- Project 1x01 `9-vector_asset_matrix.md`
- Project 1x02 `2-cvss_analysis.md`
- Project 1x02 `10-critical_cves.md`
- Project 1x02 `14-network_posture.md`

## BD / Vulnerability Sources

- BD — Alaris 8015 PC Unit and Systems Manager Network Session Vulnerability:  
  https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-8015-pc-unit-and-bd-alaris-systems-manager-network-s
- NVD — CVE-2020-25165:  
  https://nvd.nist.gov/vuln/detail/CVE-2020-25165
- BD — Alaris System with Guardrails Suite MX Security Bulletin:  
  https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-system-with-guardrails-suite-mx
- NVD — CVE-2023-30562:  
  https://nvd.nist.gov/vuln/detail/CVE-2023-30562
- BD — Alaris System v12.1.2 Customer Highlights:  
  https://www.bd.com/content/dam/bd-assets/bd-com/en-us/document/support/alaris-customer-highlights-v12-1-2.pdf

## Philips Sources

- Philips — IntelliVue Information Center brochure
- Philips — PIC iX Instructions for Use / feature documentation
- Philips — IntelliBridge Enterprise and IntelliVue Patient Monitoring System
- Philips — IntelliVue 802.11 Clinical Network
- Philips — Functional considerations for portable bedside IntelliVue patient monitors

## Medical-Device Cybersecurity Guidance

- FDA — Medical Device Cybersecurity: What You Need to Know:  
  https://www.fda.gov/consumers/consumer-updates/medical-device-cybersecurity-what-you-need-know
- FDA — Cybersecurity in Medical Devices FAQs:  
  https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity-medical-devices-frequently-asked-questions-faqs
- FDA — Postmarket Management of Cybersecurity in Medical Devices:  
  https://www.fda.gov/regulatory-information/search-fda-guidance-documents/postmarket-management-cybersecurity-medical-devices
