# 19. The Remediation Map

**Project:** `1x02_the_weak_links`  
**Goal:** Define safe, specific remediation actions for the eight prioritized findings from Task 17, including operational impact, rollback/containment considerations, ownership, timelines and cost.  
**Repository path:** `blue_team/1x02_the_weak_links/19-remediation_map.md`  
**Assessment date:** 16 September 2026

---

## 1. Remediation Principles

The eight prioritized findings from Task 17 are **004, 003, 007, 001, 002, 011, 009 and 010**.

The remediation plan follows four rules:

1. **Do not trade a security incident for a clinical outage.** EHR, MRI and infusion-pump changes require validation with the teams that operate them.
2. **Patch and configuration changes must be reversible.** Backups, configuration exports, known-good snapshots and tested rollback steps are part of the change.
3. **Containment can precede permanent remediation.** This is especially important for unsupported clinical technology such as `WS-RAD-01`.
4. **Version applicability must be verified before changing a medical device.** Finding 010 remains validation-gated because MedDefense records Alaris 12.1.2, while BD states that PC Unit 12.1.1 and newer addresses CVE-2020-25165.

---

## Finding 004 — Windows XP MRI Control Workstation / Legacy Windows RCEs

```yaml
Finding 004:
  Response Type: Compensating Control

  Compensating Control:
    Control Description: >
      Place WS-RAD-01 (A-022) in a dedicated MRI/Radiology security zone with
      default-deny east-west firewall policy. Permit only vendor-confirmed
      clinical flows to PACS/imaging systems and explicitly approved management
      traffic. Block direct RDP and SMB access from general workstation,
      server and medical-device ranges; if remote administration is required,
      restrict it to an approved management/jump-host path. Add monitoring for
      unexpected connections to or from the MRI zone and begin a supported
      replacement plan with the MRI vendor.

    Residual Risk: >
      The workstation remains Windows XP and therefore remains intrinsically
      vulnerable. An attacker who gains access through an explicitly permitted
      path, local access or another device inside the MRI zone could still
      exploit it. Segmentation reduces reachability and blast radius; it does
      not make the operating system secure.

  Change / Safety Checks: >
    Capture the current MRI-to-PACS communication flows before enforcing the
    ACL. Review the rule set with Radiology/Clinical Engineering and the vendor.
    Apply rules in monitor/log mode first where possible, then enforce during a
    low-impact maintenance window.

  Rollback Plan: >
    Export the current switch/firewall configuration before the change. If
    legitimate MRI/PACS traffic is blocked, revert only the affected ACL rule
    to the last known-good configuration while keeping the workstation isolated
    from unrelated user/server networks.

  Operational Risk: >
    An overly restrictive rule can interrupt image transfer, modality worklist,
    vendor support or other MRI workflow traffic. A broad emergency exception
    would restore service but also restore the security exposure, so any
    temporary rule must be narrow and time-limited.

  Timeline: Immediate
  Owner: IT + Security + Clinical + Vendor
  Cost Estimate: $1-10K
```

**Why this response fits:** Project 1x02 already showed that enforced segmentation can reduce Finding 004 from an organisation-wide foothold risk to a much more contained Radiology incident. The long-term replacement of the unsupported MRI environment is a separate capital project and may cost substantially more than the immediate network containment.

---

## Finding 003 — Unrestricted PostgreSQL Reachability on `ehr-db-01`

```yaml
Finding 003:
  Response Type: Configuration Change

  Configuration Change:
    Change Description: >
      Remove the broad PostgreSQL access rule covering 10.10.0.0/16 from
      pg_hba.conf and replace it with explicit source rules for the EHR
      application server (ehr-srv-01, 10.10.2.10/32) and any separately
      validated administration/monitoring sources. Add a host/network firewall
      rule permitting TCP/5432 only from those approved sources. Where the
      application architecture permits it, change PostgreSQL listen_addresses
      from '*' to localhost and the database server's required interface
      (10.10.2.11).

    Impact Assessment: >
      Any application, administrator, reporting job, backup job or monitoring
      process that currently connects directly to PostgreSQL from an
      undocumented source will fail after the rule is enforced. Because this
      database supports the EHR, an incomplete dependency inventory could
      create a clinical outage.

  Prerequisites: >
    Review PostgreSQL connection logs and current sessions to identify legitimate
    source systems; confirm the required EHR application path; export
    postgresql.conf and pg_hba.conf; record firewall state; confirm a current
    database/VM backup; test the proposed restriction in staging or with a
    temporary monitored firewall rule.

  Rollback Plan: >
    Restore the previous pg_hba.conf/firewall rule set from the configuration
    backup and reload PostgreSQL if a legitimate clinical dependency was missed.
    Do not leave the broad /16 rule permanently restored; document the missing
    dependency and create the narrowest temporary exception needed.

  Operational Risk: >
    Incorrect source allow-listing can make the EHR unable to read or write
    patient records. The main remediation risk is therefore Availability, even
    though the vulnerability primarily increases Confidentiality and Integrity
    exposure.

  Timeline: Immediate
  Owner: IT + Security
  Cost Estimate: $0-1K
```

---

## Finding 007 — LDAP Signing Not Enforced on `ad-dc-01`

```yaml
Finding 007:
  Response Type: Configuration Change

  Configuration Change:
    Change Description: >
      Identify LDAP clients that still perform unsigned binds, remediate or
      reconfigure those clients, then set the domain-controller security policy
      "Domain controller: LDAP server signing requirements" to "Require
      signing". Apply the change through controlled Group Policy so the setting
      is documented and reproducible across the domain controllers.

    Impact Assessment: >
      Legacy applications, appliances or clinical systems that use unsigned
      LDAP/simple binds may lose authentication or directory lookup capability
      when signing is enforced. Because Active Directory supports many systems,
      enforcing the policy without first identifying these clients could cause
      widespread authentication failures.

  Prerequisites: >
    Use AD/DC logging to identify unsigned LDAP use, inventory the affected
    clients and contact application owners before enforcement. Test the policy
    in a representative environment or controlled pilot, confirm ad-dc-02 is
    healthy, verify current AD backups and schedule the production change
    outside peak clinical/administrative activity.

  Rollback Plan: >
    Revert the Group Policy setting to the previous value if a critical
    application fails and no immediate client-side fix is available. Record a
    time-limited exception for the affected system rather than abandoning the
    signing project, and continue monitoring that client until it is remediated.

  Operational Risk: >
    The security change can break old LDAP integrations that were built without
    signing support. The risk is highest where undocumented clinical or vendor
    software depends on Active Directory.

  Timeline: 7 days
  Owner: IT + Security
  Cost Estimate: $0-1K
```

---

## Finding 001 — CVE-2021-44790 Apache `mod_lua` Memory Corruption

```yaml
Finding 001:
  Response Type: Patch

  Patch:
    Patch Source: >
      Apache HTTP Server security advisory:
      https://httpd.apache.org/security/vulnerabilities_24.html
      CVE-2021-44790 is fixed upstream in Apache HTTP Server 2.4.52.
      MedDefense should use the supported operating-system/vendor package
      channel on the replacement/supported billing platform rather than
      building an unmanaged Apache version from source.

    Prerequisites: >
      Confirm whether mod_lua is actually required by the billing application.
      Clone or snapshot the server and back up Apache configuration and billing
      application data. Test the upgraded Apache package and application in a
      representative environment, including authentication, billing workflows,
      scheduled jobs and reverse-proxy/module dependencies. Obtain a maintenance
      window and notify Finance/application users before the service restart.

    Rollback Plan: >
      Keep a known-good VM/application snapshot and configuration export. If the
      upgrade causes a severe business outage, restore the known-good instance
      only as a temporary service-recovery measure and isolate/restrict access
      to the vulnerable host until a fixed compatible build is available.
      Do not treat rollback to a vulnerable Apache version as the final state.

    Operational Risk: >
      Apache/package changes may break modules, configuration syntax, PHP or
      application dependencies and will require a service restart. Billing
      transactions or claims processing could be interrupted if compatibility
      testing is incomplete.

  Validation: >
    Confirm the running Apache package/version after the change, verify that the
    vulnerable mod_lua path is no longer present, run application smoke tests,
    review logs and rescan the host.

  Timeline: Immediate
  Owner: IT + Security
  Cost Estimate: $1-10K
```

---

## Finding 002 — CVE-2019-0211 Apache Local Privilege Escalation

```yaml
Finding 002:
  Response Type: Patch

  Patch:
    Patch Source: >
      Apache HTTP Server security advisory:
      https://httpd.apache.org/security/vulnerabilities_24.html
      Remediate through the same supported Apache upgrade/change package used
      for Finding 001. Do not create a separate maintenance event for the same
      server if one tested upgrade can close both Apache findings.

    Prerequisites: >
      Use the same staging test, backup, application validation and maintenance
      window as Finding 001. Verify that the resulting vendor-supported Apache
      package contains the fix for CVE-2019-0211 as well as CVE-2021-44790.

    Rollback Plan: >
      Use the Finding 001 rollback package. If rollback is necessary for
      business continuity, keep the vulnerable server isolated and re-plan the
      fixed package immediately rather than leaving the privilege-escalation
      path accepted indefinitely.

    Operational Risk: >
      The risk is the same Apache/application compatibility and service-restart
      risk as Finding 001. Treating the two CVEs as separate production changes
      would add outage risk without adding security value.

  Validation: >
    Verify the post-change package/build, confirm Apache starts cleanly, run
    billing application tests and rescan. Close Findings 001 and 002 only after
    the fixed state is verified.

  Timeline: Immediate
  Owner: IT + Security
  Cost Estimate: $0-1K
```

**Change-package note:** Findings **001 and 002 should be remediated together**. The cost estimate for Finding 002 is incremental; it should not be interpreted as a second full Apache migration budget.

---

## Finding 011 — Unsupported Ubuntu 18.04 Security-Maintenance State

```yaml
Finding 011:
  Response Type: Patch

  Patch:
    Patch Source: >
      Migrate billing-srv-01 from Ubuntu 18.04 to a currently supported Ubuntu
      LTS release using Canonical's supported release-upgrade/rebuild process
      and supported package repositories. The preferred design is a tested
      replacement/rebuild rather than continuing to accumulate one-off fixes on
      the legacy host.

    Prerequisites: >
      Build a full dependency inventory for the billing application, including
      Apache modules, database/client libraries, scheduled jobs, certificates,
      service accounts and external integrations. Take a recoverable VM/image
      backup and application/database backup. Build and test the supported OS in
      staging, perform representative billing/claims tests and agree a cutover
      window with the application/business owner.

    Rollback Plan: >
      Prefer a parallel/blue-green cutover: retain the old VM powered off or
      network-isolated during the validation period and redirect service back
      only if the new platform fails acceptance testing. If rollback is needed,
      the old host must remain under the emergency network restrictions applied
      for Findings 001/002/009 until the supported migration is completed.

    Operational Risk: >
      A major OS migration can expose application incompatibilities involving
      Apache, PHP/runtime versions, libraries, database connectors, cron jobs
      and vendor software. A rushed in-place upgrade could cause prolonged
      billing downtime or data-processing errors.

  Interim Containment: >
    Patch Findings 001/002 immediately, disable unnecessary services, restrict
    network reachability and harden SSH under Finding 009 while the supported
    replacement is being tested.

  Timeline: 30 days
  Owner: IT + Vendor
  Cost Estimate: $10-50K
```

---

## Finding 009 — Password-Based SSH Authentication on `billing-srv-01`

```yaml
Finding 009:
  Response Type: Configuration Change

  Configuration Change:
    Change Description: >
      Create and validate approved SSH public keys for every required
      administrator/service account, then set PasswordAuthentication no and
      PubkeyAuthentication yes in the effective sshd configuration. Restrict
      SSH network access to approved administrative sources where possible.
      Validate configuration with sshd -t before reloading the SSH service.

    Impact Assessment: >
      Administrators, scripts or vendor processes that still rely on passwords
      will lose SSH access. A configuration error or missing key could lock
      administrators out of the server, so the stronger setting must not be
      enabled until all required access paths are tested.

  Prerequisites: >
    Inventory interactive and automated SSH users; provision/test keys; verify
    console or hypervisor access for recovery; back up sshd configuration; keep
    one confirmed administrative session open while testing a second key-based
    login.

  Rollback Plan: >
    If a legitimate dependency fails, restore the previous sshd configuration
    from console/hypervisor access or the already-open administrative session.
    Use a short, documented exception for the specific dependency while its key
    authentication is fixed; do not broadly re-enable password authentication
    as the permanent solution.

  Operational Risk: >
    The primary change risk is administrative lockout or failure of unattended
    jobs that use password-based SSH. The security risk of delaying the change
    is credential reuse/guessing against a repeatedly compromised server.

  Timeline: Immediate
  Owner: IT + Security
  Cost Estimate: $0-1K
```

---

## Finding 010 — BD Alaris / CVE-2020-25165 (Validation-Gated)

```yaml
Finding 010:
  Response Type: Compensating Control

  Compensating Control:
    Control Description: >
      Begin by verifying the exact Alaris PC Unit and Systems Manager component
      versions with Clinical Engineering and BD. Regardless of the older
      CVE-2020-25165 match, place Alaris PCUs in their own enforced clinical
      device VLAN/security zone and use firewall/ACL rules to allow only the
      vendor-required endpoints and ports. Restrict Systems Manager access,
      use valid SSL certificates, enable the supported authentication challenge
      for network-configuration changes, rotate Wi-Fi credentials under policy,
      monitor unexpected device traffic and use allow-listing/MAC controls where
      operationally appropriate.

    Residual Risk: >
      Segmentation does not remove vulnerabilities inside the Alaris platform
      and does not protect against misuse by an already authorized management
      system or insider. In addition, MedDefense records 12.1.2, which may make
      CVE-2020-25165 version-inapplicable for the PC Unit while still leaving the
      12.1.x platform within scope of later BD security advisories. Exact
      component/version verification and vendor-supported updating remain
      necessary.

  Vendor Validation: >
    BD states that PC Unit software 12.1.1 and newer addresses
    CVE-2020-25165. If the scanned component is genuinely 12.1.2, close the
    specific CVE as version-inapplicable after evidence is recorded. Separately
    assess the later BD Alaris System with Guardrails Suite MX bulletin and move
    to the vendor-supported release path appropriate to MedDefense's regulatory
    and clinical environment.

  Change / Safety Checks: >
    Clinical Engineering and BD must confirm which flows are required before
    ACL enforcement. Pilot the network restrictions on a controlled subset or
    maintenance environment where possible and verify medication-library,
    Systems Manager and normal pump communication before wider rollout.

  Rollback Plan: >
    Export the pre-change network policy. If a required clinical communication
    path is blocked, restore only that validated flow while maintaining the
    device zone boundary. Any temporary broad rule must be documented,
    monitored and removed after the missing dependency is identified.

  Operational Risk: >
    Incorrect VLAN/ACL rules can interrupt pump-to-management communication,
    dataset distribution or other supported workflows. Uncoordinated software
    changes may also conflict with vendor/regulatory requirements for medical
    devices, so the clinical/vendor approval path is mandatory.

  Timeline: 7 days
  Owner: Clinical + Vendor + IT + Security
  Cost Estimate: $1-10K
```

**Vendor source:**  
BD Alaris 8015 PC Unit / Systems Manager bulletin:  
https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-8015-pc-unit-and-bd-alaris-systems-manager-network-s

BD Alaris System with Guardrails Suite MX bulletin:  
https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-system-with-guardrails-suite-mx

---

# 2. Remediation Schedule

| Order | Finding | Response | Timeline | Primary Owner | Cost |
|---:|---:|---|---|---|---|
| **1** | **004** | MRI segmentation / compensating control | **Immediate** | IT + Security + Clinical + Vendor | **$1-10K** |
| **2** | **003** | Restrict PostgreSQL reachability | **Immediate** | IT + Security | **$0-1K** |
| **3** | **001** | Apache patch/upgrade | **Immediate** | IT + Security | **$1-10K** |
| **4** | **002** | Same Apache change package as 001 | **Immediate** | IT + Security | **$0-1K incremental** |
| **5** | **009** | Disable SSH password authentication | **Immediate** | IT + Security | **$0-1K** |
| **6** | **007** | Enforce LDAP signing after client validation | **7 days** | IT + Security | **$0-1K** |
| **7** | **010** | Alaris validation + device isolation | **7 days** | Clinical + Vendor + IT + Security | **$1-10K** |
| **8** | **011** | Supported billing-server OS migration | **30 days** | IT + Vendor | **$10-50K** |

The schedule deliberately separates **immediate containment** from changes that require broader compatibility testing. For example, forcing LDAP signing without discovering legacy LDAP clients could disrupt authentication, while replacing the billing operating system without application testing could cause a revenue-system outage. Those risks justify controlled implementation, not indefinite delay.

---

# 3. Cross-Finding Change Packages

## Billing Server — Findings 001, 002, 009 and 011

These four findings should be managed as one coordinated remediation programme rather than four unrelated tickets:

1. **Immediate:** restrict unnecessary network access, patch Apache for Findings 001/002 and move SSH to key-only authentication for Finding 009.
2. **Short-term:** verify the server is no longer compromised and rescan/retest the web and SSH layers.
3. **Within 30 days:** migrate the workload from unsupported Ubuntu 18.04 to a supported platform for Finding 011.

This approach avoids repeatedly restarting the same production server and reduces the risk that one change undoes another.

## EHR Database — Finding 003

The fastest high-value change is to make PostgreSQL reachable only from systems that actually need it. Because an incorrect rule can interrupt EHR access, connection logging and a verified rollback rule are required before enforcement.

## Active Directory — Finding 007

LDAP signing should be enforced, but **client discovery comes first**. A staged change closes the identity weakness without unnecessarily breaking legacy applications that have not yet been identified.

## Clinical Technology — Findings 004 and 010

For the MRI workstation and Alaris estate, the safe remediation pattern is **vendor-aware isolation first**. Network segmentation reduces exposure while preserving the ability to coordinate supported replacements/upgrades with Clinical Engineering and device vendors.

---

# 4. Completion Criteria

A finding is not closed simply because a change ticket says "implemented." Security should require evidence appropriate to the response type:

- **Patch:** fixed package/version verified, service tested, host rescanned and no regression detected.
- **Configuration Change:** expected setting verified from the running system, legitimate workflow tested and unauthorized access path retested.
- **Compensating Control:** firewall/VLAN policy verified, traffic tested from both allowed and denied sources, monitoring enabled and residual risk documented.
- **Exception:** written justification, owner, review date and compensating monitoring recorded.

The final operational objective is not merely to reduce scanner findings. It is to remove the attack path **without creating an avoidable EHR, MRI, identity, billing or medication-delivery outage**.

---

# Sources

## MedDefense Project Evidence

- Project 1x00 — Asset Registry
- Project 1x00 — Complete Control Matrix
- Project 1x00 — Prioritized Gap Analysis
- Project 1x01 — Threat Actor Matrix / Critical Kill Chains
- Project 1x02 — `1-cve_ecosystem.md`
- Project 1x02 — `4-exploit_hunt.md`
- Project 1x02 — `6-misconfiguration_analysis.md`
- Project 1x02 — `10-critical_cves.md`
- Project 1x02 — `14-network_posture.md`
- Project 1x02 — `15-medical_iot.md`
- Project 1x02 — `16-triage.md`
- Project 1x02 — `17-cvss_contextualizer.md`
- Project 1x02 — `18-threat_vuln_correlation.md`

## Vendor References

- Apache HTTP Server 2.4 vulnerabilities:  
  https://httpd.apache.org/security/vulnerabilities_24.html
- BD Alaris 8015 PC Unit / Systems Manager bulletin:  
  https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-8015-pc-unit-and-bd-alaris-systems-manager-network-s
- BD Alaris System with Guardrails Suite MX bulletin:  
  https://www.bd.com/en-us/about-bd/cybersecurity/bulletin/bd-alaris-system-with-guardrails-suite-mx
