# Task 3 - The 72-Hour Plan

# MedDefense Health Systems
## 72-Hour Emergency Response Plan - Crimson Tide

**Project:** `1x05_board_briefing`  
**Repository path:** `blue_team/1x05_board_briefing/3-emergency_plan.md`  
**Timeframe:** First 72 hours after the Crimson Tide advisory

---

## Response Approach

The goal for the next 72 hours is not to complete the full six-month security roadmap. That is not realistic with Sarah Park and two IT staff.

The priority is to break the Crimson Tide attack chain as early as possible, protect MedDefense's recovery capability and avoid making rushed changes that create a clinical outage.

The order is:

```text
1. Reduce the chance of initial access
2. Check whether access may already have happened
3. Protect backups before the attacker can reach them
4. Limit credential abuse and lateral movement
5. Patch the FortiGate
6. Put temporary and then permanent barriers around Critical systems
7. Make the higher-risk AD changes only after compatibility testing
```

A control that is funded or designed but not yet deployed is not treated as current protection.

---

# Tier 1 - Tonight (0-12 Hours)

These actions can be taken immediately without procurement or new budget approval. The focus is containment, evidence preservation and protecting recovery.

## Action 1 - Temporarily Remove the SSL-VPN Attack Path

```yaml
Action: >
  Temporarily disable the Internet-facing SSL-VPN service on the FortiGate
  until the appliance can be patched. Keep required site-to-site connectivity
  running if it is technically separate from the vulnerable SSL-VPN service.
  If SSL-VPN cannot be fully disabled, restrict it to approved source IPs as
  an emergency compensating control.

Phase Blocked:
  - Phase 1 - Initial Access
  - Phase 2 - Internal Reconnaissance

Owner: Sarah

Prerequisites: >
  Confirm which VPN services are used for site-to-site connectivity and which
  are used for remote-user SSL-VPN so that essential site connectivity is not
  accidentally removed.

Risk of Action: >
  Remote staff or vendors may temporarily lose VPN access. A configuration
  mistake could also affect required connectivity if the VPN services are not
  clearly separated.

Risk of Inaction: >
  FortiOS 7.0.9 remains directly exposed to the exact pre-authentication
  vulnerability used by Crimson Tide, leaving MedDefense open to the first
  phase of the attack.
```

### Why it is tonight

This is the fastest way to remove the known initial-access route while the support contract problem is being resolved. It is a temporary control, not a replacement for patching.

---

## Action 2 - Preserve FortiGate Evidence and Check for Signs of Exploitation

```yaml
Action: >
  Export the current FortiGate configuration and relevant VPN, administrator
  and system logs before making further changes. Review them for unusual
  administrator creation, configuration changes, unexpected VPN activity,
  unfamiliar source IPs and activity matching indicators from the Crimson
  Tide advisory.

Phase Blocked:
  - Phase 1 - Initial Access
  - Phase 2 - Internal Reconnaissance
  - Phase 3 - Lateral Movement

Owner: You

Prerequisites: >
  Sarah provides read-only access or exports the required FortiGate logs and
  configuration. Evidence must be copied to a separate protected location.

Risk of Action: >
  Very low. The main risk is accidentally changing configuration while
  collecting evidence, so the review should remain read-only.

Risk of Inaction: >
  MedDefense could patch the FortiGate tomorrow without realizing that an
  attacker already used it. If compromise has already occurred, patching alone
  would not remove stolen credentials, malicious accounts or persistence.
```

### Why it is tonight

The advisory arrived four hours ago, but the vulnerability existed before today. MedDefense therefore needs to answer two different questions: **Are we vulnerable?** and **Have we already been exploited?**

---

## Action 3 - Isolate `NAS-01` from the Production Network

```yaml
Action: >
  Confirm the status of the latest backup, document it, then physically
  disconnect NAS-01 from the production network. Keep the NAS powered down or
  network-isolated and reconnect it only through a controlled recovery or
  backup procedure until stronger isolation is in place.

Phase Blocked:
  - Phase 5 - Backup Destruction
  - Phase 7 - Extortion

Owner: Sarah

Prerequisites: >
  Confirm that the latest backup job has completed or document exactly what
  backup coverage exists before disconnecting the NAS. Record the disconnect
  time and responsible administrator.

Risk of Action: >
  Scheduled backup jobs will fail while NAS-01 is disconnected and routine
  restores will require a controlled reconnection.

Risk of Inaction: >
  Crimson Tide specifically targets network-accessible backups before
  ransomware deployment. NAS-01 is currently reachable from the same broad
  environment as production systems, so leaving it connected risks losing the
  recovery copy at the same time as production.
```

### Why it is tonight

This is one of the highest-value actions available because the scenario confirms that physical backup isolation can be done immediately.

---

## Action 4 - Lock Down Privileged FortiGate Access

```yaml
Action: >
  Review all FortiGate administrator accounts, disable any unused or unexpected
  accounts, rotate privileged administrator passwords and restrict management
  access to the approved IT administration sources only.

Phase Blocked:
  - Phase 2 - Internal Reconnaissance
  - Phase 3 - Lateral Movement

Owner: Sarah

Prerequisites: >
  The FortiGate configuration and logs from Action 2 must be preserved first.
  At least one tested emergency administrator account must remain available.

Risk of Action: >
  A mistaken account disablement or password change could lock IT staff out of
  the firewall. The emergency administrator account must therefore be tested
  before old credentials are retired.

Risk of Inaction: >
  If privileged credentials have already been exposed or an unauthorized
  administrator account exists, the attacker may retain access even after the
  firmware is patched.
```

---

## Action 5 - Start an Active Directory and Endpoint Threat Hunt

```yaml
Action: >
  Review high-value authentication and endpoint logs for signs of credential
  abuse, Kerberoasting and lateral movement. Prioritize Kerberos Event ID 4769,
  unusual privileged logons, new service creation, unexpected RDP/SSH/WMI use,
  mass authentication failures and suspicious access to EHR, billing and
  backup systems.

Phase Blocked:
  - Phase 2 - Internal Reconnaissance
  - Phase 3 - Lateral Movement
  - Phase 6 - Ransomware Deployment

Owner: You

Prerequisites: >
  Access to current AD, Windows, Linux and available endpoint-security logs.
  No production configuration change is required for the initial review.

Risk of Action: >
  Very low. The main limitation is incomplete logging and the lack of fully
  centralized monitoring.

Risk of Inaction: >
  MedDefense may focus only on patching the FortiGate while an attacker is
  already moving through the internal network using valid credentials.
```

---

# Tier 2 - Tomorrow (12-36 Hours)

These actions need coordination, a maintenance window or emergency Board approval.

## Action 6 - Renew FortiGate Support and Patch to FortiOS 7.0.14

```yaml
Action: >
  Obtain emergency approval for the $2,400 FortiGate support renewal, download
  FortiOS 7.0.14 through the supported channel, back up the configuration,
  apply the firmware during an emergency maintenance window and verify firewall,
  VPN and routing operation after the upgrade.

Phase Blocked:
  - Phase 1 - Initial Access
  - Phase 2 - Internal Reconnaissance

Owner: Sarah

Prerequisites: >
  James obtains emergency budget approval. The support contract is renewed,
  firmware is downloaded from the official source, the current configuration
  is backed up and the maintenance/rollback plan is ready.

Risk of Action: >
  The firewall may require a reboot and VPN or Internet connectivity may be
  interrupted. A failed upgrade could create a wider outage because there is
  no redundant perimeter firewall.

Risk of Inaction: >
  MedDefense remains exposed to a Critical, remotely exploitable FortiGate
  vulnerability that is being used as the initial-access route in the Crimson
  Tide campaign.
```

### Priority

This is the **highest-priority Tier 2 change**. Other production changes should not delay it.

---

## Action 7 - Rotate VPN Credentials and Invalidate Existing Sessions After Patching

```yaml
Action: >
  After the FortiGate is patched, invalidate active remote-access sessions and
  rotate VPN and other high-risk credentials that could have been exposed
  through the vulnerable appliance. Prioritize privileged, vendor and remote
  administration accounts.

Phase Blocked:
  - Phase 2 - Internal Reconnaissance
  - Phase 3 - Lateral Movement

Owner: Sarah

Prerequisites: >
  Complete the FortiGate patch first, preserve relevant evidence and confirm
  which accounts or secrets are used for remote and administrative access.

Risk of Action: >
  Users and vendors may temporarily lose access and saved credentials may stop
  working. Changes must be communicated and tested in a controlled order.

Risk of Inaction: >
  An attacker who captured credentials before the patch may still be able to
  log in normally even though CVE-2023-27997 itself has been fixed.
```

---

## Action 8 - Require MFA for VPN and Administrative Access

```yaml
Action: >
  Activate MFA first for VPN, privileged administrator and vendor accounts,
  using the funded 1x03 MFA control. Do not wait for organization-wide rollout
  before protecting the accounts that can provide broad access.

Phase Blocked:
  - Phase 2 - Internal Reconnaissance
  - Phase 3 - Lateral Movement
  - Phase 6 - Ransomware Deployment

Owner: Sarah

Prerequisites: >
  Emergency approval if any additional licensing or implementation cost is
  required, a confirmed inventory of privileged/VPN accounts, and a tested
  break-glass access process.

Risk of Action: >
  Misconfiguration could lock out legitimate administrators or vendors.
  Break-glass access must be tested and tightly controlled.

Risk of Inaction: >
  Stolen credentials remain enough to access high-value systems, allowing
  Crimson Tide to continue the attack even after the original FortiGate entry
  point is patched.
```

---

## Action 9 - Restrict Direct Access to the EHR and Billing Databases

```yaml
Action: >
  Restrict PostgreSQL TCP/5432 on ehr-db-01 to ehr-srv-01 and approved
  administration sources only. Restrict MySQL TCP/3306 on billing-srv-01 to
  the required billing application and approved administration sources.

Phase Blocked:
  - Phase 3 - Lateral Movement
  - Phase 4 - Data Exfiltration

Owner: Sarah

Prerequisites: >
  Confirm legitimate application and administration source addresses, back up
  the current firewall/database access configuration and prepare rollback.

Risk of Action: >
  An incomplete allow-list could interrupt EHR or billing application access.
  Changes must therefore be tested with the application owners during a brief
  controlled window.

Risk of Inaction: >
  A compromised internal account or host can continue to reach sensitive
  databases directly. Because the EHR and billing databases are not yet
  encrypted at rest, successful access could lead to readable data theft.
```

---

## Action 10 - Apply Temporary Lateral-Movement Restrictions

```yaml
Action: >
  Use existing host firewalls and any currently available network ACLs to block
  unnecessary RDP, SMB, SSH and WMI traffic between ordinary user systems and
  Critical servers. Permit only documented administration sources and required
  application flows.

Phase Blocked:
  - Phase 3 - Lateral Movement
  - Phase 6 - Ransomware Deployment

Owner: Sarah

Prerequisites: >
  Identify the approved management systems and critical application flows.
  Make the changes in small groups with rollback available rather than trying
  to redesign the entire network overnight.

Risk of Action: >
  Poorly tested rules could interrupt legitimate administration or legacy
  clinical workflows.

Risk of Inaction: >
  MedDefense remains effectively flat, allowing one compromised account or
  workstation to become a route toward Active Directory, EHR, billing and
  backup infrastructure.
```

---

# Tier 3 - This Week (36-72 Hours)

These actions need testing, vendor involvement or more substantial configuration work.

## Action 11 - Implement the Priority Segmentation Boundaries

```yaml
Action: >
  Begin the 1x03 segmentation design using the new switch configurations.
  Prioritize the Management, Server/AD/EHR and Backup zones first, then the
  Clinical and Medical Device zones. Use default-deny between zones with only
  documented required flows allowed.

Phase Blocked:
  - Phase 3 - Lateral Movement
  - Phase 4 - Data Exfiltration
  - Phase 5 - Backup Destruction
  - Phase 6 - Ransomware Deployment

Owner: Sarah

Prerequisites: >
  Approved switch configurations, documented required traffic flows, backup of
  current switch configuration, test/rollback plan and coordination with
  clinical/application owners.

Risk of Action: >
  Incorrect VLAN or ACL configuration could disconnect clinical devices,
  servers or users. This is why the segmentation project cannot safely be
  compressed into a few hours.

Risk of Inaction: >
  The flat network continues to connect nearly every later phase of the
  Crimson Tide chain. Even after the FortiGate is patched, another foothold
  could still spread widely.
```

---

## Action 12 - Remove RC4/DES Kerberos and Enforce LDAP Protection

```yaml
Action: >
  Complete the compatibility checks from the 1x04 implementation playbook,
  remediate service accounts that still depend on RC4, then stage AES-only
  Kerberos and LDAP signing on ad-dc-02 before applying the same policy to
  ad-dc-01.

Phase Blocked:
  - Phase 3 - Lateral Movement
  - Phase 6 - Ransomware Deployment

Owner: Sarah

Prerequisites: >
  Review Event ID 4769 for RC4 use, confirm current AD health, create a recent
  system-state backup, test critical EHR/billing/clinical authentication and
  prepare a reversible Group Policy change.

Risk of Action: >
  Legacy systems or service accounts may fail authentication if they do not
  support the stronger settings. Applying the policy without testing could
  create a widespread authentication outage.

Risk of Inaction: >
  RC4 remains available for Kerberoasting and weak directory protection
  continues to increase the value of stolen credentials during lateral
  movement.
```

### Why this is not Tier 1

The security benefit is high, but this is exactly the kind of change that can break legitimate authentication. It should be accelerated, not rushed blindly.

---

## Action 13 - Establish an Offsite Immutable Recovery Copy

```yaml
Action: >
  Start the funded offsite immutable-backup control and create an independent
  recovery copy that cannot be deleted or modified using normal production
  credentials. Keep NAS-01 isolated until the new recovery path is verified.

Phase Blocked:
  - Phase 5 - Backup Destruction
  - Phase 7 - Extortion

Owner: Sarah

Prerequisites: >
  Vendor/cloud access or procurement, confirmed critical backup scope,
  protected backup credentials, retention settings and a successful test
  restore.

Risk of Action: >
  A rushed backup migration could produce incomplete or unusable recovery
  copies. Restore testing is required before the control is trusted.

Risk of Inaction: >
  MedDefense continues to depend heavily on a local backup environment that
  ransomware operators deliberately target before encryption.
```

---

## Action 14 - Deploy EDR First to the Systems Crimson Tide Would Use Most

```yaml
Action: >
  Begin the funded Sophos Intercept X EDR rollout with domain controllers,
  supported servers, administrator workstations and other high-value Windows
  endpoints before attempting full-estate deployment.

Phase Blocked:
  - Phase 3 - Lateral Movement
  - Phase 6 - Ransomware Deployment

Owner: Sarah

Prerequisites: >
  Licensing/vendor access, compatibility check for Critical servers,
  deployment package and an agreed exclusion/testing process for sensitive
  applications.

Risk of Action: >
  Endpoint-security agents can interfere with legacy or sensitive applications
  if deployed without testing. Unsupported systems such as the Windows XP MRI
  workstation require network isolation instead.

Risk of Inaction: >
  Existing endpoint protection remains incomplete, reducing MedDefense's
  ability to detect credential theft, suspicious process execution and
  ransomware behavior before encryption spreads.
```

---

# 72-Hour Priority Summary

| Priority | Action | Main Crimson Tide Phase(s) |
|---:|---|---|
| **1** | Temporarily close/restrict SSL-VPN | 1 |
| **2** | Preserve and review FortiGate evidence | 1-3 |
| **3** | Disconnect `NAS-01` | 5 |
| **4** | Hunt AD/endpoints for signs of compromise | 2-3, 6 |
| **5** | Renew support and patch FortiGate | 1-2 |
| **6** | Rotate exposed credentials / invalidate sessions | 2-3 |
| **7** | Require MFA for high-risk accounts | 2-3, 6 |
| **8** | Restrict EHR/billing database access | 3-4 |
| **9** | Add temporary lateral-movement restrictions | 3, 6 |
| **10** | Implement priority segmentation | 3-6 |
| **11** | Remove RC4/DES and enforce LDAP protection | 3, 6 |
| **12** | Establish immutable offsite recovery | 5, 7 |
| **13** | Start EDR rollout on high-value systems | 3, 6 |

---

# Resource Conflict Assessment

Yes. There are several resource conflicts, and the biggest one is **Sarah Park**.

Sarah is accountable for the production changes and has only **two IT staff** available. The FortiGate, database restrictions, backup work, segmentation and Active Directory changes cannot all be carried out safely at the same time.

## Conflict 1 - FortiGate Work Competes With Every Other Network Change

The FortiGate patch must take priority because it closes Crimson Tide's known initial-access route.

**Resolution:**

```text
Tonight:
  SSL-VPN containment + evidence preservation

Tomorrow:
  FortiGate patch first

Only after FortiGate validation:
  database restrictions / temporary ACL changes
```

Do not patch the FortiGate while also making unrelated network changes. If connectivity fails, the team needs to know which change caused it.

---

## Conflict 2 - Segmentation and AD Kerberos Changes Can Both Break Authentication

Changing network paths and authentication rules at the same time would make troubleshooting extremely difficult.

**Resolution:**

1. Apply and validate the priority network segmentation changes.
2. Confirm EHR, billing, AD and clinical connectivity.
3. Then stage the Kerberos/LDAP change on `ad-dc-02`.
4. Validate normal authentication.
5. Only then apply it to `ad-dc-01`.

This keeps two high-risk changes from overlapping.

---

## Conflict 3 - Backup Isolation Interrupts Normal Backup Operations

`NAS-01` cannot remain normally connected while also being treated as isolated from ransomware.

**Resolution:**

Keep it physically disconnected by default. Reconnect it only during a controlled backup or recovery window from an approved source, then disconnect it again until the immutable/offsite copy is working and tested.

The short-term inconvenience is acceptable because losing the recovery environment would have a much larger impact.

---

## Conflict 4 - The Same Small IT Team Is Needed Everywhere

Sarah and the two IT staff cannot investigate logs, patch the FortiGate, redesign switching, change AD and manage backups simultaneously.

**Resolution:**

### James

James handles:

- Board escalation;
- emergency risk decisions;
- the $2,400 support-renewal approval;
- vendor escalation;
- executive/clinical communication; and
- decisions where security and availability conflict.

### Sarah

Sarah remains the production change owner and approves the technical sequence.

### IT Staff Member 1

Focus on:

- FortiGate;
- VPN;
- firewall/ACL work; and
- switch/segmentation configuration.

### IT Staff Member 2

Focus on:

- backup isolation;
- server/database access restrictions;
- AD preparation; and
- EDR deployment support.

### You

I would stay off the critical production-change path and work in parallel on:

- FortiGate/AD/endpoint log review;
- IOC hunting;
- documenting evidence;
- tracking each emergency action;
- verifying that controls were actually applied; and
- preparing the status James needs for the Board.

This lets the technical staff make changes while Security continues checking whether MedDefense may already be compromised.

---

# Final 72-Hour Position

The first 72 hours should not be judged by how many roadmap items MedDefense completes.

Success means that by the end of the window:

- the vulnerable FortiGate is patched;
- the known SSL-VPN entry path is closed;
- there is no uninvestigated evidence of FortiGate compromise;
- exposed privileged/VPN credentials have been rotated or protected with MFA;
- `NAS-01` is no longer continuously reachable from production;
- Critical databases are no longer broadly reachable;
- unnecessary RDP/SMB/SSH/WMI paths are reduced;
- the first priority segmentation boundaries are operating;
- the AD Kerberos/LDAP change has either been safely deployed or has a documented compatibility blocker; and
- MedDefense has an independent recovery path being established and tested.

The main principle is simple: **patch the door Crimson Tide is using, protect the backups before they can destroy them, and then make it harder for one compromised account to become an organization-wide ransomware event.**
