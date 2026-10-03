# MedDefense Health Systems — Data Protection Map

## Task 0: The Crypto Inventory

This inventory maps the seven required MedDefense data categories against the three states of data: **at rest**, **in transit**, and **in use**. Each cell records the cryptographic protection currently in place, the evidence supporting the assessment, and whether the protection is **Adequate**, **Weak**, or **Absent**.

### Status Criteria

- **Adequate** — A current cryptographic control is implemented and no material weakness is identified in the available evidence.
- **Weak** — Some cryptographic protection exists, but it is optional, obsolete, mixed with weak algorithms/protocols, or otherwise insufficiently enforced.
- **Absent** — No cryptographic protection is implemented or documented for that data state.

## Data Protection Map

| Data Category | At Rest | In Transit | In Use |
|---|---|---|---|
| **Patient medical records**<br>EHR data in PostgreSQL | **Protection:** None.<br><br>**Evidence:** Crypto Audit Notes — PostgreSQL 14 on `ehr-db-01` stores its data directory on an unencrypted ext4 filesystem. Patient records are readable if the filesystem or drive is accessed.<br><br>**Status:** **Absent** | **Protection:** PostgreSQL SSL is enabled, but encryption is not enforced. Both `hostssl` and `hostnossl` rules are present in `pg_hba.conf`. The patient portal also still supports TLS 1.0 alongside TLS 1.2.<br><br>**Evidence:** Crypto Audit Notes — connections from `10.10.0.0/16` may use either encrypted or non-encrypted PostgreSQL sessions, so MedDefense cannot confirm that all EHR database traffic is encrypted. 1x02 Finding 005 also confirmed TLS 1.0 remains enabled on the patient portal, while Finding 013 identified a certificate nearing expiry with no auto-renewal configured.<br><br>**Status:** **Weak** | **Protection:** None.<br><br>**Evidence:** Crypto Audit Notes — patient records are decrypted in memory while processed on `ehr-srv-01`. Nurse-station workstations also have no automatic screen lock because the Group Policy screensaver timeout is set to `Never`.<br><br>**Status:** **Absent** |
| **Financial / billing data**<br>MySQL on `billing-srv-01` | **Protection:** None.<br><br>**Evidence:** Crypto Audit Notes and 1x00 crypto-miner incident review — the MySQL data directory is stored on unencrypted ext4 and database files were readable directly from the filesystem without MySQL credentials.<br><br>**Status:** **Absent** | **Protection:** SSL/TLS is not enforced; the billing application uses plaintext MySQL traffic over the flat network.<br><br>**Evidence:** Crypto Audit Notes — MySQL is bound to `0.0.0.0` and does not require SSL for connections.<br><br>**Status:** **Weak** | **Protection:** None documented.<br><br>**Evidence:** Crypto Audit Notes document no cryptographic mechanism protecting billing data while it is actively processed by the application or database server.<br><br>**Status:** **Absent** |
| **Medical images**<br>DICOM on PACS | **Protection:** None.<br><br>**Evidence:** Crypto Audit Notes — PACS stores DICOM images on local disk without encryption. Patient identifiers embedded in DICOM headers remain readable.<br><br>**Status:** **Absent** | **Protection:** None. Standard DICOM is used without DICOM TLS.<br><br>**Evidence:** Crypto Audit Notes — MRI, CT and X-ray data travels between the MRI workstation, radiology workstations and `pacs-srv-01` on ports `4242` and `11112` in cleartext.<br><br>**Status:** **Absent** | **Protection:** None documented.<br><br>**Evidence:** Crypto Audit Notes — DICOM files and embedded patient identifiers are readable by DICOM viewers and portions of the header are plaintext; no additional protection for images while being viewed or processed is documented.<br><br>**Status:** **Absent** |
| **Credentials**<br>Active Directory and application passwords | **Protection:** NTHash based on MD4 for NTLM-compatible password storage.<br><br>**Evidence:** Crypto Audit Notes — Active Directory uses NTHash/MD4 for NTLM compatibility. MD4 is an obsolete password-hashing primitive and does not provide modern password-storage protection.<br><br>**Status:** **Weak** | **Protection:** Mixed Kerberos encryption support: AES-256 and AES-128 are available, but RC4 and DES remain enabled. LDAP is not encrypted by default and LDAP signing is not required.<br><br>**Evidence:** 1x02 Finding 018 confirmed DES and RC4 are enabled. 1x02 Finding 007 confirmed LDAP signing is not required.<br><br>**Status:** **Weak** | **Protection:** None documented.<br><br>**Evidence:** The Crypto Audit Notes identify no dedicated cryptographic mechanism protecting credential material while authentication operations are actively processed in memory.<br><br>**Status:** **Absent** |
| **Backup data**<br>`NAS-01` | **Protection:** None.<br><br>**Evidence:** Crypto Audit Notes — the Synology NAS stores backups on RAID-5 with no encryption layer. PostgreSQL and MySQL database dumps are readable in plaintext. Synology shared-folder encryption is supported but has not been enabled.<br><br>**Status:** **Absent** | **Protection:** None documented.<br><br>**Evidence:** The Crypto Audit Notes identify no transport-encryption mechanism for backup transfers to `NAS-01`. The NAS management interface is also reachable over the flat network; 1x02 Finding 015 documented this exposure.<br><br>**Status:** **Absent** | **Protection:** None documented.<br><br>**Evidence:** No cryptographic control is documented for backup data while it is being accessed, restored or processed.<br><br>**Status:** **Absent** |
| **Email**<br>Microsoft O365 | **Protection:** BitLocker on Microsoft datacenter disks plus per-mailbox encryption with Microsoft-managed keys.<br><br>**Evidence:** Crypto Audit Notes — Microsoft provides encryption at rest for Exchange Online.<br><br>**Status:** **Adequate** | **Protection:** TLS 1.2 for Exchange Online connections.<br><br>**Evidence:** Crypto Audit Notes — O365 uses TLS 1.2 for email transport connections.<br><br>**Status:** **Adequate** | **Protection:** No message-level S/MIME or OME protection is configured.<br><br>**Evidence:** Crypto Audit Notes — MedDefense does not use individual message encryption and sensitive patient information is sometimes sent by physicians without message-level encryption.<br><br>**Status:** **Absent** |
| **VPN traffic**<br>Site-to-site FortiGate tunnels | **Protection:** None provided by the VPN for data after it is stored at either endpoint.<br><br>**Evidence:** Crypto Audit Notes only document protection while traffic crosses the VPN tunnel; no VPN-based at-rest protection exists once data reaches the destination system.<br><br>**Status:** **Absent** | **Protection:** IPsec using AES-256 for encryption, SHA-256 for integrity, and IKEv2 with Diffie-Hellman Group 14 for key exchange.<br><br>**Evidence:** Crypto Audit Notes — Central-to-Westside and Central-to-HQ tunnels use this configuration. The Westside endpoint is a consumer Netgear Nighthawk router with unknown firmware history, but no weakness in the configured cryptographic algorithms is identified.<br><br>**Status:** **Adequate** | **Protection:** None provided once tunnel traffic is decrypted at the VPN endpoints.<br><br>**Evidence:** The Crypto Audit Notes describe encryption for the tunnel only; no cryptographic mechanism is documented for traffic while it is actively processed after decryption.<br><br>**Status:** **Absent** |

## Gap Summary

Across the **21 assessed cells** (7 data categories × 3 data states):

| Status | Cells | Percentage |
|---|---:|---:|
| **Adequate** | 3 | 14.3% |
| **Weak** | 4 | 19.0% |
| **Absent** | 14 | 66.7% |
| **Total** | 21 | 100% |

### Cryptographic Coverage

If cryptographic coverage is defined as cells with **any implemented cryptographic protection**, including controls currently rated as weak, MedDefense has protection in **7 of 21 cells**, giving an overall crypto coverage of **33.3%**.

Only **3 of 21 cells (14.3%)** currently have protection that can be rated **Adequate**. The remaining **18 cells (85.7%)** either have weak protection or no documented cryptographic protection at all.

The inventory therefore supports Sarah Park's overall assessment: MedDefense provides adequate cryptographic protection mainly where it is handled by an external platform such as O365 or where a dedicated IPsec VPN has already been configured. Core systems controlled directly by MedDefense — including the EHR database, billing database, PACS/DICOM environment and NAS backups — contain substantial cryptographic gaps that require remediation during the cryptographic foundation project.

## Key Gaps Identified

1. **EHR and billing databases are not encrypted at rest.** Direct filesystem access exposes sensitive patient and billing information.
2. **Database transport encryption is inconsistent or absent.** PostgreSQL permits non-SSL connections and the billing application uses plaintext MySQL traffic.
3. **DICOM data has no cryptographic protection at rest or in transit.** Medical images and embedded patient identifiers can cross the network in cleartext.
4. **Legacy credential mechanisms remain enabled.** Active Directory still supports DES and RC4 Kerberos encryption types, while NTLM-compatible password storage relies on NTHash/MD4.
5. **LDAP protections are insufficient.** LDAP signing is not required and encryption is not enabled by default.
6. **Backups are stored without encryption.** Compromise of `NAS-01` would expose plaintext database dumps and other backup content.
7. **Email is protected by O365 at rest and in transit, but MedDefense has no message-level encryption for sensitive PHI.**
8. **Site-to-site VPN cryptography is currently adequate, but the Westside consumer-router endpoint introduces an implementation risk because its firmware status is unknown.**

