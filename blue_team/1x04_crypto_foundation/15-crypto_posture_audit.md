# Task 15 - The Crypto Posture Audit

## MedDefense Health Systems

### Scope

This audit revisits the Data Protection Map from Task 0 and converts every cell previously rated **Weak** or **Absent** into a formal Crypto Finding.

The original map contained:

- **21 total data-state cells**
- **3 Adequate**
- **4 Weak**
- **14 Absent**

Therefore, this report contains **18 Crypto Findings**.

The three cells already rated Adequate are not repeated as findings:

1. O365 email at rest
2. O365 email in transit
3. Site-to-site VPN traffic in transit

---

# Crypto Findings

## CRYPTO-001 - Patient Records at Rest

**Finding ID:** CRYPTO-001  
**Data Category:** Patient medical records - PostgreSQL on `ehr-db-01`  
**Data State:** At rest  
**Current Protection:** None. The PostgreSQL data directory is stored on an unencrypted ext4 filesystem.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding; related to the exposure of `ehr-db-01` and broad access documented around the EHR environment.  
**Risk Reference:** **RISK-001 - EHR ransomware double extortion**; also relevant to **RISK-009 - malicious insider EHR misuse**.  
**Algorithm Assessment:** No encryption algorithm is currently protecting the database files. T6 identifies AES as an approved modern symmetric algorithm and recommends AES-GCM for new MedDefense cryptographic controls.  
**Recommended Protection:** Encrypt the EHR database using **AES-256** at the database/storage layer, with **AES-256-GCM** for application or field-level protection of especially sensitive records where supported.  
**Encryption Level:** **Database-level encryption**, with **record-level encryption** for especially sensitive fields.  
**Key Management:** Use a database DEK protected by a KEK in the **HSM-backed KMS** defined in T14. The KEK should not be stored on `ehr-db-01`; access should be logged and limited to authorised service and infrastructure roles.  
**Implementation Priority:** **Phase 1**

### Rationale

The EHR contains MedDefense's most sensitive regulated information and is part of RISK-001, which has an ALE of **$1,050,000 per year**. Encrypting the database at rest prevents direct disk or filesystem access from immediately exposing readable patient records.

---

## CRYPTO-002 - Patient Records in Transit

**Finding ID:** CRYPTO-002  
**Data Category:** Patient medical records  
**Data State:** In transit  
**Current Protection:** PostgreSQL SSL is available but not enforced because both encrypted and non-encrypted connections are permitted. The patient portal also supports TLS 1.0 alongside TLS 1.2.  
**Vulnerability Reference:** **1x02 Finding 005 - TLS 1.0 enabled on the patient portal**; **Finding 013 - patient portal certificate nearing expiration**.  
**Risk Reference:** **RISK-001 - EHR ransomware double extortion** and **RISK-009 - malicious insider EHR misuse**.  
**Algorithm Assessment:** TLS 1.2 remains acceptable when configured with modern cipher suites, but **TLS 1.0 is obsolete**. Allowing plaintext PostgreSQL connections also defeats the protection provided by SSL-capable clients.  
**Recommended Protection:** Enforce **TLS 1.2 and TLS 1.3 only**, using **ECDHE** for forward-secret key establishment and **AES-256-GCM**, **AES-128-GCM**, or an approved equivalent AEAD cipher for bulk encryption. Require SSL for all PostgreSQL connections and remove `hostnossl` access.  
**Encryption Level:** Database/record protection at the endpoints, with **transport encryption** for the network path.  
**Key Management:** Store the patient-portal private key in a managed certificate service or HSM-backed key store as defined in T14. Generate a new private key during certificate renewal and automate renewal before expiry.  
**Implementation Priority:** **Immediate**

### Rationale

This finding combines a known legacy TLS exposure with optional database transport encryption. Because the portal certificate is also close to expiration, remediation should be completed before a trust failure affects patient access.

---

## CRYPTO-003 - Patient Records in Use

**Finding ID:** CRYPTO-003  
**Data Category:** Patient medical records  
**Data State:** In use  
**Current Protection:** None beyond normal application access controls. Patient information is decrypted in memory while being processed and displayed, and nurse-station systems have no automatic screen lock.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding.  
**Risk Reference:** **RISK-009 - malicious insider EHR misuse**; also contributes to **RISK-001** if an attacker gains application-level access.  
**Algorithm Assessment:** Conventional encryption cannot keep data encrypted while an ordinary application is actively processing plaintext. The correct objective is therefore to minimise the amount of plaintext exposed and apply more granular encryption to the most sensitive fields.  
**Recommended Protection:** Use **AES-256-GCM record/field-level encryption** for selected highly sensitive data and decrypt only when the authorised application needs it. Enforce screen locking and least-privilege application access; use secure-enclave/confidential-computing capabilities only where the platform supports them.  
**Encryption Level:** **Record-level encryption** for the most sensitive fields.  
**Key Management:** Application services should request required DEKs through the central KMS and must not store plaintext master keys in configuration files.  
**Implementation Priority:** **Phase 2**

---

## CRYPTO-004 - Financial Data at Rest

**Finding ID:** CRYPTO-004  
**Data Category:** Financial/billing data - MySQL on `billing-srv-01`  
**Data State:** At rest  
**Current Protection:** None. MySQL database files are stored on unencrypted ext4 and were readable directly from the filesystem.  
**Vulnerability Reference:** Related to the multiple `billing-srv-01` weaknesses in 1x02, including broad MySQL exposure and unsupported software.  
**Risk Reference:** **RISK-004 - compromise of `billing-srv-01`**, ALE **$234,000/year**.  
**Algorithm Assessment:** No encryption algorithm currently protects the billing database files. AES is suitable for bulk data encryption; DES, 3DES and RC4 would not be acceptable replacements.  
**Recommended Protection:** Use **AES-256** database encryption, with **AES-256-GCM** for particularly sensitive financial or payment fields where application-level authenticated encryption is required.  
**Encryption Level:** **Database-level encryption**, with **record-level encryption** for sensitive financial fields.  
**Key Management:** Use a billing DEK protected by a separate KEK in the central HSM-backed KMS. Billing administrators should not automatically have permission to export the master key.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-005 - Financial Data in Transit

**Finding ID:** CRYPTO-005  
**Data Category:** Financial/billing data  
**Data State:** In transit  
**Current Protection:** SSL/TLS is not enforced and the billing application can communicate with MySQL in plaintext across the internal network.  
**Vulnerability Reference:** Related to the 1x02 MySQL exposure on `billing-srv-01`.  
**Risk Reference:** **RISK-004 - compromise of `billing-srv-01`**.  
**Algorithm Assessment:** Plaintext database traffic provides no confidentiality or integrity.  
**Recommended Protection:** Require **TLS 1.2 or TLS 1.3** for all MySQL sessions with **AES-128-GCM or AES-256-GCM** cipher suites and certificate validation. Disable non-TLS database connections.  
**Encryption Level:** Database protection at the endpoints plus **transport encryption** between application and database.  
**Key Management:** Server certificate/private key should be stored in the protected server key store or HSM-backed KMS where supported. Certificate renewal and revocation should follow the T14 lifecycle.  
**Implementation Priority:** **Immediate**

---

## CRYPTO-006 - Financial Data in Use

**Finding ID:** CRYPTO-006  
**Data Category:** Financial/billing data  
**Data State:** In use  
**Current Protection:** None documented while billing data is actively processed.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding.  
**Risk Reference:** **RISK-004 - compromise of `billing-srv-01`**.  
**Algorithm Assessment:** Data must normally be decrypted for application processing, so full encryption of ordinary in-use data is not realistic without specialised hardware.  
**Recommended Protection:** Use **AES-256-GCM field-level encryption** for payment, banking or other highly sensitive fields and decrypt only inside the authorised billing process.  
**Encryption Level:** **Record-level encryption** for the highest-sensitivity fields.  
**Key Management:** The billing application should obtain the field-encryption DEK through the central KMS and keep plaintext key material only in memory for the minimum necessary period.  
**Implementation Priority:** **Phase 2**

---

## CRYPTO-007 - Medical Images at Rest

**Finding ID:** CRYPTO-007  
**Data Category:** Medical images - DICOM on PACS  
**Data State:** At rest  
**Current Protection:** None. PACS stores DICOM images and readable patient identifiers on unencrypted local storage.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding; the medical-imaging environment is also connected to the unsupported MRI workstation exposure.  
**Risk Reference:** Most closely related to **RISK-006 - Windows XP MRI exploitation/disruption**, ALE **$163,625/year**.  
**Algorithm Assessment:** There is currently no at-rest cipher protecting the DICOM store. AES is appropriate for large storage volumes.  
**Recommended Protection:** Encrypt the PACS storage volume using **AES-256-XTS** or the platform's equivalent strong AES volume-encryption mode.  
**Encryption Level:** **Volume-level encryption**.  
**Key Management:** Store the volume recovery/master key outside `pacs-srv-01` in the central KMS or protected recovery system. Limit key administration to authorised IT personnel and retain a separately protected recovery copy.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-008 - Medical Images in Transit

**Finding ID:** CRYPTO-008  
**Data Category:** Medical images - DICOM on PACS  
**Data State:** In transit  
**Current Protection:** None. Standard DICOM traffic is sent in cleartext between imaging systems and `pacs-srv-01`.  
**Vulnerability Reference:** No direct cryptographic 1x02 finding; relevant to the MRI and clinical-network exposure identified in 1x02.  
**Risk Reference:** **RISK-006 - Windows XP MRI exploitation/disruption** and the broader clinical lateral-movement risk.  
**Algorithm Assessment:** Cleartext DICOM provides no confidentiality for images or patient identifiers.  
**Recommended Protection:** Enable **DICOM over TLS 1.2/1.3**, using **ECDHE** with **AES-128-GCM or AES-256-GCM**. Where legacy imaging equipment cannot support DICOM TLS, place traffic inside an authenticated IPsec tunnel as a compensating control until replacement.  
**Encryption Level:** **Volume-level protection at rest** plus transport-layer encryption for DICOM flows.  
**Key Management:** DICOM server certificates and private keys should follow the central certificate/key lifecycle. Legacy tunnel keys should use the same controlled VPN key-management approach defined in T14.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-009 - Medical Images in Use

**Finding ID:** CRYPTO-009  
**Data Category:** Medical images - DICOM on PACS  
**Data State:** In use  
**Current Protection:** None documented while images and DICOM headers are viewed or processed.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding.  
**Risk Reference:** Related to **RISK-006** because compromise of the imaging environment could expose or manipulate clinical data.  
**Algorithm Assessment:** DICOM viewers require plaintext image data in memory to display images, so conventional encryption cannot remain applied during normal viewing.  
**Recommended Protection:** Keep DICOM files encrypted with **AES-256** until an authorised viewer requests them, decrypt only for the active session, and enforce strong workstation access controls and automatic screen locking.  
**Encryption Level:** **File-level** protection for exported images where needed, backed by **volume-level** PACS encryption.  
**Key Management:** PACS services should retrieve required keys from the central KMS; exported encrypted files should use controlled file-encryption keys rather than embedded passwords.  
**Implementation Priority:** **Phase 2**

---

## CRYPTO-010 - Credentials at Rest

**Finding ID:** CRYPTO-010  
**Data Category:** Credentials - Active Directory and application passwords  
**Data State:** At rest  
**Current Protection:** Active Directory retains NT hash material based on MD4 for NTLM compatibility; this is a fast legacy password-hash construction and is not equivalent to modern password storage such as Argon2id.  
**Vulnerability Reference:** Related to 1x02 identity weaknesses; no direct standalone vulnerability is required for the NT hash design itself.  
**Risk Reference:** **RISK-002 - Active Directory privileged compromise**, ALE **$210,000/year**.  
**Algorithm Assessment:** **MD4/NT hash is obsolete as a modern password-storage design.** T6 identifies MD5/SHA-1-era primitives and other legacy algorithms as unsuitable for new protection.  
**Recommended Protection:** For MedDefense-developed applications, store passwords with **Argon2id** using unique salts and an appropriate memory/time cost. For Active Directory, reduce dependence on NTLM, enforce Kerberos AES, and protect `NTDS.dit` and system volumes with **XTS-AES-256 full-disk encryption**.  
**Encryption Level:** **Full-disk encryption** for domain controllers plus record/password-level protection for MedDefense applications.  
**Key Management:** Protect server disk keys using TPM-backed encryption with centrally escrowed recovery keys. Any optional application password pepper should be stored in the central KMS, not in the application database.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-011 - Credentials in Transit

**Finding ID:** CRYPTO-011  
**Data Category:** Credentials - Active Directory and application authentication  
**Data State:** In transit  
**Current Protection:** Mixed. Kerberos supports AES but still allows **DES and RC4**; LDAP signing is not required and LDAP is not encrypted by default.  
**Vulnerability Reference:** **1x02 Finding 018 - legacy DES/RC4 Kerberos support** as carried into T0; **1x02 Finding 007 - LDAP signing not enforced**.  
**Risk Reference:** **RISK-002 - Active Directory privileged compromise**.  
**Algorithm Assessment:** **AES-128/AES-256 are adequate; DES and RC4 are not.** DES has an insufficient 56-bit key, while RC4 has serious cryptographic weaknesses and should not be used for new protection.  
**Recommended Protection:** Disable **DES and RC4**, require Kerberos **AES-256/AES-128**, require LDAP signing and channel binding, and use **LDAPS/TLS 1.2 or TLS 1.3** where directory traffic requires encryption.  
**Encryption Level:** Identity/credential transport protection; endpoint credential stores remain protected at full-disk/application level.  
**Key Management:** Domain and service keys should remain under Active Directory's controlled key lifecycle; privileged administrative access should require MFA, and certificate/private-key material for LDAPS should follow the central certificate process.  
**Implementation Priority:** **Immediate**

---

## CRYPTO-012 - Credentials in Use

**Finding ID:** CRYPTO-012  
**Data Category:** Credentials  
**Data State:** In use  
**Current Protection:** No dedicated cryptographic mechanism is documented for credentials while authentication operations are active in memory.  
**Vulnerability Reference:** Related to 1x02 identity and credential-control findings.  
**Risk Reference:** **RISK-002 - Active Directory privileged compromise**.  
**Algorithm Assessment:** Credentials inevitably exist briefly in usable form during authentication, so the main objective is to prevent reusable plaintext secrets and minimise memory exposure.  
**Recommended Protection:** Prefer **Kerberos AES-256/AES-128** and non-reusable authentication mechanisms over plaintext passwords; enable Windows credential protections such as protected LSASS/Credential Guard where supported and avoid applications that keep plaintext passwords in memory.  
**Encryption Level:** Endpoint/full-disk protection plus application/credential-level controls.  
**Key Management:** Device-bound credential keys should use TPM-backed protection where supported; domain/service keys remain centrally governed and should rotate when accounts or services change.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-013 - Backup Data at Rest

**Finding ID:** CRYPTO-013  
**Data Category:** Backup data - `NAS-01`  
**Data State:** At rest  
**Current Protection:** None. RAID-5 provides availability but not confidentiality; database dumps are readable in plaintext and Synology shared-folder encryption is not enabled.  
**Vulnerability Reference:** **1x02 Finding 015 - NAS management exposure** is relevant to the accessibility of the same backup infrastructure.  
**Risk Reference:** **RISK-003 - backup and recovery infrastructure neutralized during ransomware**; its financial impact is included in **RISK-001**.  
**Algorithm Assessment:** RAID is not encryption. The absence of a cryptographic layer means anyone with storage or authorised filesystem access can read the backups.  
**Recommended Protection:** Encrypt the NAS backup volume using **AES-256-XTS** or the NAS/LUKS-equivalent strong AES volume mode. Sensitive backup sets should additionally be encrypted before replication using **AES-256-GCM**.  
**Encryption Level:** **Volume-level encryption**, with file/backup-set encryption as defense in depth.  
**Key Management:** Use a separate KMS/HSM-backed backup key and a protected recovery copy. The key must not be stored in plaintext on `NAS-01`.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-014 - Backup Data in Transit

**Finding ID:** CRYPTO-014  
**Data Category:** Backup data - `NAS-01`  
**Data State:** In transit  
**Current Protection:** None documented for backup transfers to NAS-01.  
**Vulnerability Reference:** **1x02 Finding 015 - NAS management exposure**; broader network exposure also increases the importance of encrypted backup transport.  
**Risk Reference:** **RISK-003 - backup/recovery neutralization** and **RISK-001 - ransomware double extortion**.  
**Algorithm Assessment:** A plaintext backup transfer can expose an entire copy of sensitive systems even if the final storage is later encrypted.  
**Recommended Protection:** Use **TLS 1.2/1.3 with AES-GCM** for backup software transfers or an authenticated **IPsec/IKEv2 AES-256** tunnel when the backup product cannot provide strong native TLS.  
**Encryption Level:** **Volume-level encryption at rest** plus transport encryption during transfer.  
**Key Management:** Backup transfer certificates or tunnel authentication keys should be stored separately from backup data and rotated according to the T14 key lifecycle.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-015 - Backup Data in Use

**Finding ID:** CRYPTO-015  
**Data Category:** Backup data - `NAS-01`  
**Data State:** In use  
**Current Protection:** No cryptographic control is documented while backups are mounted, restored or processed.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding.  
**Risk Reference:** **RISK-003 - backup/recovery neutralization**.  
**Algorithm Assessment:** Once an encrypted backup volume is legitimately unlocked, the backup application must be able to read the data. Cryptography therefore needs to be combined with strict operational access controls.  
**Recommended Protection:** Keep backup sets encrypted with **AES-256-GCM** until restore operations require them, use isolated recovery systems, and minimise the duration for which decrypted backups are mounted.  
**Encryption Level:** **File/backup-set encryption** layered on top of **volume encryption**.  
**Key Management:** Restore services obtain keys from the KMS only when required; access is logged and limited to approved recovery administrators.  
**Implementation Priority:** **Phase 2**

---

## CRYPTO-016 - Email Data in Use

**Finding ID:** CRYPTO-016  
**Data Category:** Email - Microsoft O365  
**Data State:** In use  
**Current Protection:** O365 provides adequate encryption at rest and in transit, but MedDefense has no message-level S/MIME or OME protection and physicians sometimes send sensitive patient information without message-level encryption.  
**Vulnerability Reference:** No direct 1x02 cryptographic finding.  
**Risk Reference:** No specific 1x03 risk is dedicated to email disclosure; the issue contributes to broader patient-data and negligent-user exposure, including **RISK-005** where inappropriate user handling creates a foothold or data-exposure condition.  
**Algorithm Assessment:** Platform TLS does not protect a message after it arrives in a recipient mailbox. Additional message-level protection is needed when PHI must remain encrypted beyond transport.  
**Recommended Protection:** Use **Microsoft Purview Message Encryption / OME** for sensitive external mail or **S/MIME** using modern certificate algorithms such as **RSA-2048+ or ECC P-256** with **AES-256** content encryption where supported.  
**Encryption Level:** **File/message-level encryption**.  
**Key Management:** Microsoft-managed service keys can remain the baseline for normal O365 data. S/MIME private keys should be issued and managed through MedDefense's PKI/key lifecycle, with recovery/escrow only where business requirements justify it.  
**Implementation Priority:** **Phase 1**

---

## CRYPTO-017 - VPN Data at Rest at Tunnel Endpoints

**Finding ID:** CRYPTO-017  
**Data Category:** VPN traffic - site-to-site tunnels  
**Data State:** At rest  
**Current Protection:** The VPN provides no protection after transmitted data is written to storage on the destination system.  
**Vulnerability Reference:** The VPN cryptographic algorithms themselves were adequate in T0; the main 1x02 concern is the Westside consumer-router/perimeter implementation rather than the AES-256/IPsec algorithms.  
**Risk Reference:** **RISK-010 - Westside perimeter compromise** and any system-specific risk for the data stored after tunnel delivery.  
**Algorithm Assessment:** **AES-256/SHA-256/IKEv2 with DH Group 14** is adequate for the tunnel, but tunnel encryption does not provide at-rest encryption after delivery.  
**Recommended Protection:** Apply the appropriate destination control: **AES-256-XTS** for disks/volumes or **AES-256-GCM** for database/file data requiring authenticated encryption.  
**Encryption Level:** Depends on the destination: **full-disk, volume, database or record level** as defined in T13.  
**Key Management:** Endpoint storage keys should use TPM or the central HSM-backed KMS according to the destination system. VPN authentication keys remain in secure appliance/device key stores.  
**Implementation Priority:** **Phase 2**

---

## CRYPTO-018 - VPN Data in Use at Tunnel Endpoints

**Finding ID:** CRYPTO-018  
**Data Category:** VPN traffic - site-to-site tunnels  
**Data State:** In use  
**Current Protection:** Traffic is decrypted when it reaches the VPN endpoint and receives no additional VPN-layer cryptographic protection while applications process it.  
**Vulnerability Reference:** No separate 1x02 cryptographic finding; relevant to the Westside perimeter and endpoint risks.  
**Risk Reference:** **RISK-010 - Westside perimeter compromise**, together with the risk associated with whichever destination system processes the data.  
**Algorithm Assessment:** This is normal VPN behaviour rather than a broken AES implementation: traffic must be decrypted before an internal application can use it. The security gap is relying on tunnel encryption as though it also protected the destination endpoint.  
**Recommended Protection:** Use **end-to-end application encryption** such as **TLS 1.2/1.3 with AES-GCM** for sensitive application flows even when they already travel inside the IPsec VPN. Keep sensitive data field-encrypted with **AES-256-GCM** until the receiving application requires plaintext.  
**Encryption Level:** Application/database/record level depending on the destination data.  
**Key Management:** Application TLS and data-encryption keys should follow the central T14 key lifecycle independently of the VPN tunnel keys.  
**Implementation Priority:** **Phase 2**

---

# Posture Score

## Current Protection

The original Data Protection Map contained:

| Status | Cells | Percentage |
| --- | ---: | ---: |
| Adequate | 3 | 14.3% |
| Weak | 4 | 19.0% |
| Absent | 14 | 66.7% |
| **Total** | **21** | **100%** |

Only **3 of 21 data-state cells (14.3%)** currently have adequate cryptographic protection.

## Remediation Coverage

This audit creates a specific remediation path for every cell previously rated Weak or Absent:

```text
Weak or Absent cells:           18
Cells with remediation path:    18
18 / 18 × 100 = 100%
```

Therefore, **100% of the identified cryptographic gaps now have a documented remediation path**.

Looking at the full Data Protection Map:

```text
3 cells already Adequate
18 cells now have defined remediation
--------------------------------------
21 / 21 cells have a clear disposition
```

The **Posture Score for remediation coverage is therefore 100%**.

This does **not** mean MedDefense is currently 100% cryptographically protected. Current adequate implementation remains **14.3%** until the recommended controls are actually deployed and verified.

---

# Top 3 Crypto Risks

## 1. CRYPTO-001 - Unencrypted EHR Patient Database at Rest

**Risk linkage:** RISK-001 - **25 Critical**, ALE **$1,050,000/year**; also relevant to RISK-009.

This is the highest-priority cryptographic exposure because direct filesystem or disk access can expose approximately 50,000 regulated patient records without first defeating an encryption layer. The database is part of MedDefense's highest quantified risk and must receive database encryption with protected external key management during Phase 1.

## 2. CRYPTO-013 - Unencrypted Backup Data on NAS-01

**Risk linkage:** RISK-003 - **20 Critical**, with financial impact included in RISK-001.

Backups contain concentrated copies of MedDefense's most important information and are the final recovery mechanism after a ransomware event. Plaintext backups create both a confidentiality problem and a recovery problem: an attacker who reaches NAS-01 can read data and can potentially destroy the copies required for restoration.

## 3. CRYPTO-011 - Legacy Credential Cryptography and Weak Directory Transport

**Risk linkage:** RISK-002 - **20 Critical**, ALE **$210,000/year**.

Active Directory is a shared authentication dependency across MedDefense. Continuing to permit DES/RC4 while LDAP signing/encryption is insufficient creates an identity-layer weakness with organization-wide reach. Removing obsolete Kerberos algorithms and enforcing protected LDAP traffic is therefore an immediate priority.

> RISK-002 and RISK-003 both have an inherent risk score of 20. Backup encryption is placed second because loss of the recovery environment directly compounds RISK-001, MedDefense's highest-ALE risk; the ranking does not change the requirement to remediate both during the cryptographic programme.

---

# Priority Summary

| Priority | Findings | Main Actions |
| :--- | :--- | :--- |
| **Immediate** | CRYPTO-002, CRYPTO-005, CRYPTO-011 | Remove TLS 1.0, renew portal certificate, enforce encrypted database connections, disable DES/RC4, require protected LDAP |
| **Phase 1** | CRYPTO-001, CRYPTO-004, CRYPTO-007, CRYPTO-008, CRYPTO-010, CRYPTO-012, CRYPTO-013, CRYPTO-014, CRYPTO-016 | Encrypt EHR/billing/PACS/backups, protect credential stores, secure DICOM and backup transport, introduce message-level PHI protection |
| **Phase 2** | CRYPTO-003, CRYPTO-006, CRYPTO-009, CRYPTO-015, CRYPTO-017, CRYPTO-018 | Reduce in-use exposure, add granular encryption, strengthen endpoint/application protection beyond network-tunnel encryption |

---

# Overall Assessment

MedDefense's original cryptographic posture was weakest on systems managed directly by the organisation: EHR, billing, PACS, Active Directory and backups. The problem is not that MedDefense lacks access to strong algorithms; it is that strong cryptography is inconsistently applied across data states and is sometimes undermined by legacy protocols or missing key-management processes.

The remediation strategy is therefore layered:

- **AES-256-based storage encryption** for databases, volumes and backup data;
- **AES-GCM authenticated encryption** where record, file or application-level protection is required;
- **TLS 1.2/1.3 with ECDHE and AEAD suites** for application and database transport;
- removal of **DES and RC4** from credential flows;
- **HSM-backed centralized key management** for high-value server keys;
- TPM/device-bound protection where keys belong to individual endpoints; and
- tightly controlled decryption during legitimate data use.

Once these controls are implemented and verified, MedDefense will move from isolated examples of adequate cryptography to a consistent architecture covering data at rest, in transit and, where technically practical, in use.

---

## Internal References

- Task 0 - `0-crypto_inventory.md`
- Task 2 / T6 algorithm assessment - `2-asymmetric_analysis.md`
- Task 11 - `11-tls_audit.md`
- Task 12 - `12-disk_encryption.md`
- Task 13 - `13-encryption_levels.md`
- Task 14 - `14-key_management.md`
- Project 1x02 - Vulnerability Assessment
- Project 1x03 - `10-risk_register.md`
- Project 1x03 - `17-security_strategy.md`
