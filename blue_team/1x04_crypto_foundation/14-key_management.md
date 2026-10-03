# Task 14 - Hardware Security and Key Management

## Part 1 - Technology Comparison

| Technology | What It Is | What It Protects | Typical Cost | Typical Deployment |
| :--- | :--- | :--- | :--- | :--- |
| **TPM (Trusted Platform Module)** | A dedicated security chip, usually built into a computer or motherboard, that can securely generate, store and use cryptographic keys. | Device-specific keys, disk-encryption keys, boot integrity measurements and credentials. | Usually included in business laptops/desktops; a separate TPM module is generally inexpensive if the hardware supports one. | Employee laptops, desktops and servers, especially for full-disk encryption such as BitLocker. |
| **HSM (Hardware Security Module)** | A tamper-resistant hardware device or cloud service designed specifically to generate, store and use cryptographic keys without exposing the private key material. | High-value encryption keys, signing keys, certificate private keys and database master keys. | Managed cloud HSM-backed keys can cost roughly **$1–2 per key per month**; dedicated single-tenant HSM services or physical appliances can cost thousands of dollars per month or more. | Central key protection for databases, PKI, payment systems, certificate authorities and other high-value cryptographic services. |
| **Secure Enclave** | An isolated protected area inside a processor or system-on-chip that performs sensitive operations separately from the main operating system. | Device keys, biometric information, application secrets and cryptographic operations that should remain isolated even if the main OS is compromised. | Usually built into the device, so there is normally no separate hardware purchase. | Smartphones, tablets, modern laptops and some servers or embedded devices. |
| **KMS (Software)** | A centralized Key Management System that creates, stores, rotates, controls and audits access to encryption keys. It may use software protection or connect to an HSM for hardware-backed protection. | Centralized lifecycle management of encryption keys across applications and infrastructure. | Cloud software-backed KMS keys can cost only a few cents per key each month plus operations; enterprise products vary widely. | Cloud applications, databases, backups, storage systems and organizations that need centralized key rotation and access control. |

### Key Difference

A **TPM** normally protects keys for one physical device. A **secure enclave** protects sensitive operations inside a particular device or processor. A **KMS** manages keys centrally across many systems. An **HSM** provides the strongest dedicated hardware protection for high-value keys and is often used underneath or alongside a KMS.

For MedDefense, these technologies should not be treated as competitors where only one can be selected. Employee laptops can use TPM-backed full-disk encryption, while central database and backup keys can be managed through an HSM-backed KMS.

---

# Part 2 - MedDefense Key Management Plan

MedDefense now needs to manage keys for the patient database, backup storage, patient portal and VPN tunnels. The main rule is that **encryption keys must not be stored in plaintext beside the data they protect**.

The governance model from Project 1x03 gives the following responsibilities:

- **Deputy CISO - James Chen:** accountable for the key-management policy and major security decisions.
- **IT Director - Sarah Park:** responsible for technical implementation and infrastructure changes.
- **Security Analyst:** monitors key use, reviews logs and verifies that controls are working.
- **Department Heads / Data Owners:** approve access where business or clinical ownership is required.
- **CEO - Dr. Morales:** approves significant risk acceptance or major exceptions.

Access should follow least privilege and separation of duties. A person who administers a database should not automatically have unrestricted access to the master encryption key.

---

## Key Management Matrix

| System / Key | Storage Location | Who Has Access | Rotation | If Compromised | If Lost |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL patient database (`ehr-db-01`)** | HSM-backed KMS. The database uses a Data Encryption Key (DEK), while the master Key Encryption Key (KEK) remains protected by the KMS/HSM. | Database service account can request approved cryptographic operations. Sarah Park's authorised infrastructure administrators manage configuration. James Chen owns policy. Security Analyst reviews audit logs. | Rotate the KEK at least annually and immediately after suspected compromise. Generate a new DEK when required by the database encryption design; old keys remain available only as long as needed to decrypt historical data. | Disable the affected key, create a new key, re-wrap or re-encrypt the database keys, investigate KMS access logs and remove any compromised credentials. | Recover through the redundant KMS/HSM and protected key backup. Losing every valid database encryption key would make the encrypted patient data unreadable. |
| **NAS-01 backup encryption** | Separate KMS/HSM-backed key or protected enterprise secrets system. A recovery copy is held separately from NAS-01. The key must never be stored in plaintext on the NAS. | Backup service account and a very small group of authorised infrastructure/recovery administrators. Access is logged. | Rotate at least annually and when an administrator with key access leaves or a compromise is suspected. Old keys are retained until all backups encrypted with them expire. | Remove access to the old key, create a new backup key and encrypt new backup sets with it. Investigate whether existing backups were exposed and re-encrypt them when appropriate. | Use the protected recovery copy. If both the production key and recovery copy are lost, backups encrypted with that key cannot be restored. |
| **Patient portal TLS private key** | Prefer a managed certificate service or HSM-backed key store where the private key is non-exportable. If this is not technically possible, use a tightly protected OS key store with strict file permissions. | The web server process receives only the access it needs. Certificate/key administration is limited to authorised IT administrators. | Generate a new private key whenever the TLS certificate is renewed rather than repeatedly reusing the same key. Renewal should be automated well before certificate expiry. | Revoke the affected certificate where applicable, generate a new private key and certificate, deploy them immediately and investigate how the old key was exposed. | A lost TLS private key does not require recovery for future service. Generate a new key pair and obtain a replacement certificate. |
| **VPN tunnel authentication keys** | Certificate private keys stored in the VPN/firewall appliance secure key store, TPM or HSM where supported. Ephemeral session keys are generated automatically during IKE/TLS negotiation and are not permanently stored. | Network administrators under Sarah Park manage the VPN configuration. James Chen approves policy; Security Analyst reviews authentication and configuration logs. | Long-term authentication certificates are rotated according to certificate lifetime and after personnel/device changes. Session encryption keys automatically rotate according to the configured tunnel lifetime. | Revoke the affected certificate or credential, generate a replacement, update the VPN peers and review logs for unauthorized tunnel use. | Replace the long-term authentication key/certificate from the approved configuration process. Normal ephemeral session keys do not need recovery. |

---

## Key Lifecycle

MedDefense should use the same basic lifecycle for every managed key:

```text
Generate
   ↓
Store securely
   ↓
Authorise access
   ↓
Use
   ↓
Monitor
   ↓
Rotate
   ↓
Retire
   ↓
Destroy when no longer required
```

### 1. Key Generation

Keys should be generated using cryptographically secure random number generators. High-value master keys should be created inside the KMS or HSM so that the raw key does not need to be copied between systems.

### 2. Key Storage

Master encryption keys should be stored separately from the encrypted data. Database and backup keys should use centralized KMS/HSM protection, while endpoint disk-encryption keys can use each device's TPM.

### 3. Access Control

Administrative access to the key-management system should require MFA and named accounts. Service accounts should only receive permission to perform the specific cryptographic operation they require rather than permission to export master keys.

### 4. Rotation

Rotation reduces the amount of data and time covered by one key. MedDefense should use automatic rotation where the platform supports it, but should also be able to trigger immediate rotation after a security incident.

### 5. Revocation and Replacement

If a key may have been compromised, it should be disabled or revoked as quickly as possible, replaced with a new key, and affected systems should be reconfigured. Security logs should then be reviewed to determine whether the compromised key was actually used.

### 6. Recovery and Escrow

Keys that are required to recover historical encrypted data, particularly database and backup keys, need a protected recovery mechanism. Recovery copies must be stored separately from the systems they protect and access should require strong authentication and authorization.

Not every private key should be escrowed. For example, a lost patient-portal TLS private key can simply be replaced with a new key pair and certificate, so retaining unnecessary copies of that private key would create additional exposure.

---

# Part 3 - The HSM Decision

## Relevant MedDefense Risk

The closest quantified risk in the Project 1x03 Risk Register is **RISK-001 - Ransomware Double Extortion Against the EHR**.

The risk includes:

- `ehr-db-01`;
- exfiltration of patient data;
- EHR disruption; and
- an **Annual Loss Expectancy (ALE) of $1,050,000 per year**.

The Risk Register rates this risk **25 - Critical** before planned controls.

There is also **RISK-009 - Malicious Insider EHR Misuse**, which directly concerns unauthorized access to patient information, although an individual ALE was not calculated for that risk.

An HSM does not eliminate either risk. For example, it cannot stop an authorised EHR application from reading patient records while the database is legitimately unlocked. What it does reduce is the chance that an attacker can simply steal a database encryption key from a configuration file, server filesystem or administrator account and use that key elsewhere.

---

## Estimated HSM Cost

For this assessment, I would use a **managed HSM-backed KMS** rather than purchasing a dedicated physical HSM.

The task provides an estimated cost of approximately:

```text
$1-2 per protected key per month
```

For the database, MedDefense should normally maintain at least:

```text
1 current database master key
1 previous key version retained during rotation/recovery
```

Estimated annual cost:

```text
2 keys × $1/month × 12 months = $24/year
2 keys × $2/month × 12 months = $48/year
```

Therefore:

```text
Estimated HSM-backed database-key cost = approximately $24-$48/year
```

There may also be small charges for cryptographic operations, but these are unlikely to materially change the decision at MedDefense's scale.

As a real-world comparison, Google Cloud currently lists HSM-protected AES-256 key versions at approximately **$1 per month per active key version**, while software-protected KMS key versions are cheaper. A dedicated single-tenant HSM service is a very different product and can cost thousands of dollars per month, which would not be appropriate for MedDefense's current $120,000 security programme.

---

## Cost Compared with Risk

The quantified EHR risk is:

```text
RISK-001 ALE = $1,050,000/year
```

Using the high end of the estimated managed HSM cost:

```text
Annual HSM cost = $48
```

Break-even comparison:

```text
$48 / $1,050,000 × 100
≈ 0.0046%
```

This means the control would only need to reduce approximately **0.005% of the annualized EHR loss exposure** for its direct cost to be financially recovered.

This calculation does **not** mean that an HSM reduces the entire $1.05 million ransomware ALE. The ALE includes many consequences that key protection cannot prevent, including downtime, ransomware deployment and operational disruption. The comparison simply shows that the cost of protecting the database master key is extremely small relative to the value and risk of the patient-data environment.

---

## Decision

**MedDefense should use an HSM-backed KMS for the EHR database master encryption key.**

The investment is justified because:

1. the EHR contains approximately 50,000 regulated patient records;
2. RISK-001 already carries an ALE of **$1.05 million per year**;
3. the managed HSM cost is extremely small compared with that exposure;
4. keeping the master key outside `ehr-db-01` prevents the most obvious failure of storing the encrypted data and its key together;
5. HSM-backed keys can be made non-exportable and their use can be logged and controlled centrally; and
6. the same key-management platform can later support NAS backup encryption and other MedDefense cryptographic controls.

However, MedDefense should **not purchase a dedicated on-premises HSM appliance or expensive single-tenant cloud HSM at this stage** unless a compliance, performance or contractual requirement later demands it. An HSM-backed managed KMS provides an appropriate balance between security, cost and operational complexity for the current environment.

---

# Recommended MedDefense Key Architecture

```text
                   Deputy CISO
                   James Chen
                       |
                Key Management Policy
                       |
                       v
              +-------------------+
              | HSM-backed KMS    |
              | Master / KEK keys |
              +-------------------+
                 /       |       \
                /        |        \
               v         v         v
        PostgreSQL    NAS-01     Other
        database      backups    protected
        DEK           DEK        keys

Employee laptops
       |
       v
 TPM-backed full-disk encryption

Patient portal / VPN
       |
       v
Certificate private keys in secure
device/HSM-backed key stores
```

The KMS/HSM should protect the **master keys**, while systems use separate data-encryption keys wherever possible. This reduces the number of times the most valuable keys are exposed and allows keys to be rotated, disabled and audited centrally.

---

# Final Recommendation

MedDefense should adopt **centralized key management with HSM-backed protection for high-value server keys**, while using TPMs and device secure hardware where the key belongs to a single endpoint. Database, backup, portal and VPN keys should each have defined owners, rotation schedules, compromise procedures and recovery plans.

The key-management system must be treated as critical infrastructure. Strong encryption is only valuable when the keys are protected separately, access is controlled and logged, and MedDefense can recover legitimate keys without giving an attacker an easy path to the same material.

---

## References

- MedDefense Project 1x03, `10-risk_register.md`.
- MedDefense Project 1x03, `17-security_strategy.md`.
- Google Cloud, *Cloud Key Management Service pricing*.
- AWS, *Key Management Service (KMS) documentation*.
- AWS, *CloudHSM documentation*.
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management: Part 1 - General*.
