# Task 20 - The Implementation Playbook

## MedDefense Health Systems

**Purpose:** Operational deployment guide for the first five cryptographic remediation actions identified in Task 15.

This playbook is designed to be followed by Sarah Park and the MedDefense IT team during controlled production changes. Each action includes prerequisites, implementation steps, validation, rollback criteria, maintenance timing and communication requirements.

> **Operational rule:** Values shown in angle brackets such as `<PGDATA>` or `<new_encrypted_device>` are environment-specific values that must be confirmed during the pre-change check. They are not missing work and must never be guessed on a production system.

## Deployment Order

The first five changes are selected from the Task 15 priority assessment:

| Order | T15 Finding | Change | Priority |
| ---: | --- | --- | --- |
| 1 | CRYPTO-002 | Harden patient/EHR transport encryption | Immediate |
| 2 | CRYPTO-005 | Enforce TLS for MySQL billing traffic | Immediate |
| 3 | CRYPTO-011 | Remove legacy AD cryptography and enforce LDAP protection | Immediate |
| 4 | CRYPTO-001 | Encrypt the EHR PostgreSQL database at rest | Phase 1 |
| 5 | CRYPTO-013 / CRYPTO-014 | Encrypt NAS backup storage and backup transport | Phase 1 |

The Immediate items are deployed first because they remove active use of plaintext or obsolete protocols. The Phase 1 storage changes follow because they require controlled data migration and stronger rollback planning.

---

# Action #1: Harden Patient Portal and EHR Database Transport Encryption

**Priority:** Immediate  
**System Affected:** `portal.meddefense.local` and `ehr-db-01`  
**Related Finding:** CRYPTO-002  
**Risk Reference:** RISK-001 and RISK-009

## Prerequisites

- Renewed patient-portal certificate and private key are available before the existing certificate expires.
- The new private key is stored in the approved protected key store or HSM-backed service.
- The full Apache virtual-host configuration has been backed up.
- `postgresql.conf` and `pg_hba.conf` on `ehr-db-01` have been backed up.
- The application owners have confirmed which systems legitimately connect to PostgreSQL.
- A test account or test workflow is available for the patient portal and EHR application.
- A rollback engineer is present during the maintenance window.

## Steps

1. On the portal server, identify the active Apache TLS virtual host before changing anything:

```bash
sudo apachectl -S
```

2. Back up the current Apache configuration:

```bash
sudo cp -a /etc/apache2 /etc/apache2.pre-crypto-change
```

3. Install the renewed certificate and private key in the approved protected locations, then update the portal virtual host to reference them:

```apache
SSLCertificateFile /etc/ssl/certs/<meddefense_portal_certificate>.pem
SSLCertificateKeyFile /etc/ssl/private/<meddefense_portal_private_key>.pem
```

4. Restrict the portal to TLS 1.2 and TLS 1.3:

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

5. Restrict TLS 1.2 to modern forward-secret AEAD cipher suites:

```apache
SSLCipherSuite TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on
```

6. Configure the approved TLS 1.3 cipher suites:

```apache
SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
```

7. Apply additional hardening:

```apache
SSLCompression off
SSLInsecureRenegotiation off
Header always set Strict-Transport-Security "max-age=31536000"
```

8. Validate the Apache syntax before applying the change:

```bash
sudo apachectl configtest
```

Expected result:

```text
Syntax OK
```

9. Reload Apache rather than performing an unnecessary full reboot:

```bash
sudo systemctl reload apache2
```

10. On `ehr-db-01`, confirm SSL is enabled in PostgreSQL:

```bash
sudo -u postgres psql -c "SHOW ssl;"
```

Expected value:

```text
on
```

11. Back up the PostgreSQL authentication configuration:

```bash
sudo cp <pg_hba.conf_path> <pg_hba.conf_path>.pre-crypto-change
```

12. Replace broad `hostnossl` rules for the EHR application with explicit `hostssl` rules for approved sources only. Example:

```text
hostssl  <ehr_database>  <ehr_app_user>  <ehr_app_server_ip>/32  scram-sha-256
```

13. Remove or disable the equivalent `hostnossl` rule after the encrypted application connection has been tested.

14. Reload PostgreSQL configuration:

```bash
sudo -u postgres psql -c "SELECT pg_reload_conf();"
```

## Validation

- Confirm TLS 1.2 works:

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1_2
```

- Confirm TLS 1.3 works:

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1_3
```

- Confirm TLS 1.0 fails:

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1
```

- Confirm the certificate hostname and validity dates:

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

- Confirm HSTS is returned:

```bash
curl -I https://portal.meddefense.local
```

- Test an encrypted PostgreSQL connection:

```bash
psql "host=ehr-db-01 dbname=<ehr_database> user=<ehr_app_user> sslmode=require"
```

- Confirm a deliberately non-TLS connection is rejected:

```bash
psql "host=ehr-db-01 dbname=<ehr_database> user=<ehr_app_user> sslmode=disable"
```

- Complete a patient-portal login and a normal EHR read/write test using a non-production test patient.
- Monitor Apache and PostgreSQL logs for failed TLS handshakes or rejected legitimate clients for at least 30 minutes after deployment.

## Rollback

- Restore the previous Apache configuration:

```bash
sudo rm -rf /etc/apache2
sudo mv /etc/apache2.pre-crypto-change /etc/apache2
sudo apachectl configtest
sudo systemctl reload apache2
```

- Restore the previous `pg_hba.conf` if legitimate EHR database clients cannot connect:

```bash
sudo cp <pg_hba.conf_path>.pre-crypto-change <pg_hba.conf_path>
sudo -u postgres psql -c "SELECT pg_reload_conf();"
```

- Do **not** restore the old certificate if it has already expired or been revoked; issue/deploy a valid replacement instead.

**Maximum acceptable downtime before rollback is triggered:** **10 minutes** of patient-portal unavailability or inability of the EHR application to reach `ehr-db-01`.

## Maintenance Window

**Overnight / low clinical-activity window required.** Although Apache and PostgreSQL can normally reload without a long outage, transport changes can unexpectedly affect legacy clients and must be validated while support staff are available.

## Communication

**Before:** Sarah Park, James Chen, Security Analyst, EHR/application owner, Service Desk and clinical operations lead.  
**After:** Confirm successful TLS validation to the same group and advise the Service Desk that TLS 1.0/plaintext PostgreSQL connections are no longer supported.

---

# Action #2: Enforce TLS for Billing MySQL Traffic

**Priority:** Immediate  
**System Affected:** `billing-srv-01`  
**Related Finding:** CRYPTO-005  
**Risk Reference:** RISK-004

## Prerequisites

- A server certificate and private key for `billing-srv-01` have been issued by the approved MedDefense CA.
- The CA certificate is available to the billing application.
- The billing application has been tested in a staging or test session using TLS.
- The existing MySQL configuration has been backed up.
- Current billing database clients and source IP addresses have been identified.
- The application owner confirms that the billing application supports TLS before enforcement.

## Steps

1. Back up the MySQL configuration:

```bash
sudo cp -a /etc/mysql /etc/mysql.pre-tls-change
```

2. Confirm the active MySQL version:

```bash
mysql --version
```

3. Configure the MySQL server certificate, private key and CA in the server configuration under `[mysqld]`:

```ini
ssl_ca=/etc/mysql/ssl/meddefense-ca.pem
ssl_cert=/etc/mysql/ssl/billing-srv-01-cert.pem
ssl_key=/etc/mysql/ssl/billing-srv-01-key.pem
require_secure_transport=ON
```

4. Restrict the private-key permissions:

```bash
sudo chown mysql:mysql /etc/mysql/ssl/billing-srv-01-key.pem
sudo chmod 600 /etc/mysql/ssl/billing-srv-01-key.pem
```

5. Validate the configuration before restarting:

```bash
sudo mysqld --validate-config
```

If the installed MySQL version does not support `--validate-config`, use the vendor-supported configuration validation method for that version before restart.

6. Restart MySQL during the approved maintenance window:

```bash
sudo systemctl restart mysql
```

7. Confirm that secure transport is enforced:

```bash
mysql -e "SHOW VARIABLES LIKE 'require_secure_transport';"
```

Expected value:

```text
ON
```

8. Update the billing application connection string to require TLS and verify the server certificate against the MedDefense CA. Where the MySQL client supports it, use:

```text
ssl-mode=VERIFY_IDENTITY
```

## Validation

- Connect successfully with TLS:

```bash
mysql --host=billing-srv-01 \
      --ssl-mode=VERIFY_IDENTITY \
      --ssl-ca=/path/to/meddefense-ca.pem \
      -u <test_user> -p
```

- Inside the session, confirm a cipher is in use:

```sql
SHOW STATUS LIKE 'Ssl_cipher';
```

The value must not be blank.

- Confirm a plaintext connection fails:

```bash
mysql --host=billing-srv-01 --ssl-mode=DISABLED -u <test_user> -p
```

- Run a normal billing application test transaction using non-production/test data.
- Confirm no new connection errors are appearing in the MySQL and billing-application logs.
- Confirm port 3306 remains limited to required application/admin sources as a separate defense-in-depth control.

## Rollback

- Restore the previous MySQL configuration:

```bash
sudo rm -rf /etc/mysql
sudo mv /etc/mysql.pre-tls-change /etc/mysql
sudo systemctl restart mysql
```

- Restore the previous application connection string if the approved billing application cannot establish a TLS session.
- Keep the newly issued certificate/key protected even if enforcement is rolled back; do not expose private-key material to troubleshoot connectivity.

**Maximum acceptable downtime before rollback is triggered:** **15 minutes** of billing application database unavailability.

## Maintenance Window

**Overnight or outside finance/billing processing hours.** A MySQL restart and application connection-string change are required.

## Communication

**Before:** Sarah Park, James Chen, Security Analyst, billing application owner and Finance/Billing department lead.  
**After:** Confirm successful encrypted connectivity and advise application owners that plaintext MySQL sessions are no longer permitted.

---

# Action #3: Remove Legacy Kerberos Cryptography and Enforce LDAP Protection

**Priority:** Immediate  
**System Affected:** `ad-dc-01` and `ad-dc-02`  
**Related Finding:** CRYPTO-011  
**Risk Reference:** RISK-002

## Prerequisites

- Current AD health is confirmed on both domain controllers.
- A recent system-state backup exists for the domain controllers.
- Security Event 4769 logs have been reviewed to identify accounts or systems still receiving RC4 tickets.
- Legacy clinical/vendor applications have been identified and tested for AES Kerberos and LDAP signing compatibility.
- Change is prepared as a Group Policy Object so it can be reverted centrally.
- A second domain controller remains available during the staged deployment.

## Steps

1. Check domain-controller health before the change:

```powershell
dcdiag
repadmin /replsummary
```

2. Review recent Kerberos service-ticket encryption types. Event ID **4769** should be checked for legacy RC4/DES use. AES ticket types should become the expected baseline after remediation.

3. Inventory accounts with explicitly configured Kerberos encryption settings:

```powershell
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName,msDS-SupportedEncryptionTypes
```

4. Remediate service accounts or systems that depend on RC4 before enforcing the new policy. Reset service-account passwords where required so AES key material is generated.

5. Create or edit a dedicated Domain Controllers security GPO.

6. Configure:

```text
Computer Configuration
  > Windows Settings
    > Security Settings
      > Local Policies
        > Security Options
          > Network security: Configure encryption types allowed for Kerberos
```

Enable only:

```text
AES128_HMAC_SHA1
AES256_HMAC_SHA1
```

Do not enable DES or RC4.

7. In the same controlled GPO, configure:

```text
Domain controller: LDAP server signing requirements = Require signing
```

8. Configure LDAP channel binding to the organisation's tested secure setting. Where legacy compatibility is still being validated, stage enforcement first and move to full enforcement after incompatible clients are corrected.

9. Apply the GPO first to `ad-dc-02` as the staged domain controller.

10. Force policy refresh:

```powershell
gpupdate /force
```

11. Validate authentication against `ad-dc-02`.

12. If validation is successful, apply the policy to `ad-dc-01` and run:

```powershell
gpupdate /force
```

## Validation

- Confirm both domain controllers remain healthy:

```powershell
dcdiag
repadmin /replsummary
```

- Confirm normal domain logon works from representative Windows workstations.
- Confirm critical EHR, billing and clinical applications still authenticate.
- Review Event ID 4769 and confirm new Kerberos service tickets use AES rather than RC4/DES.
- Confirm LDAPS is reachable where configured:

```powershell
Test-NetConnection ad-dc-01 -Port 636
Test-NetConnection ad-dc-02 -Port 636
```

- Confirm unsigned LDAP clients are rejected after enforcement.
- Monitor Directory Service, Kerberos and application authentication logs for at least one full business workflow cycle.

## Rollback

- Remove the new encryption/signing GPO from the affected domain controller or restore the prior GPO settings.
- Run:

```powershell
gpupdate /force
```

- If a specific critical legacy application fails, temporarily isolate and document the exception rather than permanently returning the whole domain to weak cryptography.
- Re-enable RC4 only as a **time-limited emergency exception** if a clinically critical dependency has no immediate alternative, with approval from James Chen and a documented expiry/remediation date.
- Do not re-enable DES.

**Maximum acceptable downtime before rollback is triggered:** **5 minutes** of widespread authentication failure or immediate rollback if a patient-care-critical system cannot authenticate.

## Maintenance Window

**Overnight / controlled low-activity period required.** Authentication changes can affect the whole organisation and should be staged one domain controller at a time.

## Communication

**Before:** Sarah Park, James Chen, Security Analyst, Service Desk, application owners, Clinical Engineering and affected vendor contacts.  
**After:** Confirm that AES Kerberos and LDAP signing are operating correctly, list any approved temporary compatibility exceptions and assign each an owner and expiry date.

---

# Action #4: Encrypt the EHR PostgreSQL Database at Rest

**Priority:** Phase 1  
**System Affected:** `ehr-db-01`  
**Related Finding:** CRYPTO-001  
**Risk Reference:** RISK-001 and RISK-009

## Prerequisites

- A tested full PostgreSQL backup and restore are available.
- A current VM/storage snapshot exists where supported.
- The HSM-backed KMS from T14 is available for the database master/recovery key.
- An empty new storage device or logical volume has been provisioned specifically for the encrypted PostgreSQL data.
- The exact current PostgreSQL data directory has been confirmed:

```bash
sudo -u postgres psql -Atc "SHOW data_directory;"
```

- Sufficient free space exists for a complete copy of `PGDATA`.
- The EHR application owner has approved an outage window.
- The original unencrypted PostgreSQL data directory will remain untouched until validation is complete.

## Steps

1. Identify disks and confirm the new target device. **Do not guess the device name:**

```bash
lsblk -f
```

2. Record the chosen empty target as:

```text
<new_encrypted_device>
```

3. Create a LUKS2 encrypted container on the **new empty device only**:

```bash
sudo cryptsetup luksFormat --type luks2 <new_encrypted_device>
```

4. Open the encrypted volume:

```bash
sudo cryptsetup luksOpen <new_encrypted_device> ehr_data_crypt
```

5. Create the filesystem:

```bash
sudo mkfs.ext4 /dev/mapper/ehr_data_crypt
```

6. Mount the new encrypted filesystem temporarily:

```bash
sudo mkdir -p /mnt/ehr_encrypted
sudo mount /dev/mapper/ehr_data_crypt /mnt/ehr_encrypted
```

7. Perform an initial copy of PostgreSQL data while the service is still online to reduce final downtime:

```bash
sudo rsync -aHAX --numeric-ids <PGDATA>/ /mnt/ehr_encrypted/
```

8. Start the approved outage and stop PostgreSQL:

```bash
sudo systemctl stop postgresql
```

9. Perform a final synchronization after PostgreSQL has stopped:

```bash
sudo rsync -aHAX --delete --numeric-ids <PGDATA>/ /mnt/ehr_encrypted/
```

10. Verify ownership:

```bash
sudo chown -R postgres:postgres /mnt/ehr_encrypted
```

11. Configure the approved boot/unlock mechanism so the LUKS key is obtained through MedDefense's protected key-management process. **Do not place a plaintext key file on `ehr-db-01`.**

12. Configure the encrypted filesystem to mount at the PostgreSQL data location using the actual UUID obtained from:

```bash
sudo blkid <new_encrypted_device>
```

13. Preserve the original unencrypted data directory by renaming it rather than deleting it.

14. Mount the encrypted volume at the production PostgreSQL data path.

15. Start PostgreSQL:

```bash
sudo systemctl start postgresql
```

16. Confirm the database starts successfully:

```bash
sudo systemctl status postgresql
sudo -u postgres psql -c "SELECT now();"
```

## Validation

- Confirm the PostgreSQL data path is now backed by the encrypted mapper:

```bash
findmnt <PGDATA>
lsblk -f
```

- Confirm LUKS status:

```bash
sudo cryptsetup status ehr_data_crypt
```

- Confirm all required databases are present:

```bash
sudo -u postgres psql -c "\l"
```

- Run EHR application login, patient lookup and controlled test write/read.
- Compare record counts or application health checks against the pre-change baseline.
- Restart the server once during the maintenance window, if permitted, to prove the encrypted volume can be unlocked/mounted through the approved recovery process.
- Perform a test database backup and restore after the change.

## Rollback

1. Stop PostgreSQL:

```bash
sudo systemctl stop postgresql
```

2. Unmount the encrypted target and close the mapper:

```bash
sudo umount <PGDATA>
sudo cryptsetup luksClose ehr_data_crypt
```

3. Restore the original unencrypted PostgreSQL data directory to its previous path.

4. Restore the previous mount configuration.

5. Start PostgreSQL:

```bash
sudo systemctl start postgresql
```

6. Re-run the EHR health check and record-count validation.

The original unencrypted data copy must not be securely deleted until the encrypted production instance has completed validation and at least one successful backup/restore cycle.

**Maximum acceptable downtime before rollback is triggered:** **15 minutes beyond the planned EHR outage window**, or immediate rollback if PostgreSQL cannot start cleanly or data validation fails.

## Maintenance Window

**Overnight clinical maintenance window required.** This is the highest-impact storage change in the playbook and requires a controlled database stop and final data migration.

## Communication

**Before:** Sarah Park, James Chen, Security Analyst, EHR application owner, database administrator, clinical operations lead and Service Desk.  
**After:** Confirm database integrity, application availability, encrypted-volume status and successful backup. Notify the same group before the original unencrypted copy is securely retired.

---

# Action #5: Encrypt NAS-01 Backup Storage and Backup Transfers

**Priority:** Phase 1  
**System Affected:** `NAS-01` and `backup-srv-01`  
**Related Findings:** CRYPTO-013 and CRYPTO-014  
**Risk Reference:** RISK-003 and RISK-001

## Prerequisites

- At least one verified offsite or otherwise independent backup exists before modifying the local backup target.
- A restore test from the current backup set has completed successfully.
- Sufficient NAS capacity exists for a new encrypted backup location during migration.
- The NAS model/DSM version has been confirmed to support encrypted shared folders or encrypted volumes.
- A separate KMS/HSM-backed backup key and protected recovery copy have been prepared.
- The backup product has been confirmed to support TLS-protected transport or encrypted backup sets.
- Current backup jobs, schedules and retention settings have been exported or documented.

## Steps

1. Export/document the existing NAS and backup-job configuration before changing the target.

2. In Synology DSM, create a **new encrypted backup shared folder or encrypted volume** rather than converting the only existing backup copy in place.

Use a descriptive target such as:

```text
MedDefense_Backup_Encrypted
```

3. Enable the NAS-supported strong encryption option and generate the encryption key through the approved MedDefense key-management process.

4. Export any required recovery key and move it immediately to the protected recovery/KMS location.

**Do not store the only recovery key on `NAS-01`.**

5. Restrict access to the new encrypted target to the backup service account and approved recovery administrators only.

6. On `backup-srv-01`, configure the backup product to use the new encrypted target.

7. Enable encryption inside the backup product for sensitive backup sets using **AES-256** where supported. This ensures the backup remains encrypted even if it is later replicated away from the NAS.

8. Configure backup transport to use **TLS 1.2/1.3**. If the backup product cannot provide authenticated TLS natively, place the transfer inside the approved authenticated IPsec/IKEv2 tunnel.

9. Run a new test backup to the encrypted target.

10. Perform a test restore to an isolated recovery location.

11. Run at least one normal scheduled backup cycle successfully before changing the old backup share.

12. After two successful backup/restore validation cycles, set the old plaintext backup share to read-only.

13. Retain the old copy only for the approved rollback/retention period, then securely delete it according to the MedDefense data-retention policy.

14. Ensure the offsite replica is also encrypted and uses a **separate MedDefense-controlled key**, not the same key used for the local NAS volume.

## Validation

- Confirm the encrypted NAS folder/volume is shown as encrypted in DSM.
- Unmount/lock the encrypted target during a controlled test and confirm the backup files are not accessible.
- Unlock/mount it with the approved recovery process and confirm the backup files return.
- Complete a full test restore of representative PostgreSQL, MySQL and file data.
- Confirm the backup job reports encrypted transport.
- Review a network capture or backup-product session details and verify that backup payloads are not travelling in plaintext.
- Confirm the offsite copy is encrypted independently.
- Confirm restore administrators can recover the key through the documented recovery procedure without retrieving it from `NAS-01`.

## Rollback

- Keep the existing plaintext backup location intact and read-only during the migration period.
- If the encrypted backup job fails, point the job back to the previous target while the issue is investigated.
- Do not delete the encrypted target during rollback; preserve it for troubleshooting unless data integrity is in question.
- Do not destroy the old plaintext backup set until two successful encrypted backup-and-restore cycles have been completed.

**Maximum acceptable downtime before rollback is triggered:** No scheduled critical backup may be missed. If the encrypted target cannot complete the next scheduled backup within **30 minutes of the normal backup window**, revert the job to the previous known-good target.

## Maintenance Window

**Initial setup can be performed during business hours**, but the final cutover of all production backup jobs should occur **after hours** so a complete encrypted backup and restore test can be observed without competing production load.

## Communication

**Before:** Sarah Park, James Chen, Security Analyst, backup administrator, database/application owners and Service Desk.  
**After:** Confirm successful encrypted backup, restore test, key recovery test and offsite replication. Notify James Chen before the old plaintext backup set is permanently destroyed.

---

# Final Change-Control Checklist

Before each action:

```text
[ ] Approved change ticket exists
[ ] Configuration/data backup completed
[ ] Rollback method tested or verified
[ ] Required owners notified
[ ] Maintenance window confirmed
[ ] Validation commands prepared
[ ] Security Analyst available to monitor logs
```

After each action:

```text
[ ] Technical validation passed
[ ] Application/clinical workflow validation passed
[ ] No unexpected authentication or service errors
[ ] Key location and ownership documented
[ ] Security logs reviewed
[ ] Rollback artifacts retained for approved period
[ ] Change ticket updated with evidence
[ ] Stakeholders notified of completion
```

# Implementation Sequence Summary

```text
1. Remove obsolete/optional transport crypto
        |
        v
2. Protect billing database traffic
        |
        v
3. Harden AD authentication cryptography
        |
        v
4. Encrypt EHR storage with external key protection
        |
        v
5. Encrypt local and replicated backup data
```

The first three changes reduce active exposure with relatively contained configuration changes. The final two require storage migration and therefore receive larger maintenance windows, stronger recovery prerequisites and delayed destruction of the original plaintext copies.

---

## Internal References

- Task 15 - `15-crypto_posture_audit.md`
- Task 14 - `14-key_management.md`
- Task 13 - `13-encryption_levels.md`
- Task 12 - `12-disk_encryption.md`
- Task 11 - `11-tls_audit.md`
- Project 1x03 - `10-risk_register.md`
- Project 1x03 - `17-security_strategy.md`
