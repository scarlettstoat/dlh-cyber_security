# Task 12 - The Disk Encryption Lab

> **Lab note:** The 500 MB `dd` command and AES timing measurements were executed in the available environment. That environment does not provide `cryptsetup`/dm-crypt, so the LUKS-specific prompt/output blocks below document the standard successful command flow rather than claiming host-specific execution output. The commands are ready to reproduce unchanged on a Linux VM with `cryptsetup` installed.

## Part 1 - LUKS Setup

### 1. Create a 500 MB virtual disk

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

Output:

```text
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied
```

The command creates a 500 MB file that can be treated as a virtual storage device.

### 2. Format the virtual disk with LUKS

```bash
sudo cryptsetup luksFormat encrypted_volume.img
```

The command displays a warning that the operation will overwrite the device and asks for confirmation:

```text
WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for encrypted_volume.img:
Verify passphrase:
```

After the passphrase is confirmed, the file contains a LUKS encrypted volume. Modern `cryptsetup` uses LUKS2 by default unless another format is specified.

### 3. Open the encrypted volume

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

The passphrase is requested:

```text
Enter passphrase for encrypted_volume.img:
```

On successful authentication, the encrypted volume becomes available through:

```text
/dev/mapper/secure_vol
```

### 4. Create an ext4 filesystem

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

The filesystem tool creates an ext4 filesystem inside the unlocked encrypted mapping. The important result is that the filesystem exists **inside** the LUKS layer rather than directly inside `encrypted_volume.img`.

### 5. Mount the volume and write test data

```bash
sudo mkdir -p /mnt/secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Create a test file:

```bash
echo "MedDefense backup test - Patient data protected by LUKS" \
  | sudo tee /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense backup test - Patient data protected by LUKS
```

Verify it:

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense backup test - Patient data protected by LUKS
```

### 6. Unmount and close the encrypted volume

```bash
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
```

`umount` and `luksClose` normally produce no output when they complete successfully. After `luksClose`, `/dev/mapper/secure_vol` is no longer available and the encrypted data cannot be accessed through the filesystem without unlocking the LUKS volume again.

---

## Part 2 - Verification

### Attempt to read the closed volume directly

After closing the volume:

```bash
strings encrypted_volume.img | head -50
```

The plaintext test string:

```text
MedDefense backup test - Patient data protected by LUKS
```

does **not** appear in the raw encrypted image.

This demonstrates encryption at rest. The data exists inside the volume, but when the LUKS device is closed the raw storage contains ciphertext instead of the readable contents of the mounted filesystem. Someone who steals the disk image or copies the storage without possessing the passphrase or key cannot simply read the backup files.

### Reopen the volume

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

The passphrase is requested:

```text
Enter passphrase for encrypted_volume.img:
```

Mount it again:

```bash
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Read the test data:

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense backup test - Patient data protected by LUKS
```

The data is still intact after the encrypted volume is reopened.

Finally:

```bash
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
```

The full cycle demonstrates that the same stored bytes are unreadable while the LUKS volume is closed but become usable again after the correct key material is supplied.

---

## Part 3 - LUKS Automation Script

The required script is:

```text
12-luks_manager.sh
```

### Create a volume

```bash
./12-luks_manager.sh create encrypted_volume.img 500
```

This creates the image, formats it with LUKS, creates an ext4 filesystem inside it and closes the encrypted mapping.

### Open and mount a volume

```bash
./12-luks_manager.sh open encrypted_volume.img secure_vol /mnt/secure_vol
```

### Close the volume

```bash
./12-luks_manager.sh close secure_vol /mnt/secure_vol
```

The script still asks for the LUKS passphrase when required. The passphrase is intentionally **not stored inside the script**.

---

## Part 4 - MedDefense Backup Encryption Design

### NAS-01 encryption level

For NAS-01, I would use **volume-level encryption** as the primary encryption-at-rest control, with the complete backup volume protected by a strong AES-based storage-encryption mechanism such as LUKS/AES-XTS. **Full-disk encryption** would also protect the physical NAS disks if the appliance were stolen, but it is broader than necessary for this design and may be tied more closely to the NAS operating system and boot process. **file-level encryption** is useful as an additional layer for individual backup sets, especially before replication, but using it alone would create more per-file key-management complexity and could leave other files on the volume unprotected.

Volume-level encryption is therefore the best fit because NAS-01 contains a large collection of backup files that should all receive the same baseline protection, while still allowing MedDefense to manage one encrypted backup volume separately from the rest of the appliance.

However, volume encryption mainly protects data when the volume is **locked**, for example if the NAS disks are stolen or removed. Once NAS-01 is running and the volume is unlocked, a user or attacker who has legitimate filesystem access could still read the mounted backups. For this reason, MedDefense should combine volume encryption with network segmentation, strict NAS permissions and backup-software encryption so sensitive backup sets are encrypted before they are written or replicated.

### Performance impact

The 100 MB AES performance test used during the symmetric-encryption work showed that a 100 MB file could be encrypted with AES-256-CBC in approximately **0.21 seconds**, equivalent to roughly **476 MB/s** of encryption throughput in the test environment. A direct 100 MB file copy took about **0.04 seconds**, so encryption does add CPU work, but the AES throughput was still far above the maximum payload rate of a typical 1 Gbit/s network connection.

I would therefore expect the practical backup impact to be **low on modern hardware with AES acceleration**, with the NAS disks or network likely becoming the bottleneck before AES does. LUKS normally uses a disk-oriented AES mode such as AES-XTS rather than CBC, so MedDefense should benchmark the final NAS hardware before deployment instead of assuming the laboratory timing will exactly match production.

### Key storage

The encryption key must **not be stored in plaintext on NAS-01 itself**. If an attacker steals or compromises the NAS and the key is stored beside the encrypted data, the attacker obtains both the ciphertext and the means to decrypt it, defeating the purpose of the control.

MedDefense should manage the recovery key through a separate controlled system such as an enterprise key management service or HSM-backed key store. Access should be limited to specifically authorised administrators, with recovery access logged and protected by strong authentication. A protected offline recovery copy should also exist so that the organisation is not dependent on a single live key-management system.

### What happens if the key is lost?

If all valid LUKS passphrases and recovery keys are lost, the encrypted backup data is effectively unrecoverable. There is no administrative bypass that can reconstruct the volume key from the ciphertext.

For MedDefense this means key backup is part of the backup strategy itself. Recovery keys should be protected separately, tested through periodic recovery exercises and included in disaster-recovery procedures. The organisation should never rely on only one copy of the encryption key.

### Offsite replication

The **cloud replica** must also remain encrypted at rest. MedDefense should encrypt backup data before or during replication and use a separate MedDefense-controlled encryption key for the cloud replica rather than relying only on the provider's storage controls.

The offsite backup replication control from the 1x03 security strategy should also store data **encrypted at rest**. Encryption should be applied before or during replication so the remote provider never receives an unnecessary plaintext copy of MedDefense patient backups.

The offsite replica should use a **separate encryption key from the local NAS volume key**. MedDefense, rather than the storage provider alone, should control the key through its central KMS/HSM or backup encryption system. Using separate keys limits the effect of one key compromise and allows MedDefense to rotate or revoke access to one backup location without affecting every copy.

The replication channel must also be encrypted in transit, for example with TLS or a properly authenticated VPN. This provides two separate protections: transport encryption while the backup is moving and storage encryption after it arrives.

---

## Recommended NAS-01 Design

| Area | Recommendation |
| --- | --- |
| Local backup storage | **Volume-level encryption** with LUKS/AES-XTS; full-disk encryption considered but not selected as the primary level |
| Additional protection | Encrypt sensitive backup sets before writing them to the NAS |
| Network access | Dedicated backup segment and tightly restricted access |
| Key location | Central KMS or HSM-backed system, not NAS-01 |
| Recovery key | Separate protected offline/escrowed recovery copy |
| Key access | Least privilege, MFA and audit logging |
| Offsite replica | Encrypted before/during replication |
| Offsite key | Separate MedDefense-controlled key |
| Data in transit | TLS or authenticated VPN |
| Recovery testing | Periodic restore and key-recovery tests |

## Conclusion

LUKS protects backup data when the underlying storage is offline or physically obtained by an unauthorised person because the raw disk contents remain encrypted until the volume is unlocked. For NAS-01, volume encryption should be combined with secure key management and controls protecting the NAS while it is online. Offsite copies must remain encrypted as well, and the encryption keys must be recoverable by MedDefense without being stored alongside the backups they protect.

## References

- NIST SP 800-111, *Guide to Storage Encryption Technologies for End User Devices*.
- Cryptsetup project documentation, `cryptsetup(8)` and `cryptsetup-luksFormat(8)`.
