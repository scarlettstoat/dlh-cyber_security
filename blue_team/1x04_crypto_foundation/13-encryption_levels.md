# Task 13 - The Encryption Levels

## Part 1 - Comparison of Encryption Levels

| Level | Scope | Performance Impact | Key Management | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Full-disk** | Encrypts the entire physical or virtual disk, including operating-system files, applications and user data. | **Low to moderate.** Modern processors often provide hardware acceleration, so the impact is usually small during normal use. | **Relatively simple.** Usually one key or recovery key protects the whole disk. | Best for laptops, desktops and servers where the main risk is theft or loss of the physical device. |
| **Partition** | Encrypts one logical partition on a disk while leaving other partitions unencrypted. | **Low to moderate.** Only data on the encrypted partition is processed by the encryption layer. | **Moderate.** Each protected partition can have its own key and recovery process. | Best when only one section of a disk contains sensitive data and other partitions do not need encryption. |
| **Volume** | Encrypts a logical storage volume, which may exist on one disk or span several disks. | **Low to moderate.** Similar to full-disk encryption, with overhead mainly during disk reads and writes. | **Moderate.** Keys must be managed for each encrypted volume, but the whole volume can be protected under one key. | Best for shared storage, backup volumes and server data where many files need the same protection. |
| **File** | Encrypts selected individual files instead of the whole storage device. | **Low for small numbers of files, but can increase as more files are encrypted individually.** | **Moderate to high.** Keys and access permissions may need to be managed per file, user or application. | Best when only certain sensitive documents or files require encryption while the rest of the system can remain unencrypted. |
| **Database** | Encrypts an entire database, tablespace or database storage files, often using database-native encryption such as Transparent Data Encryption (TDE). | **Moderate.** Encryption and decryption occur during database read/write operations, but the impact is usually manageable with modern hardware. | **Moderate.** The database or application uses one or more centrally managed encryption keys. | Best when a complete database contains sensitive information and needs protection at rest without changing every application query. |
| **Record** | Encrypts individual database fields, columns or records, such as a medical diagnosis, national ID or payment number. | **Moderate to high.** Encryption happens at application or field level and may affect searching, indexing and reporting. | **High.** Keys must be carefully managed and access may need to differ between fields, users or applications. | Best for highly sensitive data that must remain protected even from some users who have legitimate database access. |

### Summary

The main difference between the six levels is **how much data is protected at once**. Full-disk, partition and volume encryption protect storage broadly, while file, database and record-level encryption provide more selective control. The more specific the encryption level becomes, the more complex key management and application integration usually become. MedDefense should therefore use broad storage encryption as a baseline and add more granular encryption only where the sensitivity of the data justifies the extra complexity.

---

## Part 2 - MedDefense Encryption Level Map

| MedDefense Data Store | Recommended Encryption Level | Justification |
| :--- | :--- | :--- |
| **Patient records - PostgreSQL (`ehr-db-01`)** | **Database-level encryption, with record-level encryption for especially sensitive fields** | The whole EHR database contains regulated patient information, so database encryption provides broad protection at rest without requiring major application changes. Highly sensitive fields such as diagnoses, national identifiers or other restricted clinical information can also be encrypted at record level so they remain protected even from users who can access other parts of the database. |
| **Backup data - `NAS-01`** | **Volume-level encryption** | NAS-01 stores many backup files together, making volume encryption the most practical way to protect all backup data consistently. This protects the backups if the disks or storage appliance are stolen, while backup-software encryption can provide an additional layer for replicated copies. |
| **Financial records - MySQL (`billing-srv-01`)** | **Database-level encryption, with record-level encryption for payment or highly sensitive financial fields** | The billing database contains financial and patient-related information that should be protected across the whole database. Record-level encryption can be added for fields such as payment details or banking identifiers that require tighter access control. |
| **Medical images - PACS (`pacs-srv-01`)** | **Volume-level encryption** | PACS stores large DICOM image files, so encrypting the storage volume provides strong protection with less complexity than encrypting each image separately. This is appropriate for a system holding a large number of files that all require the same level of protection. |
| **Email data - O365** | **Service/database-level encryption managed by Microsoft 365, with file/message-level protection for especially sensitive content** | O365 already provides encryption at rest within the service, so MedDefense should rely on the platform's managed encryption for normal email storage. Additional message or file-level protection should be used when sending particularly sensitive patient or financial information. |
| **Employee laptops** | **Full-disk encryption** | Full-disk encryption is the best fit because laptops can be lost or stolen and may contain cached email, documents, credentials and other sensitive information. Encrypting the entire disk protects all locally stored data when the device is powered off or locked. |
| **BD Alaris pump firmware/configuration** | **File-level encryption for stored configuration files, combined with digital signatures for firmware integrity** | The pump does not need an entire database or large storage volume encrypted, so protecting sensitive configuration files individually is more practical. Firmware should also be digitally signed so the device can verify that updates are authentic and have not been modified before installation. |

---

## MedDefense Recommendations by System

### 1. Patient Records - PostgreSQL (`ehr-db-01`)

The primary control should be **database-level encryption** because the entire EHR database contains protected health information. This can be implemented using database-native encryption or encryption of the database storage layer while keeping normal application access unchanged.

For the most sensitive fields, such as highly confidential diagnoses or identifiers, MedDefense should consider **record-level encryption**. This provides additional protection because even a user with database access may not automatically be able to decrypt every sensitive field.

### 2. Backup Data - `NAS-01`

NAS-01 should use **volume-level encryption** because all files stored on the backup volume require protection. This is simpler and easier to manage than encrypting every backup file individually.

The encryption key must be stored separately from the NAS, as described in Task 12. Offsite backup copies should also remain encrypted and should use a separate MedDefense-controlled key.

### 3. Financial Records - MySQL (`billing-srv-01`)

The MySQL database should use **database-level encryption** because the entire billing database contains sensitive business and patient information. This gives consistent protection without requiring every query or application to be rewritten.

For especially sensitive fields, such as payment or banking information, **record-level encryption** can add an extra layer of protection and restrict which applications or users can decrypt those values.

### 4. Medical Images - PACS (`pacs-srv-01`)

PACS should use **volume-level encryption** because it stores a very large number of DICOM image files. Encrypting the full storage volume protects all images at rest while avoiding the operational complexity of managing a separate encryption process for each individual image.

This should be combined with encrypted DICOM transport so that the images are protected both at rest and while moving across the network.

### 5. Email Data - O365

For normal O365 email storage, MedDefense should rely on **Microsoft 365's service-level encryption at rest**. This protects stored mailboxes without requiring users to manually encrypt every message.

For messages containing particularly sensitive patient information, MedDefense should add **message-level or file-level encryption** so the content remains protected even when it is shared externally.

### 6. Employee Laptops

Employee laptops should use **full-disk encryption**. This is the most appropriate level because laptops may store many different types of sensitive data, including cached emails, documents, credentials and downloaded patient information.

Full-disk encryption protects the entire device if it is lost or stolen and requires relatively little day-to-day effort from the employee once it is configured.

### 7. BD Alaris Pump Firmware and Configuration

The pump's stored configuration should use **file-level encryption** where sensitive settings or credentials need confidentiality. This is more appropriate than full-disk encryption for a constrained device with limited storage and processing resources.

Firmware itself should primarily be protected using **digital signatures**, because the main requirement is to verify authenticity and integrity before an update is installed. Encryption and signatures solve different problems: encryption hides data, while a signature proves that the firmware came from an authorised source and has not been modified.

---

## Overall Encryption Strategy

MedDefense should not rely on one encryption level for every system. Broad controls such as full-disk and volume encryption are appropriate where the goal is to protect an entire device or storage area, while database and record-level encryption provide stronger separation for especially sensitive information.

A practical approach is to use **layered encryption**:

- Full-disk encryption for mobile endpoints.
- Volume encryption for large shared storage systems such as NAS and PACS.
- Database encryption for PostgreSQL and MySQL.
- Record-level encryption only for the most sensitive fields.
- File or message-level encryption where individual documents or messages need separate protection.

This gives MedDefense strong protection without introducing unnecessary key-management and performance complexity into every system.
