# Task 2 - The Asymmetric Engine

## Part 1 - RSA Key Generation and Encryption

### Generate an RSA-2048 key pair

```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

Observed output from the public-key command:

```text
writing RSA key
```

### Encrypt the patient record with the public key

The same patient record from Task 1 was used:

```text
Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation
```

Encryption command:

```bash
openssl pkeyutl -encrypt \
  -pubin \
  -inkey rsa_public.pem \
  -in patient.txt \
  -out patient_rsa.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256
```

Decryption command:

```bash
openssl pkeyutl -decrypt \
  -inkey rsa_private.pem \
  -in patient_rsa.enc \
  -out patient_rsa.dec \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256
```

Verification:

```bash
cmp patient.txt patient_rsa.dec
```

The decrypted file matched the original patient record.

### Attempt to encrypt the 100 MB test file with RSA

The 100 MB file from Task 1 was created with:

```bash
dd if=/dev/urandom of=testfile bs=1M count=100
```

RSA encryption was then attempted with:

```bash
openssl pkeyutl -encrypt \
  -pubin \
  -inkey rsa_public.pem \
  -in testfile \
  -out testfile_rsa.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256
```

Observed error:

```text
Public Key operation error
error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex:data too large for key size
```

RSA cannot encrypt a large file directly because the amount of plaintext that can be processed in one RSA operation is limited by the key size and the padding scheme. A 2048-bit RSA key can only encrypt a small amount of data, so real systems use RSA or another asymmetric method to protect or establish a small symmetric key, while a fast symmetric algorithm such as AES encrypts the actual data.

---

## Part 2 - ECC Key Generation

### Generate a P-256 ECC key pair

```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

Observed output:

```text
read EC key
writing EC key
```

The private-key sizes were compared with:

```bash
wc -c rsa_private.pem ecc_private.pem
```

Observed sizes:

```text
1704 rsa_private.pem
 302 ecc_private.pem
2006 total
```

The ratio is:

```text
1704 / 302 = 5.64
```

The RSA private-key file was therefore about **5.6 times larger** than the ECC private-key file in this test environment.

ECC achieves strong security with smaller keys because its security is based on the elliptic-curve discrete logarithm problem, which provides more security per key bit than the mathematical problem used by RSA. This matters for constrained MedDefense devices such as BD Alaris pumps and Philips monitors because smaller keys reduce storage, bandwidth and processing requirements while still providing strong cryptographic protection.

---

## Part 3 - The Hybrid Model

Modern encrypted communication combines asymmetric and symmetric cryptography because each solves a different problem. During the TLS handshake, asymmetric cryptography is used for authentication and key establishment; in modern TLS this is commonly performed with certificates and ephemeral elliptic-curve Diffie-Hellman (ECDHE). Both sides then derive shared symmetric session keys from the agreed secret. Symmetric authenticated encryption such as AES-GCM is used for the actual application data because it is much faster and can efficiently protect large amounts of traffic. This gives the system the secure key-establishment benefits of asymmetric cryptography together with the performance of symmetric cryptography.

For the MedDefense patient portal, a modern HTTPS configuration should use the **TLS handshake and ECDHE for key establishment**, with the server certificate authenticating the portal. After the session keys are established, **AES-GCM or another approved AEAD cipher handles the bulk patient data exchanged over HTTPS**. The existing TLS 1.0 configuration should therefore be replaced with a modern TLS configuration rather than relying on its legacy cipher and key-exchange options.

---

## Part 4 - Key Length Comparison

> **Healthcare note:** HIPAA does not provide a simple list of individually "HIPAA-approved" algorithms. For this table, **Approved** means appropriate for new MedDefense protection when used correctly and in line with current NIST guidance. Legacy algorithms that NIST has retired or disallowed are marked **Not approved**.

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES** | Symmetric block cipher | 128 / 192 / 256 bits | 128 / 192 / 256-bit security | **Approved** | Preferred for database, backup, disk and VPN bulk encryption. AES-GCM should be preferred where authenticated encryption is required. |
| **RSA** | Asymmetric | 2048 / 4096 bits | RSA-2048 ≈ 112-bit; RSA-4096 provides at least 128-bit-class security | **Approved for appropriate asymmetric uses** | Certificates, signatures and key establishment. It should not be used to encrypt large patient files directly. |
| **ECC** | Asymmetric | P-256 / P-384 | P-256 ≈ 128-bit; P-384 ≈ 192-bit | **Approved** | Suitable for TLS key establishment/signatures and useful for constrained medical devices because of its smaller keys. |
| **DES** | Symmetric block cipher | 56 bits | 56-bit security | **Not approved** | Must be removed from MedDefense Kerberos and other legacy configurations. |
| **3DES / TDEA** | Symmetric block cipher | 168-bit nominal, about 112-bit effective | ≈ 112-bit security | **Not approved for new protection** | Legacy only. NIST disallowed TDEA for applying new cryptographic protection after 2023. |
| **ChaCha20-Poly1305** | Symmetric stream cipher + authenticator (AEAD) | 256-bit key, 128-bit authentication tag | Strong modern protection; 256-bit key with 128-bit tag | **Acceptable where organizational policy permits** | A modern TLS AEAD option, especially useful where AES hardware acceleration is unavailable. If MedDefense requires a strict FIPS/NIST-approved cryptographic-module baseline, AES-GCM is the safer policy choice. |
| **RC4** | Symmetric stream cipher | Variable; commonly 128 bits | Not considered secure because of serious statistical biases | **Not approved** | Any remaining RC4 support in legacy authentication or network services should be disabled. |

### MedDefense Recommendation

For new MedDefense cryptographic controls, the main practical choices should be **AES-GCM for bulk encryption** and **RSA-2048/3072+ or ECC P-256/P-384 for authentication and key establishment**, depending on the protocol and system. DES, 3DES and RC4 should not be used to protect new healthcare data. For constrained medical devices, ECC can provide strong security with substantially smaller keys than RSA.

---

## References

- NIST FIPS 197, *Advanced Encryption Standard (AES)*.
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management: Part 1 - General*.
- NIST SP 800-131A Rev. 2, *Transitioning the Use of Cryptographic Algorithms and Key Lengths*.
- NIST SP 800-186, *Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters*.
- HHS, *Guidance to Render Unsecured Protected Health Information Unusable, Unreadable, or Indecipherable to Unauthorized Individuals*.
