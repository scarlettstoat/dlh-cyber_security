# Task 3 - The Hash Laboratory

## Part 1 - The Avalanche Effect

The hashes were generated with the commands required by the task.

### SHA-256

```bash
echo -n "MedDefense" | sha256sum
```

```text
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098  -
```

```bash
echo -n "MedDefense1" | sha256sum
```

```text
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92  -
```

The two SHA-256 outputs differ in **62 of 64 hexadecimal characters**. Looking at the output at bit level, **131 of 256 bits (about 51.2%)** changed, which is close to the expected avalanche effect of roughly half of the output bits changing after a small input change.

### MD5

```bash
echo -n "MedDefense" | md5sum
```

```text
75d47fd4b4d183456d0f98fd9ba6ae4d  -
```

```bash
echo -n "MedDefense1" | md5sum
```

```text
0d2aed72043f78c2935e61ba8520306d  -
```

The MD5 outputs differ in **30 of 32 hexadecimal characters**. At bit level, **71 of 128 bits (about 55.5%)** changed. This demonstrates the avalanche effect as well, although MD5 is no longer considered secure for collision-resistant cryptographic use.

> Note: comparing hexadecimal characters is not the same as comparing individual bits. One hexadecimal character represents four bits, which is why almost every visible character can change while approximately half of the underlying bits change.

---

## Part 2 - Hash Collisions and the Birthday Problem

MD5 has a 128-bit output, giving:

```text
2^128 possible hash outputs
```

SHA-256 has a 256-bit output, giving:

```text
2^256 possible hash outputs
```

A shorter hash has fewer possible outputs, so collisions become statistically easier to find. A birthday attack uses the birthday paradox: an attacker does not need to test every possible output, because a collision becomes likely after roughly **2^(n/2)** attempts for an n-bit hash. This means the generic collision level is approximately **2^64 for MD5** and **2^128 for SHA-256**, before considering weaknesses specific to the algorithms themselves. MD5 also has known practical collision attacks, which is why it should not be used where collision resistance matters.

### Connection to Finding 018 - Kerberos weak encryption

Finding 018 identified weak Kerberos encryption at MedDefense. RC4-HMAC Kerberos uses MD5/HMAC-MD5 internally, but MD5 collision attacks are not the main practical password risk in this case: the RC4 Kerberos key is based on the user's unsalted NT password hash, and RC4 service tickets can be targeted by offline password-guessing attacks such as Kerberoasting. If a MedDefense service account has a weak password, an attacker who obtains an RC4 Kerberos ticket can test password guesses offline without repeatedly contacting the domain controller, so MedDefense should remove RC4 dependencies and use AES-based Kerberos encryption.

---

## Part 3 - Rainbow Table Demonstration

### Unsalted password

```bash
echo -n "password123" | md5sum
```

```text
482c811da5d5b4bc6d497ffa98491e38  -
```

The hash was entered into CrackStation and was recovered as:

```text
482c811da5d5b4bc6d497ffa98491e38
Type: md5
Result: password123
```

This demonstrates why fast, unsalted password hashes are dangerous. A common password such as `password123` is already represented in large pre-computed lookup tables, so the original password can be recovered almost immediately from the hash.

### Salted password

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

```text
6d537fa53f1db2c22b0451ef4ef9fbe8  -
```

CrackStation did **not** recover a plaintext value for the salted hash:

```text
6d537fa53f1db2c22b0451ef4ef9fbe8
Result: Not found
```

The unsalted `password123` hash was recovered immediately because it is a common password already represented in pre-computed lookup tables. Adding the salt changes the input before hashing, producing a completely different MD5 value that is not reusable across other accounts. A unique salt therefore prevents one rainbow table from being effective against every user, because the attacker would need to attack each salted hash separately. The salt does not need to be secret, but every user should have a unique randomly generated salt, and salting should still be combined with a deliberately slow password-hashing function rather than a fast function such as MD5.

---

## Part 4 - Key Stretching

### bcrypt

bcrypt is designed specifically for password storage and automatically incorporates a salt. Unlike a simple fast hash, it deliberately performs expensive work so that each password guess takes longer, which makes large brute-force attacks more costly. Its **cost factor** controls the amount of computational work; increasing the value increases the time required to calculate each hash.

### PBKDF2

PBKDF2 repeatedly applies a pseudorandom function, normally HMAC, to a password and salt. This repeated work makes each password guess much slower than a single SHA or MD5 calculation, reducing the number of guesses an attacker can test per second. Its **iteration count** determines how many rounds are performed, so a higher count increases both legitimate verification time and attacker cost.

### Argon2

Argon2 is a modern password-hashing algorithm designed to consume both processing time and memory. **Argon2id** combines protection against different attack techniques and is especially resistant to GPU-based cracking because attackers must provide substantial memory as well as computation for each guess. Its main parameters control memory usage, number of iterations and parallelism, allowing the defender to tune how expensive password verification should be.

### Recommendation for MedDefense applications

For a new MedDefense application, I would choose **Argon2id** because it is designed specifically for modern password storage and makes large-scale cracking expensive in both CPU and memory. Each password should use its own unique salt, and the cost parameters should be tuned so normal logins remain practical while offline guessing is deliberately expensive. If MedDefense has a strict requirement to use a FIPS-validated password-hashing implementation, **PBKDF2-HMAC-SHA-256** is a strong alternative.

### What Active Directory uses

Active Directory does **not** use bcrypt, PBKDF2 or Argon2 as its normal password hash. Windows creates an **NT hash**, which is based on MD4 and is not salted; the Active Directory database protects stored hash material with additional encryption, and Kerberos also maintains password-derived keys for authentication.

By modern application-password-storage standards, the NT hash alone is not ideal because a stolen NT hash can be attacked offline and can also be useful in pass-the-hash attacks. MedDefense cannot simply change Active Directory to Argon2, so the practical controls are to protect domain controllers and credentials strongly, enforce long and resistant passwords, use MFA where possible, remove legacy RC4 Kerberos support, and prefer modern AES-based Kerberos encryption.

---

## Part 5 - Integrity Verification Script

The required script is stored as:

```text
3-hash_verify.sh
```

Example use:

```bash
./3-hash_verify.sh patient.txt 39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098
```

If the calculated SHA-256 value matches the expected value, the script prints:

```text
INTEGRITY OK
```

If the values are different, it prints:

```text
INTEGRITY FAILED - expected [hash] got [hash]
```

The script returns exit code `0` for a successful match and `1` when the integrity check fails.

---

## References

- Microsoft Learn, *Passwords technical overview*: https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview
- Microsoft Learn, *Detect and Remediate RC4 Usage in Kerberos*: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
- RFC 4757, *The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows*: https://www.rfc-editor.org/rfc/rfc4757.html
- NIST SP 800-63B, *Digital Identity Guidelines - Authentication and Authenticator Management*: https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP, *Password Storage Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CrackStation, *Free Password Hash Cracker*: https://crackstation.net/
