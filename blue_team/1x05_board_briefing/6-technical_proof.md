# 6. The Technical Proof

## MedDefense Health Systems - Rapid Technical Validation

**Project:** `1x05_board_briefing`  
**Repository path:** `blue_team/1x05_board_briefing/6-technical_proof.md`

---

# Check 1 - Certificate Inspection

## Command

```bash
echo | openssl s_client \
  -connect example.com:443 \
  -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

For the key algorithm:

```bash
echo | openssl s_client \
  -connect example.com:443 \
  -servername example.com 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -A2 "Public Key Algorithm"
```

## Output Summary

```text
Subject:       CN=example.com
Issuer:        Cloudflare TLS Issuing ECC CA 3, SSL Corporation
Validity:      29 July 2026 to 27 October 2026
Key Algorithm: ECC / ECDSA P-256
SAN entries:   example.com, *.example.com
```

### What This Tells Me

This lets me confirm that the certificate belongs to the expected site, is still valid, was issued by a recognised CA and covers the correct DNS names.

The same check would be useful at MedDefense when validating certificates on services such as the patient portal.

---

# Check 2 - Hash Verification

## Create the File

```bash
printf 'MedDefense FortiGate firmware verification test\n' > firmware_check.txt
```

## First SHA-256 Hash

```bash
sha256sum firmware_check.txt
```

```text
e11416ef7cd7f259cb2ec9101398b5dd0c220ff0d7e28d874358b625943890a9  firmware_check.txt
```

## Modify the File

```bash
printf 'Modified after initial verification\n' >> firmware_check.txt
```

## Second SHA-256 Hash

```bash
sha256sum firmware_check.txt
```

```text
79353f31a6e6f5dd81a4267f2c4e8f22339328435ce36adb4a75773bac47540d  firmware_check.txt
```

## Result

```text
Original:
e11416ef7cd7f259cb2ec9101398b5dd0c220ff0d7e28d874358b625943890a9

Modified:
79353f31a6e6f5dd81a4267f2c4e8f22339328435ce36adb4a75773bac47540d

Hashes match? NO
```

Even a small change to the file produces a completely different hash.

### Why This Matters for the FortiGate Firmware

Before installing FortiOS `7.0.14`, I would compare the firmware's SHA-256 hash with Fortinet's official value. If the hashes do not match, I would not install the file because it may have been corrupted or modified.

---

# Check 3 - Exploit Research

## Commands

```bash
searchsploit fortigate
```

```bash
searchsploit fortios
```

And specifically:

```bash
searchsploit --cve 2023-27997
```

## SearchSploit Result

The CVE-specific search returned:

```text
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

The broader FortiGate/FortiOS searches returned exploits for other Fortinet vulnerabilities.

## Is There a Public Exploit for CVE-2023-27997?

**Yes.**

The important point is that SearchSploit only searches Exploit-DB. A result of `No Results` does not mean that no public exploit exists.

LEXFO, the researchers who found CVE-2023-27997, published technical details showing successful pre-authentication remote code execution against FortiGate appliances. Public PoC material also exists outside Exploit-DB.

CISA also lists the CVE in the Known Exploited Vulnerabilities catalog.

## What Does This Mean for MedDefense?

The urgency is **Critical**.

MedDefense is running FortiOS `7.0.9`, which is confirmed vulnerable. The attack can happen remotely, before authentication, and public exploitation information exists.

The fact that SearchSploit does not return a direct entry does not make the vulnerability less serious. The FortiGate should still be patched immediately.

---

# Check 4 - System Audit

## Command

```bash
sudo lynis audit system --quick
```

## Result

```text
Hardening Index: 70 / 100
Tests Performed: 248
Warnings:        0
Suggestions:     28
```

Lynis returned **0 formal warnings**, so I would not invent three just to satisfy the wording of the task.

Instead, three useful suggestions from the audit were:

```text
1. No mandatory access control framework active
2. Remote logging not enabled
3. No file-integrity monitoring tool installed
```

## Suggestion I Would Apply to `billing-srv-01`

I would prioritise **remote logging**.

`billing-srv-01` is already a high-risk system and has a history of compromise. If its logs are stored only locally, an attacker with enough access could delete or modify them.

I would forward important authentication, SSH, MySQL and system logs to the central Wazuh/SIEM environment.

Example:

```bash
sudo nano /etc/rsyslog.conf
```

Add the approved logging destination:

```text
*.info;mail.none;authpriv.none;cron.none @<WAZUH_OR_SYSLOG_SERVER>:514
```

Restart the service:

```bash
sudo systemctl restart rsyslog
```

Then test it:

```bash
logger "TEST MESSAGE FROM BILLING-SRV-01"
```

### Why This Matters

This would not stop every attack, but it would make it much easier to detect and investigate suspicious SSH activity, credential abuse, privilege escalation and activity before ransomware deployment.

It also keeps evidence away from the compromised server itself.

---

# Technical Proof Summary

| Check | Tool | Result |
|---|---|---|
| Certificate inspection | OpenSSL | Confirmed certificate identity, issuer, validity, key type and SANs |
| Hash verification | SHA-256 | Modified file produced a different hash |
| Exploit research | SearchSploit / Exploit-DB | No direct EDB result, but public exploit material exists elsewhere |
| System audit | Lynis | Hardening Index **70/100**, 0 warnings, 28 suggestions |

---

# Conclusion

These checks cover four practical security skills I have used throughout the module.

OpenSSL helps me verify certificates. SHA-256 helps me confirm that a file has not been changed. SearchSploit helps me research exploit availability, although I still need to check other sources. Lynis gives me a quick view of system-hardening weaknesses.

For MedDefense, the link is quite direct: verify the FortiGate firmware before installing it, understand how exploitable the vulnerability is and improve logging and hardening on systems such as `billing-srv-01`.

The important part is not just running the command. It is understanding what the result means and knowing what to do with it.
