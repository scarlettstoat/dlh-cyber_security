# Task 11 - The TLS Audit

**Review date:** 3 October 2026

> SSL Labs results can change when a website changes its TLS configuration or certificate. The results below reflect recent SSL Labs assessments available at the time of this review.

---

## Part 1 - SSL Labs Analysis

Two real public TLS configurations were reviewed using Qualys SSL Labs:

1. `d32rgoij5mqrrs.cloudfront.net` - strong configuration rated **A+**
2. `erp.ilsam.com` - weaker configuration rated **B**

### Site 1 - d32rgoij5mqrrs.cloudfront.net

**SSL Labs assessment:** A+

| Item | SSL Labs result |
| --- | --- |
| **Overall grade** | **A+** |
| **Protocol support** | TLS 1.3: Yes; TLS 1.2: Yes; TLS 1.1: No; TLS 1.0: No; SSL 3: No; SSL 2: No |
| **Key exchange strength** | Modern ECDH/X25519-based key exchange with forward secrecy; SSL Labs reports X25519MLKEM768 for TLS 1.3 and X25519 for TLS 1.2, approximately equivalent to 3072-bit RSA strength |
| **Cipher strength** | 128-bit and 256-bit authenticated encryption only; AES-GCM and ChaCha20-Poly1305 are supported |
| **Certificate** | RSA 2048-bit certificate for `*.cloudfront.net`, signed with SHA-256 and issued by Amazon RSA 2048 M04 |
| **Certificate validity** | 25 August 2026 to 10 March 2027 |
| **HSTS** | Enabled with `max-age=31536000; includeSubDomains; preload` |
| **Warnings / weaknesses** | No legacy TLS 1.0/1.1 support and no weak cipher suites were shown. SSL Labs notes that the site requires SNI, which is normal for modern virtual hosting. |

The configuration receives an A+ because it only supports modern TLS versions and strong authenticated cipher suites, while also using long-duration HSTS. The TLS 1.2 suites use ECDHE with AES-GCM or ChaCha20-Poly1305, which provides forward secrecy and authenticated encryption.

### Site 2 - erp.ilsam.com

**SSL Labs assessment:** B

| Item | SSL Labs result |
| --- | --- |
| **Overall grade** | **B** |
| **Protocol support** | TLS 1.3: Yes; TLS 1.2: Yes; TLS 1.1: Yes; TLS 1.0: Yes; SSL 3: No; SSL 2: No |
| **Key exchange strength** | Modern suites use X25519/ECDHE with forward secrecy and approximately 3072-bit RSA-equivalent strength |
| **Cipher strength** | Modern AES-GCM and ChaCha20-Poly1305 suites are available, but weaker CBC suites are also enabled |
| **Certificate** | RSA 2048-bit certificate for `*.ilsam.com`, signed with SHA-256 and issued by Sectigo Public Server Authentication CA DV R36 |
| **Certificate validity** | 2 July 2026 to 16 January 2027 |
| **HSTS** | Enabled with a long duration |
| **Warnings / weaknesses** | TLS 1.0 and TLS 1.1 are enabled, which causes SSL Labs to cap the grade at B. SSL Labs also identifies weak CBC-based suites, the server sends an unnecessary trust anchor in the chain, and no DNS CAA record was reported. |

The important difference is that this server still supports legacy protocols even though it also supports modern TLS 1.2 and TLS 1.3. SSL Labs explicitly states that supporting TLS 1.0 or TLS 1.1 caps the grade at **B**.

### Comparison

| Area | A+ Site | B Site |
| --- | --- | --- |
| TLS 1.3 | Yes | Yes |
| TLS 1.2 | Yes | Yes |
| TLS 1.1 | No | **Yes** |
| TLS 1.0 | No | **Yes** |
| Forward secrecy | Yes | Yes with modern suites |
| AEAD ciphers | Yes | Yes |
| Weak CBC suites | No in the listed configuration | **Yes** |
| HSTS | Yes | Yes |
| Overall | **A+** | **B** |

The comparison shows that simply supporting strong modern cryptography is not enough. Leaving older protocols and weaker cipher suites enabled can reduce the security of the whole TLS configuration.

---

## Part 2 - MedDefense Portal Assessment

Finding 005 from the MedDefense vulnerability assessment identified that the patient portal supports **TLS 1.0 and TLS 1.2**, while Finding 013 identified that its certificate is close to expiration.

If `portal.meddefense.local` were publicly accessible and tested with the current SSL Labs grading rules, I would expect it to receive approximately a **B grade while the certificate remains valid**.

### Issues affecting the grade

1. **TLS 1.0 is enabled.**  
   SSL Labs currently caps a server at **B** if it supports TLS 1.0 or TLS 1.1, even when TLS 1.2 is also available.

2. **TLS 1.3 appears to be unsupported.**  
   Finding 005 only identifies TLS 1.0 and TLS 1.2. Current SSL Labs rules warn when TLS 1.3 is not available and prevent the configuration from reaching the strongest modern rating.

3. **The certificate is near expiration.**  
   A certificate that is still valid does not automatically cause the same grade reduction as an obsolete TLS protocol, but the short remaining lifetime is an operational risk. If the certificate actually expires, browsers will no longer trust the connection normally and the portal will present a certificate warning.

4. **Legacy TLS increases the possibility of legacy cipher support.**  
   The findings do not provide the complete cipher-suite list, so I would not claim that a specific weak cipher is enabled without testing it. However, retaining TLS 1.0 creates unnecessary compatibility with older cryptographic configurations and should be removed.

The immediate remediation is therefore to disable TLS 1.0, enable TLS 1.3 alongside TLS 1.2, renew the certificate before expiration and restrict the server to modern authenticated cipher suites.

---

## Part 3 - Hardened TLS Configuration

I chose an **Apache** configuration because it allows the TLS 1.2 and TLS 1.3 cipher suites to be shown clearly.

```apache
# Allow only modern TLS versions
SSLProtocol -all +TLSv1.2 +TLSv1.3

# TLS 1.3 cipher suites, strongest preference first
SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256

# TLS 1.2 cipher suites
SSLCipherSuite TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

# Prefer the server's TLS 1.2 cipher ordering
SSLHonorCipherOrder on

# Disable TLS compression
SSLCompression off

# Do not permit insecure legacy renegotiation
SSLInsecureRenegotiation off

# Disable session tickets to avoid long-lived ticket-key exposure
SSLSessionTickets off

# Use a server-side session cache instead
SSLSessionCache "shmcb:/var/run/apache_ssl_cache(512000)"
SSLSessionCacheTimeout 300

# Staple certificate revocation information when supported by the CA
SSLUseStapling on
SSLStaplingCache "shmcb:/var/run/ocsp(128000)"

# Force browsers to use HTTPS for one year
Header always set Strict-Transport-Security "max-age=31536000"
```

### Why each choice was made

**TLS 1.2 and TLS 1.3 only:** These are the modern TLS versions required for MedDefense, while removing TLS 1.0 prevents clients from negotiating the legacy protocol identified in Finding 005.

**`TLS_AES_256_GCM_SHA384`:** This is the first TLS 1.3 preference because it combines AES-256 encryption with GCM authenticated encryption.

**`TLS_AES_128_GCM_SHA256`:** AES-128-GCM remains strongly secure while requiring less processing than AES-256.

**`TLS_CHACHA20_POLY1305_SHA256`:** ChaCha20-Poly1305 provides modern authenticated encryption and performs well on devices without dedicated AES hardware acceleration.

**ECDHE for TLS 1.2:** All selected TLS 1.2 suites use ephemeral ECDH, which provides forward secrecy so that compromise of the server's long-term private key does not reveal previously captured sessions.

**GCM and ChaCha20-Poly1305 only:** CBC-based TLS suites are excluded because modern AEAD ciphers provide encryption and integrity protection together and avoid weaknesses associated with older CBC constructions.

**Server cipher ordering:** `SSLHonorCipherOrder on` makes the server select from the approved TLS 1.2 cipher list in the configured preference order rather than allowing an older client to choose a less-preferred option.

**Compression disabled:** TLS compression is unnecessary and historically enabled attacks such as CRIME, so it should remain disabled.

**Insecure renegotiation disabled:** Only secure renegotiation should be accepted, preventing use of the obsolete insecure renegotiation mechanism.

**Session tickets disabled:** Disabling tickets avoids relying on persistent ticket-encryption keys; the server-side session cache can still provide session resumption.

**OCSP stapling enabled:** The server can provide certificate-revocation status during the TLS handshake instead of requiring every patient browser to contact the CA separately.

**HSTS for one year:** `max-age=31536000` tells browsers that have already visited the portal to use HTTPS only for the next year, reducing the risk of HTTP downgrade or SSL-stripping attacks.

> `includeSubDomains` and HSTS preload are not enabled automatically here because MedDefense should first confirm that every affected subdomain is permanently HTTPS-only before extending HSTS beyond the patient portal.

---

## Part 4 - TLS Downgrade Attack

In a downgrade attack, an attacker interferes with the negotiation of a modern TLS connection so that the client falls back to an older protocol version that both the client and server still accept. If MedDefense supports both TLS 1.0 and TLS 1.2, an attacker on the network path could disrupt attempts to establish the newer connection and try to make a legacy-capable client reconnect using TLS 1.0. The attacker could then target weaknesses available in the older protocol or its legacy cipher suites. The simplest and strongest prevention is to **disable TLS 1.0 completely**, leaving only TLS 1.2 and TLS 1.3 available.

---

## Remediation Plan for MedDefense

The patient portal should be updated before the current certificate expires. The first priority is to renew and deploy the certificate safely so that patients do not receive trust warnings. At the same time, TLS 1.0 should be disabled, TLS 1.3 enabled, and the cipher configuration restricted to ECDHE with AES-GCM or ChaCha20-Poly1305. HSTS should then be enabled with a one-year lifetime, followed by a new TLS assessment to confirm that no legacy protocols or weak suites remain.

### Verification after remediation

After applying the configuration, MedDefense should verify:

```text
TLS 1.0     Disabled
TLS 1.1     Disabled
TLS 1.2     Enabled
TLS 1.3     Enabled
Weak CBC    Disabled
RC4         Disabled
3DES        Disabled
HSTS        Enabled
Certificate Valid and trusted
```

A public-facing equivalent of the MedDefense portal should then be retested with SSL Labs to verify the final configuration.

---

## References

- Qualys SSL Labs, **SSL Server Test**, current assessments reviewed in September/October 2026.
- Qualys SSL Labs, **SSL Server Rating Guide**, version 2009r.
- Qualys SSL Labs, **SSL and TLS Deployment Best Practices**.
- MedDefense Vulnerability Assessment 1x02, **Finding 005 - TLS 1.0 enabled on patient portal**.
- MedDefense Vulnerability Assessment 1x02, **Finding 013 - patient portal certificate near expiration**.
