# Task 8 - The Certificate Anatomy

**Inspection date:** 3 October 2026

> TLS certificates are renewed regularly, so serial numbers, validity dates and issuers may change over time. The values below reflect the certificates served during this inspection.

---

## Part 1 - Inspect Three Real Certificates

For each website, the certificate can be downloaded with `openssl s_client` and then inspected with `openssl x509 -text`.

---

### 1. Let's Encrypt Certificate - cq-ecce.org

I used `cq-ecce.org` as the example of a site using a Let's Encrypt certificate.

#### Commands

```bash
openssl s_client -connect cq-ecce.org:443 -servername cq-ecce.org -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > cq-ecce.pem

openssl x509 -in cq-ecce.pem -text -noout
```

#### Certificate fields

| Field | Observed value |
| --- | --- |
| **Subject** | CN = `cq-ecce.org`; O, L, ST and C are not present in the leaf certificate |
| **Issuer** | C = `US`, O = `Let's Encrypt`, CN = `YE2` |
| **Not Before** | 8 September 2026 13:39:54 GMT |
| **Not After** | 7 December 2026 13:39:53 GMT |
| **Serial Number** | `062692E7C2CB999FB5D7E896911781D8B976` |
| **Signature Algorithm** | `ecdsa-with-SHA384` |
| **Public Key Algorithm** | `id-ecPublicKey` |
| **Public Key Size** | 256-bit EC key (P-256) |
| **Subject Alternative Names** | `cq-ecce.org`, `www.cq-ecce.org` |
| **Key Usage** | Digital Signature |
| **Extended Key Usage** | TLS Web Server Authentication |
| **Authority Information Access - CA Issuers** | `http://ye2.i.lencr.org/` |
| **Authority Information Access - OCSP** | Not present in this leaf certificate |

The certificate is a normal domain-validated TLS server certificate. The SAN extension contains the hostnames for which the certificate is valid, while the Extended Key Usage confirms that it is intended for TLS server authentication.

---

### 2. Commercial CA Certificate - github.com

GitHub was used as the commercial CA example. Its certificate was issued by Sectigo.

#### Commands

```bash
openssl s_client -connect github.com:443 -servername github.com -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > github.pem

openssl x509 -in github.pem -text -noout
```

#### Certificate fields

| Field | Observed value |
| --- | --- |
| **Subject** | CN = `github.com`; O, L, ST and C are not present in the DV leaf certificate |
| **Issuer** | C = `GB`, O = `Sectigo Limited`, CN = `Sectigo Public Server Authentication CA DV E36` |
| **Not Before** | 1 September 2026 00:00:00 GMT |
| **Not After** | 29 November 2026 23:59:59 GMT |
| **Serial Number** | `A59EBDB596751DB7F5C095079613953C` |
| **Signature Algorithm** | `ecdsa-with-SHA256` |
| **Public Key Algorithm** | EC public key |
| **Public Key Size** | 256-bit EC key (P-256) |
| **Subject Alternative Names** | `github.com`, `www.github.com` |
| **Key Usage** | Digital Signature |
| **Extended Key Usage** | TLS Web Server Authentication |
| **Authority Information Access - OCSP** | `http://ocsp.sectigo.com` |
| **Authority Information Access - CA Issuers** | `http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt` |

The subject contains only the domain name because this is a DV certificate. The CA identity appears in the Issuer field, and the certificate chain connects the GitHub certificate through Sectigo's intermediate CA to a trusted root.

---

### 3. Broken Certificate - wrong.host.badssl.com

For the deliberately broken example, I used `wrong.host.badssl.com`.

#### Commands

```bash
openssl s_client -connect wrong.host.badssl.com:443 -servername wrong.host.badssl.com -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > wrong-host.pem

openssl x509 -in wrong-host.pem -text -noout
```

A hostname check can also be performed with:

```bash
openssl s_client \
  -connect wrong.host.badssl.com:443 \
  -servername wrong.host.badssl.com \
  -verify_hostname wrong.host.badssl.com \
  </dev/null
```

The hostname verification fails because the certificate does not cover `wrong.host.badssl.com`.

#### Certificate fields

| Field | Observed value |
| --- | --- |
| **Subject** | CN = `*.badssl.com`; O, L, ST and C are not present |
| **Issuer** | C = `US`, O = `Let's Encrypt`, CN = `YR2` |
| **Not Before** | 28 July 2026 20:03:02 GMT |
| **Not After** | 26 October 2026 20:03:01 GMT |
| **Serial Number** | `065BE17B359D30FCA59459F9893231C1D87D` |
| **Signature Algorithm** | `sha256WithRSAEncryption` |
| **Public Key Algorithm** | `rsaEncryption` |
| **Public Key Size** | 2048 bits |
| **Subject Alternative Names** | `*.badssl.com`, `badssl.com` |
| **Key Usage** | Digital Signature, Key Encipherment |
| **Extended Key Usage** | TLS Web Server Authentication |
| **Authority Information Access - CA Issuers** | `http://yr2.i.lencr.org/` |
| **Authority Information Access - OCSP** | Not present in this leaf certificate |

---

## Part 2 - The Broken Certificate

The problem with `wrong.host.badssl.com` is a **hostname mismatch**. Its certificate is valid for `*.badssl.com` and `badssl.com`, but a wildcard such as `*.badssl.com` can only replace one DNS label. It can therefore match a name such as `test.badssl.com`, but it does not match `wrong.host.badssl.com` because there are two labels (`wrong.host`) before `badssl.com`.

In Chrome, this type of problem is normally shown as **"Your connection is not private"** with the error `NET::ERR_CERT_COMMON_NAME_INVALID`. The encrypted connection may still use strong cryptography, but the patient cannot reliably confirm that the server they reached is the server named in the URL. A hostname mismatch could be caused by a configuration mistake, but it can also indicate interception or redirection to the wrong system. I would **not advise a patient to continue through this warning on the MedDefense portal**; they should stop and contact MedDefense support or IT so the certificate problem can be investigated.

---

## Part 3 - Ideal MedDefense Patient Portal Certificate

### Certificate Type

I would use an **Organization Validated (OV)** certificate for the MedDefense patient portal. DV, OV and EV certificates can all provide the same cryptographic strength, but an OV certificate also verifies information about the organization requesting the certificate. This is useful for a healthcare organization because the certificate can bind the portal not only to a domain but also to the verified MedDefense organization. EV would require additional validation but would not provide stronger encryption than OV, so OV provides a reasonable balance between identity assurance and operational complexity.

### Certificate Authority

The certificate should be issued by a **widely trusted public CA that supports OV certificates**, such as DigiCert, Sectigo or GlobalSign. Using a public CA trusted by major operating systems and browsers means patients should not need to install a private MedDefense root certificate before using the portal.

### Subject Alternative Names

The SAN extension should contain the exact public hostname used by patients, for example:

```text
portal.meddefense.com
```

If MedDefense has another legitimate public alias for the same portal, that hostname should also be included. Only names that are actually required should be added. Internal hostnames and unrelated MedDefense services should not be placed into the same certificate.

### Key Algorithm and Size

A strong choice would be:

```text
ECDSA using the NIST P-256 curve
```

P-256 provides approximately 128 bits of security with a much smaller key than RSA and is supported by modern browsers. If MedDefense needs compatibility with older clients that cannot use ECDSA certificates, an RSA certificate with a key of at least 2048 bits could be used instead.

### Validity Period

As of October 2026, publicly trusted TLS subscriber certificates issued after 15 March 2026 may have a maximum validity period of **200 days**. MedDefense should therefore use a certificate within this limit and automate renewal well before expiration. This is particularly important because the current portal certificate was already identified as approaching expiry, and a missed renewal could make the portal inaccessible to patients.

### Wildcard or Single-Domain

A **single-domain or tightly scoped SAN certificate** is more appropriate than a wildcard certificate for the patient portal. A wildcard such as `*.meddefense.com` would allow one private key to represent many different MedDefense subdomains, which increases the impact if that key is compromised. Limiting the certificate to the patient portal and only its required aliases reduces that exposure and makes certificate ownership easier to manage.

---

## MedDefense Certificate Profile Summary

| Requirement | Recommended Profile |
| --- | --- |
| **Type** | OV |
| **CA** | Widely trusted public CA supporting OV |
| **Primary SAN** | Exact patient portal FQDN, e.g. `portal.meddefense.com` |
| **Additional SANs** | Only legitimate aliases that are actually required |
| **Key Algorithm** | ECDSA P-256 |
| **Alternative for legacy compatibility** | RSA 2048-bit or stronger |
| **Validity** | Maximum 200 days under current public TLS rules; automated renewal |
| **Certificate scope** | Single-domain / tightly scoped SAN |
| **Wildcard** | Avoid unless there is a demonstrated operational requirement |

---

## Conclusion

The most important certificate fields are the **Subject/SAN**, **Issuer**, **validity dates**, **public key**, **signature algorithm**, **Key Usage/Extended Key Usage** and the information used to build and validate the certificate chain. A certificate can use strong cryptography and still be unsafe if the hostname is wrong, the certificate has expired or the issuing chain cannot be trusted. For MedDefense, certificate management therefore needs to include both strong cryptographic settings and reliable renewal and hostname validation processes.
