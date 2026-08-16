# Healthcare Mobile App Threat Model

## 1. System Overview

This threat model covers a healthcare mobile application that allows patients to:

- View medical records
- Schedule appointments
- Message healthcare providers
- Receive prescription refills

The system uses:

- iOS and Android mobile clients
- A REST API backend
- A cloud-hosted database
- Integration with hospital systems

The application processes highly sensitive patient information, so security controls need to protect not only privacy but also the accuracy and availability of information used for healthcare decisions.

---

# 2. Most Critical Asset

The **most critical asset is patient electronic health information**, including medical records, diagnoses, prescription information, healthcare-provider messages, appointment information, and identifying patient data.

Under HIPAA, electronic protected health information (ePHI) must be protected for **confidentiality, integrity, and availability** [1]. This makes the CIA Triad a useful way to explain why patient health information is the application's highest-value asset.

## Confidentiality

**Confidentiality means that patient information should only be accessible to authorised people and systems.**

A patient's medical history, diagnoses, prescriptions, and private conversations with healthcare providers could cause serious privacy harm if exposed.

For example, if an attacker compromises a patient's account and downloads their medical records, the confidentiality of that information has been lost.

Confidentiality is especially important because once private medical information is disclosed, the organisation cannot simply "change" it in the same way that it could reset a password.

## Integrity

**Integrity means that patient information must remain accurate and must not be changed without authorisation.**

This is particularly important in healthcare because incorrect information could influence treatment.

For example, an attacker who changes:

- a patient's medication;
- an allergy record;
- a prescription-refill message; or
- a provider's instructions

could create a direct patient-safety risk.

A medical record that remains private but has secretly been altered is still unsafe.

## Availability

**Availability means that authorised patients and healthcare staff must be able to access the information and services when they are needed.**

If the app or its backend is unavailable, a patient may be unable to view important information, send a message, book an appointment, or request a prescription refill.

Availability therefore matters both operationally and clinically. A healthcare system cannot protect data by making it impossible for legitimate users to reach it.

## Conclusion

Patient electronic health information is the most critical asset because a failure in **any part of the CIA Triad** can create serious consequences:

| CIA Principle | Example Failure | Possible Consequence |
|---|---|---|
| **Confidentiality** | Medical records are exposed to an unauthorised person | Privacy breach, identity misuse, regulatory consequences |
| **Integrity** | Prescription or medical information is altered | Incorrect treatment or patient-safety risk |
| **Availability** | Backend or hospital integration becomes unavailable | Patients and staff cannot access required services or information |

For this system, **confidentiality and integrity deserve particularly strong protection**, while availability must also be maintained because healthcare information may be time-sensitive.

---

# 3. STRIDE Analysis — "Message Healthcare Providers"

STRIDE categorises threats as **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service,** and **Elevation of Privilege** [2].

The secure-messaging feature is particularly sensitive because users may discuss symptoms, diagnoses, treatments, test results, and prescription information.

## Threat 1 — Spoofing a healthcare provider or patient

| Item | Analysis |
|---|---|
| **STRIDE category** | Spoofing |
| **Threat description** | An attacker pretends to be a legitimate patient or healthcare provider by using stolen credentials, a hijacked session, or another compromised authentication method. |
| **Attack scenario** | An attacker obtains a doctor's credentials through phishing and signs in as that doctor. The attacker then sends messages to patients that appear to come from a trusted healthcare professional, possibly giving false instructions or requesting sensitive information. |
| **Potential impact** | Exposure of patient information, fraudulent medical instructions, account compromise, loss of trust, and possible patient-safety consequences. |
| **Likelihood** | **Medium to High.** Healthcare accounts are valuable targets and credential theft is realistic. The likelihood depends on the strength of authentication and session security. |
| **Mitigation** | Require strong authentication, use MFA for healthcare staff and high-risk actions, protect session tokens, apply login rate limiting, detect suspicious logins, and re-authenticate users for particularly sensitive actions. |

The important point is that the system should not assume that someone is a doctor simply because they know a password.

---

## Threat 2 — Tampering with messages

| Item | Analysis |
|---|---|
| **STRIDE category** | Tampering |
| **Threat description** | An attacker modifies the content, recipient, sender information, or status of a healthcare message without authorisation. |
| **Attack scenario** | An attacker compromises an API request and changes a provider's message from "take one tablet per day" to different instructions, or changes the recipient ID so that sensitive information is sent to another account. |
| **Potential impact** | Incorrect treatment information, patient-safety risks, privacy breaches, corrupted medical communication, and legal or regulatory consequences. |
| **Likelihood** | **Medium.** Exploitation would normally require a vulnerability such as weak authorisation, an insecure API, a compromised account, or inadequate transport protection. |
| **Mitigation** | Enforce HTTPS/TLS, perform authorisation checks on every message operation, validate recipient and sender IDs server-side, protect stored message records from unauthorised modification, and maintain tamper-evident audit logs. |

In healthcare, a changed message is not merely a data-quality problem: the message may influence a real medical decision.

---

## Threat 3 — Repudiation of a message

| Item | Analysis |
|---|---|
| **STRIDE category** | Repudiation |
| **Threat description** | A patient or healthcare provider denies sending, receiving, editing, or acting on a message, while the system lacks sufficient evidence to establish what actually happened. |
| **Attack scenario** | A provider sends medication instructions through the app but later disputes having sent them. If the application records only the message text and keeps no reliable timestamp, authenticated user ID, delivery status, or audit event, investigators may be unable to reconstruct the event. |
| **Potential impact** | Disputes over medical instructions, difficult incident investigations, poor accountability, regulatory problems, and possible legal consequences. |
| **Likelihood** | **Medium.** The threat becomes more significant when logging is incomplete or logs can be altered by ordinary users or administrators. |
| **Mitigation** | Maintain protected audit logs containing authenticated user identity, timestamps, message actions, relevant message identifiers, delivery state, and security events. Restrict access to logs and protect them against unauthorised modification or deletion. |

This is why "I definitely didn't send that" should be answerable with evidence rather than guesswork.

---

## Threat 4 — Information disclosure

| Item | Analysis |
|---|---|
| **STRIDE category** | Information Disclosure |
| **Threat description** | Private messages between patients and healthcare providers are exposed to unauthorised users or systems. |
| **Attack scenario** | The mobile application stores message contents insecurely on the device, an API endpoint returns another patient's conversation because of a broken authorisation check, or sensitive message data appears in application logs or notifications visible on a locked phone. |
| **Potential impact** | Disclosure of medical information, privacy harm, identity misuse, reputational damage, and regulatory consequences. |
| **Likelihood** | **High without strong controls.** The feature handles sensitive information across several components: the mobile device, network, API, cloud database, and hospital integration. |
| **Mitigation** | Encrypt data in transit and at rest, enforce object-level authorisation on API requests, minimise locally stored message data, avoid placing sensitive medical content in lock-screen notifications, redact sensitive data from logs, and restrict database access using least privilege. |

---

## Threat 5 — Denial of Service

Although only four threats are required, Denial of Service is also relevant to this feature.

| Item | Analysis |
|---|---|
| **STRIDE category** | Denial of Service |
| **Threat description** | An attacker overwhelms the messaging service or backend so that patients and healthcare providers cannot send or retrieve messages. |
| **Attack scenario** | An attacker uses automated requests to send very large numbers of messages or repeatedly calls the messaging API, consuming application or database resources until legitimate requests become slow or fail. |
| **Potential impact** | Delayed communication, unavailable healthcare services, increased workload for staff, and possible patient-safety consequences if an important message cannot be delivered. |
| **Likelihood** | **Medium.** Internet-facing APIs are accessible targets, although rate limiting and cloud infrastructure can reduce the likelihood and impact. |
| **Mitigation** | Apply API rate limiting, request-size limits, authentication controls, monitoring and alerting, scalable infrastructure, and abuse detection. Provide alternative communication procedures for critical situations. |

---

# 4. Priority Security Controls for Patient Data

The controls below are ordered by priority. In practice they should work together as **defence in depth** rather than being treated as alternatives.

NIST guidance for electronic health records on mobile devices identifies security characteristics including access control, audit controls and monitoring, device integrity, person or entity authentication, and transmission security [3].

## Priority 1 — Strong Authentication and Secure Session Management

The first priority is making sure that the person accessing the application is actually who they claim to be.

### Controls

- Strong password requirements
- MFA, especially for healthcare professionals and privileged accounts
- Protection of authentication/session tokens
- Secure session expiry
- Re-authentication for high-risk actions
- Login rate limiting and suspicious-login detection

### Why this is first

If an attacker can simply sign in as a patient or doctor, many other security controls become less effective because the application may treat the attacker as a legitimate user.

Strong authentication therefore reduces the risk of account takeover at the first major access point.

---

## Priority 2 — Encryption of Patient Data

Patient information should be encrypted both **in transit** and **at rest**.

### Controls

- HTTPS/TLS for all mobile-app, API, hospital-system, and cloud communications
- Encryption for sensitive database data and backups
- Secure mobile-device storage
- Strong encryption-key management
- No secrets or patient records stored unnecessarily in plaintext

### Why this is second

The information crosses multiple systems: mobile device → REST API → cloud infrastructure → hospital systems.

Encryption reduces the chance that stolen or intercepted data can be read by an attacker. However, encryption alone is not enough; HHS specifically notes that protecting confidentiality through encryption does not by itself provide integrity and availability [4].

---

## Priority 3 — Authorisation and Least Privilege

Authentication answers **"Who are you?"**  
Authorisation answers **"What are you allowed to do?"**

Both are necessary.

### Controls

- Role-based or attribute-based access control
- Server-side authorisation for every sensitive API request
- Object-level checks so a patient can access only the correct records and conversations
- Least-privilege access for hospital integrations and database accounts
- Separate administrative privileges from ordinary healthcare accounts

### Why this is third

A perfectly authenticated user should still not have access to everyone else's medical history.

For example:

```text
Patient A → /api/messages/PatientA     ALLOWED
Patient A → /api/messages/PatientB     DENIED
```

The server must enforce that rule. Hiding Patient B's messages in the mobile interface is not a security control if the API still returns them.

---

## Priority 4 — Audit Logging and Security Monitoring

Sensitive healthcare actions should leave a reliable audit trail.

### Log important events such as:

- Successful and failed logins
- Access to medical records
- Messages sent, edited, or deleted
- Prescription-related actions
- Permission changes
- Administrative activity
- Unusual API activity

### Why this is fourth

Logging does not necessarily prevent the first attack, but it allows the organisation to identify suspicious behaviour, investigate incidents, establish accountability, and detect ongoing compromise.

The logs themselves must also be protected. An attacker should not be able to compromise an account and then erase the evidence.

---

## Priority 5 — Secure API, Mobile Application, and Integration Hardening

The REST API and hospital-system integration form major attack surfaces because sensitive information moves through them.

### Controls

- Validate and sanitise untrusted input
- Enforce authentication and authorisation server-side
- Apply API rate limits
- Keep operating systems, libraries, frameworks, and dependencies patched
- Store API secrets securely and never embed backend secrets in the mobile application
- Use secure error handling
- Test APIs for common vulnerabilities
- Monitor third-party and hospital-system integrations
- Minimise the patient data collected and retained

### Why this is fifth

The application may have excellent encryption and authentication but still be compromised through a vulnerable API endpoint, outdated dependency, leaked secret, or poorly secured hospital integration.

This control therefore reduces the remaining technical attack surface and supports all of the higher-priority controls.

---

# 5. Real-World Implementation Considerations

A healthcare organisation must balance security with usability, cost, staff resources, and patient access.

The highest-value controls should therefore be implemented first:

1. **Authentication and session security**
2. **Encryption**
3. **Authorisation and least privilege**
4. **Audit logging and monitoring**
5. **API, mobile, and integration hardening**

Where budget is limited, the organisation can use managed cloud identity, key-management, logging, and monitoring services rather than building every security component from scratch.

Security must also avoid making healthcare inaccessible. For example, MFA should improve account security without creating unreasonable barriers for patients who may have accessibility needs or limited technical experience.

---

# 6. Conclusion

The most critical asset in this healthcare mobile application is **patient electronic health information** because its confidentiality, integrity, and availability all directly affect privacy, trust, and potentially patient safety.

Applying STRIDE to the healthcare messaging feature identified five important threats:

- **Spoofing** a patient or healthcare provider
- **Tampering** with messages
- **Repudiation** of sent or received messages
- **Information Disclosure** of private medical conversations
- **Denial of Service** against the messaging platform

The most important controls are strong authentication, encryption, server-side authorisation, protected audit logging, and secure API/mobile/integration design.

The key principle is that healthcare data should remain **private, accurate, and available to the right person at the right time**.

---

# References

[1] U.S. Department of Health and Human Services (HHS), **The HIPAA Security Rule**.  
https://www.hhs.gov/hipaa/for-professionals/security/index.html

[2] Microsoft Learn, **Microsoft Threat Modeling Tool threats**.  
https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats

[3] NIST National Cybersecurity Center of Excellence, **Securing Electronic Health Records on Mobile Devices (NIST SP 1800-1)**.  
https://www.nccoe.nist.gov/publication/1800-1

[4] U.S. Department of Health and Human Services (HHS), **Guidance on HIPAA & Cloud Computing**.  
https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html
