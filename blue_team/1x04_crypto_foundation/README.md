# The Cryptographic Foundation - AKA How did MedDefense get so insecure? 

It's week 5 at MedDefense and we're finally trading the text editor for the terminal (sort of). Perhaps the most daunting MedDefense project thus far because I need an understanding of the cryptographic primitives well enough to choose the right algorithm, 
configure the right protocol, generate the right certificate and validate the right implementation. It's the first time combining theoretical knowledge with practical know-how.
I'll have to generate keys, encrypt files, hash passwords, inspect certificates, configure TLS parameters, set up disk encryption and write scripts that automate cryptographic operations.

Let's start.

Introduction
"The enemy knows the system." - Auguste Kerckhoffs, 1883

Four weeks of security work at MedDefense and you have never once encrypted a file. You have identified the gaps, profiled the adversaries, triaged the vulnerabilities, built the strategy and secured the budget. Now the Board has signed the check. The Security Strategy Document you wrote in Project 1x03 has "cryptographic controls" on the roadmap. Phase 1 begins this week.

Here is the problem: recommending "encryption" is easy. Implementing encryption correctly is where organizations fail. The 2023 Thales Data Threat Report found that 62% of organizations with encryption programs still experienced a data breach involving encrypted assets. Not because the algorithms were broken, but because the keys were mismanaged, the protocols were misconfigured, the certificates expired or the wrong encryption level was chosen for the wrong data.

MedDefense stores 50,000 patient records in a PostgreSQL database with zero encryption at rest. It transmits appointment data through a patient portal running TLS 1.0, a protocol broken since 2011. It backs up everything to a NAS that stores data in plaintext on the same network as every other device. Its medical imaging traffic flows unencrypted between the MRI workstation and the PACS server. Its Kerberos authentication still accepts DES, an algorithm broken since 1999.

These are not theoretical problems. They are the findings from YOUR vulnerability assessment. And now YOU are the person who must fix them. Not by recommending that someone else fix them, but by understanding the cryptographic primitives well enough to choose the right algorithm, configure the right protocol, generate the right certificate and validate the right implementation.

This project is fundamentally different from the four before it. You will spend more time in a terminal than in a text editor. You will generate keys, encrypt files, hash passwords, inspect certificates, configure TLS parameters, set up disk encryption and write scripts that automate cryptographic operations. Every concept you learn, from AES to X.509, will be learned by DOING it with OpenSSL, LUKS and real-world inspection tools, then connecting it back to the MedDefense environment you know inside and out.

Why It Matters
Every security control you recommended in your strategy depends on cryptography working correctly. Network segmentation means nothing if the traffic traversing the segments is unencrypted. MFA is useless if the authentication protocol is vulnerable to downgrade. Backup replication is a liability if the replicated data is plaintext. Cryptography is not a topic. It is the foundation under every other control you have designed.

The professionals who get hired are not the ones who can say "use AES-256." They are the ones who can explain WHY AES-256, configure it correctly, verify it is working and diagnose it when it is not.

Context
Week five at MedDefense Health Systems.

The Board meeting went exactly as planned. Dr. Morales approved the $120,000 security budget. Robert Kim signed the check (reluctantly, but he signed it). The Security Strategy Document is now an active project plan.

James Chen calls you into his office Monday morning. On the whiteboard, the 6-month roadmap is pinned next to a calendar with Phase 1 highlighted in red.

"Phase 1 starts now. The first items on the roadmap are all crypto-related. We need to encrypt the patient database at rest. We need to fix the TLS configuration on the patient portal before that certificate expires in 18 days. We need to encrypt the backup storage. And we need to sort out the DICOM traffic."

He pauses.

"But before we touch a single production system, I need to be confident that you understand what you are configuring. A misconfigured TLS deployment on the patient portal locks out 800 patients. A botched database encryption breaks the EHR. A wrong cipher suite on the VPN disconnects all three sites."

He slides a laptop toward you.

"This week is your crypto lab. Learn the tools. Understand the primitives. Then we deploy to production next week with confidence, not hope."

Sarah Park adds from the doorway: "And I need documentation. When the auditor asks why we chose AES-256-GCM instead of AES-256-CBC for the database, I want a written justification that references the actual properties of each mode, not 'because Google said so.'"

Learning Objectives
By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

Cryptographic Primitives

The operational difference between symmetric and asymmetric encryption, including when each is appropriate and why both are needed

How AES, RSA, ECC, ChaCha20 work at a conceptual level and what key lengths are considered secure today

How cryptographic hashing works (SHA-2, SHA-3), what properties a hash function must have, why MD5 and SHA-1 are broken and what salting and key stretching accomplish

How Diffie-Hellman key exchange solves the key distribution problem and why it is vulnerable to man-in-the-middle attacks without authentication

How digital signatures provide integrity, authentication and non-repudiation simultaneously

The difference between encryption, hashing, obfuscation, tokenization, masking and steganography

PKI and Certificates

How X.509 certificates work: every field, what it means and why it matters

The chain of trust model: root CAs, intermediate CAs, leaf certificates

Certificate lifecycle: CSR generation, issuance, renewal, revocation (CRL and OCSP)

The difference between self-signed, third-party, wildcard and SAN certificates

How TLS uses certificates to establish encrypted communication and how to evaluate a TLS configuration

Data Protection

The three states of data (at rest, in transit, in use) and the different protection mechanisms each requires

Encryption levels: full-disk, partition, file, volume, database, record

Data classification, data types (regulated, PII, financial, IP) and how classification drives protection decisions

Hardware security: TPM, HSM, key management systems, secure enclaves

Operational Skills

How to use OpenSSL for symmetric encryption, asymmetric encryption, hashing, key generation, CSR creation and certificate inspection

How to set up LUKS disk encryption on Linux

How to use SSL Labs to evaluate a TLS configuration

How to write bash scripts that automate cryptographic operations

Resources
Read or Watch:

Cryptographic Fundamentals

NIST SP 800-175B: Guideline for Using Cryptographic Standards -- Read Section 3 (Cryptographic Mechanisms).

Crypto 101 (free ebook) -- Chapters 1-6 cover the primitives used in this project.

Computerphile: AES Explained -- 10-minute visual explanation.

PKI and Certificates

Let's Encrypt: How It Works -- The ACME protocol explained simply.

Qualys SSL Labs: SSL/TLS Deployment Best Practices -- The authoritative guide for TLS configuration.

badssl.com -- Intentionally misconfigured TLS endpoints for testing.

Data Protection

NIST SP 800-111: Guide to Storage Encryption -- Reference for encryption at rest.

HIPAA Security Rule: Encryption Standards -- Healthcare encryption requirements.

Man or Help:

man openssl

man openssl-enc

man openssl-genrsa

man openssl-req

man openssl-s_client

man openssl-dgst

man cryptsetup

Requirements
General
All deliverables must be written in professional English.

A README.md file, at the root of the folder of the project, is mandatory.

All your files should end with a new line.

Bash Scripting
All your scripts must be executable.

The first line of all your scripts should be exactly #!/bin/bash.

All your files should end with a new line.

Specific Project Rules
Hands-on first, analysis second. When a task involves both a CLI exercise and an analysis component, complete the CLI exercise before writing the analysis. The understanding comes from doing.

Show your commands. Every CLI exercise must document the exact commands used and their output. A claim without evidence is not a finding.

Real tools, real sites. When the task says "inspect a certificate with OpenSSL," use OpenSSL. When it says "test on SSL Labs," use ssllabs.com. Do not fabricate outputs.

Connect to MedDefense. Every cryptographic concept must be connected to a specific MedDefense system, vulnerability or requirement from prior projects.

Cross-reference your prior work. The vulnerability findings (1x02), the risk register (1x03) and the security strategy (1x03) are inputs to this project.

Lab Access
No remote lab is required. You will need:

A Linux machine or VM with OpenSSL installed (standard on all major distributions)

cryptsetup package installed (for LUKS exercises)

Internet access (for SSL Labs, badssl.com, certificate inspection)

Your deliverables from Projects 1x00 through 1x03
