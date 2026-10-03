# Task 5 - Digital Signatures in Practice

## Part 1 - Sign and Verify

The RSA key pair generated in Task 2 was reused for this exercise.

### Create the prescription file

```bash
echo "Patient: John Smith | MRN: MED-10042 | Rx: Metoprolol 50mg | Prescriber: Dr. Patel" > prescription.txt
```

Contents:

```text
Patient: John Smith | MRN: MED-10042 | Rx: Metoprolol 50mg | Prescriber: Dr. Patel
```

### Sign the file with SHA-256 and the RSA private key

```bash
openssl dgst -sha256 -sign rsa_private.pem -out prescription.sig prescription.txt
```

Observed output:

```text
(no terminal output)
```

The command completed successfully and created `prescription.sig`.

### Verify the signature with the RSA public key

```bash
openssl dgst -sha256 -verify rsa_public.pem -signature prescription.sig prescription.txt
```

Observed output:

```text
Verified OK
```

This confirms that the signature matches the file and the RSA public key.

### Modify one character and verify again

The prescription was changed from `50mg` to `51mg`:

```text
Patient: John Smith | MRN: MED-10042 | Rx: Metoprolol 51mg | Prescriber: Dr. Patel
```

The same verification command was run again:

```bash
openssl dgst -sha256 -verify rsa_public.pem -signature prescription.sig prescription.txt
```

Observed output:

```text
40875296477F0000:error:02000068:rsa routines:ossl_rsa_verify:bad signature:../crypto/rsa/rsa_sign.c:441:
40875296477F0000:error:1C880004:Provider routines:rsa_verify_directly:RSA lib:../providers/implementations/signature/rsa_sig.c:1035:
Verification failure
```

The verification failed because the signature was created from the original file. Even a one-character change changes the SHA-256 digest, so the existing digital signature no longer matches. This demonstrates the integrity property of digital signatures: a modification to the signed content can be detected.

## Part 2 - Signing Script

The required script is `5-sign_verify.sh`.

Sign a file:

```bash
./5-sign_verify.sh sign prescription.txt rsa_private.pem
```

This produces:

```text
prescription.txt.sig
```

Verify a signature:

```bash
./5-sign_verify.sh verify prescription.txt prescription.txt.sig rsa_public.pem
```

A valid signature produces:

```text
Verified OK
```

If the signed file has been modified, verification produces:

```text
Verification failure
```
