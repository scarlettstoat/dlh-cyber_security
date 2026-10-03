#!/bin/bash

set -euo pipefail

# MedDefense Health Systems - The Cryptographic Foundation
# Task 1: The Symmetric Engine
#
# Usage:
#   ./1-symmetric_encrypt.sh <input_file> <output_file> <cbc|gcm>
#
# Notes:
# - CBC uses the OpenSSL "enc" interface with AES-256-CBC.
# - Modern OpenSSL intentionally does not support AES-GCM through "openssl enc".
#   For GCM, this script uses OpenSSL CMS, which supports AES-GCM and correctly
#   handles the authentication tag and nonce. A local recipient certificate/key
#   pair is created on first use and stored outside the repository in:
#       ~/.meddefense_crypto_lab/
#
# Manual lab commands to run/document later:
#
# 1) Create the patient test file:
# printf '%s\n' 'Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation' > patient.txt
#
# 2) AES-256-CBC encryption and decryption:
# openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in patient.txt -out patient-aes256-cbc.enc
# openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in patient-aes256-cbc.enc -out patient-aes256-cbc.dec.txt
#
# 3) AES-256-GCM with OpenSSL CMS. First create a local lab recipient
#    key/certificate, then encrypt and decrypt:
# openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 -subj "/CN=MedDefense Crypto Lab GCM Recipient" -keyout gcm-recipient-key.pem -out gcm-recipient-cert.pem
# openssl cms -encrypt -binary -aes-256-gcm -in patient.txt -out patient-aes256-gcm.cms -outform DER gcm-recipient-cert.pem
# openssl cms -decrypt -binary -inform DER -in patient-aes256-gcm.cms -out patient-aes256-gcm.dec.txt -recip gcm-recipient-cert.pem -inkey gcm-recipient-key.pem
#
# 4) AES-128-CBC encryption and decryption:
# openssl enc -aes-128-cbc -salt -pbkdf2 -iter 100000 -in patient.txt -out patient-aes128-cbc.enc
# openssl enc -d -aes-128-cbc -pbkdf2 -iter 100000 -in patient-aes128-cbc.enc -out patient-aes128-cbc.dec.txt
#
# 5) Create the 100 MB performance test file:
# dd if=/dev/urandom of=testfile bs=1M count=100

usage() {
    echo "Usage: $0 <input_file> <output_file> <cbc|gcm>" >&2
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

input_file="$1"
output_file="$2"
mode="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"

if [ ! -f "$input_file" ]; then
    echo "Error: input file '$input_file' does not exist." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: OpenSSL is not installed or is not in PATH." >&2
    exit 1
fi

case "$mode" in
    cbc)
        # AES-256-CBC provides confidentiality but not built-in authentication.
        # PBKDF2 derives the encryption key from the passphrase entered by the user.
        openssl enc \
            -aes-256-cbc \
            -salt \
            -pbkdf2 \
            -iter 100000 \
            -in "$input_file" \
            -out "$output_file"
        ;;

    gcm)
        # The OpenSSL "enc" command does not support AEAD modes such as GCM.
        # CMS is therefore used for AES-256-GCM. CMS generates and manages the
        # AES content-encryption key, nonce and authentication tag.
        key_dir="${HOME}/.meddefense_crypto_lab"
        private_key="${key_dir}/gcm-recipient-key.pem"
        certificate="${key_dir}/gcm-recipient-cert.pem"

        mkdir -p "$key_dir"
        chmod 700 "$key_dir"

        if [ ! -f "$private_key" ] || [ ! -f "$certificate" ]; then
            echo "Creating local GCM recipient key and certificate in $key_dir ..."
            openssl req \
                -x509 \
                -newkey rsa:3072 \
                -sha256 \
                -nodes \
                -days 365 \
                -subj "/CN=MedDefense Crypto Lab GCM Recipient" \
                -keyout "$private_key" \
                -out "$certificate" \
                >/dev/null 2>&1

            chmod 600 "$private_key"
            chmod 644 "$certificate"
        fi

        openssl cms \
            -encrypt \
            -binary \
            -aes-256-gcm \
            -in "$input_file" \
            -out "$output_file" \
            -outform DER \
            "$certificate"
        ;;

    *)
        echo "Error: mode must be 'cbc' or 'gcm'." >&2
        usage
        ;;
esac

echo "Encryption complete: $output_file"
