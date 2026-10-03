#!/bin/bash

mode="$1"

if [ "$mode" = "sign" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 sign <file> <private_key>"
        exit 1
    fi

    file="$2"
    private_key="$3"
    signature="${file}.sig"

    openssl dgst -sha256 -sign "$private_key" -out "$signature" "$file"

    if [ "$?" -eq 0 ]; then
        echo "Signature created: $signature"
        exit 0
    else
        exit 1
    fi

elif [ "$mode" = "verify" ]; then
    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 verify <file> <signature_file> <public_key>"
        exit 1
    fi

    file="$2"
    signature="$3"
    public_key="$4"

    openssl dgst -sha256 -verify "$public_key" -signature "$signature" "$file"
    exit $?

else
    echo "Invalid mode. Use sign or verify."
    exit 1
fi
