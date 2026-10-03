#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file> <expected_sha256_hash>"
    exit 1
fi

file="$1"
expected_hash="$2"

if [ ! -f "$file" ]; then
    echo "INTEGRITY FAILED - file not found: $file"
    exit 1
fi

actual_hash=$(sha256sum "$file" | cut -d ' ' -f1)

if [ "$actual_hash" = "$expected_hash" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $expected_hash got $actual_hash"
    exit 1
fi
