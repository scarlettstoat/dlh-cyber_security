#!/bin/bash
h=$(sha256sum "$1" | cut -d ' ' -f1)
if [ "$h" = "$2" ]
then echo "$1: OK"
else echo "$1: FAIL"
fi
