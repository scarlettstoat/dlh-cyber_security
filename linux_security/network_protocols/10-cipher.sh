#!/bin/bash
sudo nmap --script ssl-enum-ciphers -p 443 "$1"
