# The Patch Equation — Task 0: Vulnerability Inventory

## Overview

This task creates a vulnerability inventory for the MedDefense Ubuntu server, billing-srv-01. It checks which software packages are installed, identifies available security updates and produces a report showing possible vulnerabilities.

## Files

- **0-vuln_inventory.sh** — the script that checks installed packages and available security updates.
- **cve_feed.json** — the CVE information provided for the exercise.
- **vulnerability_inventory.json** — the report created by the script.

## What the script does

The script compares installed packages with available security updates. It looks for related CVEs and uses the supplied feed to identify severity scores and whether a vulnerability is listed in CISA's Known Exploited Vulnerabilities catalogue.

## Notes

The inventory should be collected from the Ubuntu server, not Kali, so the results reflect the system being assessed.

The script does not install updates or change the system. Missing vulnerability information is marked as unknown rather than treated as proof that a package is safe.
