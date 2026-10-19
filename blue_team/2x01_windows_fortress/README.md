# Windows Fortress — MedDefense

## Task 0: Domain reconnaissance

`0-domain_baseline.ps1` gathers a **read-only** baseline of the MedDefense Active Directory domain from DC01 (Windows Server 2022). It inventories domain controllers, users, groups and direct members, service accounts, GPOs and their links, password and lockout policies, Kerberos encryption settings, and privileged group members. It also produces a security-findings summary.

### Requirements

- Run from a PowerShell session on **DC01** using the authorized `meddefense.local` lab account.
- The **ActiveDirectory** and **GroupPolicy** Windows PowerShell modules must be installed.
- The account must have permission to enumerate the relevant directory and policy objects.

### Run

```powershell
Set-Location <path-to-project-folder>
.\0-domain_baseline.ps1
```

Or specify an output destination:

```powershell
.\0-domain_baseline.ps1 -OutputPath '.\baseline_dc01.json'
```

The script prints a summary and saves a full timestamped **JSON** report in the working directory. The JSON report includes individual account records, group members, direct GPO links on the domain and OUs, policy settings, findings, and collection limitations.

### Interpretation and limitations

- This is a **baseline**, not a hardening script. It makes no Active Directory, GPO, or registry changes.
- The number of findings depends on what the live domain returns; no result is hard-coded to match the task example.
- `LastLogonDate` is based on a replicated attribute and is only an approximate last logon time.
- The service-account identification rule follows the task instructions: names containing `svc` or accounts located in an OU named `Service Accounts`. Other service identities may require manual review.
- `TrustedForDelegation` identifies **unconstrained delegation**. `TrustedToAuthForDelegation` is a different setting and must not be used as a substitute.
- The JSON records directly linked GPOs for the domain and its OUs; it does not analyze GPO links on Active Directory sites, security filtering, or the resultant policy of each workstation.
- Kerberos account masks, the DC01 allowed-encryption policy, and the KDC fallback value are configuration indicators, **not proof** of ticket encryption actually in use. Review all domain controllers and check DC security events (such as 4768 and 4769) for actual negotiated types, and investigate collection limitations.
- A report may include account names, organizational structure, and security settings. Keep it within the authorized lab and avoid publishing live-domain reports publicly.

### Validation

Run from DC01 and confirm that the JSON exists and can be parsed:

```powershell
Get-ChildItem .\DomainBaseline_*.json
Get-Content (Get-ChildItem .\DomainBaseline_*.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Raw | ConvertFrom-Json | Select-Object -ExpandProperty Summary
```

**Status:** Drafted offline. Execute and validate on DC01 before submitting as verified evidence.
