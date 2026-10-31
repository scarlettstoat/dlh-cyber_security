# Eyes on the Endpoint

MedDefense endpoint telemetry validation project.

## Task 0: Sysmon Telemetry Validation

`0-sysmon_validation.ps1` runs five controlled tests on the Windows DC01 host and checks the Sysmon Operational log for the expected event IDs and details:

- **1:** Process creation and full command line (`cmd.exe /c whoami`)
- **3:** Outbound network connection with destination IP, port and process
- **11:** File creation with target filename and creating process
- **13:** Registry value modification with target path, value and operation
- **22:** DNS query with query name and results

The script displays each test's timestamp and PASS/FAIL result, removes the temporary test file and registry key, and prints captured/missed totals.

Run in an elevated Windows PowerShell session on DC01:

```powershell
.\0-sysmon_validation.ps1
```

A failed test can indicate missing or filtered Sysmon telemetry, a blocked connection, or another environmental issue. Results must be verified on DC01; merely having Sysmon installed does not guarantee coverage.
