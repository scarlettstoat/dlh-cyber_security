# The Patch Equation

## Project overview

This MedDefense Health Systems project is about managing Linux security patches safely. It covers finding vulnerabilities, understanding which services could be affected, taking a snapshot before changes, planning and applying updates, and checking that services still work afterwards.

## Tasks

**Task 0 – Vulnerability Inventory**  
Lists installed packages and identifies available security updates and known CVEs.  
Files: `0-vuln_inventory.sh` and `vulnerability_inventory.json`.

**Task 1 – Service Dependency Map**  
Identifies running services, their executables and package dependencies so patch impact can be assessed.  
Files: `1-service_deps.sh` and `service_dependency_map.json`.

**Task 2 – Pre-Patch Snapshot**  
Captures package versions, service states, listening ports, configuration file hashes and reboot status before changes.  
Files: `2-pre_patch_snapshot.sh` and `pre_patch_state.json`.

**Task 3 – Patch Plan**  
Combines vulnerability findings and service dependencies to prioritise patches and record affected services and rollback versions.  
Files: `3-patch_plan.sh` and `patch_plan.json`.

**Task 4 – Safe Patch Execution**  
Processes the patch plan with checks, locking and a record of each attempted update. Actual installation should only happen after reviewing the plan and confirming rollback readiness.  
Files: `4-patch_execute.sh` and `patch_execution_log.json`.

**Task 5 – Post-Patch Service Validation**  
Compares services and listening ports with the original snapshot and checks critical service availability.  
Files: `5-post_patch_validate.sh` and `post_patch_validation.json`.

## Supporting files

The exercises also use provided data files, including `cve_feed.json`, `service_criticality.json` and `service_probes.json`. These should be kept with the project files when required.

## Important notes

The generated JSON files are intended to hold results from the Ubuntu endpoint. Any empty templates must be replaced with real results before they can be treated as evidence. A successful simulated or local script test does not prove the scripts have passed checks on the target server.

The scripts should be reviewed and checked before use. System changes require an approved maintenance window, a saved baseline and a workable recovery plan. The original pre-patch snapshot must be preserved for comparison and rollback.
