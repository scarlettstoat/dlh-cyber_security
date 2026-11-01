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
