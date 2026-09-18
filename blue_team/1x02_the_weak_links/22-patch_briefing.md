# 22. The Patch Briefing

**For:** MedDefense Board  
**Action window:** Next 24–48 hours

MedDefense should execute three immediate actions this week.

### 1. Isolate the Windows XP MRI workstation — Finding 004

**What it is:** The MRI control workstation runs unsupported Windows XP and exposes old remote-access services with well-known attack methods.

**If exploited:** An attacker could disrupt MRI operations, compromise imaging data and use the workstation as a foothold into other hospital systems. Because the device cannot be safely patched like a normal PC, the immediate fix is containment.

**Fix:** Place it in a dedicated MRI network zone, block general RDP/SMB access and allow only validated PACS/vendor traffic.  
**Time / cost:** **24–48 hours / $7,000.**

### 2. Restrict access to the EHR database — Finding 003

**What it is:** The patient-record database currently accepts connections from far more of the internal network than necessary.

**If exploited:** A compromised internal computer could reach the database directly, increasing the risk of patient-data theft, alteration or EHR disruption.

**Fix:** Allow database access only from the EHR application server and approved administration systems.  
**Time / cost:** **24–48 hours / $500.**

### 3. Patch the billing Apache server — Finding 001

**What it is:** The billing server has a serious Apache flaw that can allow an attacker to run code on the server.

**If exploited:** Billing could be taken over, disrupted or used as a stepping stone into the wider MedDefense network.

**Fix:** Upgrade Apache through a supported package path, verify whether `mod_lua` is required, test billing and rescan; the same change also closes Finding 002 at no additional cost.  
**Time / cost:** **24–48 hours / $1,000.**

**Three-week progress:** MedDefense has moved from identifying security gaps, to mapping realistic threat paths, to validating 31 scan findings and turning them into a prioritized, funded remediation plan.
