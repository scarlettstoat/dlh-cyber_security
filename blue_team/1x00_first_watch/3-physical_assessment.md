# Physical Security Assessment

## Observation 1: Server Room Access

**Vulnerability:** The server room uses the same generic employee badge issued to clinical, administrative and custodial staff, with no camera coverage or visitor log to restrict or audit access.

**Threat:** An employee or other person with access to a valid staff badge could enter the server room without authorization and tamper with, disconnect or remove equipment without being easily identified.

**Impact:** **Confidentiality, Integrity and Availability** — unauthorized physical access could expose sensitive information, allow systems or configurations to be altered, or cause critical systems to become unavailable.

**Severity:** **Critical** — unrestricted badge access to a server room, combined with the absence of monitoring and access logging, creates the potential for direct compromise of critical IT infrastructure.

---

## Observation 2: Network Closet

**Vulnerability:** The network closet is unlocked and left open, while valid switch management credentials are visibly posted beside the network equipment.

**Threat:** An unauthorized person could enter the closet, use the exposed credentials to access the switch management interface and change network configurations, connect an unauthorized device or disrupt network connectivity.

**Impact:** **Integrity, Availability and Confidentiality** — network configurations could be modified, connectivity could be interrupted, and unauthorized access to network traffic or connected systems could become possible.

**Severity:** **Critical** — physical access to network equipment combined with exposed administrative credentials gives an unauthorized person both direct and logical access to network infrastructure.

---

## Observation 3: Nurse Station

**Vulnerability:** An EHR workstation is left unattended while authenticated with a patient record visible, and staff are instructed not to log out between shifts.

**Threat:** An unauthorized person could use the unattended authenticated session to view patient information or make unauthorized changes to records under another user's session.

**Impact:** **Confidentiality and Integrity** — patient information could be viewed by an unauthorized person, and EHR data could potentially be altered without authorization.

**Severity:** **High** — the unattended active EHR session exposes sensitive patient information and provides an immediate opportunity for unauthorized access or modification.

---

## Observation 4: Medical IoT

**Vulnerability:** The connected vital signs monitor is running firmware last updated in 2019 and appears to share the same IP range as nurse-station workstations, indicating potentially outdated software and insufficient network segmentation.

**Threat:** An attacker who compromises the medical device could manipulate its operation or diagnostic information and potentially use the device as a point from which to reach other systems on the same network range.

**Impact:** **Integrity, Availability and Confidentiality** — altered diagnostic information could affect clinical decisions, disruption could make the device unavailable for patient monitoring, and compromise could expose diagnostic data or provide access toward other networked systems.

**Severity:** **Critical** — a compromise could affect both patient-care information and connected clinical systems, while the apparent lack of segmentation increases the potential scope of impact.

---

## Observation 5: Emergency Exit

**Vulnerability:** A door separating the public waiting area from the restricted administrative wing is deliberately propped open, bypassing the physical access control boundary.

**Threat:** A member of the public or other unauthorized person could enter the restricted wing and gain physical access to administrative or IT areas, including the hallway leading to the IT department.

**Impact:** **Confidentiality, Integrity and Availability** — unauthorized access could expose sensitive information, enable tampering with devices or records, or disrupt IT and administrative operations.

**Severity:** **High** — the open door provides a direct and uncontrolled path from a public area into a restricted area containing security-sensitive offices and IT functions.
