# MedDefense Health Systems — Social Engineering Analysis

## Scenario 1 — FortiGate Emergency Patch Email

**Vector Type:** **Phishing**

**Target:** **Sarah Park, IT Director.** She is a high-value target because she is responsible for MedDefense infrastructure and is expected to respond quickly to urgent security issues involving the FortiGate 100F.

**Psychological Lever:** **Urgency**

**Red Flags:**
1. The sender domain is `fortinet-support.net`, not Fortinet's legitimate corporate domain.
2. The message threatens service termination within 24 hours, creating artificial pressure to act before verifying the request.
3. It directs Sarah to download an "emergency patch" from an email link rather than through the vendor's authenticated support portal.

**Technical Control:** Deploy an email-security gateway with **lookalike-domain detection, URL reputation checking and attachment/link sandboxing** to quarantine messages impersonating trusted security vendors.

**Administrative Control:** Require all firmware and security updates to be obtained **only through the vendor's verified support portal or an independently confirmed vendor channel**, never from links supplied in unsolicited email.

**MedDefense Relevance:** This attack is particularly credible because the FortiGate is a Critical network asset in the Project 1x00 Criticality Assessment. MedDefense already relies heavily on perimeter controls, so compromising the administrator responsible for that device could create a direct path toward wider infrastructure.

---

## Scenario 2 — CEO Wire-Transfer Request

**Vector Type:** **Business Email Compromise (BEC)**

**Target:** **Robert Kim, CFO.** He has authority over high-value financial transactions and routinely receives sensitive requests from senior leadership, making him an attractive target for executive impersonation.

**Psychological Lever:** **Authority**

**Red Flags:**
1. The sender address differs subtly from the CEO's legitimate email address.
2. The request demands an immediate **$85,000 wire transfer** with no normal procurement or approval context.
3. The sender instructs Robert not to discuss the transaction and insists on "email only," deliberately preventing independent verification.

**Technical Control:** Configure the email platform to detect **executive impersonation, display-name spoofing and lookalike domains**, and clearly flag messages originating outside MedDefense.

**Administrative Control:** Enforce **dual approval and out-of-band verification** for high-value or unusual wire transfers, using a known phone number or established finance workflow rather than replying to the requesting email.

**MedDefense Relevance:** The attack bypasses firewalls entirely and targets the authority structure of the organization. Even a technically convincing email should not be sufficient to authorize an exceptional financial transaction.

---

## Scenario 3 — "Mike from IT" Credential Request

**Vector Type:** **Vishing**

**Target:** **A nurse at MedDefense Central.** Nurses are busy, accustomed to urgent operational requests and motivated to keep clinical systems working, making helpfulness and time pressure powerful social-engineering levers.

**Psychological Lever:** **Helpfulness**

**Red Flags:**
1. The caller asks the nurse to disclose an **EHR password**, which legitimate IT staff should never need to know.
2. The caller invokes the recent billing-server incident to make the request sound timely and credible.
3. The identity "Mike from IT" is not independently verified before sensitive information is requested.

**Technical Control:** Implement **phishing-resistant MFA for EHR and sensitive remote access**, so possession of a stolen password alone is insufficient to authenticate.

**Administrative Control:** Establish and reinforce a clear help-desk policy that **IT personnel will never ask users to disclose passwords**; staff should terminate suspicious calls and call the help desk back using the official internal number.

**MedDefense Relevance:** Project 1x00 identified **GAP-007 — MFA and privileged-access controls are not broadly implemented**. Password disclosure is therefore more dangerous at MedDefense because a stolen credential may still be enough to access sensitive systems. fileciteturn55file1L217-L227

---

## Scenario 4 — Staff Parking Renewal Text

**Vector Type:** **Smishing**

**Target:** **All MedDefense employees.** Parking is a routine staff concern, and the threat of towing creates a believable reason to act quickly without closely inspecting the link.

**Psychological Lever:** **Fear**

**Red Flags:**
1. The text creates urgency by claiming the permit expires **tomorrow** and threatens towing.
2. The embedded link is unsolicited and leads to a page reached outside the employee's normal HR navigation path.
3. The page requests **Active Directory credentials** for a parking transaction, which should prompt additional verification.

**Technical Control:** Deploy **phishing-resistant MFA for Active Directory-backed services** and, on managed mobile devices, protective DNS/mobile threat protection that blocks known phishing domains.

**Administrative Control:** Require parking renewals to be completed only through the **known internal HR portal**, and state clearly that MedDefense will not send credential-collection links by SMS.

**MedDefense Relevance:** Because Active Directory is a Critical shared identity dependency, stolen credentials could affect much more than parking access. The Project 1x00 Control Matrix shows that AD has password controls but no broadly deployed MFA. fileciteturn55file0L94-L98

---

## Scenario 5 — Compromised Regional Healthcare Association Website

**Vector Type:** **Watering Hole**

**Target:** **MedDefense physicians seeking CME credits.** The attackers compromise a website that the target population already trusts and visits regularly, so the malicious interaction occurs within a familiar professional workflow.

**Psychological Lever:** **Familiarity**

**Red Flags:**
1. Browsing the site unexpectedly redirects the user to a different domain or opens unfamiliar content.
2. The browser displays security warnings, requests an unusual download or begins unexpected activity on pages that normally contain only CME content.
3. The site behaves differently from previous visits, such as repeated redirects, pop-ups or requests to enable software/plugins.

**Technical Control:** Enforce **rapid browser patching and endpoint detection/protection on managed workstations**, supported by secure web/DNS filtering to block known malicious redirect destinations.

**Administrative Control:** Require CME and other professional web access from **managed, patched MedDefense devices**, and instruct staff to report unexpected redirects or download prompts from otherwise trusted sites.

**MedDefense Relevance:** Project 1x00 identified incomplete endpoint-security coverage under **GAP-013**, meaning not every device can be assumed to have the same level of protection if a trusted website becomes hostile. fileciteturn55file1L301-L311

---

## Scenario 6 — Fake MedDefense Patient Portal

**Vector Type:** **Typosquatting**

**Target:** **MedDefense patients searching online for the patient portal.** Patients may not know the exact MedDefense domain and are likely to trust a convincing search result, especially when a paid advertisement appears above the legitimate portal.

**Psychological Lever:** **Familiarity**

**Red Flags:**
1. The domain uses `meddefence` rather than the organization's correct `meddefense` spelling.
2. The fake site is reached through a **sponsored search result** rather than a known MedDefense link.
3. The page may look identical to the legitimate portal, but the browser's address bar does not show the official MedDefense domain.

**Technical Control:** Use **defensive domain registration and continuous lookalike-domain monitoring** for high-risk variants of the MedDefense name, with rapid takedown procedures for fraudulent domains.

**Administrative Control:** Publish the exact patient-portal address consistently on appointment letters, official emails and the MedDefense public website, and advise patients to use those verified links rather than search-engine advertisements.

**MedDefense Relevance:** The patient portal already handles **Restricted** health information and was previously affected by a broken authorization issue in Project 1x00 (**GAP-010**). Protecting the legitimate access route is therefore important even though the typosquatted site itself exists outside MedDefense infrastructure. fileciteturn55file1L259-L269

---

## Scenario 7 — Person in Scrubs Tailgating into IT

**Vector Type:** **Impersonation**

**Target:** **A staff member entering the restricted IT corridor.** Hospital employees routinely encounter clinicians and contractors they do not personally know, and a person wearing scrubs and carrying familiar hospital items can appear legitimate enough to discourage challenge.

**Psychological Lever:** **Helpfulness**

**Red Flags:**
1. The individual does not badge into the restricted area and instead follows another employee through the door.
2. The explanation that the badge is "in my locker" is a pretext for bypassing the access-control requirement.
3. The partially hidden visitor badge is **expired by two days**, directly contradicting the appearance of legitimate access.

**Technical Control:** Install an **anti-tailgating access control such as a turnstile or mantrap** that requires each person to present a valid badge individually before entering the restricted corridor.

**Administrative Control:** Enforce a **no-tailgating / individual-badge policy** requiring staff to challenge or report anyone attempting to follow through a controlled door without presenting valid credentials.

**MedDefense Relevance:** Project 1x00 already found that physical preventive controls are weak: **C-033 HID Badge Access Control** is rated Weak, and GAP-004/GAP-005 document insufficient protection of Critical infrastructure areas. fileciteturn55file0L56-L58 fileciteturn55file1L175-L199

---

# Summary

The seven scenarios show that social engineering attacks do not rely on one channel or one psychological weakness. MedDefense personnel and patients can be targeted through **email, voice, SMS, trusted websites, search results and face-to-face interaction**, with attackers exploiting urgency, authority, familiarity, fear and helpfulness. The strongest defense is therefore layered: technical controls should reduce the value of stolen credentials and block known malicious infrastructure, while administrative procedures should remove the attacker's ability to make an unusual request appear sufficient on its own. Project 1x00 already shows why this matters at MedDefense: identity controls are incomplete, endpoint coverage is uneven and physical-access controls are weak, so a successful human-vector attack could quickly become a broader technical compromise.
