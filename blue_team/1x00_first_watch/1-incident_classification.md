# Incident Classification

The six incidents from Marcus's log are classified below using the CIA Triad: Confidentiality, Integrity and Availability.

| Incident | CIA Classification | Analysis |
|---|---|---|
| **A — January 15** | **Primary:** Availability<br>**Secondary:** Integrity | **Availability:** The ransomware encrypted `billing-srv-01`, preventing the finance team from processing insurance claims for four days.<br><br>**Integrity:** The ransomware also modified the server's data through unauthorized encryption, while the three-week-old backup limited recovery of current data. |
| **B — February 2** | **Primary:** Confidentiality<br>**Secondary:** None identified | **Confidentiality:** The broken access control allowed authenticated patients to view other patients' lab results by changing a URL parameter.<br><br>No modification of records or service outage was reported. |
| **C — March 18** | **Primary:** Integrity<br>**Secondary:** None identified | **Integrity:** A faulty database update script overwrote medication dosage values, causing the pharmacy system to display incorrect information for approximately six hours.<br><br>The system remained accessible, and no unauthorized disclosure was reported. |
| **D — April 5** | **Primary:** Integrity<br>**Secondary:** Availability | **Integrity:** The public website was altered without authorization when its homepage was replaced with a political message.<br><br>**Availability:** The legitimate website content was unavailable until the site was restored from backup within two hours. |
| **E — May 22** | **Primary:** Availability<br>**Secondary:** None identified | **Availability:** The EHR system was inaccessible for nine hours during the database migration, forcing physicians to use paper records.<br><br>No alteration or disclosure of EHR data was reported. |
| **F — June 10** | **Primary:** Confidentiality<br>**Secondary:** None confirmed | **Confidentiality:** An unmanaged personal laptop running file-sharing software was connected to the internal network on the same segment as the HR file share, creating exposure of sensitive internal data to an unauthorized endpoint.<br><br>The log does not confirm that HR files were actually accessed, modified or disclosed, so no secondary CIA impact can be confirmed. |
