# Windows-Event-Log-Analysis-with-Splunk

## Objective

This project involved importing Windows Security Event Logs into Splunk to analyze authentication activity and identify abnormal login behavior. The goal was to gain hands-on experience with Windows log analysis, Splunk searching, event correlation, and brute-force detection using Event ID 4624 and Event ID 4625.

### Skills Learned

- Imported Windows Security Event Logs into Splunk for centralized log analysis.
- Analyzed Windows authentication activity using Event ID 4624 and Event ID 4625.
- Identified successful logons, failed logons, and abnormal authentication patterns.
- Used Splunk SPL searches to filter and investigate Windows Security Events.
- Improved understanding of Windows Security Logs, SIEM analysis, and authentication monitoring.

### Tools Used

- Windows Event Viewer — Used to inspect local Windows Security Event Logs.
- Windows Security Logs — Used as the main log source for authentication activity.
- Splunk — Used as the SIEM platform to import, search, and analyze Windows logs.
- SPL — Used to write searches for successful logons, failed logons, and suspicious authentication patterns.
- Windows Host/VM — Used to generate authentication events for analysis.

# Windows-Event-Log-Analysis-with-Splunk

> **Disclaimer:** This lab was originally completed in March. My Splunk Enterprise Trial license has since expired, so I am currently unable to access the original Splunk environment to capture additional screenshots. Because of this, the screenshots included are limited to the ones I took while recreating this write-up.

## Steps

1: Windows Log Activity Generation

Generated Windows authentication activity by logging into the Windows system and attempting failed logins. This created both successful and failed authentication events that could be reviewed in Windows Event Viewer and later analyzed in Splunk.

2: Windows Event Viewer Review

Opened Windows Event Viewer and navigated to the Security logs. Reviewed authentication-related events to confirm that Windows was recording successful and failed login activity.

3: Event ID 4624, 4625 Identification

Located Event ID 4624 and 4625 in the Security logs. Event ID 4624 represents a successful logon attempts while Event ID 4625 represents a failed logon.

<img width="1920" height="1009" alt="Event Viewer 4_28_2026 7_38_40 PM" src="https://github.com/user-attachments/assets/6c83e3a8-01b5-4a72-8a60-77ffdcbfa646" />



4: Windows Security Log Export

Exported Windows Security Event Logs from Event Viewer so they could be imported into Splunk for centralized analysis.

5: Splunk Log Import

Imported the Windows Security Event Logs into Splunk. This allowed the authentication events to be searched, filtered, and analyzed using SPL queries.

<img width="1920" height="1032" alt="Add Data - Select Source _ Splunk 10 2 0 - Google Chrome 4_28_2026 12_52_18 AM" src="https://github.com/user-attachments/assets/2db98cf2-9fe7-4dbe-8774-d9b13f1f8d3f" />


6: Basic Authentication Event Search

Used Splunk to search for both successful and failed login events.

index=* (EventCode=4624 OR EventCode=4625)



This query returned Windows authentication events related to both successful and failed logon activity.

7: Successful Logon Analysis

Used SPL to analyze successful login activity from Event ID 4624.

index=* EventCode=4624
| table _time, Account_Name, Logon_Type, Source_Network_Address, ComputerName

This helped identify which users logged in, when they logged in, the logon type, source address, and host involved.

8: Failed Logon Analysis

Used SPL to analyze failed login attempts from Event ID 4625.

index=* EventCode=4625
| table _time, Account_Name, Failure_Reason, Source_Network_Address, ComputerName

This helped identify failed authentication attempts, affected usernames, failure reasons, source IP addresses, and hostnames.

9: Brute-Force Pattern Detection

Created an SPL search to identify repeated failed login attempts.

index=* EventCode=4625
| stats count by Account_Name, Source_Network_Address, ComputerName
| where count >= 5
| sort - count

This query helped identify accounts or source addresses with multiple failed login attempts, which may indicate brute-force activity.

9: Failed and Successful Login Correlation

Correlated failed and successful logon events to identify possible successful authentication after repeated failures.

index=* (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as failed_logins count(eval(EventCode=4624)) as successful_logins by Account_Name, Source_Network_Address, ComputerName
| where failed_logins >= 5 AND successful_logins >= 1

This helped identify suspicious behavior where an account had multiple failed logins followed by a successful login.

10: Field Correlation

Reviewed key fields such as username, timestamp, source IP address, hostname, and logon type. These fields were used to understand who attempted to log in, when the activity occurred, where it came from, and whether the authentication attempt succeeded or failed.

11: Suspicious Activity Review

Reviewed the results for abnormal authentication patterns, including repeated failed logins, unusual source addresses, and successful logins after failed attempts.
