# Splunk SIEM Log Analysis Project

This project demonstrates how to upload and analyze logs using Splunk SIEM.

## Features
- Log ingestion
- Search & Reporting
- Alerting


## Tools Used
- Splunk Enterprise
- Windows Logs

## Steps
1. Install Splunk
2. Add data
3. Search logs using:
   ```spl
   index=main 

**Here, the main index is used because it is the default index in Splunk Enterprise. Splunk also provides an option to create separate custom indexes for organizing different types of log data.**

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 1. Bruteforce# Brute Force Detection Using Splunk ##

## Objective
Detect brute-force login attempts using Splunk SIEM by analyzing failed and successful login events.

## Queries Used

### Failed Login Attempts count by src_ip
```spl
index=main EventCode=4625 
| stats count by src_ip
```
- This query shows the count of failed login attempts based on source IP addresses.

### success Login Attempts count by src_ip
```spl
index=main EventCode=4624 
| stats count by src_ip
```
-This query shows the count of successful login attempts based on source IP addresses.


### Failed Login Attempts count by src_ip 
```spl
index=main status=failed user=administrator src_ip=45.67.210.12  OR index=main status=failed (src_ip=45.67.210.12 OR src_ip=77.120.10.88) 
```
-This query displays failed login events for the user administrator from the source IP address 45.67.210.12.

#### Main Brute Force Detection Alert Query
```spl
index=main status=failed
| bucket span=5m _time
| stats count by _time, user, src_ip
| where count > 5
```
-This alert detects more than 5 failed login attempts from the same source IP against a user within 5 minutes.

In the uploaded dataset, two suspicious IP addresses were identified performing multiple brute-force login attempts against user accounts.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 80)
-77.120.10.** (Count of failed attempts = 40)

## Findings

-Multiple failed login attempts were detected from suspicious IP addresses.
-Repeated authentication failures indicate brute-force attack behavior.
-Suspicious activity targeted user authentication services.

## conclusion 

-The investigation successfully identified brute-force attack attempts using Splunk SIEM. Detection queries and alert rules were created to monitor repeated failed authentication attempts   and suspicious login activity.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 2. Successful Brute Force Detection Using Splunk ##

## Objective
-The objective of this investigation is to detect successful brute-force login attacks using Splunk SIEM by identifying multiple failed login attempts followed by a successful   authentication event from the same source IP address.

---

## Investigation Overview
-Authentication logs were analyzed in Splunk to identify suspicious login activity. The investigation focused on detecting attackers attempting repeated password guessing attacks against  user accounts.

---

## Queries Used

### Failed Login Attempts

```spl
index=bruteforce EventCode=4625
```
-Displays all failed login events.

### Successful Login Attempts
```
index=bruteforce EventCode=4624
```
-Displays all successful login events.

### Failed Login Count by Source IP
```
index=bruteforce EventCode=4625
| stats count by src_ip
```
-Shows the number of failed login attempts from each source IP address.

### Successful Login Count by Source IP
```
index=bruteforce EventCode=4624
| stats count by src_ip
```
-Shows the number of successful login attempts from each source IP address.

### Investigation of Suspicious Source IP
```
index=bruteforce EventCode=4625 src_ip=45.67.210.12
```
-Displays failed login attempts originating from a suspicious IP address.

## Successful Brute Force Detection Query
```
index=bruteforce (EventCode=4624 OR EventCode=4625)
| transaction user src_ip maxspan=5m
| search EventCode=4624 EventCode=4625
| where eventcount > 5
```
-Detects multiple failed login attempts followed by a successful login from the same source IP and user within 5 minutes.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 133)
-77.120.10.** (Count of failed attempts = 139)

## Findings

-Multiple failed authentication attempts were detected from suspicious IP addresses.
-Successful authentication after repeated failures indicates possible account compromise.
-Brute-force attack behavior was successfully identified using Splunk SIEM.

## Conclusion

-The investigation successfully identified successful brute-force attack activity using Splunk SIEM using custom authentication logs and SPL queries.
