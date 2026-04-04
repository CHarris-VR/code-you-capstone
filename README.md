# Code:You Capstone Project
By Curtis Harris


# Log Analyzer Tool

### Overview

This tool was created to quickly analyze and find suspicious activity from a given log.txt file for quick and effective log analysis.
It works by separating various data from the sample_log.txt such as AUTH_SUCCESS and PRIV_CHANGE and will store the data to be pulled for later use in the summary.txt


## How to use this tool:

First you will need to have a file provided [here!](https://github.com/CHarris-VR/code-you-capstone/blob/main/sample_log.txt) or by clicking on the link above to the sample_log.txt

### IMPORTANT:
If you have compatibility issues, this code was created in Python 3.11.5 Try switching to this version of python when running the code to
ensure everything works properly.


## Log Source:

### sample_log.txt Overview:

This particular log contains various important information that can be used to quickly
find and summarize activities from various events. The dataset contains fields that can be
easily categorized into various parts such as:


- date time
- AUTH_SUCCESS
- PRIV_CHANGE
- user
- ip
- message


From there, the information is used to create a summary.txt file that can be shared for later analysis by other members
of the team working on the project.


## Detection Logic:


The logic uses counts to collect data based on lines of data like you would in a spreadsheet.
organizing the data to detect what ip has failed multiple times and how many to then store it as repeated failed logins.
From there, suspicious privilege escalation indicators are stored for things based on a criteria of keywords within the messages such as "admin", "root", "sudo", "elevated".
Suspicious IP behavior such as repeated failed logins have been added and logged from particular users to detect how often a user fails to log in on multiple occasions in the log.


## Findings:


With 970 Successful Authentications and 169 Failures, it was able to be determined that there were several suspicious privilege changes involving admin, root, jtoll, tbraxter, and jdoe.


Given the consistency of failures from the above-mentioned users having over 10 failed attempts each, accounts show indicators of compromise due to the volume of failed attempts mixed with the type of accounts involved and the privilege changes given by various users.


## Recommendations:


Rapid Response:
- Investigate IP's relevant to any privilege changes from suspicious users that had several account auth failure attempts
- Limit the number of failed attempts to log in before an account is locked out and needs to be reset by an admin to 4-5
- Create a policy to not allow certain users to use any privilege changes based on user account level.


Long-Term Remediation:
- Implement MFA for user access
- Review admin privilege changes
- implement better methods for logging massive amounts of data in case an incident like this occurs again.
- Think with the CIA Triad (Confidentiality, Integrity, Availability) in mind while reviewing options.
- Create important roles to deal with protection of data breach or admin account compromising
- Train all team members on phishing and proper methods of account access.
- Create lessons learned sessions to help better deal with a similar issue that may occur in the future.












