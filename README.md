# Integration ASoC/AS360 and SIEM tools
A Bash script that retrieves issues from ASoC or AS360, converts them into a specific format (LEEF, CEF or SYSLOG RFC5424), and sends them to a SIEM via Syslog.<br>
<br>
1 - Download the script file.<br>
2 - Fill in the variables at the beginning of the script.<br>
3 - Make the script executable. <br>
4 - Usage:<br>
./appscan_issues_syslog_forwarder.sh <start_date> <start_hour> <end_date> <end_hour><br>
Example:<br> 
./appscan_issues_syslog_forwarder.sh 2025-01-26 08 2025-01-27 18<br>
5 - You can add it to your cron job to fetch issues daily or hourly.<br>
<br>
##########variables##########<br>
asocApiKeyId='xxxxxxxxxxxxxxxxxxxxxxxxxx'<br>
asocApiKeySecret='xxxxxxxxxxxxxxxxxxxxxxxxxx'<br>
serviceUrl='cloud.appscan.com' # AS360 or ASoC url<br>
syslogServer='10.10.10.10' # SIEM IP that will receive the messages<br>
syslogPort='514'<br>
messageFormat='LEEF' #i t could be LEEF, CEF or RFC5424<br>
#############################<br>
<br>
After the script is configured to send logs to the SIEM:<br>
1 - Verify Log Ingestion<br>
Check if logs are arriving as expected using SIEM’s built-in log viewer or a search query.<br>
Validate timestamp accuracy and log integrity.<br>
2 - Normalize and Parse Logs<br>
Map log fields to your SIEM’s schema.<br>
Convert raw logs into structured data for easier analysis.<br>
3 - Create and Tune Correlation Rules<br>
Set up rules to detect security threats or anomalies.<br>
<br>
Use cases example: <br>
USE CASE DAST - Correlate WAF/IPS events with URL vulnerables.<br>
USE CASE DAST - Generate offenses when vulnerabilities with CVSS greater than 9.<br>
USE CASE SAST - Check Reference Set list by API Blacklisted.<br>
USE CASE SAST/DAST/SCA – Alert in case New Issues.<br>
