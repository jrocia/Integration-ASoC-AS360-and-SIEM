# Integration ASoC/AS360 and SIEM
A Bash script that retrieves issues from ASoC or AS360, converts them into a specific format, and sends them to a SIEM via Syslog.<br>
<br>
1 - Download the script file.<br>
2 - Fill in the variables at the beginning of the script.<br>
2 - Make the script executable. <br>
3 - Usage: appscan_issues_syslog_forwarder.sh <start_date> <start_hour> <end_date> <end_hour>. Example: .\appscan_issues_syslog_forwarder.sh 2025-01-26 08 2025-01-27 18"<br>
4 - You can add it to your cron job to fetch issues daily or hourly.<br>
<br>
##########variables##########<br>
asocApiKeyId='xxxxxxxxxxxxxxxxxxxxxxxxxx'<br>
asocApiKeySecret='xxxxxxxxxxxxxxxxxxxxxxxxxx'<br>
serviceUrl='cloud.appscan.com' # it could be as360 url<br>
syslogServer='10.10.10.10' # SIEM IP that will receive the messages<br>
syslogPort='514'<br>
messageFormat='LEEF' #i t could be LEEF, CEF or RFC5424<br>
#############################<br>
