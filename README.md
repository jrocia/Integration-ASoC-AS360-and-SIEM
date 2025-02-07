# Integration ASoC/AS360 and SIEM tools
A Bash script that retrieves issues from ASoC or AS360, converts them into a specific format (LEEF, CEF or SYSLOG RFC5424), and sends them to a SIEM via Syslog.<br>
<br>
1 - Download the script file.<br>
2 - Fill in the variables at the beginning of the script.<br>
````
##########variables##########
asocApiKeyId='xxxxxxxxxxxxxxxxxxxxxxxxxx'
asocApiKeySecret='xxxxxxxxxxxxxxxxxxxxxxxxxx'
serviceUrl='cloud.appscan.com' # AS360 or ASoC url
syslogServer='10.10.10.10' # SIEM IP that will receive the messages
syslogPort='514'
messageFormat='LEEF' #i t could be LEEF, CEF or RFC5424
#############################
````
3 - Make the script executable. <br>
4 - Usage:<br>
````
./appscan_issues_syslog_forwarder.sh <start_date> <start_hour> <end_date> <end_hour>
````
Example:<br> 
````
./appscan_issues_syslog_forwarder.sh 2025-01-26 08 2025-01-27 18
````
5 - You can add it to your cron job to fetch issues daily or hourly.<br>
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
<br>
Example in how SIEM will receive it:<br>
````
LEEF:2.0|HCL|AppScan|1.0|AppScan_Vulnerability|scanId=351aabc0-6794-4d16-9816-22e8c121f661	appName=teste123	scanName=SAST 2025-01-26 Allinone.zip	scanTech=StaticAnalyzer	scanCreatedBy=email@domain.com	scanProgress=Completed	executionId=12b5cade-45d4-48f8-b99c-7925a1e012fd	executionDurationInSec=18	infoIssues=0	issueType=Cross-Site Scripting	language=JAVASCRIPT	issueSeverity=High	issueLocation=Allinone.js:29	issueApi=Allinone.js:29	issueStatus=Open	issueSource=Bypass Security For Untrusted Items	issueSourceFile=Allinone.js	issueLine=29	issueScanner=AppScan Static Analyzer	issueCWE=79	issueVulnName=Bypass Security For Untrusted Items	issueId=32b3af21-3adc-ef11-88f6-000d3ae45b58	issueDateCreated=2025-01-26T23:06:20.117807Z	issueLastUpdated=2025-01-26T23:06:20.1178071Z	issueLastFound=2025-01-26T23:07:24.4251848Z	issueCallingMethod=null	issueLibraryName=null	issueLibraryVersion=null	issueScaTech=null	issueContext=sanitizer.bypassSecurityTrustHtml('<h1>DomSanitizer</h1><script>ourisSafeCode()	issueCveId=null	issueCvePublishDate=null	issueCvss=null	issueDiscMethod=SAST	issueDomain=null	issueElement=null	issueElementType=None	issueHost=null	issueTypeId=CrossSiteScripting	issuePath=null	devTime=2025-02-07T14:16:14.681Z	src=xfce-VirtualBox
````
````
asdsadasd
````
