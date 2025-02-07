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
<br>
Example in how SIEM will receive it:<br>
````
LEEF:2.0|HCL|AppScan|1.0|AppScan_Vulnerability|scanId=351aabc0-6794-4d16-9816-22e8c121f661	appName=teste123	scanName=SAST 2025-01-26 Allinone.zip	scanTech=StaticAnalyzer	scanCreatedBy=email@domain.com	scanProgress=Completed	executionId=12b5cade-45d4-48f8-b99c-7925a1e012fd	executionDurationInSec=18	infoIssues=0	issueType=Cross-Site Scripting	language=JAVASCRIPT	issueSeverity=High	issueLocation=Allinone.js:29	issueApi=Allinone.js:29	issueStatus=Open	issueSource=Bypass Security For Untrusted Items	issueSourceFile=Allinone.js	issueLine=29	issueScanner=AppScan Static Analyzer	issueCWE=79	issueVulnName=Bypass Security For Untrusted Items	issueId=32b3af21-3adc-ef11-88f6-000d3ae45b58	issueDateCreated=2025-01-26T23:06:20.117807Z	issueLastUpdated=2025-01-26T23:06:20.1178071Z	issueLastFound=2025-01-26T23:07:24.4251848Z	issueCallingMethod=null	issueLibraryName=null	issueLibraryVersion=null	issueScaTech=null	issueContext=sanitizer.bypassSecurityTrustHtml('<h1>DomSanitizer</h1><script>ourisSafeCode()	issueCveId=null	issueCvePublishDate=null	issueCvss=null	issueDiscMethod=SAST	issueDomain=null	issueElement=null	issueElementType=None	issueHost=null	issueTypeId=CrossSiteScripting	issuePath=null	devTime=2025-02-07T14:16:14.681Z	src=xfce-VirtualBox
````
<br>
````
CEF:0|AppScan|Security Scanner|1.0|CrossSiteScripting|Bypass Security For Untrusted Items|High|act=detected rt=2025-02-07T14:16:58.545Z src=xfce-VirtualBox cs1Label=Scan\ ID cs1=351aabc0-6794-4d16-9816-22e8c121f661 cs2Label=App\ Name cs2=teste123 cs3Label=Scan\ Name cs3=SAST 2025-01-26 Allinone.zip cs4Label=Scan\ Tech cs4=StaticAnalyzer cs5Label=Scan\ Created\ By cs5=email@domain.com cs6Label=Scan\ Progress cs6=Completed flexString1Label=Execution\ ID flexString1=12b5cade-45d4-48f8-b99c-7925a1e012fd flexNumber1Label=Execution\ Duration\ (sec) flexNumber1=18 cnt=0 cs7Label=Issue\ Type cs7=Cross-Site Scripting cs8Label=Language cs8=JAVASCRIPT cs9Label=Issue\ Location cs9=Allinone.js:29 cs10Label=API cs10=Allinone.js:29 cs11Label=Issue\ Status cs11=Open cs12Label=Source cs12=Bypass Security For Untrusted Items cs13Label=Source\ File cs13=Allinone.js cs14Label=Source\ Line cs14=29 cs15Label=Scanner cs15=AppScan Static Analyzer cs16Label=CWE cs16=79 cs17Label=Vulnerability\ Name cs17=Bypass Security For Untrusted Items cs18Label=Issue\ ID cs18=32b3af21-3adc-ef11-88f6-000d3ae45b58 cs19Label=Date\ Created cs19=2025-01-26T23:06:20.117807Z cs20Label=Last\ Updated cs20=2025-01-26T23:06:20.1178071Z cs21Label=Last\ Found cs21=2025-01-26T23:07:24.4251848Z cs22Label=Calling\ Method cs22=null cs23Label=Library\ Name cs23=null cs24Label=Library\ Version cs24=null cs25Label=SCA\ Tech cs25=null cs26Label=Context cs26=sanitizer.bypassSecurityTrustHtml('<h1>DomSanitizer</h1><script>ourisSafeCode() cs27Label=CVE\ ID cs27=null cs28Label=CVE\ Publish\ Date cs28=null cs29Label=CVSS\ Score cs29=null cs30Label=Discovery\ Method cs30=SAST cs31Label=Domain cs31=null cs32Label=Element cs32=null cs33Label=Element\ Type cs33=None cs34Label=Host cs34=null cs35Label=Path cs35=null
````
<br>
````
<134>1 2025-02-07T14:18:03.035Z xfce-VirtualBox AppScan - - [issue scanId="351aabc0-6794-4d16-9816-22e8c121f661" appName="teste123" scanName="SAST 2025-01-26 Allinone.zip" scanTech="StaticAnalyzer" scanCreatedBy="email@domain.com" scanProgress="Completed" executionId="12b5cade-45d4-48f8-b99c-7925a1e012fd" executionDurationInSec="18" infoIssues="0" issueType="Cross-Site Scripting" language="JAVASCRIPT" issueSeverity="High" issueLocation="Allinone.js:29" issueApi="Allinone.js:29" issueStatus="Open" issueSource="Bypass Security For Untrusted Items" issueSourceFile="Allinone.js" issueLine="29" issueScanner="AppScan Static Analyzer" issueCWE="79" issueVulnName="Bypass Security For Untrusted Items" issueId="32b3af21-3adc-ef11-88f6-000d3ae45b58" issueDateCreated="2025-01-26T23:06:20.117807Z" issueLastUpdated="2025-01-26T23:06:20.1178071Z" issueLastFound="2025-01-26T23:07:24.4251848Z" issueCallingMethod="null" issueLibraryName="null" issueLibraryVersion="null" issueScaTech="null" issueContext="sanitizer.bypassSecurityTrustHtml('<h1>DomSanitizer</h1><script>ourisSafeCode()" issueCveId="null" issueCvePublishDate="null" issueCvss="null" issueDiscMethod="SAST" issueDomain="null" issueElement="null" issueElementType="None" issueHost="null" issueTypeId="CrossSiteScripting" issuePath="null"]
````
