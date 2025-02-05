#!/bin/bash
##########variables##########
asocApiKeyId='xxxxxxxxxxxxxxxxxxxxxxxxxx'
asocApiKeySecret='xxxxxxxxxxxxxxxxxxxxxxxxxx'
serviceUrl='cloud.appscan.com' # it could be as360 url
syslogServer='10.10.10.10' # SIEM IP that will receive the messages
syslogPort='514'
messageFormat='LEEF' #i t could be LEEF, CEF or RFC5424
#############################

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <start_date> <start_hour> <end_date> <end_hour>"
  echo "Example: $0 2025-01-26 08 2025-01-27 18"
  exit 1
fi

start_day=$1  # format: YYYY-MM-DD
start_hour=$2 # format: HH
end_day=$3    # format: YYYY-MM-DD
end_hour=$4   # formato: HH

start_date="${start_day}T${start_hour}:00:00.000Z"
end_date="${end_day}T${end_hour}:00:00.000Z"

asocToken=$(curl -k -s -X POST --header 'Content-Type:application/json' --header 'Accept:application/json' -d '{"KeyId":"'"$asocApiKeyId"'","KeySecret":"'"$asocApiKeySecret"'"}' "https://$serviceUrl/api/v4/Account/ApiKeyLogin" | grep -oP '(?<="Token":\ ")[^"]*')

if [ -z "$asocToken" ]; then
	echo "The token variable is empty. Check the authentication process.";
    exit 1
fi

scans=$(curl -k -s -X 'GET' -H 'accept:application/json' -H "Authorization:Bearer $asocToken" "https://$serviceUrl/api/v4/Scans?%24filter=%28%28LatestExecution%2FCreatedAt%20gt%20$start_date%20and%20LatestExecution%2FCreatedAt%20lt%20$end_date%29%29")

totalScans=$(echo "$scans" | jq '.Items | length')

for ((a=0; a<totalScans; a++)); do
    scanId=$(echo "$scans" | jq -r ".Items[$a].Id")
    appName=$(echo "$scans" | jq -r ".Items[$a].AppName")
    scanName=$(echo "$scans" | jq -r ".Items[$a].Name")
    scanTech=$(echo "$scans" | jq -r ".Items[$a].Technology")
    scanCreatedBy=$(echo "$scans" | jq -r ".Items[$a].CreatedBy.Email")
    scanLastModified=$(echo "$scans" | jq -r ".Items[$a].LastModified")
    scanProgress=$(echo "$scans" | jq -r ".Items[$a].LatestExecution.ExecutionProgress")

    executions=$(curl -k -s -X 'GET' "https://$serviceUrl/api/v4/Scans/$scanId/Executions" -H 'accept: application/json' -H "Authorization: Bearer $asocToken")
    totalExecutions=$(echo "$executions" | jq '. | length')

    for ((i=0; i<totalExecutions; i++)); do
        executionId=$(echo "$executions" | jq -r ".[$i].Id")
        executionDuration=$(echo "$executions" | jq -r ".[$i].ExecutionDurationSec")
        criticalIssues=$(echo "$executions" | jq -r ".[$i].NCriticalIssues")
        highIssues=$(echo "$executions" | jq -r ".[$i].NHighIssues")
        mediumIssues=$(echo "$executions" | jq -r ".[$i].NMediumIssues")
        lowIssues=$(echo "$executions" | jq -r ".[$i].NLowIssues")
        infoIssues=$(echo "$executions" | jq -r ".[$i].NInfoIssues")

        issues=$(curl -k -s -X 'GET' "https://$serviceUrl/api/v4/Issues/ScanExecution/$executionId" -H 'accept: application/json' -H "Authorization: Bearer $asocToken")
        totalIssues=$(echo "$issues" | jq '.Items | length')

        for ((f=0; f<totalIssues; f++)); do
            issueType=$(echo "$issues" | jq -r ".Items[$f].IssueType")
            codeLanguage=$(echo "$issues" | jq -r ".Items[$f].Language")
            issueSeverity=$(echo "$issues" | jq -r ".Items[$f].Severity")
            issueLocation=$(echo "$issues" | jq -r ".Items[$f].Location")
            issueApi=$(echo "$issues" | jq -r ".Items[$f].Api")
            issueStatus=$(echo "$issues" | jq -r ".Items[$f].Status")
            issueSource=$(echo "$issues" | jq -r ".Items[$f].Source")
            issueSourceFile=$(echo "$issues" | jq -r ".Items[$f].SourceFile")
            issueLine=$(echo "$issues" | jq -r ".Items[$f].Line")
            issueScanner=$(echo "$issues" | jq -r ".Items[$f].Scanner")
            issueCWE=$(echo "$issues" | jq -r ".Items[$f].Cwe")
            issueVulnName=$(echo "$issues" | jq -r ".Items[$f].ApiVulnName")
            issueId=$(echo "$issues" | jq -r ".Items[$f].Id")
            issueDateCreated=$(echo "$issues" | jq -r ".Items[$f].DateCreated")
            issueLastUpdated=$(echo "$issues" | jq -r ".Items[$f].LastUpdated")
            issueLastFound=$(echo "$issues" | jq -r ".Items[$f].LastFound")
            issueCallingMethod=$(echo "$issues" | jq -r ".Items[$f].CallingMethod")
            issueLibraryName=$(echo "$issues" | jq -r ".Items[$f].LibraryName")
            issueLibraryVersion=$(echo "$issues" | jq -r ".Items[$f].LibraryVersion")
            issueScaTech=$(echo "$issues" | jq -r ".Items[$f].ScaTechnology")
            issueContext=$(echo "$issues" | jq -r ".Items[$f].Context")
            issueCveId=$(echo "$issues" | jq -r ".Items[$f].CveId")
            issueCvePublishDate=$(echo "$issues" | jq -r ".Items[$f].CvePublishDate")
            issueCvss=$(echo "$issues" | jq -r ".Items[$f].Cvss")
            issueDiscMethod=$(echo "$issues" | jq -r ".Items[$f].DiscoveryMethod")
            issueDomain=$(echo "$issues" | jq -r ".Items[$f].Domain")
            issueElement=$(echo "$issues" | jq -r ".Items[$f].Element")
            issueElementType=$(echo "$issues" | jq -r ".Items[$f].ElementType")
            issueHost=$(echo "$issues" | jq -r ".Items[$f].Host")
            issueTypeId=$(echo "$issues" | jq -r ".Items[$f].IssueTypeId")
            issuePath=$(echo "$issues" | jq -r ".Items[$f].Path")
            issueScanName=$(echo "$issues" | jq -r ".Items[$f].ScanName")

            hostname=$(hostname)
            timestamp=$(date -u "+%Y-%m-%dT%H:%M:%S.%3NZ")

            if [ "$messageFormat" == "LEEF" ]; then
                syslog_message="LEEF:2.0|HCL|AppScan|1.0|AppScan_Vulnerability|scanId=$scanId	appName=$appName	scanName=$scanName	scanTech=$scanTech	scanCreatedBy=$scanCreatedBy	scanProgress=$scanProgress	executionId=$executionId	executionDurationInSec=$executionDuration	infoIssues=$infoIssues	issueType=$issueType	language=$codeLanguage	issueSeverity=$issueSeverity	issueLocation=$issueLocation	issueApi=$issueApi	issueStatus=$issueStatus	issueSource=$issueSource	issueSourceFile=$issueSourceFile	issueLine=$issueLine	issueScanner=$issueScanner	issueCWE=$issueCWE	issueVulnName=$issueVulnName	issueId=$issueId	issueDateCreated=$issueDateCreated	issueLastUpdated=$issueLastUpdated	issueLastFound=$issueLastFound	issueCallingMethod=$issueCallingMethod	issueLibraryName=$issueLibraryName	issueLibraryVersion=$issueLibraryVersion	issueScaTech=$issueScaTech	issueContext=$issueContext	issueCveId=$issueCveId	issueCvePublishDate=$issueCvePublishDate	issueCvss=$issueCvss	issueDiscMethod=$issueDiscMethod	issueDomain=$issueDomain	issueElement=$issueElement	issueElementType=$issueElementType	issueHost=$issueHost	issueTypeId=$issueTypeId	issuePath=$issuePath	devTime=$timestamp	src=$hostname"            
                echo "$syslog_message"
                echo "$syslog_message" | nc -u -w 1 "$syslogServer" "$syslogPort"
            elif [ "$messageFormat" == "RFC5424" ]; then
                syslog_message="<134>1 $timestamp $hostname AppScan - - [issue scanId=\"$scanId\" appName=\"$appName\" scanName=\"$scanName\" scanTech=\"$scanTech\" scanCreatedBy=\"$scanCreatedBy\" scanProgress=\"$scanProgress\" executionId=\"$executionId\" executionDurationInSec=\"$executionDuration\" infoIssues=\"$infoIssues\" issueType=\"$issueType\" language=\"$codeLanguage\" issueSeverity=\"$issueSeverity\" issueLocation=\"$issueLocation\" issueApi=\"$issueApi\" issueStatus=\"$issueStatus\" issueSource=\"$issueSource\" issueSourceFile=\"$issueSourceFile\" issueLine=\"$issueLine\" issueScanner=\"$issueScanner\" issueCWE=\"$issueCWE\" issueVulnName=\"$issueVulnName\" issueId=\"$issueId\" issueDateCreated=\"$issueDateCreated\" issueLastUpdated=\"$issueLastUpdated\" issueLastFound=\"$issueLastFound\" issueCallingMethod=\"$issueCallingMethod\" issueLibraryName=\"$issueLibraryName\" issueLibraryVersion=\"$issueLibraryVersion\" issueScaTech=\"$issueScaTech\" issueContext=\"$issueContext\" issueCveId=\"$issueCveId\" issueCvePublishDate=\"$issueCvePublishDate\" issueCvss=\"$issueCvss\" issueDiscMethod=\"$issueDiscMethod\" issueDomain=\"$issueDomain\" issueElement=\"$issueElement\" issueElementType=\"$issueElementType\" issueHost=\"$issueHost\" issueTypeId=\"$issueTypeId\" issuePath=\"$issuePath\"]"
                echo "$syslog_message"
                echo "$syslog_message" | nc -u -w 1 "$syslogServer" "$syslogPort"
            elif [ "$messageFormat" == "CEF" ]; then
                syslog_message="CEF:0|AppScan|Security Scanner|1.0|$issueTypeId|$issueVulnName|$issueSeverity|act=detected rt=$timestamp src=$hostname cs1Label=Scan\ ID cs1=$scanId cs2Label=App\ Name cs2=$appName cs3Label=Scan\ Name cs3=$scanName cs4Label=Scan\ Tech cs4=$scanTech cs5Label=Scan\ Created\ By cs5=$scanCreatedBy cs6Label=Scan\ Progress cs6=$scanProgress flexString1Label=Execution\ ID flexString1=$executionId flexNumber1Label=Execution\ Duration\ (sec) flexNumber1=$executionDuration cnt=$infoIssues cs7Label=Issue\ Type cs7=$issueType cs8Label=Language cs8=$codeLanguage cs9Label=Issue\ Location cs9=$issueLocation cs10Label=API cs10=$issueApi cs11Label=Issue\ Status cs11=$issueStatus cs12Label=Source cs12=$issueSource cs13Label=Source\ File cs13=$issueSourceFile cs14Label=Source\ Line cs14=$issueLine cs15Label=Scanner cs15=$issueScanner cs16Label=CWE cs16=$issueCWE cs17Label=Vulnerability\ Name cs17=$issueVulnName cs18Label=Issue\ ID cs18=$issueId cs19Label=Date\ Created cs19=$issueDateCreated cs20Label=Last\ Updated cs20=$issueLastUpdated cs21Label=Last\ Found cs21=$issueLastFound cs22Label=Calling\ Method cs22=$issueCallingMethod cs23Label=Library\ Name cs23=$issueLibraryName cs24Label=Library\ Version cs24=$issueLibraryVersion cs25Label=SCA\ Tech cs25=$issueScaTech cs26Label=Context cs26=$issueContext cs27Label=CVE\ ID cs27=$issueCveId cs28Label=CVE\ Publish\ Date cs28=$issueCvePublishDate cs29Label=CVSS\ Score cs29=$issueCvss cs30Label=Discovery\ Method cs30=$issueDiscMethod cs31Label=Domain cs31=$issueDomain cs32Label=Element cs32=$issueElement cs33Label=Element\ Type cs33=$issueElementType cs34Label=Host cs34=$issueHost cs35Label=Path cs35=$issuePath"
                echo "$syslog_message"
                echo "$syslog_message" | nc -u -w 1 "$syslogServer" "$syslogPort"
            else
                echo "Message format not specified. It must be LEEF or RFC5424."
                exit 1
            fi
        done
    done
done
curl -k -s -X 'GET' "https://$serviceUrl/api/v4/Account/Logout" -H 'accept: */*' -H "Authorization: Bearer $asocToken"
