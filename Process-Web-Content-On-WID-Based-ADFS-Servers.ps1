### Abstract: This PoSH Script Configures Web Content On All WID Based ADFS Servers Due To The Replication Of Web Content Bug In Windows Server 2012 R2 ADFS
### Written by: Jorge de Almeida Pinto [MVP-Enterprise Mobility And Security (EMS)]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2016-07-17: Initial version of the script (v0.1)
### 2016-07-18: Implemented custom event log 'Custom - Support' to log all custom messages and fixed a bug when
###				comparing windows version Numbers, added a check to see if user is running with admin privileges (v0.2)
### 2016-07-19: Added the option to target a list of command line specified ADFS servers (v0.3)
###

<#
.SYNOPSIS
	This PoSH Script Configures Web Content On All WID Based ADFS Servers Due To The Replication Of Web Content Bug
	In Windows Server 2012 R2 ADFS

.DESCRIPTION
	This PoSH script reads the XML configuration file to determine all ADFS servers and to determine which ADFS
	server hosts the primary role and which ADFS servers host the secondary role.
	It first targets the server configured as primary, checks if it is indeed the primary and execute the PowerShell
	commands to configure the web content.
	It moves on to the next secondary ADFS server, checks it is indeed a secondary server, checks which ADFS server
	is the primary and checks if that matches the XML configuration file and executes the PowerShell commands to
	configure the web content.
	NOT specifying a list of ADFS servers through the command line is when a new change must be committed on all ADFS servers
	Specifying a list of ADFS servers through the command line is when existing changes must be committed on new ADFS servers

.PARAMETER adfsServers
	When this parameter is specified, the XML config file is NOT read and a separated list of FQDNs must be specified through this
	parameter listing the ADFS servers that must be targeted. This may for example be used when you have just one or more new
	secondary ADFS server to update after those have been installed in addition to the existing ones.
	However, if you have a new configuration that must be applied to all ADFS servers, you may still use this parameter, but you
	can also create an XML file that contains all ADFS servers. This can be handy when you must apply changes to all existing ADFS
	servers. When you want to use the XML config file, do not use this parameter and the script will look for the XML config file
	which must be in the same folder as the script itself. By default the script will look for the XML file! It will abort if it
	does not find the XML config file!

	EXAMPLE Contents of “ADFS-STS-SCRIPT-CONFIG.XML”
	<?xml version="1.0" encoding="utf-8"?>
	<adfsScriptConfig xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<adfsServers>
			<adfsServer serverName="R1FSRWDC1.IAMTEC.NET" />
			<adfsServer serverName="R1FSRWDC2.IAMTEC.NET" />
			<adfsServer serverName="R1FSRWDC3.IAMTEC.NET" />
			<adfsServer serverName="R1FSRWDC4.IAMTEC.NET" />
		</adfsServers>
	</adfsScriptConfig>

.PARAMETER scriptBlock
	With this parameter one PowerShell command can be specified as a value for this parameter. Pay very special attention to the
	quotes used!
	Example value: "Set-AdfsRelyingPartyWebContent -Name 'SALESFORCE dot COM' -ErrorPageAuthorizationErrorMessage `"<B><Font size='4' color='red'>Authorization Has Been Denied For 'SALESFORCE.COM'.</Font></B><BR><BR>You Either Do Not Have The Correct Authorization Or You Have Been Assigned More Than One Profile ID.<BR><BR>Please Contact <A HREF='mailto:ADM.ROOT@IAMTEC.NL?subject=Access Request For Application &#39;SALESFORCE.COM&#39;'>ADM.ROOT</A> To Resolve This If You Require Access.`""

.PARAMETER scriptFile
	With this parameter one or more PowerShell commands can be specified in a text file. The complete path of the text is then used
	as a value for this parameter.
	Example value: "C:\TEMP\ScriptBlock.txt"

.PARAMETER showScriptOutput
	This parameter tells the script to display the output of the commands on screen, if there is anything to display
	at all.
	
.EXAMPLE
	Configure ADFS Web Content By Using A Scriptblock On ADFS Servers Listed In The XML Config File
	(Please pay special attention to how the quotes are used!)
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -scriptBlock "Set-AdfsAuthenticationProviderWebContent -Name AzureMfaServerAuthentication -DisplayName 'Azure AD MFA AuthN'"

.EXAMPLE
	Configure ADFS Web Content By Using A Scriptblock On ADFS Servers Listed In The XML Config File And Display Any Output On Screen For The Commands Processed
	(Please pay special attention to how the quotes are used!)
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -scriptBlock "Set-AdfsAuthenticationProviderWebContent -Name AzureMfaServerAuthentication -DisplayName 'Azure AD MFA AuthN'" -showScriptOutput

.EXAMPLE
	Configure ADFS Web Content By Using A Scriptblock On ADFS Servers Specified Throught The Command Line
	(Please pay special attention to how the quotes are used!)
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -adfsServers ADFS3.COMPANY.COM,ADFS4.COMPANY.COM -scriptBlock "Set-AdfsAuthenticationProviderWebContent -Name AzureMfaServerAuthentication -DisplayName 'Azure AD MFA AuthN'"

.EXAMPLE
	Configure ADFS Web Content By Using A Scriptblock On ADFS Servers Specified Throught The Command Line And Display Any Output On Screen For The Commands Processed
	(Please pay special attention to how the quotes are used!)
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -adfsServers ADFS3.COMPANY.COM,ADFS4.COMPANY.COM -scriptBlock "Set-AdfsAuthenticationProviderWebContent -Name AzureMfaServerAuthentication -DisplayName 'Azure AD MFA AuthN'" -showScriptOutput
	
.EXAMPLE
	Configure ADFS Web Content By Using A Scriptblock And Display Any Output On Screen For The Commands Processed
	(Please pay special attention to how the quotes are used!)
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -scriptBlock "Set-AdfsRelyingPartyWebContent -Name 'SALESFORCE dot COM' -ErrorPageAuthorizationErrorMessage `"<B><Font size='4' color='red'>Authorization Has Been Denied For 'SALESFORCE.COM'.</Font></B><BR><BR>You Either Do Not Have The Correct Authorization Or You Have Been Assigned More Than One Profile ID.<BR><BR>Please Contact <A HREF='mailto:ADM.ROOT@IAMTEC.NL?subject=Access Request For Application &#39;SALESFORCE.COM&#39;'>ADM.ROOT</A> To Resolve This If You Require Access.`""
	
.EXAMPLE
	Configure ADFS Web Content By Using A Text File With A Script Block
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -scriptFile "C:\TEMP\ScriptBlock.txt"

.EXAMPLE
	Configure ADFS Web Content By Using A Text File With A Script Block And Display Any Output On Screen For The
	Commands Processed
	
	Process-Web-Content-On-WID-Based-ADFS-Servers.ps1 -scriptFile "C:\TEMP\ScriptBlock.txt" -showScriptOutput
	
.NOTES
	This script requires administrator equivalent permissions on every local ADFS server.
	When quotes are part of the commands, please pay special attention when and which quotes you use (", ', `)
	
	Example Content For "C:\TEMP\ScriptBlock.txt" (between the lines ############)
	
	############
	Import-Module ADFS

	Set-AdfsRelyingPartyWebContent -Name 'SALESFORCE.COM' -ErrorPageAuthorizationErrorMessage "<B><Font size='4' color='red'>Authorization Has Been Denied For 'SALESFORCE.COM'.</Font></B><BR><BR>You Either Do Not Have The Correct Authorization Or You Have Been Assigned More Than One Profile ID.<BR><BR>Please Contact <A HREF='mailto:ADM.ROOT@IAMTEC.NL?subject=Access Request For Application &#39;SALESFORCE.COM&#39;'>ADM.ROOT</A> To Resolve This If You Require Access."

	Get-AdfsRelyingPartyWebContent

	Set-AdfsAuthenticationProviderWebContent -Name AzureMfaServerAuthentication -DisplayName 'Azure AD MFA AuthN' -Description 'Azure AD MFA Based Upon SMS, Phone Call Or Authenticator App'

	Set-AdfsAuthenticationProviderWebContent -Name 'Zetetic SMS' -DisplayName 'Zetetic SMS PIN AuthN' -Description 'SMS PIN Authentication By Zetetic'

	Set-AdfsAuthenticationProviderWebContent -Name 'Zetetic TOTP' -DisplayName 'Zetetic Software OTP AuthN' -Description 'Software Based OTP Authentication By Zetetic'

	Set-AdfsAuthenticationProviderWebContent -Name 'Zetetic Voice' -DisplayName 'Zetetic Phone Call AuthN' -Description 'Phone Call Authentication By Zetetic'

	Get-AdfsAuthenticationProviderWebContent
	############
#>

Param (
	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify a comma separated list of WID based ADFS server to target.')]
	[string[]]$adfsServers,

	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the command to process against the targeted ADFS servers.')]
	[string]$scriptBlock,
	
	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the path to the text file that contains all the commands to process against the targeted ADFS servers.')]
	[string]$scriptFile,

	[switch]$showScriptOutput
)

### FUNCTION: Test The Port Connection
Function PortConnectionCheck($fqdnServer,$port,$timeOut) {
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer,$port,$null,$null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		#$error.Clear()
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Write Event Log Of Specified Server
Function writeToEventLog($server,$eventLog,$eventSource,$eventID,$eventMessage,$eventType) {
	If (!([System.Diagnostics.EventLog]::SourceExists($eventSource, $server))) {
		New-EventLog -ComputerName $server -logname $eventLog -Source $eventSource
	}
	Write-EventLog -ComputerName $server -LogName $eventLog -Source $eventSource -EventID $eventID -Message $eventMessage -EntryType $eventType
}

### FUNCTION: Test Credentials For Admin Privileges
Function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ PROCESS WEB CONTENT ON WID BASED ADFS SERVERS +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 140
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 140) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 140
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

Write-Host ""
Write-Host "**********************************************************" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "*  --> Process Web Content On WID Based ADFS Servers <-- *" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "*      Written By: Jorge de Almeida Pinto [MVP-EMS]      *" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "**********************************************************" -ForeGroundColor Cyan
Write-Host ""

If (!(Test-Admin)) {
	Write-Host ""
	Write-Host "WARNING: Your User Account Is Either Not Running With Or Local Administrator Equivalent Permissions Have Not Been Assigned!..." -ForeGroundColor Red
	Write-Host "For This Script To Run Successfully, Local Administrator Equivalent Permissions Are Required..."  -ForegroundColor Red
	Write-Host "Aborting Script..."
	Write-Host ""
	EXIT
}

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeDisplay = Get-Date $execDateTime -f "yyyy-MM-dd HH:mm:ss"
$runningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$cmdLineUsed = $MyInvocation.Line
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
$fqdnDomainName = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$fqdnLocalComputer = $localComputerName + "." + $fqdnDomainName

### Logging Who Started The Script
$server = $fqdnLocalComputer
$eventLog = "Custom - Support"
$eventSource = "ADFS Support"
$eventID = "9999"
$eventMessage = "The user '$runningUserAccount' executed the script:`n`n'$cmdLineUsed'..."
$eventType = "Information"
writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType

### Get The Config File
[string]$scriptXMLConfigFilePath = Join-Path $currentScriptFolderPath "ADFS-STS-SCRIPT-CONFIG.XML"
If (!(Test-Path $scriptXMLConfigFilePath)) {
    Write-Host "The XML Config File '$scriptXMLConfigFilePath' CANNOT Be Found!..." -ForeGroundColor Red
    Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""
    EXIT    
} Else {
    [XML] $global:configInXMLFile = Get-Content $scriptXMLConfigFilePath
    Write-Host "The XML Config File '$scriptXMLConfigFilePath' Has Been Found!..." -ForeGroundColor Green
    Write-Host "Continuing Script..." -ForeGroundColor Green
    Write-Host ""
}

### Get The List Of The Targeted ADFS Servers, Either From The Command Line Or From The XML Config File
If ($adfsServers) {
	$adfsServerFQDNs = $adfsServers
} Else {
	$adfsServerFQDNs = $configInXMLFile.adfsScriptConfig.adfsServers.adfsServer.serverName
}

Write-Host "Execution Date And Time.............: $execDateTimeDisplay" -ForegroundColor Yellow
Write-Host "Running User Account................: $runningUserAccount" -ForegroundColor Yellow
Write-Host "XML Config File.....................: '$scriptXMLConfigFilePath'" -ForeGroundColor Yellow
Write-Host ""
Write-Host "Command Line Used...................: $cmdLineUsed" -ForegroundColor Yellow
Write-Host ""

$srv = 1
$adfsServerFQDNs | %{
	Write-Host "ADFS Server ($srv).....................: '$($_.ToUpper())'" -ForegroundColor Yello
	$srv += 1
}

If (!$adfsServers) {
	Write-Host ""
	Write-Host "Make Sure The XML Config File Lists ALL ADFS Servers!..." -ForeGroundColor Yellow
	Write-Host ""
	Write-Host "Explanations:" -ForeGroundColor Cyan
	Write-Host " >>> Responding 'YES' Or 'Y' Allows The Script To Continue..." -ForeGroundColor Cyan
	Write-Host " >>> Responding 'NO' Or 'N' Allows The Script To Abort..." -ForeGroundColor Cyan
	Write-Host " >>> Responding 'OPEN' Or 'O' Allows The Script To Open The XML Config File For Checking And Editing..." -ForeGroundColor Cyan
	Write-Host " >>> Responding 'REREAD' Or 'R' Allows The Script To Reread The XML Config File To Process Any Changes..." -ForeGroundColor Cyan
	$action = "DO_NOT_CONTINUE"

	Do {
		Write-Host ""
		$response = $null
		$response = Read-Host "Does The XML Config File Have ALL ADFS Servers Listed?...[YES|NO|OPEN|REREAD]"
		If ($response.ToUpper() -eq "YES" -Or $response.ToUpper() -eq "Y") {
			Write-Host "Continuing Script..." -ForeGroundColor Green
			Write-Host ""
			$action = "CONTINUE"
		}
		If ($response.ToUpper() -eq "NO" -Or $response.ToUpper() -eq "N") {
			Write-Host "Aborting Script..." -ForeGroundColor Red
			Write-Host ""
			EXIT
		}
		If ($response.ToUpper() -eq "OPEN" -Or $response.ToUpper() -eq "O") {
			Start-Process C:\Windows\System32\Notepad.exe -ArgumentList $scriptXMLConfigFilePath
		}
		If ($response.ToUpper() -eq "REREAD" -Or $response.ToUpper() -eq "R") {
			[XML] $global:configInXMLFile = Get-Content $scriptXMLConfigFilePath
			$adfsServerFQDNs = $configInXMLFile.adfsScriptConfig.adfsServers.adfsServer.serverName
			$srv = 1
			$adfsServerFQDNs | %{
				Write-Host "ADFS Server ($srv).....................: '$($_.ToUpper())'" -ForegroundColor Yello
				$srv += 1
			}
		}
	} While ($action -ne "CONTINUE")
}

### Logging The Server List That Will Be Used
$server = $fqdnLocalComputer
$eventLog = "Custom - Support"
$eventSource = "ADFS Support"
$eventID = "9100"
$eventMessage = "The user '$runningUserAccount' accepted the following ADFS server list to be processed:`n`n$adfsServerFQDNs"
$eventType = "Information"
writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType

### Get The ScriptBlock From The Parameter Or The Text File
If ($scriptBlock) {
	$commandsToExecute = $scriptBlock | Out-String
}
If ($scriptFile) {
	$commandsToExecute = Get-Content $scriptFile | Out-String
}
If (!$scriptBlock -And !$scriptFile -And !$commandsToExecute) {
	Write-Host ""
	Write-Host "No Command Was Specified To Process..." -ForeGroundColor Red
	Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""
	EXIT
}
$server = $fqdnLocalComputer
$eventLog = "Custom - Support"
$eventSource = "ADFS Support"
$eventID = "9110"
$eventMessage = "The script will execute using the following commands:`n`n$commandsToExecute"
$eventType = "Information"
writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType

### Checking Local Server Is An ADFS Server
Write-Host ""
Write-Host "--------------------------------------------------------------------------------------------" -ForeGroundColor DarkCyan
Write-Host "+++ CHECKING LOCAL SERVER IS AN ADFS SERVER +++"  -ForegroundColor Cyan
Write-Host ""

$windowsVersion = (Get-WmiObject Win32_OperatingSystem).Version
$windowsBuildNumber = (Get-WmiObject Win32_OperatingSystem).BuildNumber

If ([decimal]$($windowsVersion.SubString(0, $windowsVersion.Length - $windowsBuildNumber.Length - 1)) -eq "6.3") {
	Write-Host "The Local Computer '$fqdnLocalComputer' IS Running Windows Server 2012 R2..." -ForeGroundColor Green
	Write-Host "Continuing Script..." -ForeGroundColor Green
	Write-Host ""
	

	$adfsSvc = $null
	$adfsSvc = Get-WmiObject Win32_service -Filter "Name='ADFSSRV'"
	If ($adfsSvc) {
		$adfsSvcMode = $adfsSvc.StartMode
		$adfsSvcState = $adfsSvc.State
	}

	If ($adfsSvc -And $adfsSvcMode.ToUpper() -eq "AUTO" -And $adfsSvcState.ToUpper() -eq "RUNNING") {
		Write-Host "The Local Computer '$fqdnLocalComputer' IS An ADFS Server..." -ForeGroundColor Green
		Write-Host "Continuing Script..." -ForeGroundColor Green
		
		$server = $fqdnLocalComputer
		$eventLog = "Custom - Support"
		$eventSource = "ADFS Support"
		$eventID = "9120"
		$eventMessage = "The Local Computer '$fqdnLocalComputer' IS An ADFS Server Running Windows Server 2012 R2...`n`nContinuing Script..."
		$eventType = "Information"
		writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
	} Else {
		Write-Host "The Local Computer '$fqdnLocalComputer' IS NOT An ADFS Server..." -ForeGroundColor Red
		Write-Host "This Script Must Be Executed On An ADFS Server!..." -ForeGroundColor Red
		Write-Host "Aborting Script..." -ForeGroundColor Red
		Write-Host ""
		
		$server = $fqdnLocalComputer
		$eventLog = "Application"
		$eventSource = "ADFS Support"
		$eventID = "9121"
		$eventMessage = "The Local Computer '$fqdnLocalComputer' IS NOT An ADFS Server...`nAborting Script..."
		$eventType = "Error"
		writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType

		EXIT
	}
} Else {
	Write-Host "The Local Computer '$fqdnLocalComputer' IS NOT Running Windows Server 2012 R2..." -ForeGroundColor Red
	Write-Host "This Script Must Be Executed On An ADFS Server Running Windows Server 2012 R2!..." -ForeGroundColor Red
	Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""

	$server = $fqdnLocalComputer
	$eventLog = "Application"
	$eventSource = "ADFS Support"
	$eventID = "9122"
	$eventMessage = "The Local Computer '$fqdnLocalComputer' IS NOT Running Windows Server 2012 R2...`nAborting Script..."
	$eventType = "Error"
	writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType

	EXIT
}

### Checking The Local ADFS Server Is Leveraging WID As A Database
Write-Host ""
Write-Host "--------------------------------------------------------------------------------------------" -ForeGroundColor DarkCyan
Write-Host "+++ CHECKING THE LOCAL ADFS SERVER IS LEVERAGING WID AS A DATABASE +++"  -ForegroundColor Cyan
Write-Host ""

$fedSvcSTS = $null
$fedSvcSTS = Get-WmiObject -ComputerName $fqdnLocalComputer -namespace root/ADFS -class SecurityTokenService
$fedSvcSTSConfigDBConnectionString = $null
[string]$fedSvcSTSConfigDBConnectionString = $fedSvcSTS.ConfigurationdatabaseConnectionstring
If ($fedSvcSTSConfigDBConnectionString.contains("\\.\pipe\")) {
	$dbType = "WID"
	If ((Get-AdfsSyncProperties).Role -eq "PrimaryComputer") {
		$localFedSrvIsPrimary = $TRUE
		$primaryFedSrv = $fqdnLocalComputer
	} Else {
		$localFedSrvIsPrimary = $FALSE
		$primaryFedSrv = (Get-AdfsSyncProperties).PrimaryComputerName
	}
} Else {
	$dbType = "SQL"
}

If ($dbType -eq "WID") {
	Write-Host "The Local ADFS Server Is Leveraging WID For Its Database..." -ForeGroundColor Green
	Write-Host "Continuing Script..." -ForeGroundColor Green
	Write-Host ""
	Write-Host "Database Type Used..................: $dbType" -ForegroundColor Yellow
	Write-Host "Primary Federation Service Server...: '$primaryFedSrv'" -ForegroundColor Yellow
	Write-Host "Local ADFS STS Is Primary?..........: $localFedSrvIsPrimary" -ForegroundColor Yellow
	
	$server = $fqdnLocalComputer
	$eventLog = "Custom - Support"
	$eventSource = "ADFS Support"
	$eventID = "9130"
	$eventMessage = "The Local ADFS Server Is Leveraging WID For Its Database...`n`nContinuing Script..."
	$eventType = "Information"
	writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
}
If ($dbType -eq "SQL") {
    Write-Host "The Local ADFS Server Is Leveraging SQL For Its Database..." -ForeGroundColor Red
	Write-Host "This Script Only Needs To Be Used When ADFS Is Leveraging WID For Its Database!..." -ForeGroundColor Red
    Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""
	
	$server = $fqdnLocalComputer
	$eventLog = "Custom - Support"
	$eventSource = "ADFS Support"
	$eventID = "9131"
	$eventMessage = "The Local ADFS Server Is Leveraging SQL For Its Database...`nThis Script Only Needs To Be Used When ADFS Is Leveraging WID For Its Database!...`nAborting Script..."
	$eventType = "Error"
	writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
	
	EXIT
}

### Execute Command(s) On Every Targeted ADFS Server
Write-Host ""
Write-Host "--------------------------------------------------------------------------------------------" -ForeGroundColor DarkCyan
Write-Host "+++ EXECUTE COMMAND(S) ON EVERY ADFS SERVER +++" -ForegroundColor Cyan
Write-Host ""

$adfsServerFQDNs | %{
	$adfsServerFQDN = $null
	$adfsServerFQDN = $_
	
	$scriptBlockToProcess = {
		Param(
			[string]$adfsServerFQDN = $adfsServerFQDN,
			[string]$commandsToExecute = $commandsToExecute,
			[string]$fqdnLocalComputer = $fqdnLocalComputer,
			[bool]$showScriptOutput = $showScriptOutput
		)
		
		### FUNCTION: Write Event Log Of Specified Server
		Function writeToEventLog($server,$eventLog,$eventSource,$eventID,$eventMessage,$eventType) {
			If (!([System.Diagnostics.EventLog]::SourceExists($eventSource, $server))) {
				New-EventLog -ComputerName $server -logname $eventLog -Source $eventSource
			}
			Write-EventLog -ComputerName $server -LogName $eventLog -Source $eventSource -EventID $eventID -Message $eventMessage -EntryType $eventType
		}
		
		$adfsSvc = $null
		$adfsSvc = Get-WmiObject Win32_service -Filter "Name='ADFSSRV'"
		If ($adfsSvc) {
			$adfsSvcMode = $adfsSvc.StartMode
			$adfsSvcState = $adfsSvc.State
		}

		If ($adfsSvc -And $adfsSvcMode.ToUpper() -eq "AUTO" -And $adfsSvcState.ToUpper() -eq "RUNNING") {
			Write-Host "Targeted Server Is An ADFS Server?..: TRUE" -ForegroundColor Green
			
			$server = $fqdnLocalComputer
			$eventLog = "Custom - Support"
			$eventSource = "ADFS Support"
			$eventID = "9150"
			$eventMessage = "The Target Server '$adfsServerFQDN' IS An ADFS Server..."
			$eventType = "Information"
			writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
			
			$fedSvcSTS = $null
			$fedSvcSTS = Get-WmiObject -ComputerName $adfsServerFQDN -namespace root/ADFS -class SecurityTokenService
			[string]$fedSvcSTSConfigDBConnectionString = $fedSvcSTS.ConfigurationdatabaseConnectionstring
			
			If ($fedSvcSTSConfigDBConnectionString.contains("\\.\pipe\")) {
				Write-Host "Targeted ADFS Server Is Using WID?..: TRUE" -ForegroundColor Green
				
				$server = $fqdnLocalComputer
				$eventLog = "Custom - Support"
				$eventSource = "ADFS Support"
				$eventID = "9152"
				$eventMessage = "The Target ADFS Server '$adfsServerFQDN' IS Using WID..."
				$eventType = "Information"
				writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
				
				$adfsSyncProperties = $null
				$adfsSyncProperties = Get-ADFSSyncProperties
				$adfsServerRole = $null
				$adfsServerRole = $adfsSyncProperties.Role

				Write-Host "Original Role.......................: '$adfsServerRole'" -ForegroundColor Yellow
				
				$server = $fqdnLocalComputer
				$eventLog = "Custom - Support"
				$eventSource = "ADFS Support"
				$eventID = "9154"
				$eventMessage = "The Target ADFS Server '$adfsServerFQDN' Has The Role '$adfsServerRole'..."
				$eventType = "Information"
				writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
			
				If ($adfsServerRole.ToUpper() -eq "PRIMARYCOMPUTER") {
					Write-Host ""
					Write-Host "There Is No Need To Change The Role On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Yellow
					Write-Host "Executing Command(s) On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Yellow
					
					$server = $fqdnLocalComputer
					$eventLog = "Custom - Support"
					$eventSource = "ADFS Support"
					$eventID = "9155"
					$eventMessage = "No Need To Change The Role Of The ADFS Server '$adfsServerFQDN'. Executing The Commands On The Target ADFS Server '$adfsServerFQDN'..."
					$eventType = "Information"
					writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
					
					If ($showScriptOutput) {
						Write-Host "------------------------------------" -ForegroundColor Magenta
						Write-Host "OUTPUT (IF ANY)..." -ForegroundColor Magenta
						$output = $null
						$output = Invoke-Expression $commandsToExecute | Out-String
						Write-Host "$output" -ForegroundColor Magenta
						Write-Host "------------------------------------" -ForegroundColor Magenta
					} Else {
						Invoke-Expression $commandsToExecute | Out-Null
					}
					If ($?) {
						Write-Host "   >>> The Command Executed Successfully On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Green
					} Else {
						Write-Host "   >>> The Command Failed To Execute On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
					}
				}
				If ($adfsServerRole.ToUpper() -eq "SECONDARYCOMPUTER") {
					$adfsServerPrimary = $null
					$adfsServerPrimary = $adfsSyncProperties.PrimaryComputerName
					Write-Host ""
					Write-Host "Configuring The ADFS Server '$adfsServerFQDN' With The Primary Role..." -ForegroundColor Yellow
					
					$server = $fqdnLocalComputer
					$eventLog = "Custom - Support"
					$eventSource = "ADFS Support"
					$eventID = "9156"
					$eventMessage = "Configuring The ADFS Server '$adfsServerFQDN' With The Primary Role..."
					$eventType = "Information"
					writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
					
					Set-AdfsSyncProperties -Role PrimaryComputer
					If ($?) {
						Write-Host "   >>> The Command Executed Successfully On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Green
					} Else {
						Write-Host "   >>> The Command Failed To Execute On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
					}
					$adfsSyncPropertiesCheck1 = $null
					$adfsSyncPropertiesCheck1 = Get-ADFSSyncProperties
					$adfsServerRoleCheck1 = $adfsSyncPropertiesCheck1.Role
					If ($adfsServerRoleCheck1.ToUpper() -eq "PRIMARYCOMPUTER") {
						Write-Host "   >>> The ADFS Server '$adfsServerFQDN' Now Has The Primary Role Configured..." -ForegroundColor Green
						Write-Host ""
						Write-Host "Executing Command(s) On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Yellow
						
						$server = $fqdnLocalComputer
						$eventLog = "Custom - Support"
						$eventSource = "ADFS Support"
						$eventID = "9157"
						$eventMessage = "The ADFS Server '$adfsServerFQDN' Now Has The Primary Role Configured.`n`nExecuting Command(s) On ADFS Server '$adfsServerFQDN'..."
						$eventType = "Information"
						writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
						
						If ($showScriptOutput) {
							Write-Host "------------------------------------" -ForegroundColor Magenta
							Write-Host "OUTPUT (IF ANY)..." -ForegroundColor Magenta
							$output = $null
							$output = Invoke-Expression $commandsToExecute | Out-String
							Write-Host "$output" -ForegroundColor Magenta
							Write-Host "------------------------------------" -ForegroundColor Magenta
						} Else {
							Invoke-Expression $commandsToExecute | Out-Null
						}
						If ($?) {
							Write-Host "   >>> The Command Executed Successfully On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Green
						} Else {
							Write-Host "   >>> The Command Failed To Execute On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
						}
						$nextAction = "RECONFIGURE-ROLE"
					}
					If ($adfsServerRoleCheck1.ToUpper() -eq "SECONDARYCOMPUTER") {
						Write-Host ""
						Write-Host "   >>> There Was A Failure Configuring The ADFS Server '$adfsServerFQDN' With The Primary Role..." -ForegroundColor Red
						Write-Host "Skipping The ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
						Write-Host "Investigate The Reason It Failed!..." -ForegroundColor Red
						Write-Host "Configure This Server Manually Afterwards!..." -ForegroundColor Red
						
						$server = $fqdnLocalComputer
						$eventLog = "Custom - Support"
						$eventSource = "ADFS Support"
						$eventID = "9158"
						$eventMessage = "There Was A Failure Configuring The ADFS Server '$adfsServerFQDN' With The Primary Role.`n`nSkipping The ADFS Server '$adfsServerFQDN'..."
						$eventType = "Error"
						writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
					}
					
					If ($nextAction -eq "RECONFIGURE-ROLE") {
						Write-Host ""
						Write-Host "Reconfiguring The ADFS Server '$adfsServerFQDN' With The Secondary Role..."
						
						$server = $fqdnLocalComputer
						$eventLog = "Custom - Support"
						$eventSource = "ADFS Support"
						$eventID = "9159"
						$eventMessage = "Reconfiguring The ADFS Server '$adfsServerFQDN' With The Secondary Role..."
						$eventType = "Information"
						writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
						
						Set-AdfsSyncProperties -Role SecondaryComputer -PrimaryComputerName $adfsServerPrimary
						If ($?) {
							Write-Host "   >>> The Command Executed Successfully On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Green
						} Else {
							Write-Host "   >>> The Command Failed To Execute On ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
						}
						$adfsSyncPropertiesCheck2 = $null
						$adfsSyncPropertiesCheck2 = Get-ADFSSyncProperties
						$adfsServerRoleCheck2 = $adfsSyncPropertiesCheck2.Role
						If ($adfsServerRoleCheck2.ToUpper() -eq "SECONDARYCOMPUTER") {
							Write-Host "   >>> The ADFS Server '$adfsServerFQDN' Now Has The Secondary Role Configured Again..." -ForegroundColor Green
							Write-Host ""
							
							$server = $fqdnLocalComputer
							$eventLog = "Custom - Support"
							$eventSource = "ADFS Support"
							$eventID = "9160"
							$eventMessage = "The ADFS Server '$adfsServerFQDN' Now Has The Secondary Role Configured Again..."
							$eventType = "Information"
							writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
						}
						If ($adfsServerRoleCheck2.ToUpper() -eq "PRIMARYCOMPUTER") {
							Write-Host ""
							Write-Host "   >>> There Was A Failure Reconfiguring The ADFS Server '$adfsServerFQDN' Back With The Secondary Role..." -ForegroundColor Red
							Write-Host "Skipping The ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
							Write-Host "Investigate The Reason It Failed!..." -ForegroundColor Red
							Write-Host "Configure This Server Manually Afterwards!..." -ForegroundColor Red
							
							$server = $fqdnLocalComputer
							$eventLog = "Custom - Support"
							$eventSource = "ADFS Support"
							$eventID = "9161"
							$eventMessage = "There Was A Failure Reconfiguring The ADFS Server '$adfsServerFQDN' Back With The Secondary Role.`n`nSkipping The ADFS Server '$adfsServerFQDN'..."
							$eventType = "Error"
							writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
						}
					}
				}
			} Else {
				Write-Host "Targeted ADFS Server Is Using WID?..: FALSE" -ForegroundColor Red
				
				$server = $fqdnLocalComputer
				$eventLog = "Custom - Support"
				$eventSource = "ADFS Support"
				$eventID = "9153"
				$eventMessage = "The Target ADFS Server '$adfsServerFQDN' IS NOT Using WID..."
				$eventType = "Error"
				writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
			}
		} Else {
			Write-Host "Targeted Server Is An ADFS Server?..: FALSE" -ForegroundColor Red
			
			$server = $fqdnLocalComputer
			$eventLog = "Application"
			$eventSource = "ADFS Support"
			$eventID = "9151"
			$eventMessage = "The Target Server '$adfsServerFQDN' IS NOT An ADFS Server..."
			$eventType = "Error"
			writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
		}
	}

	Write-Host ""
	Write-Host "--------------------------------------------------------------------------------------------"
	Write-Host "Processing ADFS Server..............: '$adfsServerFQDN'" -ForegroundColor Yellow
	
	$server = $fqdnLocalComputer
	$eventLog = "Custom - Support"
	$eventSource = "ADFS Support"
	$eventID = "9140"
	$eventMessage = "Processing ADFS Server:`n`n$adfsServerFQDN"
	$eventType = "Information"
	writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
	
	If ($fqdnLocalComputer -eq $adfsServerFQDN) {
		Write-Host "Local Or Remote Server..............: LOCAL" -ForegroundColor Yellow
		Invoke-Command -ScriptBlock $scriptBlockToProcess -Args $adfsServerFQDN,$commandsToExecute,$fqdnLocalComputer,$showScriptOutput
	}
	If ($fqdnLocalComputer -ne $adfsServerFQDN) {
		Write-Host "Local Or Remote Server..............: REMOTE" -ForegroundColor Yellow
		$ports = 5985,443,80	# WinRM For Remote PowerShell, ADFS HTTPS, ADFS HTTP
		$checkOK = $true
		$ports | %{
			$port = $_
			$connectionResult = $null
			$connectionResult = PortConnectionCheck $adfsServerFQDN $port 500
			If ($connectionResult -eq "SUCCESS") {
				Write-Host "Listening On Port...................: '$port'" -ForeGroundColor Green
			}
			If ($connectionResult -eq "ERROR") {
				Write-Host "NOT Listening On Port...............: '$port'" -ForeGroundColor Red
				$checkOK = $false
			}
		}

		If ($checkOK) {		
			Write-Host "All Required Ports Available?.......: TRUE" -ForegroundColor Green
			Write-Host ""
			Write-Host "Contacting The ADFS Server '$adfsServerFQDN'..." -ForegroundColor Yellow
			
			$server = $fqdnLocalComputer
			$eventLog = "Custom - Support"
			$eventSource = "ADFS Support"
			$eventID = "9141"
			$eventMessage = "The Target Server '$adfsServerFQDN' IS Listening To All Required Ports ($ports) And Will Be Contacted For Processing..."
			$eventType = "Information"
			writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
			
			$adfsServerSession = $null
			$adfsServerSession = New-PSSession -ComputerName $adfsServerFQDN
			Invoke-Command -Session $adfsServerSession -ScriptBlock $scriptBlockToProcess -Args $adfsServerFQDN,$commandsToExecute,$fqdnLocalComputer,$showScriptOutput
			Remove-PSSession $adfsServerSession
		} Else {
			Write-Host "All Required Ports Available?.......: FALSE" -ForegroundColor Red
			Write-Host ""
			Write-Host "The ADFS Server '$adfsServerFQDN' Will Not Be Contacted..." -ForegroundColor Red
			Write-Host "Skipping The ADFS Server '$adfsServerFQDN'..." -ForegroundColor Red
			Write-Host "Investigate Why It Cannot Be Contacted!..." -ForegroundColor Red
			Write-Host "Configure This Server Manually Afterwards!..." -ForegroundColor Red
			
			$server = $fqdnLocalComputer
			$eventLog = "Custom - Support"
			$eventSource = "ADFS Support"
			$eventID = "9142"
			$eventMessage = "The ADFS Server '$adfsServerFQDN' IS NOT Listening To All Required Ports ($ports) And Will Therefore NOT Be Contacted For Processing..."
			$eventType = "Error"
			writeToEventLog $server $eventLog $eventSource $eventID $eventMessage $eventType
		}
	}
}

Write-Host ""
Write-Host "DONE..." -ForeGroundColor Green
Write-Host ""