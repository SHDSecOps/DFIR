<#
.SYNOPSIS
    Parses Security Eventlog for successful Logons/Logoffs and matches LogonIDs
    mbeckert 2024
.DESCRIPTION
    ProTip: use with | ft to print a table of the combined Events to console
    
    This Script reads the live Security Eventlog (if you are admin), or a saved Eventlog EVTX File,
    parses the Log for successful logon/logoff Events,
    filters for relevant info if you want (AllEvents, or real User)
    tries to match the LogonIDs
    and returns the Object for further use, or exports it to csv

    Bonus Tip: Parameter CompleteSessionsOnly does not give you active sessions, use verbose if you still want to print that information

    EventIDs checked:
    4624 - An account was successfully logged on
    4634 - An account was logged off
    4647 - User initiated logoff

    Logon Type Description 
    2	Interactive (logon at keyboard and screen of system)
    3	Network (i.e. connection to shared folder on this computer from elsewhere on network)
    4	Batch (i.e. scheduled task)
    5	Service (Service startup)
    7	Unlock (i.e. unnattended workstation with password protected screen saver)
    8	NetworkCleartext (Logon with credentials sent in the clear text. Most often indicates a logon to IIS with "basic authentication") See this article for more information.
    9	NewCredentials such as with RunAs or mapping a network drive with alternate credentials.  This logon type does not seem to show up in any events.  If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."
    10	RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)
    11	CachedInteractive (logon with cached domain credentials such as when logging on to a laptop when away from the network)
.NOTES
    EventData.Data matching
    #5=username
    #8=logontype
    #18=logonIP
    #7=LogonID

    TODOs:
    - new mode for excluding computeraccounts
.LINK
    https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
.EXAMPLE
    Test-MyTestFunction -Verbose
    Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
#>

[CmdletBinding()]

Param(
    [Parameter( Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true )] 
    [ValidateNotNullOrEmpty()]
    [string]$LogFile = '', # Log file - leave blank for live event log (must be run as administrator)

    [Parameter( Position = 1, Mandatory = $true )] 
    [ValidateNotNullOrEmpty()]
    [ValidateSet("CompleteSessionsOnly", "AllEventsButNoSYSTEM", "AllEvents")]
    [string]$Mode = 'CompleteSessionsOnly',

    [Parameter( Position = 2, Mandatory = $false )] 
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile = "" # CSV output file - leave blank for terminal-only results
)

#print vars (this is a test, if I want to use this kind of printing in my future scripts)

Write-Host "[+] Parsing variables..." -f Cyan

if ( $logFile -eq "") { Write-Host "[o] Reading live Security log - must be run as administrator" }
else { Write-Host "[o] Reading static EVTX file from $logFile" }

if ( $Mode -eq "CompleteSessionsOnly") { Write-Host "[o] Mode: CompleteSessionsOnly - shows complete sessions only; default mode" }
elseif ( $Mode -eq "AllEventsButNoSYSTEM") { Write-Host "[o] Mode: AllEventsButNoSYSTEM - shows all events, no SYSTEM account" }
elseif ( $Mode -eq "AllEvents") { Write-Host "[o] Mode: AllEvents - shows all Logon/logoff events" }

if ( $outputFile -eq "") { Write-Host "[o] No path provided - CSV will not be written. Only ft cmdline Output " }
else { Write-Host "[o] CSV will be written to $outputFile" }

### Get events from Security log
$loginEvents = @()
$logoutEvents = @()
if ($logFile -eq "") {
    try {
        Write-Host "[+] Reading live Security log - must be run as administrator" -f Cyan
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isadmin) {
            Write-Host "[+] You are admin! Retrieving events from Security log..." -f Green
        }
        else {
            Write-Host "[+] You are not Admin! Trying to retrieve events from Security log anyway..." -f DarkMagenta
        }
        Write-Host "[o] Note, that this can be very slow"
        $tempLoginEvents = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4624 } #yes i know this could be faster
        $tempLogoutEvents = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4634, 4647 }
    }
    catch {
        Write-Error "[+] See? I told you, that you are missing admin privileges!"
    }
}
else {
    Write-Host "[+] Reading static EVTX file from $logFile" -f Cyan
    if (!(Test-Path $LogFile)) {
        Write-Error "EVTX File not found! Script stopped."
        break
    }
    Write-Host "[+] EVTX $logFile found. Retrieving events..." -f Green
    Write-Host "[o] Note, that this can be very slow"
    $tempLoginEvents = Get-WinEvent -FilterHashtable @{Path = $logFile; ID = 4624 } #yes i know this could be faster
    $tempLogoutEvents = Get-WinEvent -FilterHashtable @{Path = $logFile; ID = 4634, 4647 }
}

Write-Host ("[o] Login Events found:  {0}" -f $tempLoginEvents.count)
Write-Host ("[o] Logoff Events found: {0}" -f $tempLogoutEvents.count)

### Retrieve login event data (message) (required fields: timestamp, username, logon type, logon ID)
Write-Host "[+] Processing login event fields..." -f Cyan
foreach ($event in $tempLoginEvents) {
    #$tempTable = @{} #testing
    $eventXML = [xml]$event.ToXml()
    $loginEvents += @{
        LoginTime     = $event.timecreated;
        LoginEventID  = $event.id;
        LoginUserName = $eventXML.Event.EventData.Data[5].'#text'; #5=username
        LoginType     = $eventXML.Event.EventData.Data[8].'#text'; #8=logontype
        LoginIP       = $eventXML.Event.EventData.Data[18].'#text'; #18=logonIP
        LoginID       = $eventXML.Event.EventData.Data[7].'#text' #7=LogonID
    }
}
# Convert to a usable format and exclude events for local machine account
if ($Mode -ne "AllEvents") {
    Write-Verbose "Filtering local machine Account"
    $loginEvents = $loginEvents | foreach { New-Object PSObject -Property $_ } | Where-Object { $_.LoginUserName -ne 'SYSTEM' }
}
else {
    $loginEvents = $loginEvents | foreach { New-Object PSObject -Property $_ }
}

### Retrieve logout event data (required fields: timestamp, username, logon ID)
Write-Host "[+] Processing logout event fields..." -f Cyan
foreach ($event in $tempLogoutEvents) {
    #$tempTable = @{} #testing
    $eventXML = [xml]$event.ToXml()
    $logoutEvents += @{
        LogoutTime     = $event.timecreated;
        LogoutEventID  = $event.id;
        LogoutUserName = $eventXML.Event.EventData.Data[1].'#text';
        LoginID        = $eventXML.Event.EventData.Data[3].'#text'
    }
}
# Convert to a usable format and exclude events for local machine account
if ($Mode -ne "AllEvents") {
    $logoutEvents = $logoutEvents | foreach { New-Object PSObject -Property $_ } | where { $_.UserName -ne 'SYSTEM' }
}
else {
    $logoutEvents = $logoutEvents | foreach { New-Object PSObject -Property $_ }
}

### Match login and logout events based on the common LoginID field to find full session info
Write-Host "[+] Finding Logon ID matches..." -f Cyan
$combinedEvents = @()
foreach ($login in $loginEvents) {
    foreach ($logout in $logoutEvents) {
        $matchFound = 0
        if ($login.LoginID -eq $logout.LoginID) {
            $matchFound = 1
            $tempLIT = $login.LoginTime | Out-String
            $tempLOT = $logout.LogoutTime | Out-String
            if ($tempLIT -ne $tempLOT) {
                # Filter out duplicate matches where login and logout times are identical
                Write-Verbose "Match on LogonID $($login.LoginID) found!"
                $combinedEvents += @{
                    LoginTime      = $login.LoginTime;
                    LogoutTime     = $logout.LogoutTime;
                    LoginEventID   = $login.LoginEventID;
                    LogoutEventID  = $logout.LogOutEventID;
                    LoginUserName  = $login.LoginUserName;
                    LogoutUserName = $logout.LogoutUserName;
                    LoginType      = $login.LoginType;
                    LoginIP        = $login.LoginIP;
                    LoginID        = $login.LoginID
                }
            }
        }
        # Add an entry for logins without logouts (i.e. active sessions)
        if ($matchFound -eq 0) {
            if ($Mode -ne "CompleteSessionsOnly") {
                $combinedEvents += @{
                    LoginTime      = $login.LoginTime;
                    LogoutTime     = "";
                    LoginEventID   = $login.LoginEventID;
                    LogoutEventID  = "";
                    LoginUserName  = $login.LoginUserName;
                    LogoutUserName = "";
                    LoginType      = $login.LoginType;
                    LoginIP        = $login.LoginIP;
                    # LoginID = $login.LoginID # excluded LoginID to avoid duplicate blanks in results
                }
            }
        }
    }
} # thats a lot of braces lol

# Convert to a usable format, print to screen, and create CSV if path set
Write-Host "[+] Producing final table..." -f Cyan

$combinedEvents = $combinedEvents | foreach { New-Object PSObject -Property $_ } | sort -Property LoginTime, LogoutTime, LoginEventID, LogoutEventID, LoginUserName, LogoutUserName, LoginType, LoginIP, LoginID -Unique

#write csv if selected
if ($outputFile -ne "") {
    Write-Host "[+] Writing CSV to $outputFile" -f Cyan
    $combinedEvents | select LoginTime, LogoutTime, LoginEventID, LogoutEventID, LoginUserName, LogoutUserName, LoginType, LoginIP, LoginID | Export-Csv $outputFile -NoTypeInformation -Encoding UTF8 -Delimiter ';'
}
Write-Host "[+] Finished - SUCCESS" -f Green
return $combinedEvents | select LoginTime, LogoutTime, LoginEventID, LogoutEventID, LoginUserName, LogoutUserName, LoginType, LoginIP, LoginID 

#\MB