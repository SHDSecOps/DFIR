<#
.SYNOPSIS
    Mike Beckert (SHD) 2024
    This Script returns all Indicators (e.g. IPs) from a given String, File, Folder or Log
.DESCRIPTION
    This Script searches for all IPs, Mac,Mailaddresses,URLs or custom pattern in a given Input via RegEx.

    Short Version of this Script is at the End of this Description

    Minimun inputs are at least one of these:
    -inputstring -> String, searches inside the given String; Default Parameter. Can also be pipelined into this script with <string> | Find-IP.ps1
    -File        -> filepath, searches inside the given file
    -folder      -> folderpath, searches in all inside Files in that folder
    -Log         -> EventlogName (e.g. Security or Application)
    -LogFile     -> Saved evtx file to search for
    
    Search parameters:
    - FindIPv4 -> default; matches IPv4 addresses
    - FindIPv6 -> matches IPv6 addresses
    - FindMac  -> matches mac addresses
    - FindMail -> matches typical mail addresses (sometimes not working properly!)
    - FindURL  -> matches https/www addresses - I need to find a better regex for this!
    - customregex -> if you want to change the regex 
    - FindSuccessfulLoginIPs -> searches the Security Eventlog for successful logins and returns IPv4 addresses that logged on
    - FindFailedLoginIPs     -> searches the Security Eventlog for failed login attempts and returns IPv4 addresses that tried
    
    Other valid parameters are
    - formatcommaseperated -> formats the output in with "," so you can copy it into another System; Alias = format
    - verbose -> also outputs some more runtime informations like found files, regex etc
    - debug -> also outputs the whole content which is searched for IPs

    Normal Output:
    a distinct list of all matches (default=IPv4), that match the regex pattern and the number of occurences
    pipe the output for further use (e.g. ... | Export-csv .\myfindings.csv)

    Formatted Output:
    comma seperated String with all distincs IPs, surrounded by "" -> Optimized for Azure Sentinel copypaste

    Short Version:
    #yourstring = "Erwin@knatterhose.lol-myipaddressisnot192.168.1.254duh"
    $ipregex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    [regex]::Matches($yourstring, $ipregex) | foreach { $_.Value }
.OUTPUTS
    >Default: Selected.Microsoft.PowerShell.Commands.GroupInfo
    Example Output
    Name           Count
    ----           -----
    109.40.240.215     1
    84.143.17.151      4
    51.163.4.52       10
    -or-
    >with Format Switch: System.String
    Example Output
    "51.163.4.52","84.143.17.151","109.40.240.215"
.INPUTS
    Important: Powershell is trying to get the right Encoding - if you want to force a specific encoding, alter this script @ command "Get-Content -encoding <your encoding>"    
    String, Filename, Foldername, eventlog, evtx eventlog file
.NOTES
    Default Regex used in this script:
    IPv4 '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    IPv6 '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
    Mac  '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    Mail '(([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)(\s*;\s*|\s*$))*' -> regeex ist falsch!
    Mail funktionierend \w+@\w+\.\w{2,3}
    URLs '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'

    TODOs:
    - move verififications of files/folders to param section
    - output, where each indicator was found in verbose mode
    - change write methods to [+] -> its prettier!
.LINK
    https://github.com/joshbrunty/DFIR-Regular-Expressions
.PARAMETER inputstring
    Text that contains the informations you want to gather
    Default Parameter @ Position 0 (doesn't need to be named)
    You can also pipe any string into this script
.PARAMETER file
    Filepath that contains the informations you want to gather
.PARAMETER folder
    Folderpath that contains the informations you want to gather
.PARAMETER EventlogName
    Log that contains the informations you want to gather
    Use Get-EventLog -List to get the names
.PARAMETER SavedEventlogFile   
    LogFile path in evtx that contains the informations you want to gather
.PARAMETER FindIPv4
    default; use IPv4 address pattern
.PARAMETER FindIPv6
    use IPv6 address Pattern
.PARAMETER FindMac
    use Mac address pattern
.PARAMETER FindMail
    use mail address pattern
.PARAMETER FindURL
    use URL pattern
.PARAMETER FindSuccessfulLoginIPs
    Switch if you want to get all IPv4 that were used to successfully login
.PARAMETER FindFailedLoginIPs
    Switch if you want to get all IPv4 that tried unsuccessfully to login
.PARAMETER customregex
    Pattern as Text, if you want to search for something different
.PARAMETER formatcommaseperated
    Switch if you want to change Outputformat
    Alias = format
.EXAMPLE
    Find-Indicators.ps1 -file "C:\temp\myfile.log"
    Finds all IPv4 Addresses in the myfile.log file and outputs a table with distinct IPs and the number of occurences
.EXAMPLE
    Find-Indicators.ps1 -folder "C:\temp" -FindURL
    Finds all URLs in all files in the folder C:\temp and outputs a table with distinct URLs and the number of occurences over all files
.EXAMPLE
    Find-Indicators.ps1 -folder "C:\temp\" -format -FindIPv6
    Finds all IPv6 Addresses in all files in the folder C:\temp and outputs the distinct IPs as comma seperated string, which can be copied e.g. into Azure Sentinel TI
.EXAMPLE
    "my192.168.12.1string10.1.1.4with172.0.0.1some51.99.99.11IP" | Find-Indicators.ps1 -verbose
    Finds all IPv4 Addresses in the string "my192.168.12.1string10.1.1.4with172.0.0.1some51.99.99.11IP" and outputs a table with distinct IPs and the number of occurences. Also outputs some more runtime informations because of the verbose switch
.EXAMPLE
    Find-Indicators.ps1 -Log System
    Finds all IPv4 Addresses in the System EventLog and outputs a table with distinct IPs and the number of occurences
.EXAMPLE
    Find-Indicators.ps1 -FindSuccessfulLoginIPs
    Finds all IPv4 Addresses of successful Logins in the Security EventLog and outputs a table with distinct IPs and the number of occurences
.EXAMPLE
    Find-Indicators.ps1 -FindFailedLoginIPs -SavedEventlogFile "C:\temp\mysecuritylog.evtx"
    Finds all IPv4 Addresses of failed Login atempts in the mysecuritylog.evtx FIle and outputs a table with distinct IPs and the number of occurences
#>

[CmdletBinding()]

Param(
    [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'string'  )] 
    [ValidateNotNullOrEmpty()]
    [string]$inputstring = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'file'  )]
    [ValidateNotNullOrEmpty()]
    [string]$file = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'folder'  )]
    [ValidateNotNullOrEmpty()]
    [string]$folder = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'Log'  )]
    [Alias( 'Log' )]
    [ValidateNotNullOrEmpty()]
    [string]$EventlogName = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'savedLog'  )]
    [Parameter(Mandatory = $true, ParameterSetName = 'savedLog1'  )]
    [Alias( 'LogFile' )]
    [ValidateNotNullOrEmpty()]
    [string]$SavedEventlogFile = '',

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindIPv4 = $true,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindIPv6,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindMac,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindMail,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindURL,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [string]$customregex = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'successful'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindSuccessfulLoginIPs,

    [Parameter(Mandatory = $true, ParameterSetName = 'failed'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog1'  )]
    [ValidateNotNullOrEmpty()]
    [switch]$FindFailedLoginIPs,

    [Parameter(Mandatory = $false, ParameterSetName = 'string'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'file'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'folder'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'Log'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'savedLog'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'failed'  )]
    [Parameter(Mandatory = $false, ParameterSetName = 'successful'  )]
    [Alias( 'format' )]
    [ValidateNotNullOrEmpty()]
    [switch]$formatcommaseperated

)
#fancy SHD Forensics Logo >_>
Write-Host ("{0}`n{1}`n{2}`n{3}`n{4}`n{5}`n{6}`n{7}`n" -f "  _____ _    _ _____    ______                       _          ", " / ____| |  | |  __ \  |  ____|                     (_)         ", "| (___ | |__| | |  | | | |__ ___  _ __ ___ _ __  ___ _  ___ ___ ", " \___ \|  __  | |  | | |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|", " ____) | |  | | |__| | | | | (_) | | |  __/ | | \__ \ | (__\__ \", "|_____/|_|  |_|_____/  |_|  \___/|_|  \___|_| |_|___/_|\___|___/", "              ", "mbeckert 2024") -ForegroundColor Green

Write-Host "Starttime (local):" (get-date -Format "dddd, yyyy-MM-dd HH:mm") 
#finding out what to check for 
#fancy fancy if if if if if if fi if I know, I know
if ($FindIPv6) {
    Write-Host "Mode: Find IPv6 Addresses"
    $FindIPv4 = $false
    [string]$regex = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'}
if ($FindMac)  {
    Write-Host "Mode: Find Mac Addresses"
    $FindIPv4 = $false
    [string]$regex = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'}
if ($FindMail) {
    Write-Host "Mode: Find Mail Addresses"
    $FindIPv4 = $false
    [string]$regex = '\w+@\w+\.\w{2,3}' } # alternative Mail regex '(([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)(\s*;\s*|\s*$))*' -> regeex ist falsch! }
if ($FindURL)  {
    Write-Host "Mode: Find URLs"
    $FindIPv4 = $false
    [string]$regex = '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'}
if ($customregex.Length -ne 0) {
    Write-Host "Mode: Find custom regex"
    $FindIPv4 = $false
    [string]$regex = $customregex}
if ($FindSuccessfulLoginIPs) {
    #successful logins in security eventlog are currently only available in IPv4
    Write-Host "Mode: Find Successful Logins and get their IPv4 Addresses"
    $FindIPv4 = $false
    [string]$regex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'} 
if ($FindFailedLoginIPs) {
    #failed logins in security eventlog are currently only available in IPv4
    Write-Host "Mode: Find failed Logins and get their IPv4 Addresses"
    $FindIPv4 = $false
    [string]$regex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'} 
if ($FindIPv4) {
    Write-Host "Mode: Find IPv4 Addresses"
    [string]$regex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'}  

#check for admin privileges - mainly for security event log
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Verbose "Current User is admin? $isadmin"

Write-Host "Fetching Input..." -ForegroundColor Cyan

if ("" -ne $file) {
    #Errorhandling
    try { gi $file | Out-Null; Write-Verbose "File found: $file" }
    catch { Write-Error "No File $file found! Script Stopped."; break}

    $inputstring = get-content $file -Raw
}
if ("" -ne $folder) {
    #errorhandling
    try { gi $folder | Out-Null; Write-Verbose "Folder found: $folder" }
    catch { Write-Error "No Folder named $folder found! Script Stopped."; break }

    $files = (gci $folder -File -Recurse ).FullName
    $sb = [System.Text.StringBuilder]::new()
    foreach ($file in $files) {
        Write-Verbose "File found: $file"
        $content = (Get-Content $file -Raw)
        [void]$sb.AppendLine($content)
        Write-Verbose "Stringbuilder Lenght: $($sb.Length)"
    }
    $inputstring = $sb.ToString()
}

if ("" -ne $EventlogName) {
    #errorhandling
    try { Get-EventLog $EventlogName | select -First 1 | Out-Null; Write-Verbose "Getting Entries from Log: $EventlogName" }
    catch { Write-Error "No Log named $EventlogName found! Script Stopped."; break }

    Write-Host "Note, that this is very slow!" -ForegroundColor DarkYellow
    $log = Get-WinEvent -FilterHashTable @{LogName = $EventlogName }
    Write-Verbose "Here are some of the events found:"
    Write-Verbose ($log | select -First 20 | ft -au)
    $inputstring = $log | fl | Out-String
}

if (("" -ne $SavedEventlogFile) -and (!$FindSuccessfulLoginIPs -or !$FindFailedLoginIPs)) {
    #errorhandling
    try { gi $SavedEventlogFile | Out-Null; Write-Verbose "Getting Entries from saved Logfile: $SavedEventlogFile" }
    catch { Write-Error "No saved Log at $SavedEventlogFile found! Script Stopped."; break }

    Write-Host "Note, that this is very slow!" -ForegroundColor DarkYellow
    $log = Get-WinEvent -FilterHashTable @{Path = $SavedEventlogFile }
    Write-Verbose "Here are some of the events found:"
    Write-Verbose ($log | select -First 20 | ft -au)
    $inputstring = $log | fl | Out-String
}

if ($FindSuccessfulLoginIPs -or $FindFailedLoginIPs) { #saved eventlog missing!!!
    if (!$isadmin) { #errorhandling
        Write-Host "You are no admin! Trying to read Security Eventlog anyway..." -ForegroundColor DarkYellow
    }
    try {
        if ($FindSuccessfulLoginIPs) {
            Write-Verbose "Getting sucessful Logins from the Security Log"
            $eventid = 4624
        }
        if ($FindFailedLoginIPs) {
            Write-Verbose "Getting failed Logins from the Security Log"
            $eventid = 4625
        }
        Write-Host "Note, that this is very slow!" -ForegroundColor DarkYellow
        if ("" -ne $SavedEventlogFile) {
            $log = Get-WinEvent -FilterHashTable @{Path = $SavedEventlogFile; ID = $eventid } -ErrorAction SilentlyContinue -Verbose:$false
        }
        else {
            $log = Get-WinEvent -FilterHashTable @{LogName = "Security"; ID = $eventid } -ErrorAction SilentlyContinue -Verbose:$false
        }
        Write-Verbose "Here are some of the events found:"
        Write-Verbose ($log | select -First 20 | ft -au | Out-String)
        $inputstring = $log | fl | Out-String
    }
    catch {
        Write-Error "See? I told you, that you are missing admin privileges! But there could be some other error tho... use the -debug param"
        Write-Debug $error[0]
        break
    }
}
#Write-Debug $inputstring

Write-Verbose "Current Regex is: $regex"
Write-Host "Finding your desired stuff..." -ForegroundColor Cyan
$matchingIPs = [regex]::Matches($inputstring, $regex) | foreach { $_.Value } #this is where the magic happens

Write-Host "Endtime (local):" (get-date -Format "dddd, yyyy-MM-dd HH:mm") 

if ($formatcommaseperated) {
    Write-Verbose "Formatting Output..."
    $delimiter = ','
    $IPs = $matchingIPs | select -Unique
    $sbip = [System.Text.StringBuilder]::new()
    foreach ($IP in $IPs) {
        [void]$sbip.Append('"')
        [void]$sbip.Append($IP)
        [void]$sbip.Append('"')
        [void]$sbip.Append($delimiter)
    }
    $sbip.Length-- #letztes komma wieder entfernen
    return ($sbip.ToString())
}
else {
    if ($matchingIPs.Length -eq 0) {
        write-host "Nothing found" -ForegroundColor Red
        return $false
    }
    else {
        Write-Host "Here is your result:" -ForegroundColor Green
        return $matchingIPs | group | select Name, Count | sort count
    }
}

#MB