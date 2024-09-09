<#
.SYNOPSIS
    This Script exports specified Eventlog to csv
    mbeckert 2024
.DESCRIPTION
    This Script will export your specified Windows Eventlog to csv.
    You can choose between:
    - default Windows Logs like System, Security, Application
    - other, more advanced Windows Logs like Microsoft-Windows-PowerShell/Operational
    - a saved EVTX file

    you can also choose the days (in numbers) you want to search back; if none is specified, all events will be collected

    lastly you can choose your outputdirectory; if none is specified, default temp folder will be used (e.g. C:\Users\myuser\AppData\Local\Temp)

    Important:
    If you collect from saved evtx file, make sure, that you run this script on a computer, that has the needed WindowsFeature installed,
    otherwise the "message" attribute will not be populated! This script does not check if the needed provider is installed!
.NOTES
    mbeckert 2024    
    encoding used:  UTF8
    Delimiter used: ;   

    I removed admin privileges check intentionally. I think you know what to do.

    TODOs:
    - check if log has a valid provider (aka installed windows feature)   
    - remove redundant calls of convertto-csv - its ugly
    - display events count
.LINK
    https://github.com/SHDSecOps
.EXAMPLE
    Export-EventlogToCsv.ps1 -EventLog System -OutputPath "C:\temp"
    Exports all events from the System Event log to csv into folder C:\temp
.EXAMPLE
    Export-EventlogToCsv.ps1 -SpecialEventLog "Microsoft-Windows-PowerShell/Operational" -Days 1  
    Exports all events from the PowerShell/Operational Event log to csv into your default temp folder
.EXAMPLE
    Export-EventlogToCsv.ps1 -LogFile "c:\temp\mySecuritylog.evtx" -OutputPath "\\myshare\eventlogs"
    Exports all events from the saved mySecuritylog.evtx Event log to csv into share \\myshare\eventlogs
#>

param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Log')]
    [ValidateSet("Application", "Security", "System")]
    [String]$EventLog,

    [Parameter(Mandatory = $true, ParameterSetName = 'special')]
    [String]$SpecialEventLog,

    [Parameter(Mandatory = $true, ParameterSetName = 'file')]
    [String]$LogFile,

    [Parameter(Mandatory = $false, ParameterSetName = 'Log')]
    [Parameter(Mandatory = $false, ParameterSetName = 'special')]
    [Parameter(Mandatory = $false, ParameterSetName = 'file')]
    [Int16]$Days, 

    [Parameter(Mandatory = $false, ParameterSetName = 'Log')]
    [Parameter(Mandatory = $false, ParameterSetName = 'special')]
    [Parameter(Mandatory = $false, ParameterSetName = 'file')]
    [ValidateScript({ #all this just to verify that input is actually a valid path, and if there is none - use current locations
            if (-Not ($_ | Test-Path) ) {
                throw "File or folder does not exist" 
            }
            return $true
        })]
    [String]$OutputPath
)

$ASCIIBanner = @"
    _____ _    _ _____    ______                       _          
   / ____| |  | |  __ \  |  ____|                     (_)         
  | (___ | |__| | |  | | | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
   \___ \|  __  | |  | | |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
   ____) | |  | | |__| | | | | (_) | | |  __/ | | \__ \ | (__\__ \
  |_____/|_|  |_|_____/  |_|  \___/|_|  \___|_| |_|___/_|\___|___/
                   
  mbeckert 2024"`n
"@
Write-Host $ASCIIBanner -f Green

if (!$OutputPath) {
    $OutputPath = $env:TEMP | select -First 1
    Write-Host "[+] No Output Path specified. Using temp folder: $OutputPath" -f DarkYellow
}

### Default Eventlog
if ($EventLog) {
    $exportfilepath = Join-Path $OutputPath -ChildPath ("EventlogExport_{0}_{1}_{2}.csv" -f $env:COMPUTERNAME, $EventLog, (Get-Date -Format "yyyyMMdd-HHmm"))
    Write-Host "[+] Saving Output to $exportfilepath" -f Cyan

    if ($Days) {
        Write-Host "[+] Collecting Events from $Eventlog of the last $Days days..." -f Cyan
        get-eventlog $EventLog -After (Get-Date).AddDays(-$Days) | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8 
        # I dont remember why i split convert and export - but there is a reason ... maybe...
    }
    else {
        Write-Host "[+] Collecting Events from $Eventlog..." -f Cyan
        get-eventlog $EventLog | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8
    }
}

### Microsoft Windows Eventlog
if ($SpecialEventLog) {
    $exportfilepath = Join-Path $OutputPath -ChildPath ("EventlogExport_{0}_{1}_{2}.csv" -f $env:COMPUTERNAME, ($SpecialEventLog -replace ('/', "_")), (Get-Date -Format "yyyyMMdd-HHmm"))
    Write-Host "[+] Saving Output to $exportfilepath" -f Cyan

    if ($Days) {
        Write-Host "[+] Collecting Events from $SpecialEventLog of the last $Days days..." -f Cyan
        Get-WinEvent -FilterHashtable @{LogName = $SpecialEventLog; StartTime = ((Get-Date).AddDays(-$Days)) } | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8
    }
    else {
        Write-Host "[+] Collecting Events from $SpecialEventLog..." -f Cyan
        Get-WinEvent -FilterHashtable @{LogName = $SpecialEventLog } | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8
    }
}

###Eventlog EVTX File 
if ($LogFile) {
    $exportfilepath = Join-Path $OutputPath -ChildPath ("EventlogExport_{0}_{1}_{2}.csv" -f $env:COMPUTERNAME, ($SpecialEventLog -replace ('.', "_")), (Get-Date -Format "yyyyMMdd-HHmm"))
    Write-Host "[+] Saving Output to $exportfilepath" -f Cyan

    if ($Days) {
        Write-Host "[+] Collecting Events from $LogFile of the last $Days days..." -f Cyan
        Get-WinEvent -FilterHashtable @{Path = $LogFile; StartTime = ((Get-Date).AddDays(-$Days)) } | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8
    }
    else {
        Write-Host "[+] Collecting Events from $LogFile..." -f Cyan
        Get-WinEvent -FilterHashtable @{Path = $LogFile } | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath $exportfilepath -Encoding UTF8
    }
}
Write-Host "[+] Done." -ForegroundColor Green
