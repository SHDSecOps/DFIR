# SYNOPSIS
This Script exports specified Eventlog to csv
# DESCRIPTION
This Script will export your specified Windows Eventlog to csv.
- You can choose between:
-- default Windows Logs like System, Security, Application
-- other, more advanced Windows Logs like Microsoft-Windows-PowerShell/Operational
-- a saved EVTX file
- you can also choose the days (in numbers) you want to search back; if none is specified, all events will be collected
- lastly you can choose your outputdirectory; if none is specified, default temp folder will be used (e.g. C:\Users\myuser\AppData\Local\Temp)

**Important:**
If you collect from saved evtx file, make sure, that you run this script on a computer, that has the needed WindowsFeature installed,
otherwise the "message" attribute will not be populated! This script does not check if the needed provider is installed!
# NOTES
mbeckert 2024
encoding used:  UTF8
Delimiter used: ;   

I removed admin privileges check intentionally. I think you know what to do.
## TODOs:
- check if log has a valid provider (aka installed windows feature)   
- remove redundant calls of convertto-csv - its ugly
- display events count
# LINK
https://github.com/SHDSecOps
# EXAMPLES
## EXAMPLE 1
Export-EventlogToCsv.ps1 -EventLog System -OutputPath "C:\temp"
Exports all events from the System Event log to csv into folder C:\temp
## EXAMPLE 2
Export-EventlogToCsv.ps1 -SpecialEventLog "Microsoft-Windows-PowerShell/Operational" -Days 1  
Exports all events from the PowerShell/Operational Event log to csv into your default temp folder
## EXAMPLE 3
Export-EventlogToCsv.ps1 -LogFile "c:\temp\mySecuritylog.evtx" -OutputPath "\\myshare\eventlogs"
Exports all events from the saved mySecuritylog.evtx Event log to csv into share \\myshare\eventlogs
