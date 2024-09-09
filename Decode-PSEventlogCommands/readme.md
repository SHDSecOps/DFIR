# SYNOPSIS
Searches for encoded command exections in a Powershell Operational Eventlog and tries to decode it
# DESCRIPTION
Searches for encoded command exections in a Powershell Operational Eventlog with regex and tries to decode it. Returns an Arraylist with all necessary informations. Use -PreFormatAsTable if you only want to see the Output in console
# NOTES
Mike Beckert 2022-12-28 @ SHD Systemhaus Dresden GmbH
## TODOs:
 - Errorhandling when failure at decoding
 - Searching in remote Eventlogs (credential, computername)
 - Prevalidate all possible Eventlogs
 - piping stuff in
 - minicommands for quick usage
 - -e can also be -encoded lol -> fix it pls asap
# PARAMETERS
## SavedEventFile
Specifies the evtx File in filesystem
Alias: file
## LogName
Sepcifies the WindowsEventlog. Get Name by using: Get-WinEvent -ListLog *
Alias: log
## PreFormatAsTable
When using this switch, the Array is preformatted as Table with Unique rows for console Output
Alias: pf
## FullOutput
When using this switch, the Array crowded with more informations like RecordID, MachineName, LogName, Level, Keywords, EventId, Provider
Alias: full
## verbose
Gets you more informations about what's happening
# INPUTS
None. Currently you cannot pipe anything into this script
# OUTPUTS
System.Collections.ArrayList for further usage
-OR-
Formatted Table with unique rows and sorted by TimeCreated. Columns: TimeCreatedLocal, TimeCreatedUTC, DecodedCommand, EncodedCommand
# EXAMPLES
## EXAMPLE 1
```
.\Decode-PSEventlogCommands.ps1 -File .\PowershellToolsDownload.evtx -FullOutput -Verbose
```
Outputs all the informations as array for further usage
## EXAMPLE 2
```
.\Decode-PSEventlogCommands.ps1 -File C:\temp\PowershellToolsDownload.evtx -FullOutput -Verbose | where {$_.decodedcommand -like "*download*"} | select timecreatedutc, decodedcommand, machinename | ft -au
```
Outputs only the downloads as table
## EXAMPLE 3
```
.\Decode-PSEventlogCommands.ps1 -File .\PowershellToolsDownload.evtx -PreFormatAsTable
```
Gives you a quick overview of unique commands from the evtx file in console
## EXAMPLE 4
```
.\Decode-PSEventlogCommands.ps1 -LogName Microsoft-Windows-PowerShell/Operational
```
Gives you a quick overview of unique commands from the PS EventLog in console
