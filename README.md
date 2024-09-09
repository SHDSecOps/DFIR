# DFIR
Welcome to the SHD DFIR Repo

![SHD Logo](https://github.com/SHDSecOps/SHDSecOps/blob/main/shd-secops%20350px%20round%20trans.png)

This Repo contains public scripts that we find handy in DFIR Cases. 
They are by no means perfect, since are not software developer - but they worked for us at least once.
We tried to make them as readable as we could.



# Principles
While developing there were some principles:
- cleartext language - so no compiled stuff. Sometimes you only can copy/paste stuff via text
- function > form
- a dummy needs do work with this

*If you have any suggestions or tips - contact us SHDSecOps@shd-online.de.*

# Content

## Decode-PSEventlogCommands
Searches for encoded command exections in a Powershell Operational Eventlog and tries to decode it
## Export-EventlogToCsv
This Script exports specified Eventlog to csv
## Find-Indicators (deprecated)
This Script returns all Indicators (e.g. IPs) from a given String, File, Folder or Log
## Get-ExecutableFiles
Returns all Executable Files of a given FolderPath
## Get-LogonLogoffEvents
Parses Security Eventlog for successful Logons/Logoffs and matches on LogonIDs
## Get-ScheduledTaskModifications
Searches for modified Scheduled Tasks in Security Eventlog
## IOCExtractor
Starts UI for IOC Extraction from a given String or File
## Invoke-VTReport
Tests the given String Array against VT and returns a formatted table sorted by malicious analysis count.
## Purge-KerbTicketsLocal
This script will purge all cached Kerberos tickets on the local computer for all sessions (whether interactive, network or other sessions).



