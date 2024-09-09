# SYNOPSIS
Searches for modified Scheduled Tasks in Security Eventlog
# DESCRIPTION
Searches for modified Scheduled Tasks in Security Eventlog. Does not work with other EventIDs since the XML schema is fixed for TaskScheduler
**Features:**
- displays your auditing settings
- per default looks for EventIDs 4698, 4699, 4700, 4701, 4702 or the ones you choose
- composes the events into a nice array
- Output options: exports as csv, print object for further use or print formatted table
- can exclude noisy Microsoft stuff like deviceenroller or defender
- Warning: only selects the first trigger
- Warning: maybe doesnt show additional commands correctly (more than 1 command)
- Warning: sorting doent quite work since I was lazy with the objects in the end :)

For more informations on the output fields, check readme file
# NOTES
mbeckert 2024

### TODOs
- input evtx file instead of live security eventlog
- start time 
- catch empty events error
# PARAMETERS
## ExportPath
If specified, exports the output to csv. does not display the result on console
## EventIds
If specified uses the ones given, otherwise uses the default IDs
4698 - Task created
4699 - Task deleted
4700 - Task enabled
4701 - Task disabled
4702 - Task updated

##  ExcludeKnownMicrosoft
If specified, excludes some noisy Microsoft stuff:
- Source = Microsoft
- SvcRestartTask
- RefreshCache
- Intune Enroller
- UpdateOrchestrator Scan
- UpdateOrchestrator Reboot Info
- WindowsUpdate start
- Windows Defender scan
## QuickFormat
If specified, formats the output in a table with the most important informations. Dont use this, if you want to dig deeper.
# EXAMPLES
## EXAMPLE 1
```
.\Get-ScheduledTaskModifications.ps1 | fl
```
Searches for modified Scheduled Tasks in Security Eventlog and returns a list with all useful informations
## EXAMPLE 2
```
.\Get-ScheduledTaskModifications.ps1 -ExportPath c:\forensics\taskmods.csv
```
Exports the found modifications to scheduled tasks to a csv
## EXAMPLE 3
```
.\Get-ScheduledTaskModifications.ps1 -EventIds 4702 -QuickFormat
```
Only searches for tasks, that have been updated and prints a formatted table with most useful informations
## EXAMPLE 4
```
.\Get-ScheduledTaskModifications.ps1 -ExcludeKnownMicrosoft -verbose | ft Timecreated, command, user
```
Searches for modified Scheduled Tasks in Security Eventlog but excludes noisy microsoft stuff.
Prints a table when task was modified by whom and what command is specified in the task.
Also gives more informations while the script is runnning (for example the exclusions)
## EXAMPLE 5
```
.\Get-ScheduledTaskModifications.ps1 | where {$_.user -like "*mbeckert*"} | fl 
```
Prints a list of all modifications to scheduled tasks by mbeckert
