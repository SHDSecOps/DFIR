<#
.SYNOPSIS
    Searches for modified Scheduled Tasks in Security Eventlog
.DESCRIPTION
    Searches for modified Scheduled Tasks in Security Eventlog. Does not work with other EventIDs since the XML schema is fixed for TaskScheduler
    Features:
    - displays your auditing settings
    - per default looks for EventIDs 4698, 4699, 4700, 4701, 4702 or the ones you choose
    - composes the events into a nice array
    - Output options: exports as csv, print object for further use or print formatted table
    - can exclude noisy Microsoft stuff like deviceenroller or defender
    - Warning: only selects the first trigger
    - Warning: maybe doesnt show additional commands correctly (more than 1 command)
    - Warning: sorting doent quite work since I was lazy with the objects in the end :)
    
    For more informations on the output fields, check readme file
.NOTES
    mbeckert 2024

    TODOs
    - input evtx file instead of live security eventlog
    - start time 
    - catch empty events error
.PARAMETER ExportPath
    If specified, exports the output to csv. does not display the result on console
.PARAMETER EventIds
    If specified uses the ones given, otherwise uses the default IDs
    4698 - Task created
    4699 - Task deleted
    4700 - Task enabled
    4701 - Task disabled
    4702 - Task updated
.PARAMETER ExcludeKnownMicrosoft
    If specified, excludes some noisy Microsoft stuff:
    - Source = Microsoft
    - SvcRestartTask
    - RefreshCache
    - Intune Enroller
    - UpdateOrchestrator Scan
    - UpdateOrchestrator Reboot Info
    - WindowsUpdate start
    - Windows Defender scan
.PARAMETER QuickFormat
    If specified, formats the output in a table with the most important informations. Dont use this, if you want to dig deeper.
.EXAMPLE
    .\Get-ScheduledTaskModifications.ps1 | fl
    Searches for modified Scheduled Tasks in Security Eventlog and returns a list with all useful informations
.EXAMPLE
    .\Get-ScheduledTaskModifications.ps1 -ExportPath c:\forensics\taskmods.csv
    Exports the found modifications to scheduled tasks to a csv
.EXAMPLE
    .\Get-ScheduledTaskModifications.ps1 -EventIds 4702 -QuickFormat
    Only searches for tasks, that have been updated and prints a formatted table with most useful informations
.EXAMPLE
    .\Get-ScheduledTaskModifications.ps1 -ExcludeKnownMicrosoft -verbose | ft Timecreated, command, user
    Searches for modified Scheduled Tasks in Security Eventlog but excludes noisy microsoft stuff.
    Prints a table when task was modified by whom and what command is specified in the task.
    Also gives more informations while the script is runnning (for example the exclusions)
.EXAMPLE   
    .\Get-ScheduledTaskModifications.ps1 | where {$_.user -like "*mbeckert*"} | fl 
    Prints a list of all modifications to scheduled tasks by mbeckert
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateScript({ #all this just to verify that input is actually a valid path
            if (-Not ($_ | Test-Path) ) {
                throw "File or folder does not exist" 
            }
            return $true
        })]
    [string]$ExportPath,
    [Parameter(Mandatory = $false)]
    [ValidateSet(4698, 4699, 4700, 4701, 4702)]
    [Int32[]]$EventIds = (4698, 4699, 4700, 4701, 4702),
    [Parameter(Mandatory = $false)]
    [Switch]$ExcludeKnownMicrosoft = $false,
    [Parameter(Mandatory = $false)]
    [Switch]$QuickFormat = $false
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

#display auditsettings
try {
    
    Write-Host "Check if your Auditing is enabled correctly - otherwise there may not be any events logged" -ForegroundColor DarkYellow
    if ((Get-WinSystemLocale).name -eq "en-US") {
        Write-Verbose "[+] english OS detected"
        auditpol.exe /get /subcategory:"Other Object Access Events"  #HKLM\SECURITY\Policy\PolAdtEv
    }
    elseif ((Get-WinSystemLocale).name -eq "de-DE" ) {
        Write-Verbose "[+] german OS detected"
        auditpol.exe /get /subcategory:"Andere Objektzugriffsereignisse"
    }
    else {
        Write-Warning "Unknown Language detected"
    }
}
catch {
    Write-Verbose "[-] Cant display Auditsettings continuing"
}

if ($ExcludeKnownMicrosoft) {
    Write-Warning "Known noisy Microsoft Tasks will be excluded. Be careful with that switch!"
}

#[Int32[]]$EventIds = (4698, 4699, 4700, 4701, 4702) #testing
#[Int32[]]$EventIds = (4702) #testing
$addedresult = @()
foreach ($EventId in $EventIds) {
    Write-Verbose "[+] Getting Events of EventID $EventId"
    $Events = Get-WinEvent -FilterHashTable @{ LogName = "Security"; ID = $EventId } #testing maxevents 1
    Write-Verbose "[+] Found $($Events.Count) Events"
    foreach ($Event in $Events) {
        #[string]$command = "" #is this important?
        $EventXml = [xml]$Event.ToXml()
        if ($EventId -eq 4702) {
            [xml]$taskcontentxml = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "TaskContentNew" }).'#text') 
        }
        else {
            [xml]$taskcontentxml = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "TaskContent" }).'#text')  #taskcontent bei 4700
        }

        if ($ExcludeKnownMicrosoft) {
            Write-Verbose "[-] Excluding Source = Microsoft"
            if ($taskcontentxml.Task.RegistrationInfo.Source -eq "Microsoft Corporation.") {
                continue
            }
            Write-Verbose "[-] Excluding SvcRestartTask"
            if ($taskcontentxml.Task.RegistrationInfo.Source -match '\$\(@%systemroot%\\system32\\sppc\.dll') {
                continue
            }
            Write-Verbose "[-] Excluding RefreshCache"
            if ($taskcontentxml.Task.RegistrationInfo.Source -match '\$\(@%systemroot%\\system32\\wosc\.dll') {
                continue
            }
            Write-Verbose "[-] Excluding Intune Enroller"
            if ($taskcontentxml.task.actions.exec.command -eq '%windir%\system32\deviceenroller.exe' -and $taskcontentxml.task.actions.exec.arguments -eq '/c /AutoEnrollMDMUsingAADDeviceCredential') {
                continue
            }
            Write-Verbose "[-] Excluding UpdateOrchestrator Scan"
            if ($taskcontentxml.task.actions.exec.command -eq '%systemroot%\system32\usoclient.exe' -and $taskcontentxml.task.actions.exec.arguments -eq 'StartScan') {
                continue
            }
            Write-Verbose "[-] Excluding UpdateOrchestrator Reboot Info"
            if ($taskcontentxml.task.actions.exec.command -eq '%systemroot%\system32\MusNotification.exe') {
                continue
            }
            Write-Verbose "[-] Excluding WindowsUpdate start"
            if ($taskcontentxml.task.actions.exec.arguments -eq 'start wuauserv' -and $taskcontentxml.task.actions.exec.command -eq 'C:\Windows\system32\sc.exe') {
                continue
            }
            Write-Verbose "[-] Excluding Windows Defender scan"
            if ($taskcontentxml.task.actions.exec.arguments -eq 'Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob' -and $taskcontentxml.task.actions.exec.command -eq 'C:\Program Files\Windows Defender\MpCmdRun.exe') {
                continue
            }
        }
    
    
        #trigger calc
        if ($taskcontentxml.Task.Triggers.LogonTrigger) { $trigger = "On Logon" }
        elseif ($taskcontentxml.Task.Triggers.TimeTrigger) { $trigger = "On Schedule" }
        elseif ($taskcontentxml.Task.Triggers.IdleTrigger) { $trigger = "On Idle" } 
        elseif ($taskcontentxml.Task.Triggers.SessionStateChangeTrigger) { $trigger = "On Lock" } #lock
        elseif ($taskcontentxml.Task.Triggers.BootTrigger) { $trigger = "On Startup" } #startup
        else { $trigger = "Unknown trigger" }

        #if there are more than 1 commands
        #$taskcontentxml.task.actions.exec.command | foreach {$command+="$_ "}
        #if there are more than 1 args
        #$taskcontentxml.task.actions.exec.arguments | foreach {$comparguments+="$_ "}

        switch ($EventId) {
            4698 { $eventiddisplayname = "created" }
            4699 { $eventiddisplayname = "deleted" }
            4700 { $eventiddisplayname = "enabled" }
            4701 { $eventiddisplayname = "disabled" }
            4702 { $eventiddisplayname = "updated" }
            Default { $eventiddisplayname = "other" }
        }
        Write-Debug "Composing Event" #noisy
        $Result = [pscustomobject]@{
            TimeCreated = $event.TimeCreated
            eventid     = $Event.ID
            EventName   = $eventiddisplayname
            Name        = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "TaskName" }).'#text')
            SID         = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "SubjectUserSid" }).'#text')
            User        = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "SubjectUserName" }).'#text')
            LogonID     = ((($EventXml.Event.EventData.Data) | where { $_.name -eq "SubjectLogonId" }).'#text')
            Author      = $taskcontentxml.Task.RegistrationInfo.Author
            Source      = $taskcontentxml.Task.RegistrationInfo.Source
            Hidden      = $taskcontentxml.task.Settings.Hidden
            Enabled     = $taskcontentxml.task.Settings.Enabled
            Trigger     = $trigger #caution - only selects the first trigger
            Principal   = $taskcontentxml.task.principals.principal.userid #principal = the one running the task
            RunLevel    = $taskcontentxml.task.principals.principal.runlevel
            principalid = $taskcontentxml.task.principals.principal.id
            runcontext  = $taskcontentxml.Task.Actions.Context
            command     = $taskcontentxml.task.actions.exec.command #not always run command
            argument    = $taskcontentxml.task.actions.exec.arguments #not always run command
            Path        = $taskcontentxml.Task.RegistrationInfo.URI
            Description = $taskcontentxml.Task.RegistrationInfo.Description
            #((($EventXml.Event.EventData.Data) | where {$_.name -eq "TaskContentNew"}).'#text')# raw event data
        }
        $addedresult += $Result
    }
}
if ($ExportPath) {
    $addedresult | Export-Csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Path $ExportPath
}
elseif ($QuickFormat) {
    $addedresult | sort TimeCreated -Descending | ft TimeCreated, EventName, User, name, command, runcontext, runlevel
}
else {
    $addedresult
}

