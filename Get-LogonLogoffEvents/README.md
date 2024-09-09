# SYNOPSIS
Parses Security Eventlog for successful Logons/Logoffs and matches on LogonIDs
# DESCRIPTION
ProTip: use with | ft to print a table of the combined Events to console
Bonus Tip: Parameter CompleteSessionsOnly does not give you active sessions (obviously!)

## Features:
This Script reads the live Security Eventlog (if you are admin), or a saved Eventlog EVTX File,
parses the Log for successful logon/logoff Events,
filters for relevant info if you want (AllEvents, or real User),
tries to match the LogonIDs,
and returns the Object for further use, or exports it to csv.

**EventIDs checked:**
4624 - An account was successfully logged on
4634 - An account was logged off
4647 - User initiated logoff

# NOTES
mbeckert 2024

**TODOs:**
- print active sessions in completesessionsonly mode

**EventData.Data matching IDs**
- 5=username
- 8=logontype
- 18=logonIP
- 7=LogonID

**Logon Type Description**
- 2	Interactive (logon at keyboard and screen of system)
- 3	Network (i.e. connection to shared folder on this computer from elsewhere on network)
- 4	Batch (i.e. scheduled task)
- 5	Service (Service startup)
- 7	Unlock (i.e. unnattended workstation with password protected screen saver)
- 8	NetworkCleartext (Logon with credentials sent in the clear text. Most often indicates a logon to IIS with "basic authentication") See this article for more - information.
- 9	NewCredentials such as with RunAs or mapping a network drive with alternate credentials.  This logon type does not seem to show up in any events.  If you want to - track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. - The new logon session has the same local identity, but uses different credentials for other network connections."
- 10	RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)
- 11	CachedInteractive (logon with cached domain credentials such as when logging on to a laptop when away from the network)
# LINK
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
# PARAMETERS
## -LogFile
Path to a Logfile. Leave blank for live Security event Log (must be admin)
## -Mode
How output is composed
CompleteSessionsOnly    - show only entries that have logon and logoff events matched
AllEvents               - show all logon/logoff events, even if no logoff event was found
AllEventsButNoSYSTEM    - same as AllEvents but removes the SYSTEM Account, since it is very noisy
AllUserEvents           - same as AllEvents but removes SYSTEM and ComputerAccounts (less noise)
## -OutputFile
Path to CSV output file - leave blank for terminal-only results
# EXAMPLES
## EXAMPLE 1
``` powershell
.\Get-LogonLogoffEvents.ps1 | ft
```
Prints a detailed table on the console with every logon event, where the user logged off again
# EXAMPLE 2
``` powershell
.\Get-LogonLogoffEvents.ps1 -Mode AllEvents -Verbose | ft
```
Prints a detailed table on the console with every logon event and also gives you some infos of what is happening while the script is executing
# EXAMPLE 3
``` powershell
Get-LogonLogoffEvents.ps1 -Mode AllUserEvents -Verbose -OutputFile C:\temp\AllUserLogons.csv
```
Writes a CSV with every logon event of a user (so no SYSTEM or MachineAccount) and also gives you some infos of what is happening while the script is executing
# EXAMPLE 4
``` powershell
.\Get-LogonLogoffEvents.ps1 -Mode AllEventsButNoSYSTEM | fl
```
Prints a detailed list on the console with every logon event, but skippes the SYSTEM Account logons
