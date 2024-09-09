# SYNOPSIS
This script will purge all cached Kerberos tickets on the local computer for all sessions (whether interactive, network or other sessions).
# DESCRIPTION
This script finds all logon sessions which have Kerberos tickets cached and for each session purges the ticket granting tickets and the tickets using klist.exe..
In a well-connected environment clients will request and obtain Kerberos tickets on demand without interruption.
If not well-connected to a domain controller (remote network) then further network resource authentication may fail or use NTLM if tickets are purged.
# NOTES
SHD Forensics
mbeckert 2024
# LINK
www.shd-online.de
# EXAMPLE
```powershell
Purge-TicketsLocal.ps1
```
Just confirm activity in the warning and all Tickets of all logon sessions will be purged
