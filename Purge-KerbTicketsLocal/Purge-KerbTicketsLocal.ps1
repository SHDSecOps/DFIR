<#
.SYNOPSIS
	This script will purge all cached Kerberos tickets on the local computer for all sessions (whether interactive, network or other sessions).
.DESCRIPTION
	This script finds all logon sessions which have Kerberos tickets cached and for each session purges the ticket granting tickets and the tickets using klist.exe..
	In a well-connected environment clients will request and obtain Kerberos tickets on demand without interruption.
	If not well-connected to a domain controller (remote network) then further network resource authentication may fail or use NTLM if tickets are purged.
.NOTES
	SHD Forensics
	mbeckert 2024
.LINK
	www.shd-online.de
.EXAMPLE
	Purge-KerbTicketsLocal.ps1
	Just confirm activity in the warning and all Tickets of all logon sessions will be purged
#>

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

#test ob local admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isadmin) {
    Write-Host "[+] Script is running with admin privileges." -f Gray
}
else {
	Write-Warning "[-] Script is not running with admin privileges. Still try?" -WarningAction Inquire
}

#purge all the tickets 
Write-Warning "This script will purge all saved Kerberos tickets!" -WarningAction Inquire
$sessions = @()
(Get-WmiObject win32_LogonSession) | foreach { $sessions += '0x' + [Convert]::ToString($_.LogonID, 16) }
$Sessions | foreach	{ klist.exe -li $_ purge }

Write-Host "Remember to close current sessions (SMB, Web, etc.)" -f Magenta
Write-Host "Use <Get-SmbSession | Close-SmbSession> on Servers" -f Magenta
