<#
.SYNOPSIS
  Searches for encoded command exections in a Powershell Operational Eventlog and tries to decode it
.DESCRIPTION
  Searches for encoded command exections in a Powershell Operational Eventlog with regex and tries to decode it. Returns an Arraylist with all necessary informations. Use -PreFormatAsTable if you only want to see the Output in console
.NOTES
  Mike Beckert 2022-12-28 @ SHD Systemhaus Dresden GmbH
  TODOs:
   - Errorhandling when failure at decoding
   - Searching in remote Eventlogs (credential, computername)
   - Prevalidate all possible Eventlogs
   - piping stuff in
   - minicommands for quick usage
   - -e can also be -encoded lol -> fix it pls asap
.PARAMETER SavedEventFile
  Specifies the evtx File in filesystem
  Alias: file
.PARAMETER LogName
  Sepcifies the WindowsEventlog. Get Name by using: Get-WinEvent -ListLog *
  Alias: log
.PARAMETER PreFormatAsTable
  When using this switch, the Array is preformatted as Table with Unique rows for console Output
  Alias: pf
.PARAMETER FullOutput
  When using this switch, the Array crowded with more informations like RecordID, MachineName, LogName, Level, Keywords, EventId, Provider
  Alias: full
.PARAMETER verbose
  Gets you more informations about what's happening
.INPUTS
  None. Currently you cannot pipe anything into this script
.OUTPUTS
  System.Collections.ArrayList for further usage
  -OR-
  Formatted Table with unique rows and sorted by TimeCreated. Columns: TimeCreatedLocal, TimeCreatedUTC, DecodedCommand, EncodedCommand
.EXAMPLE
  .\Decode-PSEventlogCommands.ps1 -File .\PowershellToolsDownload.evtx -FullOutput -Verbose
  Outputs all the informations as array for further usage
.EXAMPLE
  .\Decode-PSEventlogCommands.ps1 -File C:\temp\PowershellToolsDownload.evtx -FullOutput -Verbose | where {$_.decodedcommand -like "*download*"} | select timecreatedutc, decodedcommand, machinename | ft -au
  Outputs only the downloads as table
.EXAMPLE
  .\Decode-PSEventlogCommands.ps1 -File .\PowershellToolsDownload.evtx -PreFormatAsTable
  Gives you a quick overview of unique commands from the evtx file in console
.EXAMPLE
  .\Decode-PSEventlogCommands.ps1 -LogName Microsoft-Windows-PowerShell/Operational
  Gives you a quick overview of unique commands from the PS EventLog in console
#>
[CmdletBinding()]

Param(
  [Parameter( Position = 0, Mandatory = $false, ParameterSetName = 'File' )] 
  [Alias( 'file' )]
  [ValidateNotNullOrEmpty()]
  [string]$SavedEventFile = '',

  [Parameter(Mandatory = $false, ParameterSetName = 'Online' )]
  [Alias( 'log' )]
  [ValidateNotNullOrEmpty()]
  [string]$LogName = '',

  [Parameter( Mandatory = $false, ParameterSetName = 'File' )]
  [Parameter( Mandatory = $false, ParameterSetName = 'Online' )]
  [Parameter( Mandatory = $false, ParameterSetName = 'full' )]
  [Alias( 'full' )]
  [switch]$FullOutput,
  
  [Parameter( Mandatory = $false, ParameterSetName = 'File' )]
  [Parameter( Mandatory = $false, ParameterSetName = 'Online' )]
  [Parameter( Mandatory = $false, ParameterSetName = 'format' )]
  [Alias( 'pf' )]
  [switch]$PreFormatAsTable
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
Write-Host $ASCIIBanner -ForegroundColor Green

Write-Verbose "Fetching Events..."
try {
  
  if ($SavedEventFile -ne '') {
    $events = Get-WinEvent -Path $SavedEventFile
  }
  elseif ($LogName -ne '') {
    $events = Get-WinEvent -LogName $LogName
  } 
  else {
    Write-Error "No valid WinEventLog was specified"
  }
}
catch {
  $_.Exception
}
Write-Verbose "$($events.Count) Events found"

$array = [System.Collections.ArrayList]@()
$matchedevents = 0

<#
.SYNOPSIS
  Decode base64 byte array to readable string
#>
function Convert-Command {
  param ([Parameter(Position = 0, Mandatory = $true)][string]$encodedcommand)
  Write-Verbose "Decoding command: $encodedcommand"
  try {
    return ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedcommand)))
  }
  catch {
    Write-Host "Cannot decode command! Propably not a valid base64 string." -ForegroundColor Red
    Write-Host 'Use the following command to encrypt your string yourself: ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(<yourencodedcommand>)))' -ForegroundColor DarkMagenta
    $_.Exception
  }
}

Write-Verbose "Searching for encoded commands..."

foreach ($event in $events) {
  if ($event.message -match "powershell\.exe.*\s-e\s") {
    $matchedevents++
    Write-Verbose "Matched $matchedevents. Event at $($event.TimeCreated.tostring())"
    [string]$message = ($event | select -ExpandProperty message).tostring()
    $message -match "-e\s.*" | Out-Null
    $encodedcommand = $Matches[0].substring(3) #das bringt bestimmt mal paar fehler aber yolo

    Write-Verbose "Building Array..."
    $col0 = $event.RecordID
    $col1 = $event.TimeCreated.ToString()
    $col2 = $event.TimeCreated.ToUniversalTime()
    $col3 = Convert-Command $encodedcommand 
    $col4 = $encodedcommand

    if (!$FullOutput) {
      $array += [pscustomobject]@{
        RecordID         = $col0
        TimeCreatedLocal = $col1
        TimeCreatedUTC   = $col2
        DecodedCommand   = $col3
        EncodedCommand   = $col4 
      }
    }
    else {
      $col5 = $event.MachineName
      $col6 = $event.LogName
      $col7 = $event.LevelDisplayName
      $col8 = $event.KeywordsDisplayNames
      $col9 = $event.Id
      $col10 = $event.ProviderName
  
      $array += [pscustomobject]@{
        RecordID         = $col0
        TimeCreatedLocal = $col1
        TimeCreatedUTC   = $col2
        DecodedCommand   = $col3
        EncodedCommand   = $col4
        MachineName      = $col5
        LogName          = $col6
        Level            = $col7
        Keywords         = $col8
        EventId          = $col9 
        Provider         = $col10
      }
    }
  }
}
write-host "Found $matchedevents Encoded Commands" -ForegroundColor Cyan

if ($PreFormatAsTable) {
  $array | select TimeCreatedLocal, TimeCreatedUTC, DecodedCommand, EncodedCommand -Unique | sort timestamp | ft -au
}
else {
  return $array
}

<# #alt
(Get-WinEvent -Path .\PowershellToolsDownload.evtx | where {$_.message -match "powershell.exe -e"}) | select -ExpandProperty message | out-string | out-file .\eventmessages.txt
$matching = (Get-Content .\eventmessages.txt | Select-String -Pattern "-e.*") 

#-match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$" #match base64 encoded string

$x = $matching | foreach {$_.tostring().replace("HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -e","") } #TODO besser machen
#{[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_))} #decode

#>

<#
Ids CommandLine
 --
}-
   1 (Get-WinEvent -Path .\PowershellToolsDownload.evtx | where {$_.message -match "powershell.exe -e"}) | select -ExpandProperty message)
   2 (Get-WinEvent -Path .\PowershellToolsDownload.evtx | where {$_.message -match "powershell.exe -e"}) | select -ExpandProperty message
   3 (Get-WinEvent -Path .\PowershellToolsDownload.evtx | where {$_.message -match "powershell.exe -e"}) | select -ExpandProperty message | out-string
   4 (Get-WinEvent -Path .\PowershellToolsDownload.evtx | where {$_.message -match "powershell.exe -e"}) | select -ExpandProperty message | out-string | out-file .\events.txt
   5 Get-Content .\events.txt | Select-String -Pattern "-e.*"
   6 history
   7 (Get-Content .\events.txt | Select-String -Pattern "-e.*") -match "^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]==|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048]=)?$"
   8 (Get-Content .\events.txt | Select-String -Pattern "-e.*").replace("HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -e","")
   9 (Get-Content .\events.txt) -match "-e.*"
  10 $Matches
  11 (Get-Content .\events.txt | Select-String -Pattern "-e.*") -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
  12 (Get-Content .\events.txt) -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
  13 Get-Content .\events.txt | Select-String -Pattern "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
  14 (Get-Content .\events.txt | Select-String -Pattern "-e.*")
  15 $matching = (Get-Content .\events.txt | Select-String -Pattern "-e.*")
  16 $matching.count()
  17 $matching.count
  18 $matching | foreach {$_.tostring().replace("HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -e","") }
  19 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"}
  20 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"; $matches[0]}
  21 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$" | out-null; $matches[0]}
  22 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$" | out-null; $x= $matches[0]}
  23 $x
  24 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$" | out-null; $x+= $matches[0]}
  25 $x
  26 $x | foreach {[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_))}
  27 $matching | foreach {$_ -match "(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$" | out-null; $x= $matches[0]}
  28 $x
  29 $x | foreach {[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_))}

#>
