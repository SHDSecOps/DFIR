# SYNOPSIS
Tests the given String Array against VT and returns a formatted table sorted by malicious analysis count.
# DESCRIPTION
This Script tests the given Inputs (String[]) against VT with your own or Mikes APIKey.
Returns a formatted table sorted by malicious analysis count or the raw object for further use.
Features:
- Takes multiple Strings and checks them
- returns formatted table or object
- doesnt make API calls if not matched to IPv4, Filehash, URL, Domain
- of you get Statuscode 429 (too many requests aka Quota Timeout), the script waits 1 minute and tries again
- use own api key or mbeckert's
- output fields: ID, Country, malicious, suspicious, undetected, harmless, votes_malicious, votes_harmless, Link
- Link is rewritted to the GUI URL, so you can paste it into the browser
# NOTES
mbeckert 2024 SHD
TODOs
- IPV6 match
- catch error codes (below the script)
- fine granular results output
- POST wenn keine url gefunden
- implement to IOCExtractor
# LINK
https://docs.virustotal.com/reference/overview
# EXAMPLE 1
```powershell
.\Invoke-VTReport.ps1 -Verbose -tests "bea7557fca6f6aa3fc3be3c2acbdb45f","92.204.58.106","https://www.eventhotels.com/","mail.ru","nomatch"
```
Tests the given Strings against VT with your default APIKey in the script and returns a formatted table sorted by malicious analysis count
# EXAMPLE 2
```powershell
.\Invoke-VTReport.ps1 -Verbose -tests "92.204.58.106" -ApiKey "myapikeyisawesome123"
```
Tests the given IP against VT with your own APIKey and returns a formatted table sorted by malicious analysis count
# EXAMPLE 3
```powershell
.\Invoke-VTReport.ps1 -Verbose -tests "92.204.58.106" -ApiKey "myapikeyisawesome123" -NoFormat
```
Tests the given IP against VT with your own APIKey and returns the pscustomobject for further use
