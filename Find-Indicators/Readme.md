# Find-Indicators
Mike Beckert (SHD) 2024
This Script returns all Indicators (e.g. IPs) from a given String, File, Folder or Log
### DESCRIPTION
This Script searches for all IPs, Mac,Mailaddresses,URLs or custom pattern in a given Input via RegEx.
*Short Version of this Script is at the End of this Description*

**Minimun inputs are at least one of these:**
- inputstring -> String, searches inside the given String; Default Parameter. Can also be pipelined into this script with <string> | Find-IP.ps1
- File        -> filepath, searches inside the given file
- folder      -> folderpath, searches in all inside Files in that folder
- Log         -> EventlogName (e.g. Security or Application)
- LogFile     -> Saved evtx file to search for

**Search parameters:**
- FindIPv4 -> default; matches IPv4 addresses
- FindIPv6 -> matches IPv6 addresses
- FindMac  -> matches mac addresses
- FindMail -> matches typical mail addresses (sometimes not working properly!)
- FindURL  -> matches https/www addresses - I need to find a better regex for this!
- customregex -> if you want to change the regex 
- FindSuccessfulLoginIPs -> searches the Security Eventlog for successful logins and returns IPv4 addresses that loggedon
- FindFailedLoginIPs     -> searches the Security Eventlog for failed login attempts and returns IPv4 addresses that tried
    
** Other valid parameters are**
- formatcommaseperated -> formats the output in with "," so you can copy it into another System; Alias = format
- verbose -> also outputs some more runtime informations like found files, regex etc
- debug -> also outputs the whole content which is searched for IPs

**Normal Output:**
a distinct list of all matches (default=IPv4), that match the regex pattern and the number of occurences
pipe the output for further use (e.g. ... | Export-csv .\myfindings.csv)

**Formatted Output:**
comma seperated String with all distincs IPs, surrounded by "" -> Optimized for Azure Sentinel copypaste

**Short Version:**
```
#yourstring = "Erwin@knatterhose.lol-myipaddressisnot192.168.1.254duh"
$ipregex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
[regex]::Matches($yourstring, $ipregex) | foreach { $_.Value }
```

### OUTPUTS
>Default: Selected.Microsoft.PowerShell.Commands.GroupInfo
    Example Output
    Name           Count
    ----           -----
    109.40.240.215     1
    84.143.17.151      4
    51.163.4.52       10
    -or-
>with Format Switch: System.String
    Example Output
    "51.163.4.52","84.143.17.151","109.40.240.215"
### INPUTS
    Important: Powershell is trying to get the right Encoding - if you want to force a specific encoding, alter this script @ command "Get-Content -encoding <your encoding>"    
    String, Filename, Foldername, eventlog, evtx eventlog file
### NOTES
Default Regex used in this script:
```
IPv4 '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
IPv6 '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
Mac  '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
Mail '(([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)(\s*;\s*|\s*$))*' -> regeex ist falsch!
Mail funktionierend \w+@\w+\.\w{2,3}
URLs '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
```
### TODOs:
- move verififications of files/folders to param section
- output, where each indicator was found in verbose mode
- change write methods to [+] -> its prettier!
### LINK
    https://github.com/joshbrunty/DFIR-Regular-Expressions
### Parameters
#### PARAMETER inputstring
    Text that contains the informations you want to gather
    Default Parameter @ Position 0 (doesn't need to be named)
    You can also pipe any string into this script
#### PARAMETER file
    Filepath that contains the informations you want to gather
#### PARAMETER folder
    Folderpath that contains the informations you want to gather
#### PARAMETER EventlogName
    Log that contains the informations you want to gather
    Use Get-EventLog -List to get the names
#### PARAMETER SavedEventlogFile   
    LogFile path in evtx that contains the informations you want to gather
#### PARAMETER FindIPv4
    default; use IPv4 address pattern
#### PARAMETER FindIPv6
    use IPv6 address Pattern
#### PARAMETER FindMac
    use Mac address pattern
#### PARAMETER FindMail
    use mail address pattern
#### PARAMETER FindURL
    use URL pattern
#### PARAMETER FindSuccessfulLoginIPs
    Switch if you want to get all IPv4 that were used to successfully login
#### PARAMETER FindFailedLoginIPs
    Switch if you want to get all IPv4 that tried unsuccessfully to login
#### PARAMETER customregex
    Pattern as Text, if you want to search for something different
#### PARAMETER formatcommaseperated
    Switch if you want to change Outputformat
    Alias = format
### Examples
#### EXAMPLE
    Find-Indicators.ps1 -file "C:\temp\myfile.log"
    Finds all IPv4 Addresses in the myfile.log file and outputs a table with distinct IPs and the number of occurences
#### EXAMPLE
    Find-Indicators.ps1 -folder "C:\temp" -FindURL
    Finds all URLs in all files in the folder C:\temp and outputs a table with distinct URLs and the number of occurences over all files
#### EXAMPLE
    Find-Indicators.ps1 -folder "C:\temp\" -format -FindIPv6
    Finds all IPv6 Addresses in all files in the folder C:\temp and outputs the distinct IPs as comma seperated string, which can be copied e.g. into Azure Sentinel TI
#### EXAMPLE
    "my192.168.12.1string10.1.1.4with172.0.0.1some51.99.99.11IP" | Find-Indicators.ps1 -verbose
    Finds all IPv4 Addresses in the string "my192.168.12.1string10.1.1.4with172.0.0.1some51.99.99.11IP" and outputs a table with distinct IPs and the number of occurences. Also outputs some more runtime informations because of the verbose switch
#### EXAMPLE
    Find-Indicators.ps1 -Log System
    Finds all IPv4 Addresses in the System EventLog and outputs a table with distinct IPs and the number of occurences
#### EXAMPLE
    Find-Indicators.ps1 -FindSuccessfulLoginIPs
    Finds all IPv4 Addresses of successful Logins in the Security EventLog and outputs a table with distinct IPs and the number of occurences
#### EXAMPLE
    Find-Indicators.ps1 -FindFailedLoginIPs -SavedEventlogFile "C:\temp\mysecuritylog.evtx"
    Finds all IPv4 Addresses of failed Login atempts in the mysecuritylog.evtx FIle and outputs a table with distinct IPs and the number of occurences
