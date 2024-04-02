### SYNOPSIS
Returns all Executable Files of a given FolderPath
mbeckert 2024
### DESCRIPTION
Returns an Array of Selected.System.IO.FileInfo of all given Executable FileExtensions of a given FolderPath. Also calculates hashes and size of the findings
**Pro Tips**
- Use with | ft to get a formatted table
- Use with | Export-Csv to export the findings
- Use with | ? {$_.creationtime -gt ((Get-date).AddDays(-10))} to get executables, that were created in the last 10 days

```
Default Executables to search for:
BAT,BIN,CMD,COM,CPL,EXE,INS,INX,ISU,JOB,JSE,LNK,MSC,MSI,MSP,MST,PAF,PIF,PS1,REG,RGS,SCR,SCT,SHB,SHS,U3P,VB,VBE,VBS,WS,WSF,WSH,GADGET,VBSCRIPT,INF1
```

Outputs following fields
- Extension     
- Name          
- Mode          
- Size (KB)     
- CreationTime  
- LastWriteTime 
- DirectoryName 
- SHA1

### NOTES
I intentionally skipped most FileInfo, because they are not relevant for fast IR

### TODOs:
- change write methods to [+] -> its prettier!
- exclude param for the lazy ones
### LINK
https://www.shd-online.de/leistungsprofil/it-security/loesungen/incident-response-team/
### EXAMPLE
Get-Executables -Verbose
Returns all executables as a List and shows some informations while processing

### EXAMPLE
"C:\myfolder" | .\Get-ExecutableFiles.ps1 | ? {$_.creationtime -gt ((Get-date).AddDays(-10))} | Export-csv c:\myfiles.csv -NoTypeInformation
Exports all executables of folder C:\myfolder, that were created in the last 10 Days to a csv

### EXAMPLE
Get-Executables -Path "C:\temp\ | ft
Returns all executables of the folder C:\temp and formats the output as a readable table
