<#
.SYNOPSIS
    Returns all Executable Files of a given FolderPath
    mbeckert 2024
.DESCRIPTION
    Returns an Array of Selected.System.IO.FileInfo of all given Executable FileExtensions of a given FolderPath. Also calculates hashes and size of the findings
    Use with | ft to get a formatted table
    Use with | Export-Csv to export the findings

    Default Executables to search for:
    BAT,BIN,CMD,COM,CPL,EXE,INS,INX,ISU
    JOB,JSE,LNK,MSC,MSI,MSP,MST,PAF,PIF
    PS1,REG,RGS,SCR,SCT,SHB,SHS,U3P,VB
    VBE,VBS,WS,WSF,WSH,GADGET,VBSCRIPT,INF1

    Outputs following fields
    - Extension     
    - Name          
    - Mode          
    - Size (KB)     
    - CreationTime  
    - LastWriteTime 
    - DirectoryName 
    - SHA1          
.NOTES
    I intentionally skipped most FileInfo, because they are not relevant for fast IR

    TODOs:
    - excludefiletype param for the lazy ones
.LINK
    https://www.shd-online.de/leistungsprofil/it-security/loesungen/incident-response-team/
.EXAMPLE
    .\Get-Executables -Verbose
    Outputs a list of all executable files that this script searches for. Uses current location since none is given. Also gives verbose infos while executing (very noisy)
.EXAMPLE
    .\Get-ExecutableFiles.ps1 -Path 'C:\Temp\' | ft -au
    Outputs a formatted table of all executable files that this script searches for in the folder c:\temp
.EXAMPLE
    .\Get-Executables -path "C:\windows\system32" -filetypes ps1,exe | Export-csv -path C:\forensics\foundfiles.csv -encoding UTF8 -notypeinformation
    Eports a csv of all .exe and .ps1 files in folder c:\windows\system32 to the folder C:\forensics\foundfiles.csv
#>

[CmdletBinding()]

Param(
    [Parameter( Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ #all this just to verify that input is actually a valid path, and if there is none - use current locations
        if(!$_) {
            $Path = Get-Location #use current location, if no path is specified
        }
        if(-Not ($_ | Test-Path) ){
            throw "File or folder does not exist" 
        }
        return $true
    })]
    [System.IO.FileInfo]$Path, 

    [Parameter( Position = 1, Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)] 
    [ValidateNotNullOrEmpty()]
    [string[]]$filetypes = @("BAT","BIN","CMD","COM","CPL","EXE","INS","INX","ISU","JOB","JSE","LNK","MSC","MSI","MSP","MST","PAF","PIF","PS1","REG","RGS","SCR","SCT","SHB","SHS","U3P","VB","VBE","VBS","WS","WSF","WSH","GADGET","VBSCRIPT","INF1")
)

#fancy SHD Forensics Logo >_>
Write-Host ("{0}`n{1}`n{2}`n{3}`n{4}`n{5}`n{6}`n{7}`n" -f "  _____ _    _ _____    ______                       _          ", " / ____| |  | |  __ \  |  ____|                     (_)         ", "| (___ | |__| | |  | | | |__ ___  _ __ ___ _ __  ___ _  ___ ___ ", " \___ \|  __  | |  | | |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|", " ____) | |  | | |__| | | | | (_) | | |  __/ | | \__ \ | (__\__ \", "|_____/|_|  |_|_____/  |_|  \___/|_|  \___|_| |_|___/_|\___|___/", "              ", "mbeckert 2024") -ForegroundColor Green
Write-Host "Reminder - File Modes are:`nd - Directory`na - Archive`nr - Read-only`nh - Hidden`ns - System`nl - Reparse point, symlink, etc." -ForegroundColor Gray

#$filetypes = @("*.exe") #testing
[System.IO.FileInfo[]]$items = $null # this has to be an array, because if the first finding has only 1 entry, the interpreter sets this to FileInfo, which does not allow additions

foreach ($filetype in $filetypes){
    Write-Host "Testing FileType $filetype" -ForegroundColor Cyan
    $filetype = '*.'+$filetype
    $tempitems = get-childitem -Filter * -include $filetype -Recurse -Path $Path #this is, where the magic happens #regex is fun
    Write-Host ("Found {0} {1} Files" -f $tempitems.count, $filetype) -ForegroundColor Cyan
    
    foreach ($tempitem in $tempitems) {
        #add column for more infos
        $tempitem | Add-Member -NotePropertyName "Description1" -NotePropertyValue ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($tempitem.FullName).FileDescription)
        $tempitem | Add-Member -NotePropertyName "SHA1" -NotePropertyValue ((Get-FileHash $tempitem.FullName -Algorithm SHA1).Hash)
    }
    Write-Verbose ($tempitems | ft Extension,Name, BaseName, Mode, Description1, CreationTime, LastWriteTime,DirectoryName,SHA1 | Out-String)
    if ($tempitems.count -gt 0) {
        $items += $tempitems
    }
}
return $items | sort DirectoryName | select Extension,Name,Mode,@{Name = 'Size (KB)'; Expression = { [math]::Round(($_.Length/1024),2)}},CreationTime,LastWriteTime,DirectoryName,SHA1
# MB
