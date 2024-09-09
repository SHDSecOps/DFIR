<#
.SYNOPSIS
    Tests the given String Array against VT and returns a formatted table sorted by malicious analysis count.
.DESCRIPTION
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
.NOTES
    mbeckert 2024 SHD
    TODOs
    - IPV6 match
    - catch error codes (below the script)
    - fine granular results output
    - POST wenn keine url gefunden
    - implement to IOCExtractor
.LINK
    https://docs.virustotal.com/reference/overview
.EXAMPLE
    .\Invoke-VTReport.ps1 -Verbose -tests "bea7557fca6f6aa3fc3be3c2acbdb45f","92.204.58.106","https://www.eventhotels.com/","mail.ru","nomatch"
    Tests the given Strings against VT with your predetermined APIKey in the script and returns a formatted table sorted by malicious analysis count
.EXAMPLE
    .\Invoke-VTReport.ps1 -Verbose -tests "92.204.58.106" -ApiKey "myapikeyisawesome123"
    Tests the given IP against VT with your own APIKey and returns a formatted table sorted by malicious analysis count
.EXAMPLE
    .\Invoke-VTReport.ps1 -Verbose -tests "92.204.58.106" -ApiKey "myapikeyisawesome123" -NoFormat
    Tests the given IP against VT with your own APIKey and returns the pscustomobject for further use
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$tests,
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,
    [Parameter(Mandatory = $false)]
    [Switch]$NoFormat=$false
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

#region functions
function Add-Result {
    param (
        $response
    )
    $myvar = $response.Content | ConvertFrom-Json

    #rückbau weil VT nur base64 codierte URLs annimmt
    if ($myvar.data.type -eq "url") {
        Write-Verbose "[-] Cant use ID Field of Response, since it only displays the base64 encoded URL. Using URL Field."
        $id = $myvar.data.attributes.url
    }
    else {
        $id = $myvar.data.id
    }
    <#
    Rewrite URLs. Otherwise only the API Call URLs are displayed
    https://www.virustotal.com/api/v3/ip_addresses/$myinput     -> https://www.virustotal.com/gui/ip-address/94.100.180.200
    https://www.virustotal.com/api/v3/domains/$myinput          -> https://www.virustotal.com/gui/domain/mail.ru
    https://www.virustotal.com/api/v3/urls/$enc                 -> https://www.virustotal.com/gui/url/079631cd0d8879a9d834aa06461d6b2cf6e3fc14729598918f959295857d526c
    https://www.virustotal.com/api/v3/files/$myinput            -> https://www.virustotal.com/gui/file/4cb019b2558f38279c200255037f329fee244ba1f7d755ac70594efd3b782e61
    #>
    Write-Verbose "[+] Rewriting VT Link Column for easier use."
    $VTLink = $myvar.data.links.self
    switch -regex ($VTLink) {
        ('https:\/\/www\.virustotal\.com\/api\/v3\/ip_addresses') { $VTLink = $VTLink -replace 'api/v3/ip_addresses', 'gui/ip-address' }
        ('https:\/\/www\.virustotal\.com\/api\/v3\/domains') { $VTLink = $VTLink -replace 'api/v3/domains', 'gui/domain' }
        ('https:\/\/www\.virustotal\.com\/api\/v3\/urls') { $VTLink = $VTLink -replace 'api/v3/urls', 'gui/url' }
        ('https:\/\/www\.virustotal\.com\/api\/v3\/files') { $VTLink = $VTLink -replace 'api/v3/files', 'gui/file' }
        Default { Write-Verbose "[-] No GUI Link found, keeping original Link." }
    }
    $FinalResults = [pscustomobject]@{
        ID              = $id
        Country         = $myvar.data.attributes.country
        malicious       = $myvar.data.attributes.last_analysis_stats.malicious
        suspicious      = $myvar.data.attributes.last_analysis_stats.suspicious
        undetected      = $myvar.data.attributes.last_analysis_stats.undetected
        harmless        = $myvar.data.attributes.last_analysis_stats.harmless
        votes_malicious = $myvar.data.attributes.total_votes.malicious
        votes_harmless  = $myvar.data.attributes.total_votes.harmless
        Link            = $VTLink
    }
    return $FinalResults
}

function Invoke-VTRequest {
    param (
        $myinput,
        $api_key
    )
    $Headers = @{ "x-apikey" = $api_key }
    #testing
    #$myinput = "www.google.com/"

    $hashregex = '^[a-fA-F0-9]{32,64}$'
    $domainregex = '^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$'
    $ipregex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    $urlregex = '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
    try {
        switch -regex ($myinput) {
        ($ipregex) {
                Write-Verbose "[+] $myinput matched IP"
                $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$myinput" -Method GET -Headers $headers -ErrorAction Ignore
                return $response 
            }
        ($domainregex) {
                Write-Verbose "[+] $myinput matched Domain"
                $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/domains/$myinput" -Method GET -Headers $headers  -ErrorAction Ignore 
                return $response
            }
        ($urlregex) {
                Write-Verbose "[+] $myinput matched URL"
                #URL base64 codieren, da es sonst kein match gibt
                $enc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($myinput))
                #letztes zeichen entfernen da VT kein padding will - source: https://docs.virustotal.com/reference/url-info
                $enc = $enc.Trim("=")
                Write-Verbose "[+] Encoded $myinput to base64, for using URL with VT API. New ID is: $enc"
                $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/urls/$enc" -Method GET -Headers $headers  -ErrorAction Ignore
                return $response 
            }
        ($hashregex) {
                Write-Verbose "[+] $myinput matched FileHash"
                $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$myinput" -Method GET -Headers $headers  -ErrorAction Ignore
                return $response
            }
            Default { 
                Write-Verbose "[-] $myinput did not match any regex - no VT API Call was made. Do it via the GUI manually or tweak Mikes regex ;)"
                return $null 
            }
        }
    }
    catch {
        Write-Host "No match found on VT of: $myinput"
        return $null
    }
}

function Invoke-Quotawait {
    Write-Host "Quota Limit Reached.
Request rate	4 lookups / min
Daily quota	500 lookups / day
Monthly quota	15.5 K lookups / month" -ForegroundColor DarkYellow
    for ($i = 1; $i -le 60; $i++ ) {
        Write-Progress -Activity "Quota Timeout 60sec" -Status "$($i)sec waited..." -PercentComplete $i
        Start-Sleep -Seconds 1 
    }
}

#endregion

#debugging
#$tests = @("https://www.shd-online.de/")

if (!$ApiKey) {
    Write-Host "No ApiKey given. Using ApiKey of mbeckert"
    Write-Host "Please do not overuse it. Register your own on https://www.virustotal.com/gui/join-us"
    $ApiKey = "<Input your own API Key here!>" #this should not be here
}

$report = @()
$notfound = @()

foreach ($test in $tests) {
    $response = $null
    #Erster Versuch API request
    $response = Invoke-VTRequest -myinput $test -api_key $ApiKey
    #wenn timeout, dann probier nach 60sec nochmal
    if ($response.StatusCode -eq 429) {
        Invoke-Quotawait
        $response = Invoke-VTRequest -myinput $test -api_key $ApiKey
    }
    #wenn response gekommen ist, aber wir noch nicht wissen welche
    if ($response) {
        #wenn statuscode nicht erfolgreich, dann fehler werfen
        if ($response.StatusCode -ne 200) {
            Write-Error "$($response.StatusCode) - $($response.StatusDescription)"
        }
        #ansonsten erfolgreich ausgeben
        $report += Add-Result -response $response
    }
    #wenn gar keine response gekommen ist, dann wurde kein match gefunden
    #TODO POST Request mit dem aktuellen input?
    else {
        $notfound += $test
    }
}

#output to console
if ($report) {
    Write-Host "Here is your report" -ForegroundColor Green
    Write-Host (Get-date)
    if ($notfound) {
        $notfound | foreach { Write-host "Analysis for $_ not found. Check or analyze manually via VT GUI." -ForegroundColor Magenta }
    }
    if ($NoFormat) {
        $report
    }
    else {
        $report | sort malicious, suspicious -Descending | ft
    }
}
else {
    Write-Host "No Check succeeded." -ForegroundColor Red
}

#region coming features
<# HTTP Code	Error code	Description
400	BadRequestError	The API request is invalid or malformed. The message usually provides details about why the request is not valid.
400	InvalidArgumentError	Some of the provided arguments are incorrect.
400	NotAvailableYet	The resource is not available yet, but will become available later.
400	UnselectiveContentQueryError	Content search query is not selective enough.
400	UnsupportedContentQueryError	Unsupported content search query.
401	AuthenticationRequiredError	The operation requires an authenticated user. Verify that you have provided your API key.
401	UserNotActiveError	The user account is not active. Make sure you properly activated your account by following the link sent to your email.
401	WrongCredentialsError	The provided API key is incorrect.
403	ForbiddenError	You are not allowed to perform the requested operation.
404	NotFoundError	The requested resource was not found.
409	AlreadyExistsError	The resource already exists.
424	FailedDependencyError	The request depended on another request and that request failed.
429	QuotaExceededError	You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.
You may have run out of disk space and/or number of files on your VirusTotal Monitor account.
429	TooManyRequestsError	Too many requests.
503	TransientError	Transient server error. Retry might work.
504	DeadlineExceededError	The operation took too long to complete.
#>

<#fine granular results
$Result = Invoke-RestMethod -Method Get -Uri $URI -Headers $Headers
#$Result
$test = $Result.data.attributes.last_analysis_results | Get-Member -MemberType NoteProperty 
$FinalResults = foreach ($Singletest in $test){
[pscustomobject]@{
Filehash = $Result.data.attributes.sha256
Name     = $Result.data.attributes.last_analysis_results.$($Singletest.name).engine_name
Catagory = $Result.data.attributes.last_analysis_results.$($Singletest.name).category
Method   = $Result.data.attributes.last_analysis_results.$($Singletest.name).method
}
}
$FinalResults
#>

#wenn invoke-webrequest
<# granular results
    $test = $myvar.data.attributes.last_analysis_results | Get-Member -MemberType NoteProperty 
    $FinalResults = foreach ($Singletest in $test) {
        [pscustomobject]@{
            Filehash = $Result.data.attributes.sha256
            Name     = $Result.data.attributes.last_analysis_results.$($Singletest.name).engine_name
            Catagory = $Result.data.attributes.last_analysis_results.$($Singletest.name).category
            Method   = $Result.data.attributes.last_analysis_results.$($Singletest.name).method
        }
    }
        #>
