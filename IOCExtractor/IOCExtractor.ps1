<#
.SYNOPSIS
    Starts UI for IOC Extraction from a given String or File
.DESCRIPTION
    This Script opens a windows forms UI from the System.Windows.Forms .NET Assembly to let you extract IOCs from a given String or File via UI.
    The reason behind this, is you cannot always use software or copy anything else than text to a given machine you want to use.

    There are better extractor tools out there - use them if you want good extractions :)
.EXAMPLE
    .\IOCExtractor.ps1 -verbose
    Starts UI and gives you some more infos on the shell
.NOTES
    mbeckert 2024
    TODOs
    - match mac
    - progressbar
    - match other IOC formats []
    - import Evtx
    - VT Check of found items
#>

[CmdletBinding()]
Param ()
#cls
Write-Host 'Running... Dialog should open now.' -ForegroundColor Cyan
Write-Host 'If you are having Errors - run this script with -verbose' -ForegroundColor Gray

#  .NET-Assemblies für die grafische Gestaltung in den RAM
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

#region form
$objForm = New-Object System.Windows.Forms.Form
$objForm.Backcolor = "white"
#$objForm.Backcolor     = '#00305d' #SHD blau
#$objForm.Backcolor     = '#62bfdc' #SHD hellblau
#$objForm.Backcolor     = '#ffe463' #SHD gelb
$objForm.StartPosition = "CenterScreen"
#$objForm.TopMost = $true #immer im vordergrund
$objForm.Size = New-Object System.Drawing.Size(1000, 600)
$objForm.minimumSize = New-Object System.Drawing.Size(1000, 600) 
$objForm.maximumSize = New-Object System.Drawing.Size(1000, 600) 
$objForm.Text = "IOC Extractor"

# This base64 string holds the bytes that make up icon (TODO 64x -> 32x)
$iconBase64 = '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'
$iconBytes = [Convert]::FromBase64String($iconBase64)
# initialize a Memory stream holding the bytes
$stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
$objForm.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))
#endregion 

#region textboxes
# input textbox
$tb_input = New-Object System.Windows.Forms.TextBox
$tb_input.Location = New-Object system.drawing.size(10, 20)
$tb_input.size = New-Object System.Drawing.Size(470, 450)
$tb_input.Multiline = $true
$tb_input.ScrollBars = "Both"

#handler
$tb_input.add_textchanged( {
        #what to do when text changes
    })
$objForm.Controls.Add($tb_input)

#output textbox
$tb_output = New-Object System.Windows.Forms.TextBox
$tb_output.Location = New-Object system.drawing.size(510, 20)
$tb_output.size = New-Object System.Drawing.Size(470, 450)
$tb_output.Multiline = $true
$tb_output.ScrollBars = "Both"
$objForm.Controls.Add($tb_output)

#endregion 

#region labels

#input label
$labelinput = New-Object System.Windows.Forms.Label
$labelinput.Location = New-Object System.Drawing.size(10, 3)
$labelinput.Size = New-Object System.Drawing.Size(100, 23)
$labelinput.Text = ("Input")
$objForm.controls.Add($labelinput)

#output label
$labeloutput = New-Object System.Windows.Forms.Label
$labeloutput.Location = New-Object System.Drawing.size(510, 3)
$labeloutput.Size = New-Object System.Drawing.Size(100, 23)
$labeloutput.Text = ("Findings")
$objForm.controls.Add($labeloutput)

#result label ipv4
$labelipv4 = New-Object System.Windows.Forms.Label
$labelipv4.Location = New-Object System.Drawing.size(10, 520)
$labelipv4.Size = New-Object System.Drawing.Size(100, 23)
$labelipv4.Text = ("0 IPv4s found")
$objForm.controls.Add($labelipv4)

#result label url
$labelurl = New-Object System.Windows.Forms.Label
$labelurl.Location = New-Object System.Drawing.size(110, 520)
$labelurl.Size = New-Object System.Drawing.Size(100, 23)
$labelurl.Text = ("0 URLs found")
$objForm.controls.Add($labelurl)

#result label mail
$labelmail = New-Object System.Windows.Forms.Label
$labelmail.Location = New-Object System.Drawing.size(210, 520)
$labelmail.Size = New-Object System.Drawing.Size(100, 23)
$labelmail.Text = ("0 Mails found")
$objForm.controls.Add($labelmail)

#result label mail
$labelipv6 = New-Object System.Windows.Forms.Label
$labelipv6.Location = New-Object System.Drawing.size(310, 520)
$labelipv6.Size = New-Object System.Drawing.Size(100, 23)
$labelipv6.Text = ("0 IPv6s found")
$objForm.controls.Add($labelipv6)

#endregion

#region checkboxen
$cb_ipv4 = New-Object System.Windows.Forms.CheckBox
$cb_ipv4.Location = New-Object System.Drawing.size(10, 480)
$cb_ipv4.Size = New-Object System.Drawing.Size(75, 23)
$cb_ipv4.Text = ("IPv4")
$cb_ipv4.Checked = $true
$cb_ipv4.Add_CheckStateChanged({
        FormStartEvent("IPv4 Checkbox changed")
    })
$objForm.controls.Add($cb_ipv4)

$cb_url = New-Object System.Windows.Forms.CheckBox
$cb_url.Location = New-Object System.Drawing.size(85, 480)
$cb_url.Size = New-Object System.Drawing.Size(75, 23)
$cb_url.Text = ("URL")
$cb_url.Checked = $true
$cb_url.Add_CheckStateChanged({
        FormStartEvent("URL Checkbox changed")
    })
$objForm.controls.Add($cb_url)

$cb_mail = New-Object System.Windows.Forms.CheckBox
$cb_mail.Location = New-Object System.Drawing.size(160, 480)
$cb_mail.Size = New-Object System.Drawing.Size(75, 23)
$cb_mail.Text = ("Mail")
$cb_mail.Checked = $true
$cb_mail.Enabled = $true
$cb_mail.Add_CheckStateChanged({
        FormStartEvent("Mail Checkbox changed")
    })
$objForm.controls.Add($cb_mail)

$cb_ipv6 = New-Object System.Windows.Forms.CheckBox
$cb_ipv6.Location = New-Object System.Drawing.size(235, 480)
$cb_ipv6.Size = New-Object System.Drawing.Size(75, 23)
$cb_ipv6.Text = ("IPv6")
$cb_ipv6.Checked = $true
$cb_ipv6.Enabled = $true
$cb_ipv6.Add_CheckStateChanged({
        FormStartEvent("ipv6 Checkbox changed")
    })
$objForm.controls.Add($cb_ipv6)

$cb_mac = New-Object System.Windows.Forms.CheckBox
$cb_mac.Location = New-Object System.Drawing.size(310, 480)
$cb_mac.Size = New-Object System.Drawing.Size(75, 23)
$cb_mac.Text = ("Mac")
$cb_mac.Checked = $false
$cb_mac.Enabled = $false
$cb_mac.Add_CheckStateChanged({
        FormStartEvent("mac Checkbox changed")
    })
$objForm.controls.Add($cb_mac)

$cb_refactor = New-Object System.Windows.Forms.CheckBox
$cb_refactor.Location = New-Object System.Drawing.size(510, 480)
$cb_refactor.Size = New-Object System.Drawing.Size(75, 23)
$cb_refactor.Text = ("Refactor")
$cb_refactor.Checked = $true
$cb_refactor.Enabled = $true
$cb_refactor.Add_CheckStateChanged({
        FormStartEvent("refactor Checkbox changed")
    })
$objForm.controls.Add($cb_refactor)

$cb_commaseparated = New-Object System.Windows.Forms.CheckBox
$cb_commaseparated.Location = New-Object System.Drawing.size(610, 480)
$cb_commaseparated.Size = New-Object System.Drawing.Size(75, 23)
$cb_commaseparated.Text = ("Format")
$cb_commaseparated.Checked = $false
$cb_commaseparated.Enabled = $true
$cb_commaseparated.Add_CheckStateChanged({
        FormStartEvent("format Checkbox changed")
    })
$objForm.controls.Add($cb_commaseparated)

$cb_unique = New-Object System.Windows.Forms.CheckBox
$cb_unique.Location = New-Object System.Drawing.size(710, 480)
$cb_unique.Size = New-Object System.Drawing.Size(100, 23)
$cb_unique.Text = ("Only Unique")
$cb_unique.Checked = $true
$cb_unique.Add_CheckStateChanged({
        FormStartEvent("unique Checkbox changed")
    })
$objForm.controls.Add($cb_unique)

#endregion

#region buttons

#OK Button 
$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Size(500, 520)
$OKButton.Size = New-Object System.Drawing.Size(75, 23)
$OKButton.Text = "GO!"
$OKButton.Name = "GO!"
$OKButton.Backcolor = '#86E67E'
#$OKButton.DialogResult = "OK" # Ansonsten wird Fenster geschlossen
$OKButton.Add_Click( {
        #ok button event
        FormStartEvent("Start Button clicked")
    })
$objForm.Controls.Add($OKButton) 

#clipboard
$clipboardButton = New-Object System.Windows.Forms.Button
$clipboardButton.Location = New-Object System.Drawing.Size(600, 520)
$clipboardButton.Size = New-Object System.Drawing.Size(75, 23)
$clipboardButton.Text = "Copy"
$clipboardButton.Name = "Copy"
$clipboardButton.Add_Click( {
        if ($tb_output.TextLength -ne 0) {
            Set-Clipboard $tb_output.Text
            Write-Verbose "[+] Output added to clipboard..."
        }
    })
$objForm.Controls.Add($clipboardButton) 

#open file Button 
$fileButton = New-Object System.Windows.Forms.Button
$fileButton.Location = New-Object System.Drawing.Size(700, 520)
$fileButton.Size = New-Object System.Drawing.Size(75, 23)
$fileButton.Text = "Open File"
$fileButton.Name = "Open File"
#$OKButton.DialogResult = "OK" # Ansonsten wird Fenster geschlossen
$fileButton.Add_Click( {
        #openfile button event
        Write-Verbose "[+] Open File Dialog..."
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = "C:\"
        #$OpenFileDialog.filter = "Documents (*.docx)|*.docx |SpreadSheet (*.xlsx)|*.xlsx"
        $result = $OpenFileDialog.ShowDialog()
        if ("OK" -eq $result) {
            Write-Verbose "[+] Selected File: $($OpenFileDialog.FileName)"
            $tb_input.Text = Get-Content ($OpenFileDialog.FileName) -Raw
            Write-Verbose "[+] File loaded. Size: $($tb_input.TextLength / 1024) KB"
        }
        else {
            Write-Verbose "[+] Dialog canceled..."
        }
    })
$objForm.Controls.Add($fileButton) 

#clear Button 
$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Size(800, 520)
$OKButton.Size = New-Object System.Drawing.Size(75, 23)
$OKButton.Text = "Clear"
$OKButton.Name = "Clear"
#$OKButton.DialogResult = "OK" # Ansonsten wird Fenster geschlossen
$OKButton.Add_Click( {
        $tb_input.Text = ""
        $tb_output.Text = ""
        Write-Verbose "[+] Textboxes cleared"
          
    })
$objForm.Controls.Add($OKButton) 

#Abbrechen Button
$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Size(900, 520)
$CancelButton.Size = New-Object System.Drawing.Size(75, 23)
$CancelButton.Text = "Close"
$CancelButton.Name = "Close"
$CancelButton.DialogResult = "Cancel"
$CancelButton.Add_Click( { 
        Write-Verbose "[+] Close Dialog..."
        Write-Host "Bye" -ForegroundColor Green
        $objForm.Close() })
$objForm.Controls.Add($CancelButton) 

#help Button
$helpButton = New-Object System.Windows.Forms.Button
$helpButton.Location = New-Object System.Drawing.Size(952, 480)
$helpButton.Size = New-Object System.Drawing.Size(23, 23)
$helpButton.Text = "?"
$helpButton.Name = "?"
$helpButton.Add_Click( { 
        Write-Verbose "[+] Show Help..."
        $Msg = @'
    SHD Forensics - mbeckert 2024
    This Tool extracts all IOCs from a given String. Matches also "defanged" IOCs (with square brackets).

Refactor = converts the findings to usable format
format = comma separated string for use in searches
unique = dedups findings

Attention
IPv6 Regex is pretty bad!
Mail regex is even worse!
'@
        [System.Windows.Forms.MessageBox]::Show($Msg, 'Help', 'OK', 'Information')
    })
$objForm.Controls.Add($helpButton) 

#endregion

#region functions

function FormStartEvent {
    param (
        $changed
    )
    Write-Verbose "[+] $changed..."
    if ($tb_input.TextLength -ne 0) {
        $objForm.Enabled = $false
        #laziest error handling in history
        try {
            Extract
        }
        catch {
            $Error
        }
        finally {
            $objForm.Enabled = $true
        }
    }
    else {
        Write-Verbose "[+] No Text to extract from found..."
    }
}
function matchIPv4s {
    param (
        $inputstring
    )
    $mymatches = $null
    Write-Verbose "[+] Matching IPv4"

    #match regular ipv4
    $regex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    $mymatches += ([regex]::Matches($inputstring, $regex) | foreach { $_.Value } ) #this is where the magic happens

    #match with [] brackets
    $regex = '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\[\.\](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    $myvar = ([regex]::Matches($inputstring, $regex) | foreach { $_.Value } )
    if ($cb_refactor.Checked) {
        $myvar = $myvar -replace '\]', ''
        $myvar = $myvar -replace '\[', ''
    }
    $mymatches += $myvar

    if ($cb_unique.Checked) {
        $mymatches = $mymatches | select -Unique
    }

    <#
    match decimal IPs
    #min decimal match = 16777216   = 1.0.0.0
    #max decimal match = 4294967295 = 255.255.255.255

    #match with decimal

    #refactor?
    [ipaddress]::new([ipaddress]::NetworkToHostOrder(16812043)).IPAddressToString
    #>
    $labelipv4.Text = ($mymatches.Count.ToString() + " IPv4s found")
    Write-Verbose "[+] Matching IPv4 done"
    return $mymatches
}

function matchurl {
    param (
        $inputstring
    )
    Write-Verbose "[+] Matching URLs"
    #match normal url
    $regex = '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
    $mymatches += ([regex]::Matches($inputstring, $regex) | foreach { $_.Value } ) #this is where the magic happens

    #TODO match url with brackets []

    if ($cb_unique.Checked) {
        $mymatches = $mymatches | select -Unique
    }

    $labelurl.Text = ($mymatches.Count.ToString() + " URLs found")
    Write-Verbose "[+] Matching URLs done"
    return $mymatches
}

function matchmail {
    param (
        $inputstring
    )
    Write-Verbose "[+] Matching Mail"

    $regex = '\w+@\w+\.\w{2,3}'     #TODO get better mail parser
    $mymatches += ([regex]::Matches($inputstring, $regex) | foreach { $_.Value } ) #this is where the magic happens
    
    if ($cb_unique.Checked) {
        $mymatches = $mymatches | select -Unique
    }

    $labelmail.Text = ($mymatches.Count.ToString() + " Mails found")
    Write-Verbose "[+] Matching Mail done"
    return $mymatches
}

function matchipv6 {
    param (
        $inputstring
    )
    Write-Verbose "[+] Matching ipv6"
    $regex = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
    $mymatches += ([regex]::Matches($inputstring, $regex) | foreach { $_.Value } ) #this is where the magic happens
    
    if ($cb_unique.Checked) {
        $mymatches = $mymatches | select -Unique
    }
    $labelmail.Text = ($mymatches.Count.ToString() + " IPv6s found")
    Write-Verbose "[+] Matching ipv6 done"
    return $mymatches
}


function Extract {
    Write-Verbose "[+] Start Extraction..."
    Write-Verbose "[+] Input length is $($tb_input.TextLength)" 
    
    $sb = New-Object System.Text.StringBuilder
    $delimiter = ','
    Write-Verbose "[+] Delimiter = ,"
    if ($cb_ipv4.Checked) {
        $items = matchIPv4s($tb_input.Text) #TODO items sind im arraw (wiederholungen bei comma, append)
        if ($cb_commaseparated.Checked) {
            Write-Verbose "[+] Checkbox Format is enabled - formatting output..."
            foreach ($item in $items) {
                [void]$sb.Append('"')
                [void]$sb.Append($item)
                [void]$sb.Append('"')
                [void]$sb.Append($delimiter)
            }
        }
        else {
            foreach ($item in $items) 
            { [void]$sb.AppendLine($item) }
        }
    }
    if ($cb_url.Checked) {
        $items = matchurl($tb_input.Text)
        if ($cb_commaseparated.Checked) {
            Write-Verbose "[+] Checkbox Format is enabled - formatting output..."
            foreach ($item in $items) {
                [void]$sb.Append('"')
                [void]$sb.Append($item)
                [void]$sb.Append('"')
                [void]$sb.Append($delimiter)
            }
        }
        else {
            foreach ($item in $items) 
            { [void]$sb.AppendLine($item) }
        }
    }
    if ($cb_mail.Checked) {
        $items = matchmail($tb_input.Text)
        if ($cb_commaseparated.Checked) {
            Write-Verbose "[+] Checkbox Format is enabled - formatting output..."
            foreach ($item in $items) {
                [void]$sb.Append('"')
                [void]$sb.Append($item)
                [void]$sb.Append('"')
                [void]$sb.Append($delimiter)
            }
        }
        else {
            foreach ($item in $items) 
            { [void]$sb.AppendLine($item) }
        }
    }
    if ($cb_ipv6.Checked) {
        $items = matchipv6($tb_input.Text)
        if ($cb_commaseparated.Checked) {
            Write-Verbose "[+] Checkbox Format is enabled - formatting output..."
            foreach ($item in $items) {
                [void]$sb.Append('"')
                [void]$sb.Append($item)
                [void]$sb.Append('"')
                [void]$sb.Append($delimiter)
            }
        }
        else {
            foreach ($item in $items) 
            { [void]$sb.AppendLine($item) }
        }
    }

    <#
    if ($cb_url.Checked) {
        matchurl($tb_input.Text) | foreach { [void]$sb.AppendLine($_) }
    }#>

    if ($cb_commaseparated.Checked) { $sb.Length-- } #letztes komma wieder entfernen

    #print to tb
    Write-Verbose "[+] Printing Output..."
    $tb_output.Text = $sb.ToString()
    Write-Verbose "[+] Output length is $($tb_output.TextLength)" 

    Write-Verbose "[+] Remove Garbage for more WAM"
    [GC]::Collect()
    return
}

<#
function appenditems {
    param (
        $items
    )
    $sbappend = New-Object System.Text.StringBuilder

    
}#>

#endregion

#show / start UI
Write-Verbose "[+] Show Dialog - lets go"
[void] $objForm.ShowDialog()
