# SYNOPSIS
Starts UI for IOC Extraction from a given String or File
# DESCRIPTION
This Script opens a windows forms UI from the System.Windows.Forms .NET Assembly to let you extract IOCs from a given String or File via UI.
The reason behind this, is you cannot always use software or copy anything else than text to a given machine you want to use.

There are better extractor tools out there - use them if you want good extractions :)
# EXAMPLE
```
.\IOCExtractor.ps1 -verbose
```
Sarts UI and gives you some more infos on the shell
# NOTES
mbeckert 2024
TODOs
- match mac
- progressbar
- match other IOC formats for example with brackets [.]
- import Evtx
- VT Check of found items (combine with Invoke-VTReport.ps1)
