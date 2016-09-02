## Questions
## can you 'Copy-Item' remotely?

New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$ | Out-Null  

$dest = "c:\"

$Date = (Get-Date).ToString('MM.dd.yyyy')

$CompName = $target

$Summary = "$dest\$CompName-$Date.html"

## Format HTML header

$a = "<style>"
$a = $a + "BODY{font-family:calibri; background-color:Aliceblue;}"
$a = $a + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
$a = $a + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:PaleGoldenrod}"
$a = $a + "</style>"	

	
ConvertTo-Html -Head $a -Title "Live Response script for $CompName" -Body "<H2> Live Forensics Script </H2> <p> Computer Name : $CompName &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp </p> " > $Summary

## OS VERSION

date | select DateTime | ConvertTo-html -Body "<H2> OS Version </H2>" >> $Summary
(gwmi win32_OperatingSystem).Version >> $Summary


## BIOS information

date | select DateTime | ConvertTo-html -Body "<H2 BIOS Information </H2>" >> $Summary
gwmi win32_BIOS |select SMBIOSBIOSVersion, Version, Manufacturer, Name, ReleaseDate, SerialNumber, Status  | ConvertTo-html -Body "Bios Info" >> $Summary


## OS ARCHITECTURE

get-wmiobject win32_processor -ComputerName $target | where {$_.deviceID -eq "CPU0"} | select AddressWidth | Convertto-Html -Body "Architecture" >> $Summary

## Process Information

	date | select DateTime | ConvertTo-html -Body "<H2> Process Information Extraction Started </H2>" >> $Summary

	date | select DateTime | ConvertTo-html -Body "<H2> Running Processes </H2>" >> $Summary
	Get-Process | ConvertTo-Html >> $Summary

	date | select DateTime | ConvertTo-html -Body "<H2> Process to EXE Mapping </H2>" >> $Summary
	gwmi win32_process |Select Name, ProcessID, ParentProcessID | sort Name | ConvertTo-html >> $Summary	
	
	date | select DateTime | ConvertTo-html -Body "<H2> Process to User Mapping </H2>" >> $Summary
	get-wmiobject win32_process | Select Name,CreationDate,Priority,ProcessID,ParentProcessID,Path,Owner,CSName | Convertto-Html >> $Summary
		
	date | select DateTime | ConvertTo-html -Body "<H2> Process Dependencies </H2>" >> $Summary
	Get-Process | select ProcessName -expand Modules -ea 0 | Format-Table Processname, modulename, filename -Groupby Processname | Convertto-html -as Table >> $Summary  #DOESN'T WORK
	
## Prefetch files

gci -path X:\windows\prefetch\*.pf -ea 0 | select Name,LastAccessTime,CreationTime | sort LastAccessTime | ConvertTo-html -Body "<H2> Prefetch Files </H2>" >> $Summary


## Network Information

