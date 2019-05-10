## ----------------------------------------------------------------------------------------------------------------------------------------
##	Powershell Memory Capture Script for use with Carbon Black Enterprise Response
##
##  Version 1.0  Updated 5/10/2019
##
##  This Powershell script is designed as a separate memory only capture script.
##	
##	
##	Copyright 2019 Jeff Rotenberger 
##
## ----------------------------------------------------------------------------------------------------------------------------------------

## ----------------------------------------------------------------------------------------------------------------------------------------
## Set Target
## ----------------------------------------------------------------------------------------------------------------------------------------
		$target = $env:computername
		$targetName = Get-WMIObject Win32_ComputerSystem -ComputerName $target | Out-Null
		echo ""
		Write-Host -ForegroundColor Yellow "==[ $targetName - $target ]=="

## ----------------------------------------------------------------------------------------------------------------------------------------
## Configure Folder for memory collection - sets up folder based on computer's name and timestamp of artifact collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	Write-Host -Fore Green "Configuring Folder"

		New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$ | Out-Null  

		$date = Get-Date -format yyyy-MM-dd_HHmm_
		$artFolder = $date + $target + "-Memory Image"
		
## ----------------------------------------------------------------------------------------------------------------------------------------		
## UPDATE THE FOLLOWING FOLDER TO CHANGE DESTINATION OF ARTIFACT DATA - POWERSHELL SUPPORTS NETWORK DRIVES
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$dest = "Directory where the image will be sent"

## ----------------------------------------------------------------------------------------------------------------------------------------		
## LOCATION OF TOOLS - CAN BE USB OR NETWORK DRIVE 
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$tools = "Directory where Memory Capture tool resides"

## ----------------------------------------------------------------------------------------------------------------------------------------

		$CompName = $target
		
		$OutLevel1 = "$dest\$CompName-$Date.html"

## ----------------------------------------------------------------------------------------------------------------------------------------
## Create Artifact Directories
## ----------------------------------------------------------------------------------------------------------------------------------------
	Write-Host -Fore Green "Creating Image Directory"
	$dirList = ("$dest\memoryimage")
	New-Item -Path $dest -ItemType Directory
	New-Item -Path $dirList -ItemType Directory | Out-Null

## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML File setup 
## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML Logfile Header
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	ConvertTo-Html -Head $head -Title "Memory Capture script for $CompName" -Body " Memory Capture Script <p> Computer Name : $CompName &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp </p> " > $OutLevel1

## ----------------------------------------------------------------------------------------------------------------------------------------	
# Record start time of collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	date | select DateTime | ConvertTo-html -Body "Current Date and Time " >> $OutLevel1


## ---------------------------------------------------------------------------------------------------------------------------------------- 
## Gather Memory from Target System - Can use other memory capture tools
## ----------------------------------------------------------------------------------------------------------------------------------------

	Write-Host -Fore Green "Capturing memory"
	
	date | select DateTime | ConvertTo-html -Body "<H2> Ram Image Started </H2>" >> $OutLevel1
		$command = '$tools\winpmem.exe $dest\memoryimage\memimage.bin'
		iex "& $command"
	
	 date | select DateTime | ConvertTo-html -Body "<H2> Ram Image Complete </H2>" >> $OutLevel1

	Write-Host -Fore Green "Done"
