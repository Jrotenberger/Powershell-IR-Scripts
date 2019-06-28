## ----------------------------------------------------------------------------------------------------------------------------------------
##	Powershell Registry Script for use with Carbon Black Enterprise Response
##
##  Version 1.0  Updated 6/26/2019
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
		# echo ""
		# Write-Host -ForegroundColor Yellow "==[ $targetName - $target ]=="

## ----------------------------------------------------------------------------------------------------------------------------------------
## Configure Folder for memory collection - sets up folder based on computer's name and timestamp of artifact collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	# Write-Host -Fore Green "Configuring Folder" 

		$date = Get-Date -UFormat %s -Millisecond 0
		$artFolder = $target + "-Registry_Hives-" + $date
		
## ----------------------------------------------------------------------------------------------------------------------------------------		
## UPDATE THE FOLLOWING FOLDER TO CHANGE DESTINATION OF ARTIFACT DATA - POWERSHELL SUPPORTS NETWORK DRIVES
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$dest = "C:\Windows\CarbonBlack\Reports\$artfolder\"

## ----------------------------------------------------------------------------------------------------------------------------------------		
## LOCATION OF TOOLS - CAN BE USB OR NETWORK DRIVE 
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$tools = "C:\Windows\CarbonBlack\Tools\"

## ----------------------------------------------------------------------------------------------------------------------------------------

		$CompName = $target
		
		$OutLevel1 = "$dest\$artFolder" + "_Report.html"

## ----------------------------------------------------------------------------------------------------------------------------------------
## Create Artifact Directories
## ----------------------------------------------------------------------------------------------------------------------------------------
	# Write-Host -Fore Green "Creating Image Directory"
	$dirList = ("$dest\reg")
	New-Item -Path $dest -ItemType Directory | Out-Null
	New-Item -Path $dirList -ItemType Directory | Out-Null

## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML File setup 
## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML Logfile Header
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	ConvertTo-Html -Head $head -Title "Registry Hive Capture script for $CompName" -Body " Registry Hive Script <p> Computer Name : $CompName &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp </p> " > $OutLevel1

## ----------------------------------------------------------------------------------------------------------------------------------------	
# Record start time of collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	date | select DateTime | ConvertTo-html -Body "Current Date and Time " >> $OutLevel1


## ----------------------------------------------------------------------------------------------------------------------------------------
	#COLLECT REGISTRY FILES  
## ----------------------------------------------------------------------------------------------------------------------------------------
	
		
		date | select DateTime | ConvertTo-html -Body "<H2> Pulling Registry Files </H2>" >> $OutLevel1
		$regLoc = "c:\windows\system32\config\"
		
		$command = '$tools\RawCopy.exe /FileNamePath:c:\windows\system32\config\SOFTWARE /OutputPath:$dest\reg'
		iex "& $command" | Out-Null
								
		$command = '$tools\RawCopy.exe /FileNamePath:c:\windows\system32\config\SYSTEM /OutputPath:$dest\reg'
		iex "& $command" | Out-Null
								
		$command = '$tools\RawCopy.exe /FileNamePath:c:\windows\system32\config\SAM /OutputPath:$dest\reg'
		iex "& $command" | Out-Null
								
		$command = '$tools\RawCopy.exe /FileNamePath:c:\windows\system32\config\SECURITY /OutputPath:$dest\reg'
		iex "& $command" | Out-Null
		
		# Write-Host "  Done..."

## ----------------------------------------------------------------------------------------------------------------------------------------		
##  COLLECT EACH USERS REGISTRY FILES
## ----------------------------------------------------------------------------------------------------------------------------------------
		#Set User path variable
		
		# Write-Host -Fore Green "User Registry Files"
		date | select DateTime | ConvertTo-html -Body "<H2> Pulling USRCLASS.DAT files.... </H2>" >> $OutLevel1
			
		$localprofiles = Get-WMIObject Win32_UserProfile -filter "Special != 'true'" -ComputerName $target | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15) }
		foreach ($localprofile in $localprofiles){
			$temppath = $localprofile.localpath
			$source = $temppath + "\appData\local\microsoft\windows\usrclass.dat"
			$eof = $temppath.Length
			$last = $temppath.LastIndexOf('\')
			$count = $eof - $last
			$user = $temppath.Substring($last,$count)
			$destination = "$dest\users" + $user
		New-Item -Path $dest\users\$user -ItemType Directory  | Out-Null
		
				$command = '$tools\RawCopy.exe /FileNamePath:$source /OutputPath:$destination'
				iex "& $command" | Out-Null
				}
		
		
		# Write-Host "  Done..."
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## Perform Operations on user files 
## ----------------------------------------------------------------------------------------------------------------------------------------

		# Write-Host -Fore Green "Pulling NTUSER.DAT files...."
		date | select DateTime | ConvertTo-html -Body "<H2> NTUSER.DAT Files Pulled </H2>" >> $OutLevel1
		
		$localprofiles = Get-WMIObject Win32_UserProfile -filter "Special != 'true'" -ComputerName $target | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15) }
		foreach ($localprofile in $localprofiles){
			$temppath = $localprofile.localpath
			$source = $temppath + "\ntuser.dat"
			$eof = $temppath.Length
			$last = $temppath.LastIndexOf('\')
			$count = $eof - $last
			$user = $temppath.Substring($last,$count)
			$destination = "$dest\users" + $user
		
		
		$command = '$tools\RawCopy.exe /FileNamePath:$source /OutputPath:$destination'
		iex "& $command" | Out-Null
		}
		
		Write-Host $dest
