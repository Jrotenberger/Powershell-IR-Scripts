## ----------------------------------------------------------------------------------------------------------------------------------------
##	Powershell Data Collection Script for use with Carbon Black Enterprise Response
##		To use, simply configure the $dest and $tools variables to reflect appropriate paths.
##
##  Version 4.1  Updated 5/28/2019
##	Changelog:
##		Version 4.1: Minor edits to code comments. 5/28/2019
##		Version 4.0: Removed unnessesary powershell modules, cleaned code. 5/7/2019
##		Version 3.0: Initial public release. 9/2/2016
##
##  This Powershell script is updated to follow the collection process modelled by Corey Harrell's
##  TR3Secure Data Collection Script: http://journeyintoir.blogspot.com/2013/09/tr3secure-data-collection-script.html and
##  https://code.google.com/p/jiir-resources/downloads/list
##	
##	References 
##		Malware Forensics: Investigating and Analyzing Malicious Code by Cameron H. Malin, Eoghan Casey, and James M. Aquilina 
## 		Windows Forensics Analysis (WFA) Second Edition by Harlan Carvey
## 		RFC 3227 - Guidelines for Evidence Collection and Archiving http://www.faqs.org/rfcs/rfc3227.html
##		Dual Purpose Volatile Data Collection Script http://journeyintoir.blogspot.com/2012/01/dual-purpose-volatile-data-collection.html
##		Corey Harrell (Journey Into Incident Response)
##		Sajeev.Nair - Nair.Sajeev@gmail.com	Live Response Script Desktop
##
##		Other contributors are mentioned in the code where applicable
##
##	Copyright 2019 Jeff Rotenberger 
##
## ----------------------------------------------------------------------------------------------------------------------------------------
##
## 		
## ----------------------------------------------------------------------------------------------------------------------------------------
## Set Module location to load external functions -  it can be a network drive
## ----------------------------------------------------------------------------------------------------------------------------------------

		#Get-Module -ListAvailable | Import-Module -Global
		$module = "NotNeeded"
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## Set Target
## ----------------------------------------------------------------------------------------------------------------------------------------
		$target = $env:computername
		$targetName = Get-WMIObject Win32_ComputerSystem -ComputerName $target | Out-Null
		echo ""
		Write-Host -ForegroundColor Yellow "==[ $targetName - $target ]=="
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## Start Artifact Gathering
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		Write-Host -Fore Green "Gathering OS Architecture Information and Version...."
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## Region OS architecture detection
## ----------------------------------------------------------------------------------------------------------------------------------------
		$proc = get-wmiobject win32_processor -ComputerName $target | where {$_.deviceID -eq "CPU0"}
			If ($proc.addresswidth -eq '64')
				{
				$OSArch = '64'
				}
			ElseIf ($proc.addresswidth -eq '32')
				{
				$OSArch = '32'
				}
				
## ----------------------------------------------------------------------------------------------------------------------------------------
## end Region OS architecture detection
## ----------------------------------------------------------------------------------------------------------------------------------------
## ----------------------------------------------------------------------------------------------------------------------------------------
## Configure Folders for data collection - sets up folders based on computer's name and timestamp of artifact collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	Write-Host -Fore Green "Configuring Folders...."

		New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$ | Out-Null  

		$date = Get-Date -format yyyy-MM-dd_HHmm_
		$artFolder = $date + $target
		
## ----------------------------------------------------------------------------------------------------------------------------------------		
## UPDATE THE FOLLOWING FOLDER TO CHANGE DESTINATION OF ARTIFACT DATA - POWERSHELL SUPPORTS NETWORK DRIVES
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$dest = "Directory of where to put artifacts, can be a network share."

## ----------------------------------------------------------------------------------------------------------------------------------------		
## LOCATION OF TOOLS - CAN BE USB OR NETWORK DRIVE 
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		$tools = "Directory of the tools referenced, can be a network share."

## ----------------------------------------------------------------------------------------------------------------------------------------

	$CompName = $target

	$UserDirectory = (gi env:\userprofile).value 

	$User = (gi env:\USERNAME).value  #this pulls logged user and should be adjusted 

	$Date = (Get-Date).ToString('MM.dd.yyyy')

	$head = '<style> BODY{font-family:caibri; background-color:Aliceblue;} 
	TABLE{border-width: 1px;border-style: solid;border-color: black;bordercollapse: collapse;} TH{font-size:1.1em; border-width: 1px;padding: 2px;borderstyle: solid;border-color: black;background-color:PowderBlue} TD{border-width: 
	1px;padding: 2px;border-style: solid;border-color: black;backgroundcolor:white} </style>'

	$OutLevel1 = "$dest\$CompName-$Date.html"
			
	$TList = @(tasklist /V /FO CSV | ConvertFrom-Csv)

	$ExecutableFiles = @("*.EXE","*.COM","*.BAT","*.BIN",
	"*.JOB","*.WS",".WSF","*.PS1",".PAF","*.MSI","*.CGI","*.CMD","*.JAR","*.JSE","*
	.SCR","*.SCRIPT","*.VB","*.VBE","*.VBS","*.VBSCRIPT","*.DLL")
	
## ----------------------------------------------------------------------------------------------------------------------------------------
## Create Artifact Directories
## ----------------------------------------------------------------------------------------------------------------------------------------
	Write-Host -Fore Green "Creating Artifact Directories...."
	$dirList = ("$dest\autoruns","$dest\logs","$dest\network","$dest\prefetch","$dest\MicrosoftAVQuarantine","$dest\memoryimage","$dest\AppCompat","$dest\reg","$dest\Group_Policy")
	New-Item -Path $dest -ItemType Directory
	New-Item -Path $dirList -ItemType Directory | Out-Null

## ----------------------------------------------------------------------------------------------------------------------------------------	
## Windows OS Version - Malware Forensics page 19
## ----------------------------------------------------------------------------------------------------------------------------------------

		$VERSION = (gwmi win32_OperatingSystem).Version 
		(gwmi win32_OperatingSystem).Version  > $dest\SystemInfo_1_os-version.txt
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## GET BIOS INFO 
## ----------------------------------------------------------------------------------------------------------------------------------------
		
		gwmi win32_BIOS |ft Manufacturer, Name, ReleaseDate, SerialNumber, Version -a > $dest\BIOS-INFO.txt
		
## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML File setup 
## ----------------------------------------------------------------------------------------------------------------------------------------
## HTML Logfile Header
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	ConvertTo-Html -Head $head -Title "Live Response script for $CompName" -Body " Live Forensics Script <p> Computer Name : $CompName &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp </p> " > $OutLevel1

## ----------------------------------------------------------------------------------------------------------------------------------------	
# Record start time of collection
## ----------------------------------------------------------------------------------------------------------------------------------------

	date | select DateTime | ConvertTo-html -Body "Current Date and Time " >> $OutLevel1
	gwmi win32_BIOS | ConvertTo-html -Body "<H2> Bios Info <H2>" >> $OutLevel1

## ----------------------------------------------------------------------------------------------------------------------------------------	
## Start Logging
## ----------------------------------------------------------------------------------------------------------------------------------------	

## ----------------------------------------------------------------------------------------------------------------------------------------
## Copy Prefetch files  - Powershell can copy without the use of robocopy
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	Write-Host -Fore Green "Pulling prefetch files...."
	
	Copy-Item x:\windows\prefetch\*.pf $dest\prefetch -recurse
	gci -path X:\windows\prefetch\*.pf -ea 0 | select Name,LastAccessTime,CreationTime | sort LastAccessTime | ConvertTo-html -Body "<H2> Prefetch Files </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Done"
	
## ----------------------------------------------------------------------------------------------------------------------------------------
## Perform Operations on user files 
## ----------------------------------------------------------------------------------------------------------------------------------------

		Write-Host -Fore Green "Pulling NTUSER.DAT files...."
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
		New-Item -Path $dest\users\$user -ItemType Directory  | Out-Null
		
		If ($OSArch -eq '32')
		{
		$command = '$tools\RawCopy.exe /FileNamePath:$source /OutputPath:$destination'
		iex "& $command"
		}
		ElseIf ($OSArch -eq '64')
		{
		$command = '$tools\RawCopy64.exe /FileNamePath:$source /OutputPath:$destination'
		iex "& $command"
		}
		}
		
		Write-Host -Fore Green "Done"
		
## ----------------------------------------------------------------------------------------------------------------------------------------		
## Copy AMCACHE.HVE
## ----------------------------------------------------------------------------------------------------------------------------------------

		Write-Host -Fore Green "Getting AMCACHE.hve...."	
		
		$source = "$env:WINDIR\AppCompat\Programs\Amcache.hve"
		$destination = "$dest\AppCompat\"
		$command = '$tools\RawCopy64.exe /FileNamePath:$source /OutputPath:$destination'
		iex "& $command"
				
		date | select DateTime | ConvertTo-html -Body "<H2> AMCACHE.HVE Copied. </H2>" >> $OutLevel1
		
		Write-Host -Fore Green "Done"
		
## ---------------------------------------------------------------------------------------------------------------------------------------- 
## Gather Memory from Target System - Can use other memory capture tools
## ----------------------------------------------------------------------------------------------------------------------------------------

	Write-Host -Fore Green "Capturing memory"
	
	date | select DateTime | ConvertTo-html -Body "<H2> Ram Image Started </H2>" >> $OutLevel1
	#	$command = '$tools\winpmem.exe $dest\memoryimage\memimage.bin'
	#	iex "& $command"
	
	 date | select DateTime | ConvertTo-html -Body "<H2> Ram Image Complete </H2>" >> $OutLevel1

	Write-Host -Fore Green "Done"
	
## ----------------------------------------------------------------------------------------------------------------------------------------	
## MAIN ROUTINE
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	date | select DateTime | ConvertTo-html -Body "<H2> Process Information Extraction Started </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Capturing Process Information"
	
	#Process Information - Malware Forensics page 35 or WFA page 26
	Get-Process | Out-File $dest\ProcessInfo_1_running-process.txt
	date | select DateTime | ConvertTo-html -Body "<H2> Running Processes </H2>" >> $OutLevel1
	
	#TastList Information - Malware Forensics page 36 and WFA page 26
	Tasklist.exe -v /fo table > $dest\ProcessInfo_1_running-process-memory-usage.txt
	date | select DateTime | ConvertTo-html -Body "<H2> Tasklist Information </H2>" >> $OutLevel1
		
	#Process to exe mapping - Malware Forensics page 37
	gwmi win32_process |ft Name, ProcessID, ParentProcessID -a > $dest\ProcessInfo_2_process-to.exe-mapping.txt
	date | select DateTime | ConvertTo-html -Body "<H2> Process to EXE Mapping </H2>" >> $OutLevel1
	
	#Process to user mapping #REFINE Malware Forensics page 38
	
	Get-Process -IncludeUserName >> $dest\ProcessInfo_3_process-to-user-mapping.txt
	date | select DateTime | ConvertTo-html -Body "<H2> Process to User Mapping </H2>" >> $OutLevel1	
	
	#Child Processes - Malware Forensics page 40 or WFA page 26
	date | select DateTime | ConvertTo-html -Body "<H2> Child Processes </H2>" >> $OutLevel1
			
			Function Show-ProcessTree
		{
			Function Get-ProcessChildren($P,$Depth=1)
			{
				$procs | Where-Object {$_.ParentProcessId -eq $p.ProcessID -and $_.ParentProcessId -ne 0} | ForEach-Object {
					"{0}|--{1}" -f (" "*3*$Depth),"$($_.Name),$($_.ProcessID)"
					Get-ProcessChildren $_ (++$Depth)
					$Depth--
				}
			}

			$filter = {-not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) -or $_.ParentProcessId -eq 0}
			$procs = Get-WmiObject Win32_Process
			$top = $procs | Where-Object $filter | Sort-Object ProcessID
			foreach ($p in $top)
			{
				Write-Output "$($p.Name),$($p.ProcessID)"
				Get-ProcessChildren $p
			}
		}

		Show-ProcessTree | Out-File $dest\ProcessInfo_4_child-processes.txt	
	
	#Process File Handles - Malware Forensics page 42 or WFA page 27
	date | select DateTime | ConvertTo-html -Body "<H2> Process File Handles </H2>" >> $OutLevel1
	$command = '$tools\handle.exe /accepteula >> $dest\ProcessInfo_5_process-file-handles.txt'
	iex "& $command"
	
	#Process Dependencies - Malware Forensics page 44 or WFA page 26
	date | select DateTime | ConvertTo-html -Body "<H2> Process Dependencies </H2>" >> $OutLevel1
	Get-Process | select ProcessName -expand Modules -ea 0 | Format-Table Processname, modulename, filename -Groupby Processname | Out-File $dest\ProcessInfo_6_process-dependencies.txt
	
	Write-Host -Fore Green "Done"
	
## ----------------------------------------------------------------------------------------------------------------------------------------	
## NETWORK INFORMATION
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	
	date | select DateTime | ConvertTo-html -Body "<H2> Gathering Network Information </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Gathering Network Information"
	
	Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" | select DNSHostName,ServiceName,MacAddress,@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}},Description | Export-CSV $dest\network\netinfo.csv -NoTypeInformation | Out-Null
	
		#Active Network Connection - Malware Forensics page 26 or WFA page 21
		
		date | select DateTime | ConvertTo-html -Body "<H2> Active Network Connections </H2>" >> $OutLevel1
		netstat.exe -ano > $dest\network\NetworkInfo_1_Active_Connections.txt
	
		#DNS Queries Cache - Malware Forensics page 27
		date | select DateTime | ConvertTo-html -Body "<H2> DNS Queries Cache </H2>" >> $OutLevel1
		ipconfig /displaydns | select-string 'Record Name' | Sort | ConvertTo-html -Body "Results">> $OutLevel1
		ipconfig /displaydns | Out-file $dest\network\NetworkInfo_2_dns-queries-cache.txt
				
		#NetBios Sessions - Malware Forensics page 29
		date | select DateTime | ConvertTo-html -Body "<H2> NetBios Sessions </H2>" >> $OutLevel1
		nbtstat.exe -s > $dest\network\NetworkInfo_3_netbios-sessions.txt
				
		#Netbios Cache - Malware Forensics page 30 or WFA page 20
		date | select DateTime | ConvertTo-html -Body "<H2> NetBios Cache </H2>" >> $OutLevel1
		nbtstat.exe -c > $dest\network\NetworkInfo_4_netbios-cache.txt
				
		#Recently Transferred Files over Netbios - Malware Forensics page 30
		date | select DateTime | ConvertTo-html -Body "<H2> Recently Transferred Files </H2>" >> $OutLevel1
		net.exe file > $dest\network\NetworkInfo_5_file-transfer-over-netbios.txt
				
		#ARP Cache - Malware Forensics page 31
		date | select DateTime | ConvertTo-html -Body "<H2> Arp Cache </H2>" >> $OutLevel1
		arp -a > $dest\NetworkInfo_6_arp-cache.txt
		
		#Routing Table - WFA page 23
		date | select DateTime | ConvertTo-html -Body "<H2> Routing Table </H2>" >> $OutLevel1
		netstat.exe -r > $dest\network\NetworkInfo_7_routing-table.txt
				
		#Open Ports - Malware Forensics page 49
		date | select DateTime | ConvertTo-html -Body "<H2> Open Ports </H2>" >> $OutLevel1
		netstat.exe -a > $dest\network\Networking_8_port-to-process-mapping-group.txt
				
		#Port to Process Mapping - WFA page 32
		
			date | select DateTime | ConvertTo-html -Body "<H2> Port to Process Mapping </H2>" >> $OutLevel1
		
			function Get-NetworkStatistics # Credit to Shay Levy for this function http://blogs.microsoft.co.il/blogs/scriptfanatic/archive/2011/02/10/How-to-find-running-processes-and-their-port-number.aspx
					{ 
						$properties = 'Protocol','LocalAddress','LocalPort' 
						$properties += 'RemoteAddress','RemotePort','State','ProcessName','PID' 

						netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object { 

							$item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries) 

							if($item[1] -notmatch '^\[::') 
							{            
								if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
								{ 
								   $localAddress = $la.IPAddressToString 
								   $localPort = $item[1].split('\]:')[-1] 
								} 
								else 
								{ 
									$localAddress = $item[1].split(':')[0] 
									$localPort = $item[1].split(':')[-1] 
								}  

								if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
								{ 
								   $remoteAddress = $ra.IPAddressToString 
								   $remotePort = $item[2].split('\]:')[-1] 
								} 
								else 
								{ 
								   $remoteAddress = $item[2].split(':')[0] 
								   $remotePort = $item[2].split(':')[-1] 
								}  

								New-Object PSObject -Property @{ 
									PID = $item[-1] 
									ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
									Protocol = $item[0] 
									LocalAddress = $localAddress 
									LocalPort = $localPort 
									RemoteAddress =$remoteAddress 
									RemotePort = $remotePort 
									State = if($item[0] -eq 'tcp') {$item[3]} else {$null} 
								} | Select-Object -Property $properties 
							} 
						} 
					}

		Get-NetworkStatistics | Format-Table | Out-File $dest\network\network_9_port-to-process-mapping-csv.txt
		
		Write-Host -Fore Green "Done"
		
## ----------------------------------------------------------------------------------------------------------------------------------------		
##	LOGGED ON USER INFORMATION
## ----------------------------------------------------------------------------------------------------------------------------------------	

		#Locally/Remotely Logged on Users - Malware Forensics page 24 or WFA page 17
		
			date | select DateTime | ConvertTo-html -Body "<H2> Logged On Users </H2>" >> $OutLevel1
			
		Write-Host -Fore Green "Capture Logged On Users"
		
			function get-loggedonuser ($target){ 
					 
					#mjolinor 3/17/10 http://gallery.technet.microsoft.com/scriptcenter/0e43993a-895a-4afe-a2b2-045a5146048a
					 
					$regexa = '.+Domain="(.+)",Name="(.+)"$' 
					$regexd = '.+LogonId="(\d+)"$' 
					 
					$logontype = @{ 
					"0"="Local System" 
					"2"="Interactive" #(Local logon) 
					"3"="Network" # (Remote logon) 
					"4"="Batch" # (Scheduled task) 
					"5"="Service" # (Service account logon) 
					"7"="Unlock" #(Screen saver) 
					"8"="NetworkCleartext" # (Cleartext network logon) 
					"9"="NewCredentials" #(RunAs using alternate credentials) 
					"10"="RemoteInteractive" #(RDP\TS\RemoteAssistance) 
					"11"="CachedInteractive" #(Local w\cached credentials) 
					} 
					 
					$logon_sessions = @(gwmi win32_logonsession -ComputerName $target) 
					$logon_users = @(gwmi win32_loggedonuser -ComputerName $target) 
					 
					$session_user = @{} 
					 
					$logon_users |% { 
					$_.antecedent -match $regexa > $nul 
					$username = $matches[1] + "\" + $matches[2] 
					$_.dependent -match $regexd > $nul 
					$session = $matches[1] 
					$session_user[$session] += $username 
					} 
					 
					 
					$logon_sessions |%{ 
					$starttime = [management.managementdatetimeconverter]::todatetime($_.starttime) 
					 
					$loggedonuser = New-Object -TypeName psobject 
					$loggedonuser | Add-Member -MemberType NoteProperty -Name "Session" -Value $_.logonid 
					$loggedonuser | Add-Member -MemberType NoteProperty -Name "User" -Value $session_user[$_.logonid] 
					$loggedonuser | Add-Member -MemberType NoteProperty -Name "Type" -Value $logontype[$_.logontype.tostring()] 
					$loggedonuser | Add-Member -MemberType NoteProperty -Name "Auth" -Value $_.authenticationpackage 
					$loggedonuser | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $starttime 
					 
					$loggedonuser 
					} 
					 
					}

					Get-loggedonuser ($target) | Out-file $dest\users\UserInfo_1_locally-remotely-logged-on-users.txt
					
		#Remote Users IP Addresses - WFA page 17
		date | select DateTime | ConvertTo-html -Body "<H2> Remote Users IP Addresses </H2>" >> $OutLevel1
		net.exe sessions > $dest\users\UserInfo_2_remote-users-ip-addresses.txt
				
		#Active Logon Sessions - Malware Forensics page 25 or WFA page 18
		date | select DateTime | ConvertTo-html -Body "<H2> Active Logon Sessions </H2>" >> $OutLevel1
		Get-LoggedOnUser $target | Out-File $dest\users\UserInfo_3_active-logon-sessions.txt 
		
		Write-Host -Fore Green "Done"

## ----------------------------------------------------------------------------------------------------------------------------------------		
	#OPENED FILES INFORMATION
## ----------------------------------------------------------------------------------------------------------------------------------------
	
		Write-Host -Fore Green "Open Files"
		
		#Open Files on the Computer  #NOT WORKING Due to Architecture - Malware Forensics page 25 or WFA page 18
		#date | select DateTime | ConvertTo-html -Body "<H2> Open files </H2>" >> $OutLevel1
		#$command = '$tools\openedfilesview.exe /stext $dest\OpenedFilesInfo_1_opened-files.txt'
		#iex "& $command"
				
		#Remotely Opened Files - Malware Forensics page 59 or WFA page 19
		date | select DateTime | ConvertTo-html -Body "<H2> Remotely Opened Files </H2>" >> $OutLevel1
		openfiles.exe /query | Out-file $dest\OpenedFilesInfo_2_remotely-opened-files.txt
		
		Write-Host -Fore Green "Done"

## ----------------------------------------------------------------------------------------------------------------------------------------		
##  MISC INFORMATION	
## ----------------------------------------------------------------------------------------------------------------------------------------

		Write-Host -Fore Green "Clipboard Contents"
		
		#Clipboard Contents - Malware Forensics page 63 and WFA page 37
		date | select DateTime | ConvertTo-html -Body "<H2> Clipboard Contents </H2>" >> $OutLevel1
		$text = & {powershell -sta {add-type -a system.windows.forms; [windows.forms.clipboard]::GetText()}} | Out-file $dest\MiscInfo_1_clipboard-contents.txt
		
		Write-Host -Fore Green "Done"

## ----------------------------------------------------------------------------------------------------------------------------------------		
##  SYSTEM INFORMATION
## ----------------------------------------------------------------------------------------------------------------------------------------

		Write-Host -Fore Green "System Information"
	
		date | select DateTime | ConvertTo-html -Body "<H2> Start System Information </H2>" >> $OutLevel1
		#Operating System Version Done when version captured at start
					
		#System Uptime  - Malware Forensics page 21
		
		date | select DateTime | ConvertTo-html -Body "<H2> System Uptime </H2>" >> $OutLevel1
		(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | Out-file $dest\System_2_system-uptime.txt
		(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | ConvertTo-html -Body "Results" >> $OutLevel1
		
		#Network Configuration - Malware Forensics page 19 and WFA page 34
		date | select DateTime | ConvertTo-html -Body "<H2> Network Configuration </H2>" >> $OutLevel1
		ipconfig.exe /all > $dest\SystemInfo_3_network-configuration.txt
				
		#Enabled Network Protocols - Malware Forensics page 20
		date | select DateTime | ConvertTo-html -Body "<H2> Network Protocols </H2>" >> $OutLevel1
		Get-NetIPv4Protocol | Format-List -Property * >> $dest\SystemInfo_4_enabled-network-protocols.txt
					
		#Network Adapters in Promiscuous mode - Malware Forensics page 19 and WFA page 35
		date | select DateTime | ConvertTo-html -Body "<H2> Promiscuous Adapters </H2>" >> $OutLevel1
		Get-NetAdapter | Format-List -Property ifAlias,PromiscuousMode >> $dest\SystemInfo_5_promiscuous-adapters.txt
		
				
		#MISC SYSTEM INFO 
		Get-WMIObject Win32_LogicalDisk -ComputerName $target | Select DeviceID,DriveType,@{l="Drive Size";e={$_.Size / 1GB -join ""}},@{l="Free Space";e={$_.FreeSpace / 1GB -join ""}} | Export-CSV $dest\diskInfo.csv -NoTypeInformation | Out-Null
		Get-WMIObject Win32_ComputerSystem -ComputerName $target | Select Name,UserName,Domain,Manufacturer,Model,PCSystemType | Export-CSV $dest\systemInfo.csv -NoTypeInformation | Out-Null
		Get-WmiObject Win32_UserProfile -ComputerName $target | select Localpath,SID,LastUseTime | Export-CSV $dest\users\users.csv -NoTypeInformation | Out-Null
		
		
		date | select DateTime | ConvertTo-html -Body "<H2> Volatile Data Collection Complete </H2>" >> $OutLevel1
		
		Write-Host -Fore Green "Done"

## ----------------------------------------------------------------------------------------------------------------------------------------		
## BOOT RECORD INFORMATION
## ----------------------------------------------------------------------------------------------------------------------------------------

		## Commenting out for now  5/9/2019
		
		#Partition Information 
		#date | select DateTime | ConvertTo-html -Body "<H2> Partition Information </H2>" >> $OutLevel1
		#$command = '$tools\mmls.exe \\.\PHYSICALDRIVE0 >> $dest\MBR\partition-info.txt'
		#iex "& $command"
				
		#Image the MBR in Sector 0  
		#date | select DateTime | ConvertTo-html -Body "<H2> Image MBR in Sector 0 </H2>" >> $OutLevel1
		#$command = '$tools\dd.exe if=\\.\PHYSICALDRIVE0 of=$dest\MBR\mbr.bin bs=512 count=1'
		#iex "& $command"
				
		#Imaging the sectors before the first partition 
		
		#date | select DateTime | ConvertTo-html -Body "<H2> Image sectors before the first partition </H2>" >> $OutLevel1
		#If ($Version -gt '5.3')
		#	{
		#	$command = '$tools\dd.exe if=\\.\PHYSICALDRIVE0 of=$dest\mbr\win7_2008-2048-bytes.bin bs=512 count=2048'
		#	iex "& $command"
		#	}
		#Else
		#	{
		#	$command = '$tools\dd.exe if=\\.\PHYSICALDRIVE0 of=$dest\mbr\winXP_2003-63-bytes.bin bs=512 count=63'
		#	iex "& $command"
		#	}

## ----------------------------------------------------------------------------------------------------------------------------------------
	#COLLECT REGISTRY FILES  
## ----------------------------------------------------------------------------------------------------------------------------------------
	
		Write-Host -Fore Green "Collecting Registry Files"
		
		date | select DateTime | ConvertTo-html -Body "<H2> Pulling Registry Files </H2>" >> $OutLevel1
		
		reg save HKLM\SOFTWARE $dest\reg\SOFTWARE
		
		
		reg save HKLM\SYSTEM $dest\reg\SYSTEM
		
		
		reg save HKLM\SAM $dest\reg\SAM
		
		
		reg save HKLM\SECURITY $dest\reg\SECURITY
		
					
		Write-Host "  Done..."

## ----------------------------------------------------------------------------------------------------------------------------------------		
##  COLLECT EACH USERS REGISTRY FILES
## ----------------------------------------------------------------------------------------------------------------------------------------
		#Set User path variable
		
		Write-Host "User Registry Files"
		
		If ($Version -lt "5.4")
		{
		$userpath = "C:\Documents and Settings"
		}
		Else
		{
		$userpath = "C:\Users"
		}
		
		If ($Version -gt "5.3")
		{
				
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
						
				If ($OSArch -eq '32')
					{
					$command = '$tools\RawCopy.exe /FileNamePath:$source /OutputPath:$destination'
					iex "& $command"
					}
				ElseIf ($OSArch -eq '64')
					{
					$command = '$tools\RawCopy64.exe /FileNamePath:$source /OutputPath:$destination'
					iex "& $command"
				}
				}
		}
		
		Write-Host "  Done..."
		
## ----------------------------------------------------------------------------------------------------------------------------------------
##  COLLECTING NTFS ARTIFACTS
## ----------------------------------------------------------------------------------------------------------------------------------------
	
		#Collecting the MFT Record
		
		date | select DateTime | ConvertTo-html -Body "<H2> Pulling the MFT.... </H2>" >> $OutLevel1
		
		Write-Host "MFT Record "
		
		If ($OSArch -eq "64")
			{
			$command = '$tools\RawCopy64.exe c:0 $dest'
			iex "& $command"
			do {(Start-Sleep -Seconds 5)}
			until ((Get-WMIobject -Class Win32_process -Filter "Name='RawCopy64.exe'" -ComputerName $target | where {$_.Name -eq "RawCopy64.exe"}).ProcessID -eq $null)
			}
		Else
			{
			$command = '$tools\RawCopy.exe c:0 $dest'
			iex "& $command"
			do {(Start-Sleep -Seconds 5)}
			until ((Get-WMIobject -Class Win32_process -Filter "Name='RawCopy.exe'" -ComputerName $target | where {$_.Name -eq "RawCopy.exe"}).ProcessID -eq $null)
			}
		
	
		#Collect LogFile Records  
		
		date | select DateTime | ConvertTo-html -Body "<H2> Log File Records </H2>" >> $OutLevel1
		If ($OSArch -eq "64")
			{
			$command = '$tools\RawCopy64.exe c:2 $dest'
			iex "& $command"
			}
		Else
			{
			$command = '$tools\RawCopy.exe c:2 $dest'
			iex "& $command"
			}

		Write-Host "  Done..."	
			
## ----------------------------------------------------------------------------------------------------------------------------------------			
##  COLLECTING AUTOSTARTING LOCATIONS  
## ----------------------------------------------------------------------------------------------------------------------------------------
	
		date | select DateTime | ConvertTo-html -Body "<H2> AutoStarting Locations </H2>" >> $OutLevel1
		
		Write-Host "  Autostart Locations"
		
		#List system autostart locations - Malware Forensics page 69 or WFA page 44
		$command = '$tools\autorunsc.exe -a /accepteula >> $dest\autoruns\$target-autostarting-locations.txt'
		iex "& $command"
		

		#List system autostart locations in csv format - Malware Forensics page 69 or WFA page 44
		Get-WMIObject Win32_Service -Computername $target | Select processid,name,state,displayname,pathname,startmode | Export-CSV $dest\autoruns\target-autostarting-locations.csv -NoTypeInformation | Out-Null
			
		#Collect at.exe scheduled task information  
		at.exe > $dest\autoruns\$target-at_info.txt
	
		#Scheduled Task Information 
		$command = 'schtasks.exe /query >> $dest\autoruns\$target-schtasks_info.txt'
		iex "& $command"
				
		#Collect Scheduled Task Log and/or Folder
		If ($Version -lt "5.4") 
		{
			If ($OSArch -eq "64")
				{
				$command = '$tools\RawCopy64.exe /FileNamePath:$env:WINDIR\Tasks\SchedLgU.txt /OutputPath:$dest\autoruns\'
				iex "& $command"
				}
			Else
				{
				$command = '$tools\RawCopy.exe /FileNamePath:$env:WINDIR\Tasks\SchedLgU.txt /OutputPath:$dest\autoruns\'
				iex "& $command"
				}}
		Else  
			{
			$command = '$tools\robocopy.exe $env:WINDIR\Tasks $dest\autoruns\ /ZB /copy:DAT /r:0 /ts /FP /np /log:$dest\autoruns\tasks-robocopy-log.txt'
			iex "& $command"
			}
		
		Write-Host "  Done..."
		
#List all installed device drivers and their properties 
## ----------------------------------------------------------------------------------------------------------------------------------------

		date | select DateTime | ConvertTo-html -Body "<H2> Installed Drivers </H2>" >> $OutLevel1
		driverquery.exe /fo csv /si >> $dest\autoruns\$target-driverquery_info.txt 

## ----------------------------------------------------------------------------------------------------------------------------------------		
##Copy Log Files
## ----------------------------------------------------------------------------------------------------------------------------------------

		Write-Host -Fore Green "Copying Event log Files...."
		
		date | select DateTime | ConvertTo-html -Body "<H2> Event Logs </H2>" >> $OutLevel1
		
		wevtutil epl Security $dest\logs\${Env:ComputerName}-Security.evtx
		wevtutil epl System $dest\logs\${Env:ComputerName}-System.evtx
		wevtutil epl Application $dest\logs\${Env:ComputerName}-Application.evtx
		wevtutil epl Microsoft-Windows-TaskScheduler/Operational $dest\logs\${Env:ComputerName}-TaskScheduler.evtx
		wevtutil epl Microsoft-Windows-PowerShell/Operational $dest\logs\${Env:ComputerName}-Powershell.evtx
		wevtutil epl 'Microsoft-Windows-User Profile Service/Operational' $dest\logs\${Env:ComputerName}-UserProfileService.evtx
		wevtutil epl Microsoft-Windows-Sysmon/Operational $dest\logs\${Env:ComputerName}-sysmon.evtx
		
		Write-Host -Fore Green "Done"

## ----------------------------------------------------------------------------------------------------------------------------------------			
#Collecting the AV log and quarantine folder - Will need to modify for AV used
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	date | select DateTime | ConvertTo-html -Body "<H2> AV Logs </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Copying AV logs and Quarantine Folder...."
	
	##Copy Microsoft Endpoint Quarantine Files (default location)##
			$QuarQ = "C:\ProgramData\Microsoft\Windows Defender\Support\Quarantine"
			if (Test-Path -Path "$QuarQ\*.vbn") {
				New-Item -Path $dest\MicrosoftAVQuarantine -ItemType Directory  | Out-Null
				Copy-Item -Path "$QuarQ\*.*" $dest\MicrosoftAVQuarantine -Force -Recurse
			}
			else
				{
				Start-Sleep -Seconds 5
				}

	##Copy Microsoft Endpoint Log Files (default location)##
			$EndLog = "C:\ProgramData\Microsoft\Windows Defender\Support"
			if (Test-Path -Path "$EndLog\*.log") {
				New-Item -Path $dest\MicrosoftAVLogs -ItemType Directory  | Out-Null
				Copy-Item -Path "$EndLog\*.Log" $dest\MicrosoftAVLogs -Force -Recurse
			}
			else
				{
				Start-Sleep -Seconds 5
				}

	Write-Host -Fore Green "Done"				
				
## ----------------------------------------------------------------------------------------------------------------------------------------				
#Group Policy Information - Malware Forensics page 73  https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	date | select DateTime | ConvertTo-html -Body "<H2> Group Policy Info </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Capturing Registry Keys for UAC Group Policy Settings"
	
	gp -ea 0 hklm:\Software\Microsoft\Windows\CurrentVersion\policies\system | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - UAC Group Policy Settings </H2>" >> $OutLevel1
	gp -ea 0 hklm:\Software\Microsoft\Windows\CurrentVersion\policies\system > $dest\group_policy\group-policy-listing.txt
	
	
				
#GPResult.exe Results - Malware Forensics page 73
## ----------------------------------------------------------------------------------------------------------------------------------------

	$command = 'gpresult /Z >> $dest\group_policy\$target-group-policy-RSoP.txt'
	iex "& $command"

	Write-Host -Fore Green "Done"
	
##Copy Internet History files##
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	date | select DateTime | ConvertTo-html -Body "<H2> Internet History Files </H2>" >> $OutLevel1
	
	Write-Host -Fore Green "Copy Internet History Files"
	
	##	Microsoft Internet Explorer

		
		New-Item -Path $dest\users\$user\InternetHistory\IE -ItemType Directory | Out-Null
		$inethist = Get-ChildItem X:\users\$user\AppData\Local\Microsoft\Windows\History -ReCurse -Force | foreach {$_.Fullname}
		foreach ($inet in $inethist) {
			Copy-Item -Path $inet -Destination $dest\users\$user\InternetHistory\IE -Force -Recurse
		}

	##Copy FireFox History files##
		$foxpath = "X:\users\$user\AppData\Roaming\Mozilla\"
		if (Test-Path -Path $foxpath) {
			
			New-Item -Path $dest\users\$user\InternetHistory\Firefox -ItemType Directory  | Out-Null
		$ffinet = Get-ChildItem X:\users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\ -Filter "places.sqlite" -Force -Recurse | foreach {$_.Fullname}
		Foreach ($ffi in $ffinet) {
			Copy-Item -Path $ffi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox
		$ffdown = Get-ChildItem X:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\ -Filter "downloads.sqlite" -Force -Recurse | foreach {$_.Fullname}
		Foreach ($ffd in $ffdown) {
			Copy-Item -Path $ffd -Destination $dest\users\$user\InternetHistory\Firefox
				}
			}
		}
		else
			{
				Start-Sleep -Seconds 5
			}

	##Copy Chrome History files##
		$chromepath = "X:\users\$user\AppData\Local\Google\Chrome\User Data\Default"
		if (Test-Path -Path $chromepath) 
		{
			
			New-Item -Path $dest\users\$user\InternetHistory\Chrome -ItemType Directory  | Out-Null
			$chromeInet = Get-ChildItem "X:\users\$user\AppData\Local\Google\Chrome\User Data\Default" -Filter "History" -Force -Recurse | foreach {$_.Fullname}
		Foreach ($chrmi in $chromeInet) 
			{
			Copy-Item -Path $chrmi -Destination $dest\users\$user\InternetHistory\Chrome
			}
		}
		else
		{
		Start-Sleep -Seconds 5
		}

		Write-Host -Fore Green "Done"
		
# Get Journal File 
## ----------------------------------------------------------------------------------------------------------------------------------------


#date | select DateTime | ConvertTo-html -Body "<H2> Journal File </H2>" >> $OutLevel1

#	If ($OSVersion = "64")
#	{
#		$command = '$tools\jp64.exe -partition c:\export\$J -csvl2t > $dest\journal.txt'
#		iex "& $command"
#		do {(Start-Sleep -Seconds 5)}
#		until ((Get-WMIobject -Class Win32_process -Filter "Name='jp64.exe'" -ComputerName $target | where {$_.Name -eq "jp64.exe"}).ProcessID -eq $null)
#	}
#	Else
#	{
#		$command = '$tools\jp.exe -partition c:\export\$J -csvl2t > $dest\journal.txt'
#		iex "& $command"
#		do {(Start-Sleep -Seconds 5)}
#		until ((Get-WMIobject -Class Win32_process -Filter "Name='jp.exe'" -ComputerName $target | where {$_.Name -eq "jp64.exe"}).ProcessID -eq $null)
#	}


## User Information  - Only pulls Users that have logged in within the last 15 days
## ----------------------------------------------------------------------------------------------------------------------------------------


Write-Host -Fore Green "Pull users that have logged in within the last 15 days"

date | select DateTime | ConvertTo-html -Body "<H2> User Info </H2>" >> $OutLevel1

$VERSION = (gwmi win32_OperatingSystem).Version
	$localprofiles = Get-WMIObject Win32_UserProfile -filter "Special != 'true'" -ComputerName $target | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15) }  #Can modify for number of days or all users
		foreach ($localprofile in $localprofiles)
		{
			$temppath = $localprofile.localpath
			$eof = $temppath.Length
			$last = $temppath.LastIndexOf('\')
			$count = $eof - $last
			$user = $temppath.Substring($last,$count)
						
			#create user data folders
			
			$UserData = "$dest\users\$user"
			$dirList = ("$UserData\Recent","$UserData\Office_Recent","$UserData\Network_Recent","$UserData\temp","$UserData\Temporary_Internet_Files","$UserData\PrivacIE","$UserData\Cookies","$UserData\Java_Cache")
			New-Item -Path $dirList -ItemType Directory | Out-Null
			
		#Collecting Recent Folder
		If ($Version -lt "5.4")
			{
			$userpath = "C:\Documents and Settings"
			$command = '$tools\robocopy.exe $userpath\$user\Recent $UserData\Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_recent.txt'
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = '$tools\robocopy.exe $userpath\$user\AppData\Roaming\Microsoft\Windows\Recent $UserData\Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_recent.txt'
			iex "& $command"
			}
		
		# Collecting Office Recent Folder 
		If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = '$tools\robocopy.exe "$userpath\$user\Application Data\Microsoft\Office\Recent" $UserData\Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_office-recent.txt'
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = '$tools\robocopy.exe $userpath\$user\AppData\Roaming\Microsoft\Office\Recent $UserData\Office_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_office-recent.txt'
			iex "& $command"
			}
		
		# Collecting Network Shares Recent Folder 
		If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = '$tools\robocopy.exe $userpath\$user\Nethood $UserData\Network_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_network-recent.txt'
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = '$tools\robocopy.exe "$userpath\$user\AppData\Roaming\Microsoft\Windows\Network Shortcuts" $UserData\Network_Recent /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_network-recent.txt'
			iex "& $command"
			}
		
		# Collecting Temporary Folder 
		If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = '$tools\robocopy.exe "$userpath\$user\Local Settings\Temp" $UserData\temp /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_temp.txt'
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = '$tools\robocopy.exe $userpath\$user\AppData\Local\Temp $UserData\temp /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_temp.txt'
			iex "& $command"
			}
		
		# Collecting Temporary Internet Files Folder 
			If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = '$tools\robocopy.exe "$userpath\$user\Local Settings\Temporary Internet Files" $UserData\Temporary_Internet_Files /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_tif.txt'
			iex "& $command"
			
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = '$tools\robocopy.exe "$userpath\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files" $UserData\Temporary_Internet_Files /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_tif.txt'
			iex "& $command"		
			}
					
		# Collecting the PrivacIE folder 
			If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = "$tools\robocopy.exe $userpath\$user\PrivacIE $UserData\PrivacIE /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_privacie.txt"
			iex "& $command"	
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = "$tools\robocopy.exe $userpath\$user\AppData\Roaming\Microsoft\Windows\PrivacIE $UserData\PrivacIE /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_privacie.txt"
			iex "& $command"	
			}
		
		# Collecting the Cookies 
			If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = "$tools\robocopy.exe $userpath\$user\Cookies $UserData\Cookies /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_cookies.txt"
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = "$tools\robocopy.exe $userpath\$user\AppData\Roaming\Microsoft\Windows\Cookies $UserData\Cookies /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_cookies.txt"
			iex "& $command"
			}
		
		# Collecting the Java Cache folder
		If ($Version -lt "5.4") 
			{
			$userpath = "C:\Documents and Settings"
			$command = "$tools\robocopy.exe $userpath\$user\ApplicationData\Sun\Java\Deployment\cache $UserData\Java_Cache /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_java.txt"
			iex "& $command"
			}
		Else 
			{
			$userpath = "C:\Users"
			$command = "$tools\robocopy.exe $userpath\$user\AppData\LocalLow\Sun\Java\Deployment\cache $UserData\Java_Cache /ZB /copy:DAT /r:0 /ts /FP /np /E /log:$dest\users\$user\robocopy-log_java.txt"
			iex "& $command"
			}
		}		
		
Write-Host -Fore Green "Done"
		
# Startup Applications

		
				
		gwmi -ea 0 Win32_StartupCommand | select command,user,caption | ConvertTo-html -Body "<H2> Startup Applications </H2>" >> $OutLevel1

		gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

		gp -ea 0 'hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

		gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce'| select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

		gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

		gp -ea 0 'hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

		gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce'| select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

# Process Artifacts

	

	gwmi -ea 0 win32_process | select processname,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},ProcessId,ParentProcessId,CommandLine,sessionID |sort ParentProcessId -desc | ConvertTo-html -Body "<H2> Running Processes sorted by ParentProcessID 
	</H2>" >> $OutLevel1

	gwmi -ea 0 win32_process | where {$_.name -eq 'svchost.exe'} | select ProcessId|foreach-object {$P = $_.ProcessID ;gwmi win32_service |where {$_.processId -eq$P} | select processID,name,DisplayName,state,startmode,PathName} | ConvertTo-html -Body "<H2> Running SVCHOST and associated Processes </H2>" >>$OutLevel1

	gwmi -ea 0 win32_Service | select Name,ProcessId,State,DisplayName,PathName | sort state | ConvertTo-html -Body "<H2> Running Services - Sorted by State </H2>" >> $OutLevel1

# last 50 dlls created

	
	gci -r -ea 0 c:\ -include *.dll | select Name,CreationTime,LastAccessTime,Directory | sort CreationTime -desc | select -first 50 | ConvertTo-html -Body "<H2> Last 50 DLLs created - Sorted by CreationTime </H2>" >> $OutLevel1

# Mapped Drives

	
	gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Mapped Drives </H2>" >> $OutLevel1

# Scheduled Jobs

	
	gwmi -ea 0 Win32_ScheduledJob | ConvertTo-html -Body "<H2> Scheduled Jobs </H2>" >> $OutLevel1

# Hotfixes Applied

	
	Get-HotFix -ea 0| Select HotfixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending | ConvertTo-html -Body "<H2> HotFixes applied - Sorted by Installed Date </H2>" >> $OutLevel1

# Installed Apps

	
	gp -ea 0 HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | Sort InstallDate -Desc | ConvertTo-html -Body "<H2> Installed Applications - Sorted by Installed Date </H2>" >> $OutLevel1

# Record end time of collection

	date | select DateTime | ConvertTo-html -Body " Current Date and Time " >> $OutLevel1

##Disconnect the PSDrive X mapping##
## ----------------------------------------------------------------------------------------------------------------------------------------
	
	Remove-PSDrive X

##Send Email  - Can delete, modify or comment out
## ----------------------------------------------------------------------------------------------------------------------------------------

##	send-mailmessage -to "Analyst <email@email.com>" -from "DESKTOP <email@email.com>" -subject "Artifacts $target $date" -body "Artifact Pull Complete and data located at $dest" -smtp smtp.company.com

##Ending##
## ----------------------------------------------------------------------------------------------------------------------------------------


