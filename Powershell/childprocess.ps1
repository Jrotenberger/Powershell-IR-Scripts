

$processcollection = Get-WMIObject Win32_process | Select-Object Name, Description, ProcessID, ParentProcessID, MachineName, PriorityClass, ProcessName, SessionID, Path 

foreach ($process in $processcollection)
	{
	Write-Host ($_.name + ' ' + $_.ProcessID + ' ' + $_.ParentProcessID)
	Group-Object -property ParentProcessID 
		}