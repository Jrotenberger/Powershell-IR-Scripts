$strComputer = "." 
 
$colItems = get-wmiobject -class "Win32_LogonSession" -namespace "root\CIMV2" -computername $strComputer 
 
foreach ($objItem in $colItems) { 
	  
      write-output "Authentication Package: " $objItem.AuthenticationPackage | out-file c:\powershell\activelogons.txt -append
      write-output "Caption: " $objItem.Caption | out-file c:\powershell\activelogons.txt -append
      write-output "Description: " $objItem.Description | out-file c:\powershell\activelogons.txt -append
      write-output "Installation Date: " $objItem.InstallDate | out-file c:\powershell\activelogons.txt -append
      write-output "Logon ID: " $objItem.LogonId | out-file c:\powershell\activelogons.txt -append
      write-output "Logon Type: " $objItem.LogonType | out-file c:\powershell\activelogons.txt -append
      write-output "Name: " $objItem.Name | out-file c:\powershell\activelogons.txt -append
      write-output "Start Time: " $objItem.StartTime | out-file c:\powershell\activelogons.txt -append
      write-output "Status: " $objItem.Status | out-file c:\powershell\activelogons.txt -append
      write-output " "
} 