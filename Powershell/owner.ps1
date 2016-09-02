. \powershell\Get-ProcessOwner

get-wmiobject win32_process | Get-ProcessOwner | Select Name,CreationDate,Priority,ProcessID,ParentProcessID,Path,Owner,Computername |Out-File C:\ProcessInfo_3_process-to-user-mapping.txt
get-wmiobject win32_process | Get-ProcessOwner | Select Name,CreationDate,Priority,ProcessID,ParentProcessID,Path,Owner,Computername |Export-CSV c:\ProcessInfo_3_process-to-user-mapping.csv
