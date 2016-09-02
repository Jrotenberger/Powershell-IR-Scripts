



gwmi win32_process |ft Name, ProcessID, ParentProcessID -a > C:\ProcessInfo_2_process-to.exe-mapping.txt


(Get-WmiObject -class win32_process | where{$_.ProcessName -eq 'mshta.exe'}).getowner() | Select -property domain, user 
