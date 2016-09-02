Function Log-Start{
    <#
    .SYNOPSIS
        Creates log file
 
    .DESCRIPTION
        Creates log file with path and name that is passed. Checks if log file exists, and if it does deletes it and creates a new one.
        Once created, writes initial logging data
 
    .PARAMETER LogPath
        Mandatory. Path of where log is to be created. Example: C:\Windows\Temp
 
    .PARAMETER LogName
        Mandatory. Name of log file to be created. Example: Test_Script.log
 
    .PARAMETER ScriptVersion
        Mandatory. Version of the running script which will be written in the log. Example: 1.5
 
    .INPUTS
        Parameters above
 
    .OUTPUTS
        Log file created
 
    .NOTES
        Version:        1.0
        Author:         Luca Sturlese
        Creation Date:  10/05/12
        Purpose/Change: Initial function development
 
        Version:        1.1
        Author:         Luca Sturlese
        Creation Date:  19/05/12
        Purpose/Change: Added debug mode support
 
    .EXAMPLE
        Log-Start -LogPath "C:\Windows\Temp" -LogName "Test_Script.log" -ScriptVersion "1.5"
    #>
 
    [CmdletBinding()]
 
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LogName, [Parameter(Mandatory=$true)][string]$ScriptVersion)
 
    Process{
        $sFullPath = $LogPath + "\" + $LogName
 
        #Check if file exists and delete if it does
        If((Test-Path -Path $sFullPath)){
            Remove-Item -Path $sFullPath -Force
        }
 
        #Create file and start logging
        New-Item -Path $LogPath -Name $LogName –ItemType File
 
        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value ""
        Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
        Add-Content -Path $sFullPath -Value ""
        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value ""
 
        #Write to screen for debug mode
        Write-Debug "***************************************************************************************************"
        Write-Debug "Started processing at [$([DateTime]::Now)]."
        Write-Debug "***************************************************************************************************"
        Write-Debug ""
        Write-Debug "Running script version [$ScriptVersion]."
        Write-Debug ""
        Write-Debug "***************************************************************************************************"
        Write-Debug ""
 
    }
}
 
Function Log-Write{
    <#
    .SYNOPSIS
        Writes to a log file
 
    .DESCRIPTION
        Appends a new line to the end of the specified log file
 
    .PARAMETER LogPath
        Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
 
    .PARAMETER LineValue
        Mandatory. The string that you want to write to the log
 
    .INPUTS
        Parameters above
 
    .OUTPUTS
        None
 
    .NOTES
        Version:        1.0
        Author:         Luca Sturlese
        Creation Date:  10/05/12
        Purpose/Change: Initial function development
 
        Version:        1.1
        Author:         Luca Sturlese
        Creation Date:  19/05/12
        Purpose/Change: Added debug mode support
 
    .EXAMPLE
        Log-Write -LogPath "C:\Windows\Temp\Test_Script.log" -LineValue "This is a new line which I am appending to the end of the log file."
    #>
 
    [CmdletBinding()]
 
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LineValue)
 
    Process{
        Add-Content -Path $LogPath -Value $LineValue
 
        #Write to screen for debug mode
        Write-Debug $LineValue
    }
}
 
Function Log-Error{
    <#
    .SYNOPSIS
        Writes an error to a log file
 
    .DESCRIPTION
        Writes the passed error to a new line at the end of the specified log file
 
    .PARAMETER LogPath
        Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
 
    .PARAMETER ErrorDesc
        Mandatory. The description of the error you want to pass (use $_.Exception)
 
    .PARAMETER ExitGracefully
        Mandatory. Boolean. If set to True, runs Log-Finish and then exits script
 
    .INPUTS
        Parameters above
 
    .OUTPUTS
        None
 
    .NOTES
        Version:        1.0
        Author:         Luca Sturlese
        Creation Date:  10/05/12
        Purpose/Change: Initial function development
 
        Version:        1.1
        Author:         Luca Sturlese
        Creation Date:  19/05/12
        Purpose/Change: Added debug mode support. Added -ExitGracefully parameter functionality
 
    .EXAMPLE
        Log-Error -LogPath "C:\Windows\Temp\Test_Script.log" -ErrorDesc $_.Exception -ExitGracefully $True
    #>
 
    [CmdletBinding()]
 
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$ErrorDesc, [Parameter(Mandatory=$true)][boolean]$ExitGracefully)
 
    Process{
        Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."
 
        #Write to screen for debug mode
        Write-Debug "Error: An error has occurred [$ErrorDesc]."
 
        #If $ExitGracefully = True then run Log-Finish and exit script
        If ($ExitGracefully -eq $True){
            Log-Finish -LogPath $LogPath
            Break
        }
    }
}
 
Function Log-Finish{
    <#
    .SYNOPSIS
        Write closing logging data & exit
 
    .DESCRIPTION
        Writes finishing logging data to specified log and then exits the calling script
 
    .PARAMETER LogPath
        Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Temp\Test_Script.log
 
    .PARAMETER NoExit
        Optional. If this is set to True, then the function will not exit the calling script, so that further execution can occur
 
    .INPUTS
        Parameters above
 
    .OUTPUTS
        None
 
    .NOTES
        Version:        1.0
        Author:         Luca Sturlese
        Creation Date:  10/05/12
        Purpose/Change: Initial function development
 
        Version:        1.1
        Author:         Luca Sturlese
        Creation Date:  19/05/12
        Purpose/Change: Added debug mode support
 
        Version:        1.2
        Author:         Luca Sturlese
        Creation Date:  01/08/12
        Purpose/Change: Added option to not exit calling script if required (via optional parameter)
 
    .EXAMPLE
        Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log"
 
    .EXAMPLE
        Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log" -NoExit $True
    #>
 
    [CmdletBinding()]
 
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$false)][string]$NoExit)
 
    Process{
        Add-Content -Path $LogPath -Value ""
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
 
        #Write to screen for debug mode
        Write-Debug ""
        Write-Debug "***************************************************************************************************"
        Write-Debug "Finished processing at [$([DateTime]::Now)]."
        Write-Debug "***************************************************************************************************"
 
        #Exit calling script if NoExit has not been specified or is set to False
        If(!($NoExit) -or ($NoExit -eq $False)){
            Exit
        }
 
    }
}
 
Function Log-Email{
    <#
    .SYNOPSIS
        Emails log file to list of recipients
 
    .DESCRIPTION
        Emails the contents of the specified log file to a list of recipients
 
    .PARAMETER LogPath
        Mandatory. Full path of the log file you want to email. Example: C:\Windows\Temp\Test_Script.log
 
    .PARAMETER EmailFrom
        Mandatory. The email addresses of who you want to send the email from. Example: "admin@9to5IT.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>"
 
    .PARAMETER EmailTo
        Mandatory. The email addresses of where to send the email to. Seperate multiple emails by ",". Example: "admin@9to5IT.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>, test@test.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>"
 
    .PARAMETER EmailSubject
        Mandatory. The subject of the email you want to send. Example: "Cool Script - [" + (Get-Date).ToShortDateString() + "]"
 
    .INPUTS
        Parameters above
 
    .OUTPUTS
        Email sent to the list of addresses specified
 
    .NOTES
        Version:        1.0
        Author:         Luca Sturlese
        Creation Date:  05.10.12
        Purpose/Change: Initial function development
 
    .EXAMPLE
        Log-Email -LogPath "C:\Windows\Temp\Test_Script.log" -EmailFrom "admin@9to5IT.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>" -EmailTo "admin@9to5IT.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>, test@test.com<script type="text/javascript">
/* <![CDATA[ */
(function(){try{var s,a,i,j,r,c,l,b=document.getElementsByTagName("script");l=b[b.length-1].previousSibling;a=l.getAttribute('data-cfemail');if(a){s='';r=parseInt(a.substr(0,2),16);for(j=2;a.length-j;j+=2){c=parseInt(a.substr(j,2),16)^r;s+=String.fromCharCode(c);}s=document.createTextNode(s);l.parentNode.replaceChild(s,l);}}catch(e){}})();
/* ]]> */
</script>" -EmailSubject "Cool Script - [" + (Get-Date).ToShortDateString() + "]"
    #>
 
    [CmdletBinding()]
 
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$EmailFrom, [Parameter(Mandatory=$true)][string]$EmailTo, [Parameter(Mandatory=$true)][string]$EmailSubject)
 
    Process{
        Try{
            $sBody = (Get-Content $LogPath | out-string)
 
            #Create SMTP object and send email
            $sSmtpServer = "smtp.yourserver"
            $oSmtp = new-object Net.Mail.SmtpClient($sSmtpServer)
            $oSmtp.Send($EmailFrom, $EmailTo, $EmailSubject, $sBody)
            Exit 0
        }
 
        Catch{
            Exit 1
        }
    }
}