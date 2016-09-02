Clear-Host

function Get-Executables()
{
    
    process
    {
        # Retrieve instance of Win32_Process based on the process name passed into the function
        $Procs = Get-WmiObject -Class CIM_ProcessExecutable

        # If there are no processes returned from the query, then simply exit the function
        if (-not $Procs)
        {
            Write-Host "No processes were found named $ProcessName"
            break
        }
        # If one process is found, get the value of __PATH, which we will use for our next query
        elseif (@($Procs).Count -eq 1)
        {
            $ProcPath = @($Procs)[0].__PATH
            Write-Verbose "Proc path is $ProcPath"
        }
        # If there is more than one process, use the process at index 0, for the time being
        elseif ($Procs.Count -gt 1)
        {
            $ProcPath = @($Procs)[0].__PATH
            Write-Host "Using process with path: $ProcPath"
        }

        # Get the CIM_ProcessExecutable instances for the process we retrieved
        $ProcQuery = "select * from CIM_ProcessExecutable where Dependent = '$ProcPath'".Replace("","\")

        Write-Verbose $ProcQuery
        $ProcExes = Get-WmiObject -Namespace rootcimv2 -Query $ProcQuery

        # If there are instances of CIM_ProcessExecutable for the specified process, go ahead and grab the important properties
        if ($ProcExes)
        {
            foreach ($ProcExe in $ProcExes)
            {
                # Use the [wmi] type accelerator to retrieve an instance of CIM_DataFile from the WMI __PATH in the Antecentdent property
                $ExeFile = [wmi]"$($ProcExe.Antecedent)"
                # If the WMI instance we just retrieve "IS A" (think WMI operator) CIM_DataFile, then write properties to console
                if ($ExeFile.__CLASS -eq 'CIM_DataFile')
                {
                    Select-Object -InputObject $ExeFile -Property FileName,Extension,Manufacturer,Version -OutVariable $Executables
                }
            }
        }
    }

    # Do a little clean-up work. Not exactly necessary, but useful for debugging in PowerGUI
    end
    {
        Write-Verbose "End: Cleaning up variables used for function"
        Remove-Item -ErrorAction SilentlyContinue -Path variable:ExeFile,variable:ProcessName,variable:ProcExe,
        variable:ProcExes,variable:ProcPath,variable:ProcQuery,variable:Procs
    }
}

# Call the function we just defined, with its single parameter
. Get-Executables 