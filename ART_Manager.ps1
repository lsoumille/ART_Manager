<#
.SYNOPSIS
  This script aims to launch Atomic Checks and log every actions

.DESCRIPTION

.PARAMETER $TestPaths
  Locations of Atomic Red Team Tests

.OUTPUTS

.NOTES
  Version:        1.0
  Author:         SOUMILL
  Creation Date:  March 25th 2018
  Purpose/Change: Initial script development
  
.EXAMPLE
 
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param(
  [string[]]$TestPaths
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$day = Get-Date -Format "dd-MMM-yyyy"
$sLogPath = ".\"
$sLogName = "art_manager_$($day).log"
$sLogFileJson = Join-Path -Path $sLogPath -ChildPath $sLogName
$Keep = 5

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Write-Verbose-Log ($Severity, $Message, $Exception, $Path_To_Log)
{
    $Log_TS = Get-Date -Format HH:mm:ss.fff

    if ($Severity -eq "ERROR")
    {
        $NewLogData = @{ "Time" = $Log_TS; "Message" = $Message; "Exception" = $Exception; "Severity" = $Severity }
    }
    else
    {
        $NewLogData = @{ "Time" = $Log_TS; "Message" = $Message; "Exception" = $Exception; "Severity" = $Severity }
    }
    $CurrentLog = ConvertTo-Json $NewLogData -Compress
    $CurrentLog | Out-File ($Path_To_Log -replace '"',"")  -Append utf8
}

function Log-Rotate ()
{
    $NumberOfFiles = Get-ChildItem $sLogPath -File *.log | Measure-Object | %{$_.Count}
    if ($NumberOfFiles -gt $Keep) 
    {
        $NumberOfFilesToDelete = $NumberOfFiles - $Keep
        Get-ChildItem $sLogPath -File *.log | Sort CreationTime | Select -First $NumberOfFilesToDelete | Remove-Item
    }
}

function Verify-Paths ()
{
    foreach ($Path in $TestPaths)
    {
        if (-not (Test-Path $Path))
        {
            Write-Verbose-Log "Error" "Specified Path does not exist : $($Path)" "" $sLogFileJson
            exit
        }
    }
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Verbose-Log "INFO" "Script Start" "" $sLogFileJson

Write-Verbose-Log "INFO" "Start Logrotate" "" $sLogFileJson
Log-Rotate

Write-Verbose-Log "INFO" "Path Verification" "" $sLogFileJson
Verify-Paths

# Load ART Powershell Framework
 
# Get Latest Atomic Checks

# Handle Parameters

# Launch Checks

Write-Verbose-Log "INFO" "Script End" "" $sLogFileJson