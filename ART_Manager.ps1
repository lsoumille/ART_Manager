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
  [string]$TestPaths,
  [string]$ARTPath = "C:\Program Files\atomic-red-team\execution-frameworks\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1"
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

$Temp_Folder = "C:\Windows\Temp"

#Git
$Test_Path_Git = "..."
$Atomic_Checks = Join-Path -Path $Temp_Folder -ChildPath "atomic_tests"


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
            Write-Verbose-Log "Error" "Specified Path does not exist : $($Path)" "MissingRequirement" $sLogFileJson
            exit
        }
    }
}

function Load-ART ()
{
    if (-not (Test-Path $ARTPath))
    {
        Write-Verbose-Log "Error" "ART Module does not exist : $($ARTPath)" "MissingRequirement" $sLogFileJson
        exit
    }
    try
    {
        Import-Module $ARTPath
    }
    catch
    {
        Write-Verbose-Log "Error" "Error when loading ART Module" $_.Exception $sLogFileJson
        exit
    }
}

function Get-Latest-Atomic-Checks ()
{
    try 
    {
        $Current_Location = Get-Location
        Set-Location $Temp_Folder
        git clone $Test_Path_Git
        Set-Location $Current_Location
    }
    catch
    {
        Set-Location $Current_Location
        Write-Verbose-Log "Error" "Error when pulling latest ART checks version" $_.Exception $sLogFileJson
        Clean-Up
        exit
    }
}

function Clean-Up ()
{
    Remove-Item -Recurse -Force -Path $Atomic_Checks
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Verbose-Log "INFO" "Script Start" "" $sLogFileJson

Write-Verbose-Log "INFO" "Start Logrotate" "" $sLogFileJson
Log-Rotate

#Write-Verbose-Log "INFO" "Path Verification" "" $sLogFileJson
#Verify-Paths

Write-Verbose-Log "INFO" "Load ART PS Framework" "" $sLogFileJson
Load-ART

Write-Verbose-Log "INFO" "Get Latest Atomic Checks" "" $sLogFileJson
#Update-Atomic-Checks-Dirs 

# Handle Parameters

# Launch Checks

Write-Verbose-Log "INFO" "Clean Up" "" $sLogFileJson
Clean-Up

Write-Verbose-Log "INFO" "Script End" "" $sLogFileJson