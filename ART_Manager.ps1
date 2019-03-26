<#
.SYNOPSIS
  This script aims to launch Atomic Checks and log every actions

.DESCRIPTION

.PARAMETER $ARTPath
  Locations of Atomic Red Team Module (psm1)

.PARAMETER $Sleeptime
  Sleeping time between two ART checks execution (default to 300 seconds)

.PARAMETER $CheckToExecute
  Specify the ATT&CK check that you want to execute or all for executing all of them (default to All)

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
  [string]$ARTPath = "C:\Program Files\atomic-red-team\execution-frameworks\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1",
  [int]$SleepTime = 300,
  [string[]]$CheckToExecute = @($Execute_All)
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
$Test_Path_Git = "ssh://git@git.iter.org/itsecu/atomic_tests.git"
$Atomic_Checks = Join-Path -Path $Temp_Folder -ChildPath "atomic_tests"

#ART constants
$Execute_All = "All"


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

function Load-Atomic-Checks ()
{
    #Dictionnary with ATT&CK ID as key and array of ART objects as value
    $All_Atomic_Tests_To_Execute = @{}
    #Get Top Level Folders
    $All_Top_Folders = Get-ChildItem -Path $Atomic_Checks
    #Get checks from all top folders
    foreach ($Top_Folder in $All_Top_Folders)
    {
        $All_Attack_Folder = Get-ChildItem -Path $Top_Folder
        foreach ($Attack_Folder in $All_Attack_Folder)
        {
            #Add check if execute all flag is set
            if ($CheckToExecute.Contains($Execute_All) -or $CheckToExecute.Contains($Attack_Folder))
            {
                $Attack_ID = Split-Path $Attack_Folder -Leaf
                $ART_Check = Create-ART-Check ($Attack_ID, $Attack_Folder)
                Add-Check-To-Queue ($All_Atomic_Tests_To_Execute, $Attack_ID, $ART_Check)
            }
        }
    }
    return $All_Atomic_Tests_To_Execute
}

#From folder create ART object
function Create-ART-Check ($Attack_ID, $Attack_Folder)
{
    $Check_Path = Join-Path -Path $Attack_Folder -ChildPath "$($Attack_ID).yaml"
    $Current_Location = Get-Location
    Set-Location $Attack_Folder
    if (-not (Test-Path $Check_Path))
    {
        Set-Location $Current_Location
        Write-Verbose-Log "Error" "Specified Path does not exist for ATT&CK ID $($Attack_ID)" "MissingRequirement" $sLogFileJson
        exit
    }
    #Create Object
    $ART_Object = Get-AtomicTechnique -Path $Check_Path
    Set-Location $Current_Location
    return $ART_Object
}

function Add-Check-To-Queue ($All_Atomic_Tests_To_Execute, $Attack_ID, $ART_Check)
{
    #Check if a check already exists in dictionary
    if ($All_Atomic_Tests_To_Execute.ContainsKey($Attack_Folder))
    {
        #Add Check to array
        $ART_Object_Array = $All_Atomic_Tests_To_Execute."$($Attack_ID)"
        $ART_Object_Array += $ART_Check
        $All_Atomic_Tests_To_Execute."$($Attack_ID)" = $ART_Object_Array
    }
    else
    {
        #Create Array
        $ART_Object_Array = @($ART_Check)
        $All_Atomic_Tests_To_Execute.Add($Attack_ID, $ART_Object_Array)
    }
    return $All_Atomic_Tests_To_Execute
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
Get-Latest-Atomic-Checks

Write-Verbose-Log "INFO" "Load Atomic Check Configuration" "" $sLogFileJson
Load-Atomic-Checks

# Launch Checks

Write-Verbose-Log "INFO" "Clean Up" "" $sLogFileJson
Clean-Up

Write-Verbose-Log "INFO" "Script End" "" $sLogFileJson