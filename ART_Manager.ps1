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

.PARAMETER $WhatIf
  Use this switch to make a dry run

.PARAMETER $LogDir
  ART check log location

.OUTPUTS

.NOTES
  Version:        0.1
  Author:         SOUMILL
  Creation Date:  March 25th 2018
  Purpose/Change: Initial script development
  
.EXAMPLE
 
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param(
  [string]$ARTPath = "C:\Program Files\atomic-red-team\execution-frameworks\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1",
  [int]$SleepTime = 300,
  [string[]]$CheckToExecute = "All",
  [switch]$WhatIf,
  [string]$LogDir = "C:\Program Files\atomic-red-team\art_launcher\logs"
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "0.1"

#ConfirmPreference
$ConfirmPreference = "High"

#Log File Info
$day = Get-Date -Format "dd-MMM-yyyy"
$Log_Name = "art_manager_$($day).log"
$Log_File = Join-Path -Path $LogDir -ChildPath $Log_Name
$Keep = 5

$Temp_Folder = "C:\Windows\Temp"

#Git
$Test_Path_Git = "XXXXX"
$Atomic_Checks = Join-Path -Path $Temp_Folder -ChildPath "atomic_tests"

#ART constants
$Execute_All = "All"


#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Write-Verbose-Log ($Severity, $Message, $Exception, $Path_To_Log, $Color)
{
    $Log_TS = Get-Date -Format HH:mm:ss.fff
	
	
    if ($Severity -eq "ERROR")
    {
        Write-Error -Exception $Exception -Message "[$($Severity) - $($Exception)] $($Message)"
    }
    elseif ($Color)
    {
        Write-Host "[$($Severity) - $($Exception)] $($Message)" -ForegroundColor DarkGreen -BackgroundColor White
    }
    else
    {
        Write-Host "[$($Severity) - $($Exception)] $($Message)"
    }
}

function Write-Trace ($ART_Output, $ART_Information_Output, $Attack_ID, $Check_Description)
{
    $Log_TS = Get-Date -Format HH:mm:ss.fff

	if (-not (Test-Path $LogDir))
	{
		New-Item -ItemType Directory -Path $LogDir
	}
    $Message = "" 
    foreach($Info_Line in $($ART_Information_Output -split "`n"))
    {
        if ($Info_Line -eq "[!!!!!!!!END TEST!!!!!!!]") 
        {
            foreach($Output_Line in $($ART_Output -split "`t"))
            {
                $Message = "$($Message)$($Output_Line.Trim())`n"
            }            
        }
        $Message = "$($Message)$($Info_Line.Trim())`n"
    }
    $Log_Data = @{ "timestamp" = $Log_TS ; "attack_id" = $Attack_ID ; "attack_test" = $Check_Description ; "message" = $Message }
    $CurrentLog = ConvertTo-Json $Log_Data -Compress
    $CurrentLog | Out-File ($Log_File -replace '"',"")  -Append utf8
}

function Log-Rotate ()
{
    $NumberOfFiles = Get-ChildItem $LogDir -File *.log | Measure-Object | %{$_.Count}
    if ($NumberOfFiles -gt $Keep) 
    {
        $NumberOfFilesToDelete = $NumberOfFiles - $Keep
        Get-ChildItem $LogDir -File *.log | Sort CreationTime | Select -First $NumberOfFilesToDelete | Remove-Item
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
        git clone -q $Test_Path_Git $null
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
    if (Test-Path -Path $Atomic_Checks)
    {
        Remove-Item -Recurse -Force -Path $Atomic_Checks
    }
    
}

function Load-Atomic-Checks ()
{
    try
    {
        #Dictionnary with ATT&CK ID as key and array of ART objects as value
        $All_Atomic_Tests_To_Execute = @{}
        #Get Top Level Folders
        $All_Top_Folders = Get-ChildItem -Path $Atomic_Checks
        #Get checks from all top folders
        foreach ($Top_Folder in $All_Top_Folders)
        {
            $Top_Folder_Path = Join-Path -Path $Atomic_Checks -ChildPath $Top_Folder
            #Check if it's folder
            if ((Get-Item $Top_Folder_Path) -is [System.IO.DirectoryInfo])
            {
                $All_Attack_Folder = Get-ChildItem -Path (Join-Path -Path $Atomic_Checks -ChildPath $Top_Folder)
                foreach ($Attack_Folder in $All_Attack_Folder)
                {
                    $Attack_Folder_Path = Join-Path -Path $Top_Folder_Path -ChildPath $Attack_Folder
                    #Check if it's folder
                    if ((Get-Item $Attack_Folder_Path) -is [System.IO.DirectoryInfo])
                    {
                        #Add check if execute all flag is set
                        if ($CheckToExecute.Contains($Execute_All) -or $CheckToExecute.Contains($Attack_Folder))
                        {
                            #$Attack_ID = Split-Path $Attack_Folder -Leaf
                            $ART_Check = Create-ART-Check $Attack_Folder_Path
                            $All_Atomic_Tests_To_Execute = Add-Check-To-Queue $All_Atomic_Tests_To_Execute $ART_Check
                        }
                    }
                }
            }
        }
        return $All_Atomic_Tests_To_Execute
    }
    catch
    {
        Write-Verbose-Log "Error" "Error during Rule loading : $($Top_Folder) / $($Attack_Folder)" $_.Exception $sLogFileJson
        Clean-Up
        exit
    }
}

#From folder create ART object
function Create-ART-Check ($Attack_Folder)
{
    try
    {
        $Attack_ID = Split-Path $Attack_Folder -Leaf
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
    catch
    {
        Set-Location $Current_Location
        Write-Verbose-Log "Error" "Error during Rule loading : $($Attack_ID)" $_.Exception $sLogFileJson
        Clean-Up
        exit
    }
}

function Add-Check-To-Queue ($All_Atomic_Tests_To_Execute, $ART_Check)
{
    #Check if a check already exists in dictionary
    if ($All_Atomic_Tests_To_Execute.ContainsKey($ART_Check.attack_technique))
    {
        #Add Check to array
        $ART_Object_Array = $All_Atomic_Tests_To_Execute."$($ART_Check.attack_technique)"
        $ART_Object_Array += $ART_Check
        $All_Atomic_Tests_To_Execute."$($ART_Check.attack_technique)" = $ART_Object_Array
    }
    else
    {
        #Create Array
        $ART_Object_Array = @($ART_Check)
        $All_Atomic_Tests_To_Execute.Add($ART_Check.attack_technique, $ART_Object_Array)
    }
    return $All_Atomic_Tests_To_Execute
}

function Launch-ART-Checks ($All_Atomic_Tests_To_Execute)
{
     #Go over all Attack IDs
     foreach($Attack_ID in $All_Atomic_Tests_To_Execute.Keys)
     {
		Write-Verbose-Log "INFO" "Start ART Checks for ATT&CK ID $($Attack_ID)" "Execution" $sLogFileJson $true
        #Go over all checks for this Attack ID 
        foreach ($ART_Check in $All_Atomic_Tests_To_Execute.$Attack_ID)
        {
            Write-Verbose-Log "INFO" "Beginning of $($ART_Check.display_name)" "Execution" $sLogFileJson
			#Check if dry run mode is set
			if ($WhatIf)
			{
				Invoke-AtomicTest -GenerateOnly -InformationAction Continue $ART_Check
			}
			else
			{
				Invoke-AtomicTest $ART_Check -InformationVariable Information_Trace -OutVariable Output | Out-Null
                Write-Trace $Output $Information_Trace $Attack_ID $ART_Check.display_name
			}
            Write-Verbose-Log "INFO" "End of $($ART_Check.display_name)" "Execution" $sLogFileJson
            if (-not $WhatIf)
            {
                #Sleep between checks
		        Start-Sleep -s $SleepTime
            }
        }
     }   
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Verbose-Log "INFO" "Script Start" "Execution" $sLogFileJson
Clean-Up

Write-Verbose-Log "INFO" "Start Logrotate" "Execution" $sLogFileJson
Log-Rotate

Write-Verbose-Log "INFO" "Load ART PS Framework" "Execution" $sLogFileJson
Load-ART

Write-Verbose-Log "INFO" "Get Latest Atomic Checks" "Execution" $sLogFileJson
Get-Latest-Atomic-Checks

Write-Verbose-Log "INFO" "Load Atomic Check Configuration" "Execution" $sLogFileJson
$All_Atomic_Tests_To_Execute = Load-Atomic-Checks

if (-not ($All_Atomic_Tests_To_Execute) -or ($All_Atomic_Tests_To_Execute.Count -eq 0))
{
    Write-Verbose-Log "ERROR" "No ART Check to run" "MissingRequirement" $sLogFileJson
    Clean-Up
    Exit
}

Write-Verbose-Log "INFO" "ART Execution" "Execution" $sLogFileJson
Launch-ART-Checks $All_Atomic_Tests_To_Execute

Write-Verbose-Log "INFO" "Clean Up" "Execution" $sLogFileJson
Clean-Up

Write-Verbose-Log "INFO" "Script End" "Execution" $sLogFileJson