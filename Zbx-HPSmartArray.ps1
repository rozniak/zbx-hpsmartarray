<#
    .SYNOPSIS
    Script for getting data from HP MSA to Zabbix monitoring system.

    .DESCRIPTION
    The script may generate LLD data for HP Smart Array Controllers, Logical Drives and Physical Drives.
    Also it can takes some components health status. It's using HP Array Configuration Utility to
    connect to controller, so you must install it first:
    https://support.hpe.com/hpsc/swd/public/detail?swItemId=MTX_33fe6fcf4fcb4beab8fee4d2dc

    Works only with PowerShell 3.0 and above.
    
    .PARAMETER action
    What we want to do - make LLD or get component health status (takes: lld, health)

    .PARAMETER part
    Smart array component - controller, logical drive or physical drive (takes: ctrl, ld, pd)

    .PARAMETER identity
    Part of target, depends of context:
    For controllers: main controller status, it's battery or cache status (takes: main, batt, cache);
    For logical drives: id of logical drive (takes: 1, 2, 3, 4 etc);
    For physical drives: id of physical drive (takes: 1E:1:1..2E:1:12 etc)

    .PARAMETER ctrlid
    Controller identity. Usual it's controller slot, but may be set to serial number.

    .PARAMETER version
    Print verion number and exit

    .EXAMPLE
    Zbx-HPSmartArray.ps1 -action lld -part ctrl
    {"data":[{"{#CTRL.MODEL}":"Smart Array P800","{#CTRL.SN}":"P98690G9SVA0BE"}]}

    .EXAMPLE
    Get-HPSmartArray.ps1 health ld 1
    OK

    .EXAMPLE
    Get-HPSmartArray.ps1 health pd 2E:1:12
    Rebuilding

    .NOTES
    Author: Khatsayuk Alexander
    Github: https://github.com/asand3r/
#>

Param (
    [switch]$version = $False,
    [ValidateSet("lld","health")][Parameter(Position=0, Mandatory=$True)][string]$action,
    [ValidateSet("ctrl","ld","pd")][Parameter(Position=1, Mandatory=$True)][string]$part,
    [string][Parameter(Position=2, Mandatory=$False)]$ctrlid,
    [string][Parameter(Position=3, Mandatory=$False)]$partid
)

# Script version
$VERSION_NUM="0.4.4"
if ($version) {
    Write-Host $VERSION_NUM
    break
}

# HP Array Configuration Utility location
$possibleSsaCliLocations = (
    "$env:ProgramFiles\hp\hpssacli\bin\hpssacli.exe",
    "$env:ProgramFiles\Smart Storage Administrator\ssacli\bin\ssacli.exe",
    "$env:ProgramFiles\Compaq\Hpacucli\Bin\hpacucli.exe"
)
$ssacli = [String]::Empty

foreach ($path in $possibleSsaCliLocations)
{
    if (Test-Path $path -PathType Leaf)
    {
        $ssacli = $path;
    }
}

if ([String]::IsNullOrEmpty($ssacli))
{
    throw [System.FileNotFoundException] "Unable to locate HP Smart Storage Administrator CLI tool."
}

# Retrieve one Smart Array Controller info from given string
function Get-CtrlInfo($ctrl) {
        $model = $ctrl -replace "\sin.*$"
        if ($ctrl -match '\(sn:\s.+$') {
            $sn = $Matches[0] -creplace '[sn:()\s]'
        } else {
            $sn = "UNKNOWN"
        }
        $slot = $ctrl -replace "^.+Slot\s" -replace "\s.+$"
        return $model, $sn, $slot
}

function Make-LLD() {
    param(
        [string]$part
    )

    # Detect all HP Smart Array Controllers
    [array]$all_ctrls = & "$ssacli" "ctrl all show".Split() | Where-Object {$_ -match "\w"}

    # Global list to store formed LLD object
    [array]$lld_obj_list = @()
    
    foreach ($ctrl in $all_ctrls) {
        $ctrl_model, $ctrl_sn, $ctrl_slot = Get-CtrlInfo($ctrl)
        switch ($part) {
            "ctrl" {
                    [array]$lld_obj_list += [psobject]@{"{#CTRL.MODEL}" = $ctrl_model; "{#CTRL.SN}" = $ctrl_sn; "{#CTRL.SLOT}" = $ctrl_slot}
            }
            "ld" {
                    $all_ld = & "$ssacli" "ctrl slot=$($ctrl_slot) ld all show status".Split() | Where-Object {$_ -match "logicaldrive"}
                    
                    foreach ($ld in $all_ld) {                     
                        if ($ld -match "logicaldrive (?<Num>\d{1,}) \((?<Capacity>[\d.]{1,} [KGT]B?), (?<RAID>RAID [\d\+]+)\)") {
                            [array]$lld_obj_list += [psobject]@{"{#LD.NUM}" = $Matches.Num;
                                                                "{#LD.CAPACITY}" = $Matches.Capacity;
                                                                "{#LD.RAID}" = $Matches.RAID;
                                                                "{#CTRL.SLOT}" = $ctrl_slot;
                                                                "{#CTRL.SN}" = $ctrl_sn;
                                                                "{#CTRL.MODEL}" = $ctrl_model
                                                                }
                        }
                    }
            }
            "pd" {
                    $all_pd = & "$ssacli" "ctrl slot=$($ctrl_slot) pd all show status".Split() | Where-Object {$_ -match "physicaldrive"}
                    
                    foreach ($pd in $all_pd) {
                        if ($pd -match "physicaldrive (?<Num>\d{1,}\w(:?\d){1,2}) \(.+ (?<Capacity>\d{1,} [KGT]B?)\)") {
                            [array]$lld_obj_list += [psobject]@{"{#PD.NUM}" = $Matches.Num;
                                                                "{#PD.CAPACITY}" = $Matches.Capacity;
                                                                "{#CTRL.SLOT}" = $ctrl_slot;
                                                                "{#CTRL.SN}" = $ctrl_sn;
                                                                "{#CTRL.MODEL}" = $ctrl_model
                                                                }
                        }
                    }
            }
        }
    }
    return ConvertTo-Json @{"data" = $lld_obj_list}
}

function Get-Health() {
    param(
        [string]$part,
        [string]$ctrlid,
        [string]$partid
    )

    # Determine which controller id is provided
    if ($ctrlid -match "^\d{1,}$") {
        $ctrid_type = "slot"
    } else {
        $ctrid_type = "sn"
    }

    switch ($part) {
        "ctrl" {
            $ctrl_status = (& "$ssacli" "ctrl $($ctrid_type)=$($ctrlid) show detail".Split(" ")).Split([Environment]::NewLine)
            
            switch ($partid) {
                "main" {
                    return Find-Value "Controller Status" $ctrl_status
                }
                "cache" {
                    return Find-Value "Cache Status" $ctrl_status
                }
                "batt" {
                    return Find-Value "Battery/Capacitor Status" $ctrl_status
                }
                "summary" {
                    $checkController = Find-Value "Controller Status" $ctrl_status -eq "OK"
                    $checkCache      = Find-Value "Cache Status" $ctrl_status -eq "OK"
                    $checkBattery    = Find-Value "Battery/Capacitor Status" $ctrl_status -eq "OK"

                    if ($checkController -and $checkCache -and $checkBattery)
                    {
                        return 0; # OK
                    }
                    else
                    {
                        return 1; # Failed
                    }
                }
            }
            
            return "Find Value Failed"
        }
        "ld" {
            $ld_status = & "$ssacli" "ctrl $($ctrid_type)=$($ctrlid) ld $($partid) show status".Split() | Where-Object {$_ -match 'logicaldrive \d'}
            return ($ld_status -replace '.+:\s')
        }
        "pd" {
            $pd_status = & "$ssacli" "ctrl $($ctrid_type)=$($ctrlid) pd $($partid) show status".Split() | Where-Object {$_ -match 'physicaldrive \d'}
            return ($pd_status -replace '.+\:\s')
        }
    }
}

function Find-Value() {
    param (
        [string]$key,
        [array]$arr
    )
    
    foreach ($str in $arr)
    {
        $split = $str.Split(":")
        
        if ($split[0].Trim() -eq $key)
        {
            return $split[1].Trim()
        }
    }
    
    return "Undefined"
}

switch ($action) {
    "lld" {
        Write-Host $(Make-LLD -part $part)
    }
    "health" {
        Write-Host $(Get-Health -part $part -ctrlid $ctrlid -partid $partid)
    }
    default {Write-Host "ERROR: Wrong first argument: use 'lld' or 'health'"}
}