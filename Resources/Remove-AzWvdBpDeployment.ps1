<#
.SYNOPSIS
    Exports logs from and removes an entire WVD Blueprint deployment
.DESCRIPTION
    Exports logs found in a WVD Blueprint deployment's Log Analytics Workspace to a csv file stored in the directory specified at runtime    

    Finds and removes the following items that were previously deployed via WVD Blueprint:
    - All SessionHosts and HostPools in a ResourceGroup based on resource prefix
    - All users discovered in 'WVD Users' group
    - 'WVD Users' group itself
    - 'AAD DC Admins' group

    
    Use of -verbose, -whatif or -comfirm ARE supported.

    Note: The script will create one Powershell Job for each Resource Group being removed

    
.LINK
    https://github.com/Azure/WVDBlueprint

.EXAMPLE
    .\Remove-AzWvdBpDeployment.ps1 -Verbose -Prefix "ABC" -LogPath "C:\projects"

    Exports logs of a WVD Blueprint deployment that used the prefix "ABC" followed by a removal of that deployment

.EXAMPLE
    .\Remove-AzWvdBpDeployment.ps1 -Verbose -Prefix "ABC" -DisableLogExport

    Performs a removal of a WVD Blueprint deployment that used the prefix "ABC" without first exporting the deployment's logs

.INPUTS
    None. You cannot pipe objects into this script.

.OUTPUTS
    None. Only console text is displayed by this script.

    Note: if a cleanup is performed, it is in the context of a Powershell Job after this script completes
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    #The prefix used to match against Azure resources for inclusion in this cleanup
    [Parameter(Mandatory=$true)]
    [string] $Prefix,
    #Switch to override the default behavior of exporting a target environment's logs prior to cleanup
    [Parameter(Mandatory=$true, ParameterSetName="DisableLogExport")]
    [switch] $DisableLogExport,
    #Path to the folder where the target environment's logs should be copied
    [Parameter(Mandatory=$true, ParameterSetName="LogExport")]
    [string] $LogPath
)

$RemovalScope = Get-AzResourceGroup | Where-Object {$_.ResourceGroupName -like "$($Prefix)*"} 
Write-Verbose "Found $($RemovalScope.count) Resource Groups"

$RemovalScope | ForEach-Object {
    $ThisRG = $_
    $AllLocks = Get-AzResourceLock -ResourceGroupName $ThisRG.ResourceGroupName
    Write-Verbose "Found $($AllLocks.count) locks"
    $AllLocks | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.Name, "Remove Lock")) {
            Remove-AzResourceLock -LockId $_.LockId -Force    
        }
    }

    $hp = Get-AzWvdHostPool -ResourceGroupName $ThisRG.ResourceGroupName
    Write-Verbose "Found $($hp.count) Host Pools"
    $hp | ForEach-Object {
        $ThisHP = $_
        Write-Verbose "Processing Host Pool $($ThisHP.Name) for Session Hosts"
        $sh = Get-AzWvdSessionHost -HostPoolName $ThisHP.Name -ResourceGroupName $ThisRG.ResourceGroupName
        Write-Verbose "Found $($sh.count) Session Hosts"
        $sh | ForEach-Object {
            #Workaround due to mismatch in Name formats between Get-AzWvdSessionHost and Remove-AzWvdSessionHost
            $ThisSH = ($_.Name -split "/")[1]

            if($PSCmdlet.ShouldProcess($ThisSH,"Remove Session Host")){
                Remove-AzWvdSessionHost -HostPoolName $ThisHP.Name -ResourceGroupName $ThisRG.ResourceGroupName -Name $ThisSH
            }
        }
        Write-Verbose "Processing Host Pool $($ThisHP.Name) for Application Groups"
        $ag = ($ThisHP | Select-Object -ExpandProperty ApplicationGroupReference) -split "/" | Select-Object -Last 1
        if ($PSCmdlet.ShouldProcess($ag, "Remove Application Group")) {
            Remove-AzWvdApplicationGroup -Name $ag -ResourceGroupName $ThisRG.ResourceGroupName
        }

        if($PSCmdlet.ShouldProcess($_.Name,"Remove Host Pool")){
            Remove-AzWvdHostPool -ResourceGroupName $RemovalScope.ResourceGroupName -Name $_.name
        }
    }
    
    Write-Verbose "Exporting logs to $LogPath"
    $laws = Get-AzOperationalInsightsWorkspace -Name "$prefix-sharedsvcs-log" -ResourceGroupName $thisrg.ResourceGroupName
    if($PSBoundParameters.ContainsKey('DisableLogExport')){
        Write-Verbose "-DisableLogExport switch called"
    } else {
        if($PSCmdlet.ShouldProcess($laws.Name, "Export logs to $LogPath")){
            Write-Verbose "Querying log data from $($laws.Name)"
            $logdata = Invoke-AzOperationalInsightsQuery -Workspace $laws -Query "search *" -Verbose
            $timestamp = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
            $tenantname = $(Get-AzTenant).Name
            $ExportFile = "$LogPath\$timestamp-$tenantname-log-export.csv"
            Write-Verbose "Writing log data to $ExportFile"
            $logdata.Results | Export-Csv -Path $ExportFile
        }
    }
   

    if($PSCmdlet.ShouldProcess($_.ResourceGroupName, "Remove ResourceGroup")){
        $_ | Remove-AzResourceGroup -Force -AsJob
    }
}

Write-Verbose "Processing tenant level items created by WVD Blueprint"

$RemoveWvdUsers = Get-AzADGroup -DisplayName "WVD Users" | Get-AzADGroupMember
Write-Verbose "Found $($RemoveWvdUsers.count) WVD users"
$RemoveWvdUsers | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.DisplayName, "Remove WVD User")) {
        Remove-AzADUser -DisplayName $_.DisplayName -Force
    }
}

$RemoveDomAdminUser = Get-AzADUser -DisplayName "domainadmin"
Write-Verbose "Found $($RemoveDomAdminUser.count) DomainAdmin user"
$RemoveDomAdminUser | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.DisplayName, "Remove DomainAdmin User")) {
        Remove-AzADUser -DisplayName $_.DisplayName -Force
    }
}

$RemoveWvdGroup = Get-AzADGroup -DisplayName "WVD Users"
if ($RemoveWvdGroup) {
    Write-Verbose "Found '$($RemoveWvdGroup.DisplayName)' group"
    if ($PSCmdlet.ShouldProcess($RemoveWvdGroup.DisplayName, "Remove WVD Group")) {
        $RemoveWvdGroup | Remove-AzADGroup -Force
    }
}

$RemoveAADDCAdminsGroup = Get-AzADGroup -DisplayName "AAD DC Administrators"
if ($RemoveAADDCAdminsGroup) {
    Write-Verbose "Found '$($RemoveAADDCAdminsGroup.DisplayName)' group"
    if ($PSCmdlet.ShouldProcess($RemoveAADDCAdminsGroup.DisplayName, "Remove AAD DC Administrators Group")) {
        $RemoveAADDCAdminsGroup | Remove-AzADGroup -Force
    }
}

if ($PSCmdlet.ShouldProcess("PowershellJobs", "DisplayActiveJobs")) {
    Get-Job | Group-Object State
    Write-Host "Use 'Get-Job | Group-Object State' to track status of Resource Group removal jobs"    
} else {
    Write-Verbose "Active removal jobs would be displayed here"
}