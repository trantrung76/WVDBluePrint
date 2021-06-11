param ($totalUsers, $prefix, $domainname, $keyvault, $forcePasswordChange, $adGroup, $wvdAppGroup, $wvdRolename, $appGroupRG)

Write-host "Total Users: $totalUsers"
Write-host "Prefix: $prefix"
Write-host "AD Group: $adGroup"
Write-host "KeyVault: $keyvault"
Write-host "Force PW Change: $forcePasswordChange"
Write-host "WVD App Group $wvdAppGroup"
Write-host " WVD Role: $wvdRolename"
Write-host "WVD App Group RG: $appGroupRG"

for ($i = 1 ; $i -le $totalUsers ; $i++) {
    $displayName = $prefix + $i
    $userPrincipalName = $displayName + '@' + $domainname
    Write-host "Creating $userPrincipalName"
    
    if ($null -eq (Get-AzADUser -UserPrincipalName $userPrincipalName)) {
        .\addADuser.ps1 -displayName "$displayName" -userPrincipalName "$userPrincipalName" -keyVault $keyvault -forcePasswordChange $forcePasswordChange
    }

    .\assignADGroup.ps1 -groupName "$adGroup" -userPrincipalName "$userPrincipalName"
    .\assignWVDRole.ps1 -upn "$userPrincipalName" -roleName "$wvdRolename" -appGroupName "$wvdAppGroup" -appGroupRG "$appGroupRG"
}
