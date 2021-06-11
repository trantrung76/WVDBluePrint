param ($displayName, $userPrincipalName, $keyvault, $forcePasswordChange, $adGroup, $wvdAppGroup, $wvdRolename, $appGroupRG)

Write-host "DisplayName: $displayName"
Write-host "User Principal: $userPrincipalName"
Write-host "AD Group: $adGroup"
Write-host "KeyVault: $keyvault"
Write-host "Force PW Change: $forcePasswordChange"
Write-host "WVD App Group $wvdAppGroup"
Write-host " WVD Role: $wvdRolename"
Write-host "WVD App Group RG: $appGroupRG"

if ($null -eq (Get-AzADUser -UserPrincipalName $userPrincipalName)) {
    .\addADuser.ps1 -displayName "$displayName" -userPrincipalName "$userPrincipalName" -keyVault $keyvault -forcePasswordChange $forcePasswordChange
}

.\assignADGroup.ps1 -groupName "$adGroup" -userPrincipalName "$userPrincipalName"

.\assignWVDRole.ps1 -upn "$userPrincipalName" -roleName "$wvdRolename" -appGroupName "$wvdAppGroup" -appGroupRG "$appGroupRG"