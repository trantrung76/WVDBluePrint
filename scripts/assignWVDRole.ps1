param ($upn, $roleName, $appGroupName, $appGroupRGName)

if ($null -eq (Get-AzRoleAssignment -SignInName $upn -ResourceGroupName $appGroupRGName -ResourceName $appGroupName -ResourceType 'Microsoft.DesktopVirtualization/applicationGroups')) {
    New-AzRoleAssignment -SignInName $upn -RoleDefinitionName "$roleName" -ResourceGroupName "$appGroupRGName" -ResourceName "$appGroupName" -ResourceType 'Microsoft.DesktopVirtualization/applicationGroups'
}