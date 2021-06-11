param ($displayName, $userPrincipalName, $keyvault, $forcePasswordChange)
Write-host "DisplayName: $displayName"
Write-host "User Principal: $userPrincipalName"

$mailNickname = $userPrincipalName -replace '[\W]',''
$pass = (Get-AzKeyVaultSecret -VaultName $keyvault -name $displayName).SecretValue

$parameters = @{
    DisplayName                  =  $displayName
    UserPrincipalName            =  $userPrincipalName
    Password                     =  $pass
    MailNickname                 =  $mailNickname
    ForceChangePasswordNextLogin = [System.Convert]::ToBoolean($forcePasswordChange)

}
if ($null -eq (Get-AzADUser -DisplayName $parameters.DisplayName)) {
    $parameters.GetEnumerator() | ForEach-Object{
        $message = '{0} is {1}.' -f $_.key, $_.value
        Write-Output $message
    }
    New-AzADUser @parameters
}