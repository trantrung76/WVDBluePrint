param ($groupName, $userPrincipalName)
Write-Host "Adding UPN ($userPrincipalName) to group ($groupName)"

if ($null -eq (Get-AzADGroup -DisplayName "$groupName")) {
    $mailNickname = $groupName -replace '[\W]',''
    New-AzADGroup -DisplayName "$groupName" -MailNickname $mailNickname
}

if ($null -eq (Get-AzADGroupMember -GroupDisplayName "$groupName" | Where-Object {$_.UserPrincipalName -eq $userPrincipalName})) {
    $parameters = @{
        TargetGroupDisplayName              =  "$groupName"
        MemberUserPrincipalName             =  $userPrincipalName
    }
    Add-AzADGroupMember @parameters
}