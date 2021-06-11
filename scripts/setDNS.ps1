param ($srcRG, $srcVnet, $srcSubnet, $dstRG, $dstVnet)
function Get-AzureSubnetPrivateIPs {
    Param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Vnet name", ValueFromPipeline = $false)] 
        $Vnet,
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Subnet name", ValueFromPipeline = $false)] 
        $subnet,
        [Parameter(Position = 1, Mandatory = $true, HelpMessage = "Resource group name", ValueFromPipeline = $false)] 
        $ResourceGroupName
    )

    Try {
        $subnet = Get-AzVirtualNetworkSubnetConfig -name $subnet -VirtualNetwork (Get-AzVirtualNetwork -Name $Vnet -ResourceGroupName $ResourceGroupName) 
    }
    Catch {
        Write-Error "VNET $Vnet can not be found!"
        break
    }

        if ($null -ne $subnet.IpConfigurations) {
            $subnetIPs = @()
            foreach ($ipconfig in $subnet.IpConfigurations) {
                $RG = $ipconfig.Id.Split("/")[4]
                $NIC = $ipconfig.Id.Split("/")[8]
                $IP = (Get-AzNetworkInterface -Name $NIC -ResourceGroupName $RG).IpConfigurations.PrivateIpAddress
                $subnetIPs += $IP
            }
            $SubnetName = $subnet.Name
            foreach ($NotAvailableIP in $subnetIPs) {
                Write-Host "Subnet $subnetname is using $NotAvailableIP."
            }
            return $subnetIPs
        }
}

function Deploy-AzureADDSDNSIPs  {
    Param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Source RG", ValueFromPipeline = $false)] 
        $srcRG,
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Source vNet", ValueFromPipeline = $false)] 
        $srcVNet,
        [Parameter(Position = 1, Mandatory = $true, HelpMessage = "Source subnet", ValueFromPipeline = $false)] 
        $srcSubnet,
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Destination RG", ValueFromPipeline = $false)] 
        $dstRG,
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Destination vNet", ValueFromPipeline = $false)] 
        $dstVNet
    )
    
    $dnsIPs = Get-AzureSubnetPrivateIPs -ResourceGroupName $srcRG -Vnet $srcVNet -subnet $srcSubnet
    $vnet = Get-AzVirtualNetwork -Name $dstVNet -ResourceGroupName $dstRG
    $obj = new-object -type PSObject -Property @{"DnsServers" = $dnsIPs}
    $vnet.DhcpOptions = $obj
    $vnet | Set-AzVirtualNetwork | out-null
    
    $DeploymentScriptOutputs = @{}
    $DeploymentScriptOutputs['dnsIPs'] = $dnsIPs
}

Deploy-AzureADDSDNSIPs -srcRG $srcRG -srcVNet $srcVnet -srcSubnet $srcSubnet -dstRG $dstRG -dstVnet $dstVnet