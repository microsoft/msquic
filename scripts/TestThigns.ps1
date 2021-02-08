function Convert-HostToNetworkOrder {
    param ($Address)
    $Bytes = $Address.GetAddressBytes()
    [Array]::Reverse($Bytes) | Out-Null
    return [System.BitConverter]::ToUInt32($Bytes, 0)
}

class IpData {
    [Int64]$PrefixLength;
    [System.Net.IPAddress]$IPv4Address;

    IpData([Int64]$PrefixLength, [System.Net.IPAddress]$Address) {
        $this.PrefixLength = $PrefixLength;
        $this.IPv4Address = $Address;
    }
}

function Get-Ipv4Addresses {
    $LocalIps = [System.Collections.Generic.List[IpData]]::new();
    $Nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces();
    foreach ($Nic in $Nics) {
        if ($Nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) {
            continue;
        }

        $UniAddresses = $Nic.GetIPProperties().UnicastAddresses;
        if ($null -eq $UniAddresses) {
            continue;
        }

        foreach ($UniAddress in $UniAddresses) {
            $Addr = $UniAddress.Address;
            if ($Addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                continue;
            }
            $LocalIps.Add([IpData]::new($UniAddress.PrefixLength, $Addr))
        }
    }
    return $LocalIps;
}

function Get-LocalAddress {
    param ($RemoteAddress)
    $PossibleRemoteIPs = [System.Net.Dns]::GetHostAddresses($RemoteAddress) | Select-Object -Property IPAddressToString
    $PossibleRemoteIPs
    $PossibleLocalIPs = Get-Ipv4Addresses
    $MatchedIPs = @()
    $PossibleLocalIPs | ForEach-Object {

        [IPAddress]$LocalIpAddr = $_.IPv4Address

        $ToMaskLocalAddress = Convert-HostToNetworkOrder -Address $LocalIpAddr

        $Mask = (1ul -shl $_.PrefixLength) - 1
        $Mask = $Mask -shl (32 - $_.PrefixLength)
        $LocalSubnet = $ToMaskLocalAddress -band $Mask

        $PossibleRemoteIPs | ForEach-Object {
            [ipaddress]$RemoteIpAddr = $_.IPAddressToString
            $ToMaskRemoteAddress = Convert-HostToNetworkOrder($RemoteIpAddr)
            $RemoteMasked = $ToMaskRemoteAddress -band $Mask

            if ($RemoteMasked -eq $LocalSubnet) {
                $MatchedIPs += $LocalIpAddr.IPAddressToString
            }
        }
    }

    if ($MatchedIPs.Length -ne 1) {
        Write-Error "Failed to parse local address matching remote"
    }

    return $MatchedIPs[0]
}

Get-LocalAddress quic-server
