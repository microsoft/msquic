Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function SetGlobals {
    param ($Local, $LocalTls, $LocalArch, $RemoteTls, $RemoteArch, $Config)
    $script:Local = $Local
    $script:LocalTls = $LocalTls
    $script:LocalArch = $LocalArch
    $script:RemoteTls = $RemoteTls
    $script:RemoteArch = $RemoteArch
    $script:Config = $Config
}

function HostToNetworkOrder {
    param ($Address)
    $Bytes = $Address.GetAddressBytes()
    [Array]::Reverse($Bytes) | Out-Null
    return [System.BitConverter]::ToUInt32($Bytes, 0)
}

function ComputeLocalAddress {
    param ($RemoteAddress)

    $PossibleRemoteIPs = [System.Net.Dns]::GetHostAddresses($RemoteAddress) | Select-Object -Property IPAddressToString

    $PossibleLocalIPs = Get-NetIPAddress -AddressFamily IPv4 | Select-Object -Property IPv4Address, PrefixLength

    $MatchedIPs = @()

    $PossibleLocalIPs | ForEach-Object {

        [IPAddress]$LocalIpAddr = $_.IPv4Address

        $ToMaskLocalAddress = HostToNetworkOrder($LocalIpAddr)

        $Mask = (1ul -shl $_.PrefixLength) - 1
        $Mask = $Mask -shl (32 - $_.PrefixLength)
        $LocalSubnet = $ToMaskLocalAddress -band $Mask

        $PossibleRemoteIPs | ForEach-Object {
            [ipaddress]$RemoteIpAddr = $_.IPAddressToString
            $ToMaskRemoteAddress = HostToNetworkOrder($RemoteIpAddr)
            $RemoteMasked = $ToMaskRemoteAddress -band $Mask

            if ($RemoteMasked -eq $LocalSubnet) {
                $MatchedIPs += $LocalIpAddr.IPAddressToString
            }
        }
    }

    if ($MatchedIPs.Length -ne 1) {
        Write-Host "Failed to parse local address. Using first address"
    }
    return $MatchedIPs[0]
}

function Invoke-TestCommand {
    param ($Session, $ScriptBlock, [Object[]]$ArgumentList = @(), [switch]$AsJob = $false)

    if ($Local) {
        if ($AsJob) {
            return Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
        return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } else {
        if ($AsJob) {
            return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -AsJob -ArgumentList $ArgumentList
        }
        return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }   
}

function Wait-ForRemoteReady {
    param ($Job, $Matcher)
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($StopWatch.ElapsedMilliseconds -lt 10000) {
        $CurrentResults = Receive-Job -Job $Job -Keep
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match $Matcher
            if ($DidMatch) {
                return $true
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }
    return $false
}

function Wait-ForRemote {
    param ($Job)
    Wait-Job -Job $Job -Timeout 10 | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    param ([string]$From, [string]$To)
    try {
        Invoke-TestCommand $session -ScriptBlock { 
            param ($To) 
            Remove-Item -Path "$To/*" -Recurse -Force 
        } -ArgumentList $To
    } catch {
        # Ignore failure, which occurs when directory does not exist
    }
    # TODO Figure out how to filter this
    Copy-Item -Path "$From\*" -Destination $To -ToSession $session  -Recurse
}

class ArgumentsSpec {
    [string]$All;
    [string]$Loopback;
    [string]$Remote;

    [string]GetArguments() {
        if ($script:Local) {
            return "$($this.All) $($this.Loopback)"
        } else {
            return "$($this.All) $($this.Remote)"
        }
    }
}

class ExecutableSpec {
    [string]$Platform;
    [string[]]$Tls;
    [string[]]$Arch;
    [string]$Exe;
    [ArgumentsSpec]$Arguments;
}

class TestDefinition {
    [string]$TestName;
    [ExecutableSpec]$Remote;
    [ExecutableSpec]$Local;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;

    [string]ToString() {
        $RetString = ("{0}_{1}_{2}_{3}" -f $this.TestName,
                                        $this.Remote.Platform,
                                        $script:RemoteTls,
                                        $script:RemoteArch
                                        )
        if ($script:Local) {
            $RetString += "_Loopback"
        }
        return $RetString
    }

    [string]ToTestPlatformString() {
        $RetString = ("{0}_{1}_{2}" -f    $this.Remote.Platform,
                                    $script:RemoteTls,
                                    $script:RemoteArch
                                         )
        if ($script:Local) {
            $RetString += "_Loopback"
        }
        return $RetString
    }
}

class TestPublishResult {
    [string]$PlatformName
    [string]$TestName
    [string]$CommitHash
    [double[]]$IndividualRunResults
}

function Get-Tests {
    param ($Path)
    return [TestDefinition[]](Get-Content -Path $Path | ConvertFrom-Json)
}

function Validate-Tests {
    param ([TestDefinition[]]$Test)

    $TestSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($T in $Test) {
        if (!$TestSet.Add($T)) {
            return $false
        }
    }

    return $true
}

function Check-Test {
    param ([TestDefinition]$Test, $RemotePlatform, $LocalPlatform)
    $PlatformCorrect = ($Test.Local.Platform -eq $LocalPlatform) -and ($Test.Remote.Platform -eq $RemotePlatform)
    if (!$PlatformCorrect) {
        return $false
    }
    if (!$Test.Local.Tls.Contains($LocalTls)) {
        return $false
    }
    if (!$Test.Remote.Tls.Contains($RemoteTls)) {
        return $false
    }
    return $true
}

function Get-GitHash {
    param ($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RootDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentCommitHash = $null
    try {
        $CurrentCommitHash = git rev-parse HEAD
    } catch {
        Write-Debug "Failed to get commit hash from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentCommitHash
}

function Get-ExeName {
    param ($PathRoot, $Platform, $IsRemote, $TestPlat)
    $ExeName = $TestPlat.Exe
    if ($Platform -eq "windows") {
        $ExeName += ".exe"
    }

    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)"
        return Invoke-TestCommand -Session $session -ScriptBlock { 
            param ($PathRoot, $Platform, $ConfigStr, $ExeName) 
            Join-Path $PathRoot $Platform $ConfigStr $ExeName
        } -ArgumentList $PathRoot, $Platform, $ConfigStr, $ExeName
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)"
        return Join-Path $PathRoot $Platform $ConfigStr $ExeName
    }
}

function RunRemote-Exe {
    param ($Exe, $RunArgs, $TestName)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-TestCommand -Session $session -ScriptBlock {
        param ($Exe)
        if (!$IsWindows) {
            chmod +x $Exe
            return Split-Path $Exe -Parent
        }
        return $null
    } -ArgumentList $Exe

    Write-Debug "Running Remote: $Exe $RunArgs" | Out-Null

    return Invoke-TestCommand -Session $session -ScriptBlock {
        param ($Exe, $RunArgs, $BasePath)
        if ($null -ne $BasePath) {
            $env:LD_LIBRARY_PATH = $BasePath
        }
        
        & $Exe ($RunArgs).Split(" ")
    } -AsJob -ArgumentList $Exe, $RunArgs, $BasePath
}


function RunLocal-Exe {
    param ($Exe, $RunArgs)

    if (!$IsWindows) {
        $BasePath = Split-Path $Exe -Parent
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    $FullCommand = "$Exe $RunArgs"
    Write-Debug "Running Locally: $FullCommand"
    return (Invoke-Expression $FullCommand) -join "`n"
}

function Get-Latest-Test-Results($Platform, $Test) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/performance/$Platform/$Test"
    Write-Debug "Requesting: $Uri"
    $LatestResult = Invoke-RestMethod -Uri $Uri
    Write-Debug "Result: $LatestResult"
    return $LatestResult
}

function Median-Test-Results($FullResults) {
    $sorted = $FullResults | Sort-Object
    return $sorted[[int](($sorted.Length - 1) / 2)]
}

Export-ModuleMember -Function * -Alias *
