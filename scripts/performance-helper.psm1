# Helper functions for msquic performance testing. As this is a module, this cannot be called directly.

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Set-ScriptVariables {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Local, $LocalTls, $LocalArch, $RemoteTls, $RemoteArch, $SharedEC, $XDP, $Config, $Publish, $Record, $LogProfile, $RemoteAddress, $Session, $Kernel, $FailOnRegression)
    $script:Local = $Local
    $script:LocalTls = $LocalTls
    $script:LocalArch = $LocalArch
    $script:RemoteTls = $RemoteTls
    $script:RemoteArch = $RemoteArch
    $script:SharedEC = $SharedEC
    $script:XDP = $XDP
    $script:Config = $Config
    $script:Publish = $Publish
    $script:Record = $Record
    $script:LogProfile = $LogProfile
    $script:RemoteAddress = $RemoteAddress
    $script:Session = $Session
    $script:Kernel = $Kernel
    $script:FailOnRegression = $FailOnRegression
    $script:OsBuildNumber = [System.Environment]::OSVersion.Version.Build
    if ($null -ne $Session) {
        Invoke-Command -Session $Session -ScriptBlock {
            $ErrorActionPreference = "Stop"
        }
    }
}

function Set-DebugLogFile {
    param ($DebugLogFile)
    $script:DebugLogFile = $DebugLogFile
}

function Write-LogAndDebug {
    param([AllowNull()]$Data)
    if ($null -eq $Data) {
        return
    }
    Write-Debug $Data
    $Data | Out-File $script:DebugLogFile -Append
}

function Set-Session {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Session)

}

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
    while ($StopWatch.ElapsedMilliseconds -lt 20000) {
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
    # Ping sidechannel socket on 9999 to tell the app to die
    $Socket = New-Object System.Net.Sockets.UDPClient
    $BytesToSend = @(
        0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
        0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c
    )
    for ($i = 0; $i -lt 120; $i++) {
        $Socket.Send($BytesToSend, $BytesToSend.Length, $RemoteAddress, 9999) | Out-Null
        $Completed = Wait-Job -Job $Job -Timeout 1
        if ($null -ne $Completed) {
            break;
        }
    }

    Stop-Job -Job $Job | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    param ([string]$From, [string]$To, [string]$SmbDir)
    if (![string]::IsNullOrWhiteSpace($SmbDir)) {
        try {
            Remove-Item -Path "$SmbDir/*" -Recurse -Force
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Ignore Not Found for when the directory does not exist
            # This will still throw if a file cannot successfuly be deleted
        }
        robocopy $From $SmbDir /e /IS /IT /IM | Out-Null
        if ($LASTEXITCODE -ne 1) {
            Write-Error "Robocopy failed: $LASTEXITCODE"
        } else {
            $global:LASTEXITCODE = 0
        }
    } else {
        Invoke-TestCommand $Session -ScriptBlock {
            param ($To)
            try {
                Remove-Item -Path "$To/*" -Recurse -Force
            } catch [System.Management.Automation.ItemNotFoundException] {
                # Ignore Not Found for when the directory does not exist
                # This will still throw if a file cannot successfuly be deleted
            }
        } -ArgumentList $To
        Copy-Item -Path "$From\*" -Destination $To -ToSession $Session  -Recurse -Force
    }
}

function Get-GitHash {
    param ($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentCommitHash = $null
    try {
        $CurrentCommitHash = git rev-parse HEAD
    } catch {
        Write-LogAndDebug "Failed to get commit hash from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentCommitHash
}

function Get-CommitDate {
    param($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentCommitDate = $null
    try {
        $CurrentCommitDate = git show -s --format=%ct
        $CurrentCommitDate = [DateTimeOffset]::FromUnixTimeSeconds($CurrentCommitDate).ToUnixTimeMilliseconds()
    } catch {
        Write-LogAndDebug "Failed to get commit date from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentCommitDate
}

function Get-CurrentBranch {
    param($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentBranch = $null
    try {
        $CurrentBranch = git branch --show-current
    } catch {
        Write-LogAndDebug "Failed to get commit date from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentBranch
}

function Get-ExePath {
    param ($PathRoot, $Platform, $IsRemote, $ExtraArtifactDir)
    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)$ExtraArtifactDir"
        return Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($PathRoot, $Platform, $ConfigStr)
            Join-Path $PathRoot $Platform $ConfigStr
        } -ArgumentList $PathRoot, $Platform, $ConfigStr
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)$ExtraArtifactDir"
        return Join-Path $PathRoot $Platform $ConfigStr
    }
}

function Get-ExeName {
    param ($PathRoot, $Platform, $IsRemote, $TestPlat, $ExtraArtifactDir)
    $ExeName = $TestPlat.Exe
    if ($Platform -eq "windows") {
        $ExeName += ".exe"
    }

    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)$ExtraArtifactDir"
        return Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($PathRoot, $Platform, $ConfigStr, $ExeName)
            Join-Path $PathRoot $Platform $ConfigStr $ExeName
        } -ArgumentList $PathRoot, $Platform, $ConfigStr, $ExeName
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)$ExtraArtifactDir"
        return Join-Path $PathRoot $Platform $ConfigStr $ExeName
    }
}

function Remove-PerfServices {
    if ($IsWindows) {
        if ($null -ne (Get-Process -Name "secnetperf" -ErrorAction Ignore)) {
            try {
                Stop-Process -Name "secnetperf" -Force | Out-Null
            }
            catch {}
        }
        if ($null -ne (Get-Service -Name "secnetperfdrvpriv" -ErrorAction Ignore)) {
            try {
                net.exe stop secnetperfdrvpriv /y | Out-Null
            }
            catch {}
            sc.exe delete secnetperfdrvpriv /y | Out-Null
        }
        if ($null -ne (Get-Service -Name "msquicpriv" -ErrorAction Ignore)) {
            try {
                net.exe stop msquicpriv /y | Out-Null
            }
            catch {}
            sc.exe delete msquicpriv /y | Out-Null
        }

        Invoke-TestCommand -Session $Session -ScriptBlock {
            if ($null -ne (Get-Process -Name "secnetperf" -ErrorAction Ignore)) {
                try {
                    Stop-Process -Name "secnetperf" -Force | Out-Null
                }
                catch {}
            }
            if ($null -ne (Get-Service -Name "secnetperfdrvpriv" -ErrorAction Ignore)) {
                try {
                    net.exe stop secnetperfdrvpriv /y | Out-Null
                }
                catch {}
                sc.exe delete secnetperfdrvpriv /y | Out-Null
            }
            if ($null -ne (Get-Service -Name "msquicpriv" -ErrorAction Ignore)) {
                try {
                    net.exe stop msquicpriv /y | Out-Null
                }
                catch {}
                sc.exe delete msquicpriv /y | Out-Null
            }
        }
    }
}

function Invoke-RemoteExe {
    param ($Exe, $RunArgs, $RemoteDirectory)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Exe)
        if (!$IsWindows) {
            chmod +x $Exe
            return Split-Path $Exe -Parent
        }
        return $null
    } -ArgumentList $Exe

    if ($Kernel) {
        $RunArgs = "-driverNamePriv:secnetperfdrvpriv $RunArgs"
    }

    Write-LogAndDebug "Running Remote: $Exe $RunArgs"

    return Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Exe, $RunArgs, $BasePath, $Record, $LogProfile, $Kernel, $RemoteDirectory)
        if ($null -ne $BasePath) {
            $env:LD_LIBRARY_PATH = $BasePath
        }

        $LogScript = Join-Path $RemoteDirectory log.ps1

        if ($Record) {
            & $LogScript -Start -Profile $LogProfile -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
        }

        $Arch = Split-Path (Split-Path $Exe -Parent) -Leaf
        $RootBinPath = Split-Path (Split-Path (Split-Path $Exe -Parent) -Parent) -Parent
        $KernelDir = Join-Path $RootBinPath "winkernel" $Arch

        if ($Kernel) {
            Copy-Item (Join-Path $KernelDir "secnetperfdrvpriv.sys") (Split-Path $Exe -Parent)
            Copy-Item (Join-Path $KernelDir "msquicpriv.sys") (Split-Path $Exe -Parent)
            sc.exe create "msquicpriv" type= kernel binpath= (Join-Path (Split-Path $Exe -Parent) "msquicpriv.sys") start= demand | Out-Null
            net.exe start msquicpriv
        }

        try {
            & $Exe ($RunArgs).Split(" ")
        } finally {
            # Uninstall the kernel mode test drivers.
            if ($Kernel) {
                net.exe stop secnetperfdrvpriv /y | Out-Null
                net.exe stop msquicpriv /y | Out-Null
                sc.exe delete secnetperfdrvpriv | Out-Null
                sc.exe delete msquicpriv | Out-Null
            }
        }

    } -AsJob -ArgumentList $Exe, $RunArgs, $BasePath, $Record, $LogProfile, $Kernel, $RemoteDirectory
}

function Cancel-RemoteLogs {
    param ($RemoteDirectory)
    Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($RemoteDirectory)

        $LogScript = Join-Path $RemoteDirectory log.ps1

        & $LogScript -Cancel -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
    } -ArgumentList $RemoteDirectory
}

function Stop-RemoteLogs {
    param ($RemoteDirectory)
    Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Record, $RemoteDirectory)

        $LogScript = Join-Path $RemoteDirectory log.ps1

        if ($Record) {
            & $LogScript -Stop -OutputPath (Join-Path $RemoteDirectory serverlogs server) -RawLogOnly -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
        }
    } -ArgumentList $Record, $RemoteDirectory
}

function Get-RemoteLogDirectory {
    param ([string]$Local, [string]$Remote, [string]$SmbDir, [switch]$Cleanup)

    New-Item -Path $Local -ItemType Directory -Force | Out-Null
    if (![string]::IsNullOrWhiteSpace($SmbDir)) {
        Write-Host $SmbDir
        Write-Host $Local
        robocopy $SmbDir $Local /e /IS /IT /IM /COMPRESS | Out-Null
        if ($LASTEXITCODE -ne 3) {
            Write-Error "Robocopy failed: $LASTEXITCODE"
        } else {
            $global:LASTEXITCODE = 0
        }
        if ($Cleanup) {
            try {
                Remove-Item -Path "$SmbDir/*" -Recurse -Force
            } catch [System.Management.Automation.ItemNotFoundException] {
                # Ignore Not Found for when the directory does not exist
                # This will still throw if a file cannot successfuly be deleted
            }
        }
    } else {
        Copy-Item -Path "$Remote\*" -Destination $Local -FromSession $Session  -Recurse -Force
        if ($Cleanup) {
            Invoke-TestCommand $Session -ScriptBlock {
                param ($Remote)
                try {
                    Remove-Item -Path "$Remote/*" -Recurse -Force
                } catch [System.Management.Automation.ItemNotFoundException] {
                    # Ignore Not Found for when the directory does not exist
                    # This will still throw if a file cannot successfuly be deleted
                }
            } -ArgumentList $Remote
        }
    }
}

function Get-RemoteFile {
    param ($From, $To)

    if ($Local) {
        Copy-Item -Path $From -Destination $To
    } else {
        Copy-Item -Path $From -Destination $To -FromSession $Session
    }
}

function Remove-RemoteFile {
    param ($Path)
    if ($Local) {
        Remove-Item -Path $Path -Force
    } else {
        Invoke-Command -Session $Session -ScriptBlock { Remove-Item -Path $using:Path -Force }
    }
}

function Start-Tracing {
    param($LocalDirectory)
    if ($Record -and !$Local) {
        $LogScript = Join-Path $LocalDirectory log.ps1
        & $LogScript -Start -Profile $LogProfile -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
    }
}

function Cancel-LocalTracing {
    param($LocalDirectory)
    $LogScript = Join-Path $LocalDirectory log.ps1
    & $LogScript -Cancel -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
}

function Stop-Tracing {
    param($LocalDirectory, $OutputDir, $Test)
    if ($Record -and !$Local) {
        $LogScript = Join-Path $LocalDirectory log.ps1
        & $LogScript -Stop -OutputPath (Join-Path $OutputDir $Test.ToString() client) -RawLogOnly -ProfileInScriptDirectory -InstanceName msquicperf | Out-Null
    }
}

function Merge-PGOCounts {
    param ($Path, $OutputDir)
    $Command = "$Path\pgomgr.exe /merge $Path $Path\msquic.pgd"
    Invoke-Expression $Command | Write-LogAndDebug
    Remove-Item "$Path\*.pgc" | Out-Null
}

# Uses CDB.exe to print the crashing callstack in the dump file.
function PrintDumpCallStack($DumpFile, $ExePath) {
    $env:_NT_SYMBOL_PATH = Split-Path $ExePath
    try {
        if ($null -ne $env:BUILD_BUILDNUMBER) {
            $env:PATH += ";c:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
        }
        $Output = cdb.exe -z $File -c "kn;q" | Join-String -Separator "`n"
        $Output = ($Output | Select-String -Pattern " # Child-SP(?s).*quit:").Matches[0].Groups[0].Value
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $DumpFile -Leaf)"
        Write-Host "=================================================================================="
        $Output -replace "quit:", "=================================================================================="
    } catch {
        # Silently fail
    }
}
function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

function Invoke-LocalExe {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    param ($Exe, $RunArgs, $Timeout, $OutputDir)
    $BasePath = Split-Path $Exe -Parent
    if (!$IsWindows) {
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    $LocalExtraFile = Join-Path $BasePath "ExtraRunFile.txt"
    $RunArgs = """--extraOutputFile:$LocalExtraFile"" $RunArgs"
    $TimeoutMs = ($Timeout - 5) * 1000;
    $RunArgs = "-watchdog:$TimeoutMs $RunArgs"

    $FullCommand = "$Exe $RunArgs"
    Write-LogAndDebug "Running Locally: $FullCommand"

    $ExeName = Split-Path $Exe -Leaf
    # Path to the WER registry key used for collecting dumps.
    $WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\$ExeName"
    # Root directory of the project.
    $LogDir = Join-Path $OutputDir "logs" $ExeName (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')

    if ($IsWindows) {
        if ($IsWindows -and !(Test-Path $WerDumpRegPath)) {
            New-Item -Path $WerDumpRegPath -Force | Out-Null
        }

        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        New-ItemProperty -Path $WerDumpRegPath -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
        New-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -PropertyType ExpandString -Value $LogDir -Force | Out-Null
    }

    $Stopwatch =  [system.diagnostics.stopwatch]::StartNew()

    $LocalJob = $null

    try {
        $LocalJob = Start-Job -ScriptBlock { & $Using:Exe ($Using:RunArgs).Split(" ") }
    } finally {
        if ($null -ne $LocalJob) {
            # Wait for the job to finish
            Wait-Job -Job $LocalJob -Timeout $Timeout | Out-Null
            Stop-Job -Job $LocalJob | Out-Null
        }
    }

    $RetVal = Receive-Job -Job $LocalJob

    $Stopwatch.Stop()

    if ($IsWindows) {
        $DumpFiles = (Get-ChildItem $LogDir) | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            Log "Dump file(s) generated"
            foreach ($File in $DumpFiles) {
                PrintDumpCallStack($File, $Exe)
            }
        }

        # Cleanup the WER registry.
        Remove-Item -Path $WerDumpRegPath -Force | Out-Null
    }

    Write-Host ("Test Run Took " + $Stopwatch.Elapsed)

    return $RetVal -join "`n"
}

function Get-TestResultAtIndex($FullResults, $Index) {
    $RetResults = @()
    foreach ($Result in $FullResults) {
        $RetResults += $Result[$Index]
    }
    return $RetResults
}

function Get-MedianTestResults($FullResults) {
    $sorted = $FullResults | Sort-Object {[int]$_}
    if ($sorted.Length -eq 1) {
        return $sorted[0]
    } else {
        return $sorted[[int](($sorted.Length - 1) / 2)]
    }
}

function Get-TestResult($Results, $Matcher) {
    $Found = $Results -match $Matcher
    if ($Found) {
        return $Matches
    } else {
        Write-Error "Error Processing Results:`n`n$Results"
    }
}

$NumberOfCommitsToAverage = 5

function Get-LatestCommitHashes([string]$Branch) {
    $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/commits.json"
    Write-LogAndDebug "Requesting: $Uri"
    try {
        $AllCommits = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
        Write-LogAndDebug "Result: $AllCommits"
        if ($AllCommits.Count -eq 0) {
            return ""
        }
        $SortedList = $AllCommits | Sort-Object -Property Date -Descending
        if ($SortedList.Count -lt $NumberOfCommitsToAverage) {
            $LatestResult = $SortedList
        } else {
            $LatestResult = $SortedList | Select-Object -First $NumberOfCommitsToAverage
        }
        Write-LogAndDebug "Latest Commits: $LatestResult"
        return $LatestResult
    } catch {
        return ""
    }
}

function Get-LatestCpuTestResults([string]$Branch, $CommitHashes) {
    $Items = [System.Collections.Generic.List[object]]::new()
    foreach ($Result in $CommitHashes) {
        try {
            $CommitHash = $Result.CommitHash
            $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/$CommitHash/cpu_data.json"
            Write-LogAndDebug "Requesting: $Uri"
            $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
            Write-LogAndDebug "Result: $LatestResult"
            $Items.Add($LatestResult)
        } catch {
        }
    }
    return $Items
}

$global:HasRegression = $false

function Log-Regression([string]$Msg) {
    Write-Host "##vso[task.LogIssue type=error;]$Msg"
    $global:HasRegression = $true
}

function Check-Regressions() {
    if ($global:HasRegression) {
        Write-Error "Performance test regressions occurred!"
    }
}

# Fail loopback tests if < 80%
$LocalRegressionThreshold = -80.0

#region Throughput Publish

class ThroughputConfiguration {
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;

    [int] GetHashCode() {
        return [HashCode]::Combine($this.Loopback, $this.Encryption, $this.SendBuffering, $this.NumberOfStreams, $this.ServerToClient)
    }

    [boolean] Equals([Object]$other) {
        return $this.Encryption -eq $other.Encryption -and
        $this.Loopback -eq $other.Loopback -and
        $this.NumberOfStreams -eq $other.NumberOfStreams -and
        $this.SendBuffering -eq $other.SendBuffering -and
        $this.ServerToClient -eq $other.ServerToClient
    }
}

class ThroughputRequest {
    [string]$PlatformName;
    [string]$TestName;
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;

    ThroughputRequest (
        [TestRunDefinition]$Test,
        [boolean]$ServerToClient,
        [string]$TestName
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
        $this.TestName = $TestName
        $this.Loopback = $Test.Loopback;
        $this.Encryption = $Test.VariableValues["Encryption"] -eq "On";
        $this.SendBuffering = $Test.VariableValues["SendBuffering"] -eq "On";
        $this.NumberOfStreams = 1;
        $this.ServerToClient = $ServerToClient;
    }

    [ThroughputConfiguration] GetConfiguration() {
        $TputConfig = [ThroughputConfiguration]::new();
        $TputConfig.Encryption = $this.Encryption;
        $TputConfig.Loopback = $this.Loopback;
        $TputConfig.NumberOfStreams = $this.NumberOfStreams;
        $TputConfig.SendBuffering = $this.SendBuffering;
        $TputConfig.ServerToClient = $this.ServerToClient;
        return $TputConfig;
    }
}

function Get-LatestThroughputRemoteTestResults($CpuData, [ThroughputRequest]$Request) {
    try {
        $Values = [System.Collections.Generic.List[int]]::new()
        $TestConfig = $Request.GetConfiguration()
        foreach ($Result in $CpuData) {
            foreach ($Test in $Result.Tests) {
                if ($null -eq $Test.TputConfig) {
                    continue;
                }

                if ($Test.TestName -eq $Request.TestName -and $TestConfig -eq $Test.TputConfig -and $Request.PlatformName -eq $Test.PlatformName) {
                    $Values.Add((Get-MedianTestResults -FullResults $Test.Results))
                    break;
                }
            }
        }
        if ($Values.Count -eq 0) {
            return $null
        }
        return ($Values | Measure-Object -Average).Average
    } catch {
    }
    return $null
}

class ThroughputTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;

    ThroughputTestPublishResult (
        [ThroughputRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash,
        [boolean]$Tcp
    ) {
        $this.TestName = $Tcp ? "TcpThroughput" : "Throughput"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
        $this.Loopback = $Request.Loopback
        $this.Encryption = $Request.Encryption
        $this.SendBuffering = $Request.SendBuffering
        $this.NumberOfStreams = $Request.NumberOfStreams
        $this.ServerToClient = $Request.ServerToClient
    }
}

function Publish-ThroughputTestResults {
    param ([TestRunDefinition]$Test, $AllRunsFullResults, $CurrentCommitHash, $CurrentCommitDate, $PreviousResults, $OutputDir, $ServerToClient, $ExePath, $Tcp)

    $Request = [ThroughputRequest]::new($Test, $ServerToClient, $Tcp ? "TcpThroughput" : "Throughput")

    $AllRunsResults = Get-TestResultAtIndex -FullResults $AllRunsFullResults -Index 1
    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestThroughputRemoteTestResults -CpuData $PreviousResults -Request $Request
    $CurrentFormatted = [string]::Format($Test.Formats[0], $MedianCurrentResult)

    if ($null -ne $FullLastResult) {
        $MedianLastResult = $FullLastResult
        if ($MedianLastResult -eq 0) {
            Write-Error "Cannot have a last result median of 0"
        }
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        $LastFormatted = [string]::Format($Test.Formats[0], $MedianLastResult)
        Write-Output "Median: $CurrentFormatted ($PercentDiffStr%)"
        Write-Output "Remote: $LastFormatted"
        if ($FailOnRegression -and !$Local -and $PercentDiff -lt $Test.RegressionThreshold) {
            #Skip no encrypt
            if ($Test.VariableName -ne "Encryption") {
                Log-Regression "Performance regression in $Test. $PercentDiffStr% < $($Test.RegressionThreshold)"
            }
        } elseif ($FailOnRegression -and $PercentDiff -lt $LocalRegressionThreshold) {
            Log-Regression "Performance regression in $Test. $PercentDiffStr% < $LocalRegressionThreshold"
        }
    } else {
        Write-Output "Median: $CurrentFormatted"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = ($script:OsBuildNumber).ToString()
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $MachineName + ":" + $env:AGENT_MACHINENAME
        }
        $Results = [ThroughputTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7), $Tcp)
        $Results.AuthKey = $CurrentCommitDate;

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-LogAndDebug "Failed to publish because of missing commit hash"
    }
}

#endregion

#region RPS Publish

class RpsConfiguration {
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    [int] GetHashCode() {
        return [HashCode]::Combine($this.ConnectionCount, $this.RequestSize, $this.ResponseSize, $this.ParallelRequests)
    }

    [boolean] Equals([Object]$other) {
        return $this.ConnectionCount -eq $other.ConnectionCount -and
        $this.RequestSize -eq $other.RequestSize -and
        $this.ResponseSize -eq $other.ResponseSize -and
        $this.ParallelRequests -eq $other.ParallelRequests
    }
}

class RPSRequest {
    [string]$PlatformName;
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    RPSRequest (
        [TestRunDefinition]$Test
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
        $this.ConnectionCount = $Test.VariableValues["ConnectionCount"];
        $this.RequestSize = $Test.VariableValues["RequestSize"];
        $this.ResponseSize = $Test.VariableValues["ResponseSize"];
        $this.ParallelRequests = 30;
    }

    [RpsConfiguration] GetConfiguration() {
        $RpsConfig = [RpsConfiguration]::new();
        $RpsConfig.ConnectionCount = $this.ConnectionCount;
        $RpsConfig.RequestSize = $this.RequestSize;
        $RpsConfig.ResponseSize = $this.ResponseSize;
        $RpsConfig.ParallelRequests = $this.ParallelRequests;
        return $RpsConfig;
    }
}

function Get-LatestRPSRemoteTestResults($CpuData, [RpsRequest]$Request) {
    try {
        $Values = [System.Collections.Generic.List[int]]::new()
        $TestConfig = $Request.GetConfiguration()
        foreach ($Result in $CpuData) {
            foreach ($Test in $Result.Tests) {
                if ($null -eq $Test.RpsConfig) {
                    continue;
                }

                if ($TestConfig -eq $Test.RpsConfig -and $Request.PlatformName -eq $Test.PlatformName) {
                    $Values.Add((Get-MedianTestResults -FullResults $Test.Results))
                    break;
                }
            }
        }
        if ($Values.Count -eq 0) {
            return $null
        }
        return ($Values | Measure-Object -Average).Average
    } catch {
    }
    return $null
}

class RPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    RPSTestPublishResult (
        [RPSRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash
    ) {
        $this.TestName = "RPS"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
        $this.ConnectionCount = $Request.ConnectionCount
        $this.RequestSize = $Request.RequestSize
        $this.ResponseSize = $Request.ResponseSize
        $this.ParallelRequests = $Request.ParallelRequests
    }
}

function Publish-RPSTestResults {
    param ([TestRunDefinition]$Test, $AllRunsFullResults, $CurrentCommitHash, $CurrentCommitDate, $PreviousResults, $OutputDir, $ExePath)

    $Request = [RPSRequest]::new($Test)

    $BasePath = Split-Path $ExePath -Parent
    $LocalExtraFile = Join-Path $BasePath "ExtraRunFile.txt"
    if (Test-Path $LocalExtraFile -PathType Leaf) {
        $ResultFile = Join-Path $OutputDir "histogram_$Test.txt"
        Copy-Item -Path $LocalExtraFile -Destination $ResultFile
    } else {
        Write-Host "Extra file $LocalExtraFile not found when expected"
    }

    $AllRunsResults = Get-TestResultAtIndex -FullResults $AllRunsFullResults -Index 1
    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestRPSRemoteTestResults -CpuData $PreviousResults -Request $Request
    $CurrentFormatted = [string]::Format($Test.Formats[0], $MedianCurrentResult)

    if ($null -ne $FullLastResult) {
        $MedianLastResult = $FullLastResult
        if ($MedianLastResult -eq 0) {
            Write-Error "Cannot have a last result median of 0"
        }
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        $LastFormatted = [string]::Format($Test.Formats[0], $MedianLastResult)
        Write-Output "Median: $CurrentFormatted ($PercentDiffStr%)"
        Write-Output "Remote: $LastFormatted"
        if ($FailOnRegression -and !$Local -and $PercentDiff -lt $Test.RegressionThreshold) {
            Log-Regression "Performance regression in $Test. $PercentDiffStr% < $($Test.RegressionThreshold)"
        } elseif ($FailOnRegression -and $PercentDiff -lt $LocalRegressionThreshold) {
            Log-Regression "Performance regression in $Test. $PercentDiffStr% < $LocalRegressionThreshold"
        }
    } else {
        Write-Output "Median: $CurrentFormatted"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = ($script:OsBuildNumber).ToString()
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $MachineName + ":" + $env:AGENT_MACHINENAME
        }
        $Results = [RPSTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7))
        $Results.AuthKey = $CurrentCommitDate;

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-LogAndDebug "Failed to publish because of missing commit hash"
    }
}

#endregion

#region HPS Publish

class HpsConfiguration {
    [int] GetHashCode() {
        return 7;
    }

    [boolean] Equals([Object]$other) {
        return $true
    }
}

class HPSRequest {
    [string]$PlatformName;

    HPSRequest (
        [TestRunDefinition]$Test
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
    }

    [HpsConfiguration] GetConfiguration() {
        $Config = [HpsConfiguration]::new();
        return $Config;
    }
}

function Get-LatestHPSRemoteTestResults($CpuData, [HpsRequest]$Request) {
    try {
        $Values = [System.Collections.Generic.List[int]]::new()
        $TestConfig = $Request.GetConfiguration()
        foreach ($Result in $CpuData) {
            foreach ($Test in $Result.Tests) {
                if ($null -eq $Test.HpsConfig) {
                    continue;
                }

                if ($TestConfig -eq $Test.HpsConfig -and $Request.PlatformName -eq $Test.PlatformName) {
                    $Values.Add((Get-MedianTestResults -FullResults $Test.Results))
                    break;
                }
            }
        }
        if ($Values.Count -eq 0) {
            return $null
        }
        return ($Values | Measure-Object -Average).Average
    } catch {
    }
    return $null
}

class HPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;

    HPSTestPublishResult (
        [HPSRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash
    ) {
        $this.TestName = "HPS"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
    }
}

function Publish-HPSTestResults {
    param ([TestRunDefinition]$Test, $AllRunsFullResults, $CurrentCommitHash, $CurrentCommitDate, $PreviousResults, $OutputDir, $ExePath)

    $Request = [HPSRequest]::new($Test)

    $AllRunsResults = Get-TestResultAtIndex -FullResults $AllRunsFullResults -Index 1
    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestHPSRemoteTestResults -CpuData $PreviousResults -Request $Request
    $CurrentFormatted = [string]::Format($Test.Formats[0], $MedianCurrentResult)

    if ($null -ne $FullLastResult) {
        $MedianLastResult = $FullLastResult
        if ($MedianLastResult -eq 0) {
            Write-Error "Cannot have a last result median of 0"
        }
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        $LastFormatted = [string]::Format($Test.Formats[0], $MedianLastResult)
        Write-Output "Median: $CurrentFormatted ($PercentDiffStr%)"
        Write-Output "Remote: $LastFormatted"
        if ($FailOnRegression -and !$Local -and $PercentDiff -lt $Test.RegressionThreshold) {
            Log-Regression "Performance regression in $Test. $PercentDiffStr% < $($Test.RegressionThreshold)"
        } elseif ($FailOnRegression -and $PercentDiff -lt $LocalRegressionThreshold) {
            Log-Regression "Performance regression in $Test. $PercentDiffStr% < $LocalRegressionThreshold"
        }
    } else {
        Write-Output "Median: $CurrentFormatted"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = ($script:OsBuildNumber).ToString()
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $MachineName + ":" + $env:AGENT_MACHINENAME
        }
        $Results = [HPSTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7))
        $Results.AuthKey = $CurrentCommitDate;

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-LogAndDebug "Failed to publish because of missing commit hash"
    }
}

#endregion

function Publish-TestResults {
    param ([TestRunDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $CurrentCommitDate, $PreviousResults, $OutputDir, $ExePath)

    if ($Test.TestName -eq "ThroughputUp") {
        Publish-ThroughputTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ServerToClient $false -ExePath $ExePath -Tcp $false
    } elseif ($Test.TestName -eq "ThroughputDown") {
        Publish-ThroughputTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ServerToClient $true -ExePath $ExePath -Tcp $false
    } elseif ($Test.TestName -eq "TcpThroughputUp") {
        Publish-ThroughputTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ServerToClient $false -ExePath $ExePath -Tcp $true
    } elseif ($Test.TestName -eq "TcpThroughputDown") {
        Publish-ThroughputTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ServerToClient $true -ExePath $ExePath -Tcp $true
    } elseif ($Test.TestName -eq "RPS") {
        Publish-RPSTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ExePath $ExePath
    } elseif ($Test.TestName -eq "HPS") {
        Publish-HPSTestResults -Test $Test -AllRunsFullResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -CurrentCommitDate $CurrentCommitDate -PreviousResults $PreviousResults -OutputDir $OutputDir -ExePath $ExePath
    } else {
        Write-Host "Unknown Test Type"
    }
}

#region Test Parsing

class ExecutableRunSpec {
    [string]$Platform;
    [string]$Exe;
    [string[]]$Tls;
    [string[]]$Arch;
    [string]$Arguments;

    ExecutableRunSpec (
        [ExecutableSpec]$existingDef,
        [string]$arguments
    ) {
        $this.Platform = $existingDef.Platform
        $this.Exe = $existingDef.Exe
        $this.Tls = $existingDef.Tls
        $this.Arch = $existingDef.Arch
        $this.Arguments = $arguments
    }
}

class TestRunDefinition {
    [string]$TestName;
    [string]$VariableName;
    [string]$VariableValue;
    [ExecutableRunSpec]$Local;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;
    [hashtable]$VariableValues;
    [boolean]$Loopback;
    [boolean]$AllowLoopback;
    [boolean]$SharedEC;
    [boolean]$XDP;
    [string[]]$Formats;
    [double]$RegressionThreshold;

    TestRunDefinition (
        [TestDefinition]$existingDef,
        [string]$variableName,
        [string]$variableValue,
        [string]$localArgs,
        [hashtable]$variableValues
    ) {
        $this.TestName = $existingDef.TestName
        $this.VariableName = $variableName
        $this.VariableValue = $variableValue
        $this.Local = [ExecutableRunSpec]::new($existingDef.Local, $localArgs)
        $this.Iterations = $existingDef.Iterations
        $this.RemoteReadyMatcher = $existingDef.RemoteReadyMatcher
        $this.ResultsMatcher = $existingDef.ResultsMatcher
        $this.VariableValues = $variableValues
        $this.Loopback = $script:Local
        $this.AllowLoopback = $existingDef.AllowLoopback
        $this.Formats = $existingDef.Formats
        $this.RegressionThreshold = $existingDef.RegressionThreshold
        $this.SharedEC = $script:SharedEC
        $this.XDP = $script:XDP
    }

    TestRunDefinition (
        [TestDefinition]$existingDef,
        [Collections.Generic.List[FullVariableSpec]]$variables
    ) {
        $this.TestName = $existingDef.TestName
        $this.Iterations = $existingDef.Iterations
        $this.RemoteReadyMatcher = $existingDef.RemoteReadyMatcher
        $this.ResultsMatcher = $existingDef.ResultsMatcher
        $this.Loopback = $script:Local
        $this.AllowLoopback = $existingDef.AllowLoopback
        $this.Formats = $existingDef.Formats
        $this.RegressionThreshold = $existingDef.RegressionThreshold
        $this.VariableValue = ""
        $this.VariableName = ""

        $this.VariableValues = @{}
        $BaseArgs = $existingDef.Local.Arguments
        foreach ($Var in $variables) {
            $this.VariableValues.Add($Var.Name, $Var.Value)
            $BaseArgs += (" " + $Var.Argument)
            $this.VariableName += ("_" + $Var.Name + "_" + $Var.Value)
        }
        $this.Local = [ExecutableRunSpec]::new($existingDef.Local, $BaseArgs)
        $this.SharedEC = $script:SharedEC
        $this.XDP = $script:XDP
    }

    TestRunDefinition (
        [TestDefinition]$existingDef,
        [string]$localArgs,
        [hashtable]$variableValues
    ) {
        $this.TestName = $existingDef.TestName
        $this.VariableName = "Default"
        $this.VariableValue = ""
        $this.Local = [ExecutableRunSpec]::new($existingDef.Local, $localArgs)
        $this.Iterations = $existingDef.Iterations
        $this.RemoteReadyMatcher = $existingDef.RemoteReadyMatcher
        $this.ResultsMatcher = $existingDef.ResultsMatcher
        $this.VariableValues = $variableValues
        $this.Loopback = $script:Local
        $this.AllowLoopback = $existingDef.AllowLoopback
        $this.Formats = $existingDef.Formats
        $this.RegressionThreshold = $existingDef.RegressionThreshold
        $this.SharedEC = $script:SharedEC
        $this.XDP = $script:XDP
    }

    [string]ToString() {
        $VarVal = "_$($this.VariableValue)"
        if ($this.VariableName -eq "Default") {
            $VarVal = ""
        }

        $RetString = "$($this.TestName)_$($this.ToTestPlatformString())_$($this.VariableName)$VarVal"
        if ($this.Loopback) {
            $RetString += "_Loopback"
        }
        return $RetString
    }

    [string]ToTestPlatformString() {
        $Platform = $this.Local.Platform
        if ($script:Kernel -and $this.Local.Platform -eq "Windows") {
            $Platform = 'Winkernel'
        }
        if ($script:SharedEC -and $this.Local.Platform -eq "Windows") {
            $Platform = 'WinSharedEC'
        }
        if ($script:SharedEC -and $this.Local.Platform -eq "Linux") {
            $Platform = 'LinuxSharedEC'
        }
        if ($script:XDP -and $this.Local.Platform -eq "Windows") {
            $Platform = 'WinXDP'
        }
        $RetString = "$($Platform)_$($script:RemoteArch)_$($script:RemoteTls)"
        return $RetString
    }
}

class TestRunConfig {
    [RemoteConfig]$Remote;
    [TestRunDefinition[]]$Tests;
}

class Defaults {
    [string]$LocalValue;
    [string]$DefaultKey;

    Defaults (
        [string]$local,
        [string]$defaultKey
    ) {
        $this.LocalValue = $local
        $this.DefaultKey = $defaultKey
    }
}

class FullVariableSpec {
    [string]$Name;
    [string]$Value;
    [string]$Argument;

    FullVariableSpec($Name, $Value, $Argument) {
        $this.Name = $Name
        $this.Value = $Value
        $this.Argument = $Argument
    }
}

function Get-FullTestMatrix {
    param ([TestConfig]$Tests, $RemotePlatform, $LocalPlatform)

    [TestRunDefinition[]]$ToRunTests = @()

    foreach ($Test in $Tests.Tests) {

        if (!(Test-CanRunTest -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform)) {
            Write-Host "Skipping $($Test.ToString())"
            continue
        }

        [Hashtable]$Variables = @{}

        # Loop throught each variable
        foreach ($Var in $Test.Variables) {
            # Loop through each inner variable
            foreach ($InnerVar in $Var.Local.Keys) {
                if ($Variables.ContainsKey($Var.Name)) {
                    $Variables[$Var.Name] += [FullVariableSpec]::new($Var.Name, $InnerVar, $Var.Local[$InnerVar]);
                } else {
                    $NewVar = @()
                    $NewVar += [FullVariableSpec]::new($Var.Name, $InnerVar, $Var.Local[$InnerVar]);
                    $Variables[$Var.Name] = $NewVar
                }
            }
        }

        if ($Variables.Count -eq 0) {
            Write-Error "Full Matrix with an empty variable set not supported"
        }

        $First = $true
        $Finished = [Collections.Generic.List[Collections.Generic.List[FullVariableSpec]]]::new()

        foreach ($Variable in $Variables.Keys) {
            if ($First) {
                $First = $false
                foreach ($InnerVar in $Variables[$Variable]) {
                    $TmpList = [Collections.Generic.List[FullVariableSpec]]::new()
                    $TmpList.Add($InnerVar)
                    $Finished.Add($TmpList)
                }
            } else {
                $NewList = [Collections.Generic.List[Collections.Generic.List[FullVariableSpec]]]::new()
                foreach($ExistingList in $Finished) {
                    foreach($InnerVar in $Variables[$Variable]) {
                        $TmpList = [Collections.Generic.List[FullVariableSpec]]::new()
                        $TmpList.AddRange($ExistingList)
                        $TmpList.Add($InnerVar)
                        $NewList.Add($TmpList)
                    }
                }
                $Finished = $NewList
            }
        }

        foreach ($TestToRun in $Finished) {
            $ToRunTests += [TestRunDefinition]::new($Test, $TestToRun)
        }
    }

    $RunConfig = [TestRunConfig]::new()
    $RunConfig.Remote = $Tests.Remote;
    $RunConfig.Tests = $ToRunTests;

    return $RunConfig
}

function Get-TestMatrix {
    param ([TestConfig]$Tests, $RemotePlatform, $LocalPlatform)

    if ($Tests.FullMatrix) {
        return Get-FullTestMatrix -Tests $Tests -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform
    }

    [TestRunDefinition[]]$ToRunTests = @()

    foreach ($Test in $Tests.Tests) {

        if (!(Test-CanRunTest -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform)) {
            Write-Host "Skipping $($Test.ToString())"
            continue
        }

        [hashtable]$DefaultVals = @{}
        # Get all default variables
        foreach ($Var in $Test.Variables) {
            $DefaultVals.Add($Var.Name, [Defaults]::new($Var.Local[$Var.Default], $Var.Default))
        }

        $LocalArgs = $Test.Local.Arguments

        $DefaultLocalArgs = $LocalArgs

        $VariableValues = @{}
        foreach ($VarKey in $DefaultVals.Keys) {
            $VariableValues.Add($VarKey, $DefaultVals[$VarKey].DefaultKey)
            $DefaultLocalArgs += (" " + $DefaultVals[$VarKey].LocalValue)
        }

        # Create the default test
        $TestRunDef = [TestRunDefinition]::new($Test, $DefaultLocalArgs, $VariableValues)
        $ToRunTests += $TestRunDef

        foreach ($Var in $Test.Variables) {
            $LocalVarArgs = @{}

            $StateKeyList = @()

            foreach ($Key in $Var.Local.Keys) {
                $LocalVarArgs.Add($Key, $LocalArgs + " " + $Var.Local[$Key])
                $StateKeyList += $Key
            }

            # Enumerate each variable, getting its value and the default
            foreach ($Key in $DefaultVals.Keys) {
                if ($Key -ne $Var.Name) {
                    foreach ($TestKey in $StateKeyList) {
                        $KeyVal =$DefaultVals[$Key]
                        $LocalVarArgs[$TestKey] += " $($KeyVal.LocalValue)"
                    }
                }
            }

            foreach ($Key in $StateKeyList) {
                $VariableValues = @{}
                foreach ($VarKey in $DefaultVals.Keys) {
                    $VariableValues.Add($VarKey, $DefaultVals[$VarKey].DefaultKey)
                }
                if ($VariableValues[$Var.Name] -eq $Key) {
                    continue
                }
                $VariableValues[$Var.Name] = $Key
                $TestRunDef = [TestRunDefinition]::new($Test, $Var.Name, $Key, $LocalVarArgs[$Key], $VariableValues)
                $ToRunTests += $TestRunDef
            }
        }
    }

    $RunConfig = [TestRunConfig]::new()
    $RunConfig.Remote = $Tests.Remote;
    $RunConfig.Tests = $ToRunTests;

    return $RunConfig
}

class VariableSpec {
    [string]$Name;
    [Hashtable]$Local;
    [string]$Default;
}

class ExecutableSpec {
    [string]$Platform;
    [string[]]$Tls;
    [string[]]$Arch;
    [string]$Exe;
    [string]$Arguments;
}

class TestDefinition {
    [string]$TestName;
    [boolean]$SkipKernel;
    [ExecutableSpec]$Local;
    [VariableSpec[]]$Variables;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;
    [boolean]$AllowLoopback;
    [string[]]$Formats;
    [double]$RegressionThreshold;

    [string]ToString() {
        $Platform = $this.Local.Platform
        if ($script:Kernel -and $this.Local.Platform -eq "Windows") {
            $Platform = 'Winkernel'
        }
        $RetString = "$($this.TestName)_$($Platform) [$($this.Local.Arch)] [$($this.Local.Tls)]"
        return $RetString
    }
}

class RemoteConfig {
    [string]$Exe;
    [string]$Arguments;
}

class TestConfig {
    [RemoteConfig]$Remote;
    [TestDefinition[]]$Tests;
    [boolean]$FullMatrix;
}

function Get-Tests {
    param ($Path, $RemotePlatform, $LocalPlatform)
    $Tests = [TestConfig](Get-Content -Path $Path | ConvertFrom-Json -AsHashtable)
    $MatrixTests = Get-TestMatrix -Tests $Tests -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform
    if (Test-AllTestsValid -Tests $MatrixTests) {
        return $MatrixTests
    } else {
        Write-Host "Error"
        return $null
    }
}

function Test-AllTestsValid {
    param ([TestRunConfig]$Tests)
    $TestSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($T in $Tests.Tests) {
        if (!$TestSet.Add($T)) {
            return $false
        }
    }

    return $true
}

function Test-CanRunTest {
    param ([TestDefinition]$Test, $RemotePlatform, $LocalPlatform)
    $PlatformCorrect = ($Test.Local.Platform -eq $LocalPlatform)
    if (!$PlatformCorrect) {
        return $false
    }
    if (!$Test.Local.Tls.Contains($LocalTls)) {
        return $false
    }
    if ($Local -and !$Test.AllowLoopback) {
        return $false
    }
    if ($script:Kernel -and $Test.SkipKernel) {
        return $false
    }
    if ($script:SharedEC -and $Test.TestName.Contains("Tcp")) {
        return $false
    }
    if ($script:XDP -and $Test.TestName.Contains("Tcp")) {
        return $false
    }
    return $true
}

#endregion

Export-ModuleMember -Function * -Alias *
