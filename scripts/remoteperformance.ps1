<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [string]$TestsFile = "",

    [Parameter(Mandatory = $false)]
    [string]$Remote = "User@172.29.119.234",

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeploy
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

Get-PSSession | Remove-PSSession

$LocalPlatform = $null
if ($IsWindows) {
    $LocalPlatform = "windows"
} else {
    $LocalPlatform = "linux"
}


if ($TestsFile -eq "") {
    $TestsFile = Join-Path $PSScriptRoot "RemoteTests.json"
}


$session = New-PSSession -HostName "$Remote"

$RemoteAddress = $session.ComputerName

if ($null -eq $session) {
    exit
}

Write-Host "Connected to: $RemoteAddress"


$RemotePlatform = Invoke-Command -Session $session -ScriptBlock { 
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-Command -Session $session -ScriptBlock { Join-Path (Get-Location) "Tests" }

$LocalDirectory = Join-Path $RootDir "artifacts"

function Start-Remote {
    param($ScriptBlock)
    $job =  Invoke-Command -Session $session -ScriptBlock $ScriptBlock -AsJob
    return $job
}

function WaitFor-Remote-Ready {
    param ($Job, $Matcher)
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($true) {
        $CurrentResults = Receive-Job -Job $Job -Keep
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match $Matcher
            if ($DidMatch) {
                return $true
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
        if ($StopWatch.ElapsedMilliseconds -gt 10000) {
            return $false
        }
    }
}

function WaitFor-Remote {
    param ($Job)
    Wait-Job -Job $Job -Timeout 10 | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    param([string]$From, [string]$To)
    try {
        Invoke-Command $session -ScriptBlock {Remove-Item -Path "$Using:To/*" -Recurse -Force }
    } catch {
        # Ignore failure
    }
    # TODO Figure out how to filter this
    Copy-Item -Path "$From\*" -Destination $To -ToSession $session  -Recurse
}

# function Run-Foreground-Executable($File, $Arguments) {
#     $pinfo = New-Object System.Diagnostics.ProcessStartInfo
#     $pinfo.FileName = $File
#     $pinfo.RedirectStandardOutput = $true
#     $pinfo.UseShellExecute = $false
#     $pinfo.Arguments = $Arguments
#     $p = New-Object System.Diagnostics.Process
#     $p.StartInfo = $pinfo
#     $p.Start() | Out-Null
#     $p.WaitForExit()
#     return $p.StandardOutput.ReadToEnd()
# }

class ExecutableSpec {
    [string]$Platform;
    [string]$Tls;
    [string]$Arch;
    [string]$Exe;
    [string]$Arguments;
}

class TestDefinition {
    [string]$TestName;
    [ExecutableSpec]$Remote;
    [ExecutableSpec]$Local;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;

    [string]ToString() {
        return ("{0}_{1}_{2}_{3}_{4}_{5}_{6}" -f $this.TestName, 
                                         $this.Local.Platform, 
                                         $this.Local.Tls,
                                         $this.Local.Arch,
                                         $this.Remote.Platform,
                                         $this.Remote.Tls,
                                         $this.Remote.Arch
                                         )
    }
}

function GetExe-Name {
    param($PathRoot, $Platform, $IsRemote, $TestPlat)
    $ExeName = $TestPlat.Exe
    if ($Platform -eq "windows") {
        $ExeName += ".exe"
    }

    $ConfigStr = "$($TestPlat.Arch)_$($Config)_$($TestPlat.Tls)"

    if ($IsRemote) {
        return Invoke-Command -Session $session -ScriptBlock { Join-Path $Using:PathRoot $Using:Platform $Using:ConfigStr $Using:ExeName  }
    } else {
        return Join-Path $PathRoot $Platform $ConfigStr $ExeName
    }
}

function Parse-Test-Results($Results, $Matcher) {
    try {
        # Unused variable on purpose
        $Results -match $Matcher | Out-Null
        return $Matches[1]
    } catch {
        Write-Host "Error Processing Results:`n`n$Results"
        throw
    }
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

function RunRemote-Exe {
    param($Exe, $RunArgs)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-Command -Session $session -ScriptBlock {
        if (!$IsWindows) {
            chmod +x $Using:Exe
            return Split-Path $Using:Exe -Parent
        }
        return $null
    }

    return Invoke-Command -Session $session -ScriptBlock {
        if ($null -ne $Using:BasePath) {
            $env:LD_LIBRARY_PATH = $Using:BasePath
        }
        
        & $Using:Exe ($Using:RunArgs).Split(" ")
    } -AsJob
}

function RunRemote-Exe2 {
    param($Exe, $RunArgs)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-Command -Session $session -ScriptBlock {
        if (!$IsWindows) {
            chmod +x $Using:Exe
            return Split-Path $Using:Exe -Parent
        }
        return $null
    }

    $LP = Invoke-Command -Session $session -ScriptBlock {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Using:Exe
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardInput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $Using:RunArgs
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $pinfo

        Write-Host $Using:Exe
        Write-Host $Using:RunArgs

        $StringBuilder = [System.Text.StringBuilder]::new();
        $WriteCount = 0;
        

        $OutEvent = Register-ObjectEvent -InputObject $Process -EventName 'OutputDataReceived' -Action {
            param
            (
                [System.Object] $sender,
                [System.Diagnostics.DataReceivedEventArgs] $e
            )
            Write-Host "Received Event"
            [System.Threading.Monitor]::Enter($StringBuilder)
            try {
                $StringBuilder.Append($e.Data);    
                $WriteCount++;
            } finally {
                [System.Threading.Monitor]::Exit($StringBuilder)
            }
            
        }

        $Process.Start() | Out-Null
        $Process.BeginOutputReadLine()

        return $Process
    }

    Write-Host $LP

    return $LP
    

    # return Invoke-Command -Session $session -ScriptBlock {
    #     if ($null -ne $Using:BasePath) {
    #         $env:LD_LIBRARY_PATH = $Using:BasePath
    #     }
        
    #     & $Using:Exe ($Using:RunArgs).Split(" ")
    # } -AsJob
}

function RunLocal-Exe {
    param ($Exe, $RunArgs)

    if (!$IsWindows) {
        $BasePath = Split-Path $Exe -Parent
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    return (Invoke-Expression "$Exe $RunArgs") -join "`n"
    #return (& $Exe $RunArgs.Split(" ")) 
}

function Run-Test {
    param($Test)

    Write-Host "Running Test $Test"

    $RemoteExe = GetExe-Name -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $Test.Remote
    $LocalExe = GetExe-Name -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local

    # Check both Exes
    $RemoteExeExists = Invoke-Command -Session $session -ScriptBlock { Test-Path $Using:RemoteExe }
    $LocalExeExists = Test-Path $LocalExe

    if (!$RemoteExeExists -or !$LocalExeExists) {
        Write-Host "Failed to Run $Test because of missing exe"
        if (!$RemoteExeExists) {
            Write-Host "Missing Remote Exe $RemoteExe"
        }
        if (!$LocalExeExists) {
            Write-Host "Missing Local Exe $LocalExe"
        }
        return
    }

    $LocalArguments = $Test.Local.Arguments.Replace('$RemoteAddress', $RemoteAddress)

    $RemoteJob = RunRemote-Exe -Exe $RemoteExe -RunArgs $Test.Remote.Arguments

    $ReadyToStart = WaitFor-Remote-Ready -Job $RemoteJob 

    if (!$ReadyToStart) {
        Write-Host "Test Remote for $Test failed to start"
        Stop-Job -Job $Job
        return
    }

    # Start-Sleep 3

    # Invoke-Command -Session $session -ScriptBlock {
    #     Write-Host $Process.StandardOutput.ReadLine()
    # }

    # $Vdd = Invoke-Command -Session $session -ScriptBlock {
    #     [System.Threading.Monitor]::Enter($StringBuilder)
    #     try {
    #         Write-Host $StringBuilder.Length
    #         Write-Host $WriteCount
    #         return $StringBuilder.ToString()
    #     } finally {
    #         [System.Threading.Monitor]::Exit($StringBuilder)
    #     }
    # }

    # Write-Host $Vdd

    # TODO figure out streaming output from remote jobs

    #WaitFor-Remote-Ready -Job $RemoteJob

    $AllRunsResults = @()

    1..$Test.Iterations | ForEach-Object {
        $LocalResults = RunLocal-Exe -Exe $LocalExe -RunArgs $LocalArguments 

        $LocalParsedResults = Parse-Test-Results -Results $LocalResults -Matcher $Test.ResultsMatcher

        
        $AllRunsResults += $LocalParsedResults

        Write-Host "Run $($_): $LocalParsedResults kbps"
        $LocalResults | Write-Debug
    }

    $RemoteResults = WaitFor-Remote -Job $RemoteJob

    $Platform = $Test.ToString()

    # Print current and latest master results to console.
    $MedianCurrentResult = Median-Test-Results -FullResults $AllRunsResults
    $fullLastResult = Get-Latest-Test-Results -Platform $Platform -Test $Test.TestName
    if ($fullLastResult -ne "") {
        $MedianLastResult = Median-Test-Results -FullResults $fullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Host "Median: $MedianCurrentResult kbps ($PercentDiffStr%)"
        Write-Host "Master: $MedianLastResult kbps"
    } else {
        Write-Host "Median: $MedianCurrentResult kbps"
    }
    Write-Debug $RemoteResults.ToString()
}

function Check-Test {
    param($Test)
    return ($Test.Local.Platform -eq $LocalPlatform) -and ($Test.Remote.Platform -eq $RemotePlatform)
}

try {
    $Tests = [TestDefinition[]](Get-Content -Path $TestsFile | ConvertFrom-Json)

    if (!$SkipDeploy) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory
    }

    foreach ($Test in $Tests) {
        if (Check-Test -Test $Test) {
            Run-Test -Test $Test
        } else {
            Write-Host "Skipping $Test"
        }
    }
} finally {
    Remove-PSSession -Session $session 
}
