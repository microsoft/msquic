<#

.SYNOPSIS
This script runs an executable and collects and logs or process dumps as necessary.

.PARAMETER Path
    The path to the executable.

.PARAMETER Arguments
    The arguments to pass to the executable.

.PARAMETER KeepOutputOnSuccess
    Don't discard console output or logs on success.

.PARAMETER GenerateXmlResults
    Generates an xml Test report for the run.

.PARAMETER Debugger
    Attaches the debugger to the process.

.PARAMETER InitialBreak
    Debugger starts broken into the process to allow setting breakpoints, etc.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER CompressOutput
    Compresses the output files generated for failed test cases.

.PARAMETER ShowOutput
    Prints the standard output/error to the console.

.Parameter EnableAppVerifier
    Enables all basic Application Verifier checks on the executable.

.Parameter CodeCoverage
    Collect code coverage for the binary being run.

.Parameter AZP
    Runs in Azure Pipelines mode.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$Arguments = "",

    [Parameter(Mandatory = $false)]
    [switch]$KeepOutputOnSuccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlResults = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InitialBreak = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ShowOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAppVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage = $false,

    [Parameter(Mandatory = $false)]
    [switch]$AZP = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$global:ExeFailed = $false

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

function LogWrn($msg) {
    if ($AZP) {
        Write-Host "##vso[task.LogIssue type=warning;][$(Get-Date)] $msg"
    } else {
        Write-Host "[$(Get-Date)] $msg"
    }
}

function LogErr($msg) {
    if ($AZP) {
        Write-Host "##vso[task.LogIssue type=error;][$(Get-Date)] $msg"
    } else {
        Write-Host "[$(Get-Date)] $msg"
    }
}

function Test-Administrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Make sure the executable is present.
if (!(Test-Path $Path)) {
    Write-Error "$($Path) does not exist!"
}

# Validate the code coverage switch
if ($CodeCoverage) {
    if (!$IsWindows) {
        Write-Error "-CodeCoverage switch only supported on Windows";
    }
    if ($Debugger) {
        Write-Error "-CodeCoverage switch is not supported with debugging";
    }
    if (!(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
        Write-Error "Code coverage tools are not installed";
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Executable name.
$ExeName = Split-Path $Path -Leaf
$CoverageName = "$(Split-Path $Path -LeafBase).cov"

$ExeLogFolder = $ExeName
if (![string]::IsNullOrWhiteSpace($ExtraArtifactDir)) {
    $ExeLogFolder += "_$ExtraArtifactDir"
}

# Path for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" $ExeLogFolder (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

# Folder for coverage files
$CoverageDir = $null
if ($CodeCoverage) {
    $CoverageDir = Join-Path $RootDir "artifacts" "coverage"
    New-Item -Path $CoverageDir -ItemType Directory -Force | Out-Null
}

# XML for creating a failure result data.
$FailXmlText = @"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="1" failures="1" disabled="0" errors="0" time="0" name="Executable">
  <testsuite name="ExeName" tests="1" failures="1" disabled="0" errors="0" timestamp="date" time="0" >
    <testcase name="ExeName" status="run" result="completed" time="0" timestamp="date" classname="ExeName">
      <failure message="Application Crashed" type=""><![CDATA[Application Crashed]]></failure>
    </testcase>
  </testsuite>
</testsuites>
"@

# XML for creating a success result data.
$SuccessXmlText = @"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="1" failures="1" disabled="0" errors="0" time="0" name="Executable">
  <testsuite name="ExeName" tests="1" failures="1" disabled="0" errors="0" timestamp="date" time="0" >
    <testcase name="ExeName" status="run" result="completed" time="0" timestamp="date" classname="ExeName" />
  </testsuite>
</testsuites>
"@

# Path to the WER registry key used for collecting dumps.
$WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\$ExeName"

# Asynchronously starts the executable with the given arguments.
function Start-Executable {
    $Now = (Get-Date -UFormat "%Y-%m-%dT%T")
    if ($LogProfile -ne "None" -and !$CodeCoverage) {
        & $LogScript -Start -Profile $LogProfile | Out-Null
    }

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows) {
        if ($EnableAppVerifier) {
            where.exe appverif.exe | Out-Null
            if ($LastExitCode -eq 0) {
                appverif.exe /verify $Path | Out-Null
            } else {
                Write-Warning "Application Verifier not installed!"
                $EnableAppVerifier = $false;
            }
        }
        if ($Debugger) {
            $pinfo.FileName = "windbg"
            if ($InitialBreak) {
                $pinfo.Arguments = "-G $($Path) $($Arguments)"
            } else {
                $pinfo.Arguments = "-g -G $($Path) $($Arguments)"
            }
        } elseif ($CodeCoverage) {
            $pinfo.FileName = "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe"
            $pinfo.Arguments = "--modules=$(Split-Path $Path -Parent) --cover_children --sources src\core --excluded_sources unittest --working_dir $($LogDir) --export_type binary:$(Join-Path $CoverageDir $CoverageName) -- $($Path) $($Arguments)"
            $pinfo.WorkingDirectory = $LogDir
        } else {
            $pinfo.FileName = $Path
            $pinfo.Arguments = $Arguments
            # Enable WER dump collection.
            New-ItemProperty -Path $WerDumpRegPath -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
            New-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -PropertyType ExpandString -Value $LogDir -Force | Out-Null
        }
    } else {
        if ($Debugger) {
            $pinfo.FileName = "gdb"
            if ($InitialBreak) {
                $pinfo.Arguments = "--args $($Path) $($Arguments)"
            } else {
                $pinfo.Arguments = "-ex=r --args $($Path) $($Arguments)"
            }
        } else {
            $pinfo.FileName = "bash"
            $pinfo.Arguments = "-c `"ulimit -c unlimited && LSAN_OPTIONS=report_objects=1 ASAN_OPTIONS=disable_coredump=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $($Path) $($Arguments) && echo Done`""
            $pinfo.WorkingDirectory = $LogDir
        }
    }
    if (!$Debugger) {
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
    }
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null

    [pscustomobject]@{
        Timestamp = $Now
        Process = $p
    }
}

# Uses CDB.exe to print the crashing callstack in the dump file.
function PrintDumpCallStack($DumpFile) {
    $env:_NT_SYMBOL_PATH = Split-Path $Path
    try {
        if ($env:BUILD_BUILDNUMBER -ne $null) {
            $env:PATH += ";c:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
        }
        $Output = cdb.exe -z $File -c "kn;q" | Join-String -Separator "`n"
        $Output = ($Output | Select-String -Pattern " # Child-SP(?s).*quit:").Matches[0].Groups[0].Value
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $DumpFile -Leaf)"
        Write-Host "=================================================================================="
        $Output -replace "quit:", "=================================================================================="
        $Output | Out-File "$DumpFile.txt"
    } catch {
        # Silently fail
    }
}

function PrintLldbCoreCallStack($CoreFile) {
    try {
        $Output = lldb $Path -c $CoreFile -b -o "`"bt all`""
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $CoreFile -Leaf)"
        Write-Host "=================================================================================="
        # Find line containing Current thread
        $Found = $false
        $LastThreadStart = 0
        for ($i = 0; $i -lt $Output.Length; $i++) {
            if ($Output[$i] -like "*stop reason =*") {
                if ($Found) {
                    break
                }
                $LastThreadStart = $i
            }
            if ($Output[$i] -like "*quic_bugcheck*") {
                $Found = $true
                for ($j = $LastThreadStart; $j -lt $i; $j++) {
                    $Output[$j]
                }
            }
            if ($Found) {
                $Output[$i]
            }
        }
        if (!$Found) {
            $Output | Join-String -Separator "`n"
        }
        $Output | Join-String -Separator "`n" | Out-File "$CoreFile.txt"
    } catch {
        # Silently Fail
    }
}

function PrintGdbCoreCallStack($CoreFile) {
    try {
        $Output = gdb $Path $CoreFile -batch -ex "`"bt`"" -ex "`"quit`""
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $CoreFile -Leaf)"
        Write-Host "=================================================================================="
        # Find line containing Current thread
        $Found = $false
        for ($i = 0; $i -lt $Output.Length; $i++) {
            if ($Output[$i] -like "*Current thread*") {
                $Found = $true
            }
            if ($Found) {
                $Output[$i]
            }
        }
        if (!$Found) {
            $Output | Join-String -Separator "`n"
        }
        $Output | Join-String -Separator "`n" | Out-File "$CoreFile.txt"
    } catch {
        # Silently Fail
    }
}

# Waits for the executable to finish and processes the results.
function Wait-Executable($Exe) {
    $stdout = $null
    $stderr = $null
    $KeepOutput = $KeepOutputOnSuccess

    try {

        if ($CodeCoverage) {
            # When measuring code coverage, wait a little bit and then force a few
            # other code paths...
            Sleep -Seconds 5
            if ($LogProfile -ne "None") {
                # Start logs to trigger the rundown code paths.
                & $LogScript -Start -Profile $LogProfile | Out-Null
            }
            # Set a registry key to trigger the settings code paths.
            reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\MsQuic\Parameters\Apps\spinquic /v InitialWindowPackets /t REG_DWORD /d 20 /f | Out-Null
            Sleep -Seconds 1
            reg.exe delete HKLM\SYSTEM\CurrentControlSet\Services\MsQuic\Parameters\Apps\spinquic /f
        }

        if (!$Debugger) {
            $stdout = $Exe.Process.StandardOutput.ReadToEnd()
            $stderr = $Exe.Process.StandardError.ReadToEnd()
            if (!$IsWindows) {
                $KeepOutput = $stderr.Contains("Aborted")
            }
        } else {
            if ($IsWindows -and $EnableAppVerifier) {
                # Wait 10 seconds for the debugger to launch the application
                Start-Sleep -Seconds 10
                # Turn off App Verifier
                appverif.exe -disable * -for $Path
            }
        }
        $Exe.Process.WaitForExit()
        if ($Exe.Process.ExitCode -ne 0) {
            LogErr "Process had nonzero exit code: $($Exe.Process.ExitCode)"
            $KeepOutput = $true
        }
        $DumpFiles = (Get-ChildItem $LogDir) | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            LogErr "Dump file(s) generated"
            foreach ($File in $DumpFiles) {
                PrintDumpCallStack($File)
            }
            $KeepOutput = $true
        }
        $CoreFiles = (Get-ChildItem $LogDir) | Where-Object { $_.Extension -eq ".core" }
        if ($CoreFiles) {
            LogWrn "Core file(s) generated"
            foreach ($File in $CoreFiles) {
                if ($IsMacOS) {
                    PrintLldbCoreCallStack $File
                } else {
                    PrintGdbCoreCallStack $File
                }
            }
            $KeepOutput = $true
        }
    } catch {
        LogWrn $_
        LogErr "Treating exception as failure!"
        $KeepOutput = $true
        throw
    } finally {
        $XmlText = $null
        if ($KeepOutput) {
            $XmlText = $FailXmlText;
            $global:ExeFailed = $true
        } else {
            $XmlText = $SuccessXmlText;
        }

        if ($GenerateXmlResults) {
            $XmlText = $XmlText.Replace("ExeName", $ExeName)
            $XmlText = $XmlText.Replace("date", $Exe.Timestamp)
            # TODO - Update time fields.
            $XmlResults = [xml]($XmlText)
            $XmlResults.Save($LogDir + "-results.xml") | Out-Null
        }

        if ($ShowOutput) {
            if ($null -ne $stdout -and "" -ne $stdout) {
                Write-Host $stdout
            }
            if ($null -ne $stderr -and "" -ne $stderr) {
                Write-Host $stderr
            }
        }

        if ($CodeCoverage) {
            # Copy coverage log
            $LogName = "LastCoverageResults-$(Split-Path $Path -LeafBase).log"
            Copy-Item (Join-Path $LogDir "LastCoverageResults.log") (Join-Path $CoverageDir $LogName) -Force
        }

        if ($KeepOutput) {
            if ($LogProfile -ne "None") {
                if ($CodeCoverage) {
                    & $LogScript -Cancel | Out-Null
                } else {
                    & $LogScript -Stop -OutputPath (Join-Path $LogDir "quic") -Tmfpath (Join-Path $RootDir "artifacts" "tmf")
                }
            }

            if ($null -ne $stdout -and "" -ne $stdout) {
                $stdout > (Join-Path $LogDir "stdout.txt")
            }

            if ($null -ne $stderr -and "" -ne $stderr) {
                $stderr > (Join-Path $LogDir "stderr.txt")
            }

            if ($CompressOutput) {
                # Zip the output.
                CompressOutput-Archive -Path "$($LogDir)\*" -DestinationPath "$($LogDir).zip" | Out-Null
                Remove-Item $LogDir -Recurse -Force | Out-Null
            }

            Log "Output available at $($LogDir)"

        } else {
            if ($LogProfile -ne "None") {
                & $LogScript -Cancel | Out-Null
            }
            Remove-Item $LogDir -Recurse -Force | Out-Null
        }
    }
}

# Initialize WER dump registry key if necessary.
if ($IsWindows -and !(Test-Path $WerDumpRegPath) -and (Test-Administrator)) {
    New-Item -Path $WerDumpRegPath -Force | Out-Null
}

# Start the executable, wait for it to complete and then generate any output.
Wait-Executable (Start-Executable)

if ($IsWindows) {
    # Cleanup the WER registry.
    Remove-Item -Path $WerDumpRegPath -Force | Out-Null
}

# Fail execution as necessary.
if ($global:ExeFailed -and $AZP) {
    Write-Error "Run executable failed!"
}
