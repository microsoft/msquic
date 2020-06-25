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

.PARAMETER ConvertLogs
    Convert any collected logs to text. Only works when LogProfile is set.

.PARAMETER CompressOutput
    Compresses the output files generated for failed test cases.

.PARAMETER ShowOutput
    Prints the standard output/error to the console.

.Parameter EnableAppVerifier
    Enables all basic Application Verifier checks on the executable.

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
    [switch]$ConvertLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ShowOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAppVerifier = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Make sure the executable is present.
if (!(Test-Path $Path)) {
    Write-Error "$($Path) does not exist!"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Executable name.
$ExeName = Split-Path $Path -Leaf

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" $ExeName (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

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
    if ($LogProfile -ne "None") {
        & $LogScript -Start -LogProfile $LogProfile | Out-Null
    }

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows) {
        if ($EnableAppVerifier) {
            where.exe appverif.exe
            if ($LastExitCode -eq 0) {
                appverif.exe /verify $Path
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
            $pinfo.Arguments = "-c `"ulimit -c unlimited && LSAN_OPTIONS=report_objects=1 ASAN_OPTIONS=disable_coredump=0:abort_on_error=1 $($Path) $($Arguments) && echo Done`""
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
    } catch {
        # Silently fail
    }
}

# Waits for the executable to finish and processes the results.
function Wait-Executable($Exe) {
    $stdout = $null
    $stderr = $null
    $KeepOutput = $KeepOutputOnSuccess

    try {
        if (!$Debugger) {
            $stdout = $Exe.Process.StandardOutput.ReadToEnd()
            $stderr = $Exe.Process.StandardError.ReadToEnd()
            if (!$isWindows) {
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
            Log "Process had nonzero exit code: $($Exe.Process.ExitCode)"
            $KeepOutput = $true
        }
        $DumpFiles = (Get-ChildItem $LogDir) | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            Log "Dump file(s) generated"
            foreach ($File in $DumpFiles) {
                PrintDumpCallStack($File)
            }
            $KeepOutput = $true
        }
    } catch {
        Log "Treating exception as failure!"
        $KeepOutput = $true
        throw
    } finally {
        $XmlText = $null
        if ($KeepOutput) {
            $XmlText = $FailXmlText;
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

        if ($KeepOutput) {
            if ($LogProfile -ne "None") {
                if ($ConvertLogs) {
                    & $LogScript -Stop -OutputDirectory $LogDir -ConvertToText
                } else {
                    & $LogScript -Stop -OutputDirectory $LogDir | Out-Null
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
if ($IsWindows -and !(Test-Path $WerDumpRegPath)) {
    New-Item -Path $WerDumpRegPath -Force | Out-Null
}

# Start the executable, wait for it to complete and then generate any output.
Wait-Executable (Start-Executable)

if ($isWindows) {
    # Cleanup the WER registry.
    Remove-Item -Path $WerDumpRegPath -Force | Out-Null
}
