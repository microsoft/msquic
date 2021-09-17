<#

.SYNOPSIS
This script cleans up after a perf run

.PARAMETER Remote
    The remote to connect to. Must have ssh remoting enabled, and public key auth. username@ip

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Remote = "",

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "quic-server",

    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "",

    [switch]$SkipRemote = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (!$IsWindows -and [string]::IsNullOrWhiteSpace($Remote)) {
    $Remote = "quic-server"
}

# Remove any previous remote PowerShell sessions
Get-PSSession | Remove-PSSession

$Session = $null

if (!$SkipRemote) {
    if ($Remote -eq "") {
        if ($WinRMUser -ne "") {
            $Session = New-PSSession -ComputerName $ComputerName -Credential $WinRMUser -ConfigurationName PowerShell.7
        } else {
            $Session = New-PSSession -ComputerName $ComputerName -ConfigurationName PowerShell.7
        }
    } else {
        $Session = New-PSSession -HostName "$Remote"
    }
}

if ($null -eq $Session) {
    Write-Host "Failed to create remote session"
} else {
    $RemoteAddress = $Session.ComputerName
    Write-Output "Connected to: $RemoteAddress"
}

try {

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

        if ($null -ne $Session) {
            Invoke-Command -Session $Session -ScriptBlock {
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

} finally  {
    if ($null -ne $Session) {
        Remove-PSSession -Session $Session
    }
}
