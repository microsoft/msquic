<#

.SYNOPSIS
This script invokes an ETW trace collection

.PARAMETER SessionName
    The name of an ETW session.

.PARAMETER SessionName
    The name of a netsh tracing scenario to start.

.PARAMETER EtlPath
    The name of an ETL file.

.PARAMETER TmfPath
    The path of the TMF files (used to convert ETL).

.PARAMETER Start
    If set, starts a new netsh.exe trace session for the given NetshScenario.

.PARAMETER Stop
    If set, stops a running netsh.exe trace session.

.PARAMETER Flush
    If set, flushes the specified SessionName. Also can populate EtlPath
    automatically from the ETW session configuration.

.PARAMETER Convert
    If set, convert the (either manually specified or automatically populated
    by -Flush) EtlPath to text.

.PARAMETER Sanitize
    If set, sanitizes IP addresses in the converted ETL file.

.PARAMETER UseSaltedHash
    If set, IP address sanitization uses a salted hash instead of REDACTED.
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$SessionName = "",

    [Parameter(Mandatory = $false)]
    [string]$NetshScenario = "",

    [Parameter(Mandatory = $false)]
    [string]$EtlPath = "",

    [Parameter(Mandatory = $false)]
    [string]$TmfPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$Start,

    [Parameter(Mandatory = $false)]
    [switch]$Stop,

    [Parameter(Mandatory = $false)]
    [switch]$Flush,

    [Parameter(Mandatory = $false)]
    [switch]$Convert,

    [Parameter(Mandatory = $false)]
    [switch]$Sanitize,

    [Parameter(Mandatory = $false)]
    [switch]$UseSaltedHash
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$IPv4Pattern = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'
$IPv6Pattern = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"

# Compile the regex for performance reasons, also ignore case
$RegexOptions = [System.Text.RegularExpressions.RegexOptions]::Compiled
$RegexOptions += [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

$IPv6Regex = [Regex]::new($IPv6Pattern, $RegexOptions)
$IPv4Regex = [Regex]::new($IPv4Pattern, $RegexOptions)

# Create HMAC for salted hashing.
$Secret = ""
for ($i = 0; $i -lt 4; $i++) {
    $Secret+= $(Get-Random).ToString('x8')
}
$HmacSha = New-Object System.Security.Cryptography.HMACSHA256
$HmacSha.key = [Text.Encoding]::ASCII.GetBytes($Secret)

function Perform-SaltedHash($Input) {
    return [Convert]::ToBase64String($HmacSha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Input))).SubString(0,12)
}

function Format-IPAddresses {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $InputData,

        [boolean]$Sanitize
    )

    process {
        if (!$Sanitize) {
            return $_
        }
        $ShrunkLine = $InputData
        # Skip to first space to bypass date, which is seen as a valid IPv6 address
        $Idx = ([string]$InputData).IndexOf(' ');
        if ($Idx -ge 0) {
            $ShrunkLine = $InputData.Substring($Idx);
        }
        $Line = $InputData

        # Explicitly check IPv4, as the way IPv4 is printed by ETW
        # partially matches the IPv6 cases, which doesn't fully match
        # and then exits, leaving the address exposed.
        if ($UseSaltedHash) {
            $IPv4Matches = $IPv4Regex.Matches($ShrunkLine)
            foreach ($Match in $IPv4Matches) {
                $HashedMatch = Perform-SaltedHash $Match
                $Line = $Line.Replace($Match, $HashedMatch);
            }

            $IPv6Matches = $IPv6Regex.Matches($ShrunkLine)
            foreach ($Match in $IPv6Matches) {
                $HashedMatch = Perform-SaltedHash $Match
                $Line = $Line.Replace($Match, $HashedMatch);
            }
        } else {
            $IPv4Matches = $IPv4Regex.Matches($ShrunkLine)
            foreach ($Match in $IPv4Matches) {
                $Line = $Line.Replace($Match, "REDACTED");
            }

            $IPv6Matches = $IPv6Regex.Matches($ShrunkLine)
            foreach ($Match in $IPv6Matches) {
                $Line = $Line.Replace($Match, "REDACTED");
            }
        }
        return $Line
    }
}

# Starts a netsh tracing ETW session for the given scenario.
if ($Start) {
    if ($NetshScenario -eq "") {
        Write-Error "No NetshScenario argument present"
    }
    if ($SessionName -eq "") {
        Write-Error "No SessionName argument present"
    }
    if ($EtlPath -eq "") {
        $EtlPath = Join-Path $env:temp "$($SessionName).etl"
    }

    # Start the ETW session running.
    $Command = "netsh.exe trace start scenario=$($NetshScenario) sessionname=$($SessionName) tracefile=$($EtlPath)"
    Write-Debug $Command
    $Result = Invoke-Expression $Command
}

# Stops a netsh tracing session
if ($Stop) {
    if ($SessionName -eq "") {
        Write-Error "No SessionName argument present"
    }
    if ($EtlPath -eq "") {
        $EtlPath = Join-Path $env:temp "$($SessionName).etl"
    }

    # Stop the ETW session.
    $Command = "netsh.exe trace stopsessionname=$($SessionName)"
    Write-Debug $Command
    $Result = Invoke-Expression $Command
}

# Flush an ETW session.
if ($Flush) {
    if ($SessionName -eq "") {
        Write-Error "No SessionName argument present"
    }

    # Query the ETW session status (and config).
    $Command = "logman.exe query $($SessionName) -ets"
    Write-Debug $Command
    $QueryResult = Invoke-Expression $Command
    if (!$QueryResult.Contains("The command completed successfully.")) {
        Write-Error "Unable to find the logging session`n$QueryResult"
    }

    # Flush the ETW memory buffers to disk.
    $Command = "logman.exe update $($SessionName) -ets -fd"
    Write-Debug $Command
    Invoke-Expression $Command 2>&1 | Out-Null

    # Grab the ETL output path if not already specified.
    if ($EtlPath -eq "") {
        $outputLocationLine = $QueryResult.Split("`r`n") | Select-String "Output Location:"
        if ($outputLocationLine -eq "") {
            Write-Error "Cannot extract EtlPath output location`n$($QueryResult)"
        }
        $EtlPath = $outputLocationLine.Line.ToString().Split(':', 2)[1].Trim()
    }
}

# Convert an ETL to text (sanitizing as necessary).
if ($Convert) {
    if ($EtlPath -eq "") {
        Write-Error "No EtlPath argument present"
    }
    if (!(Test-Path $EtlPath)) {
        Write-Error "$EtlPath file not found"
    }

    # Convert the ETL to text.
    $OutputPath = Join-Path $env:temp "temp.log"
    $Command = "netsh trace convert $($EtlPath) output=$($OutputPath) overwrite=yes report=no"
    if ($TmfPath -ne "") {
        $Command += " tmfpath=$($TmfPath)"
    }
    Write-Debug $Command
    Invoke-Expression $Command 2>&1 | Out-Null

    # Get the text content, sanitizing as necessary.
    Get-Content -Path $OutputPath `
        | Where-Object { !$_.Contains("(No Format Information found)")} `
        | Format-IPAddresses -Sanitize $Sanitize
}
