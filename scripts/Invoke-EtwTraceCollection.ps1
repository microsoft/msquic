<#

.SYNOPSIS
This script invokes an ETW trace collection

.PARAMETER FlushSession
    The name of an ETW session to flush.

.PARAMETER ConvertEtl
    The name of an ETL file to convert.

.PARAMETER TmfPath
    The path of the TMF files to use to convert the ETL.

.PARAMETER Sanitize
    If set, sanitizes IP addresses in the converted ETL file.
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$FlushSession = "",

    [Parameter(Mandatory = $false)]
    [string]$ConvertEtl = "",

    [Parameter(Mandatory = $false)]
    [string]$TmfPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$Sanitize
)

$Pattern = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"

# Compile the regex for performance reasons, also ignore case
$RegexOptions = [System.Text.RegularExpressions.RegexOptions]::Compiled
$RegexOptions += [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$Regex = [Regex]::new($Pattern, $RegexOptions)

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

        $IPMatches = $Regex.Matches($ShrunkLine)
        foreach ($Match in $IPMatches) {
            $Line = $Line.Replace($Match, "REDACTED");
        }
        return $Line
    }
}

if ($FlushSession -ne "") {
    # Flush the ETW memory buffers to disk.
    $Command = "logman.exe update $($FlushSession) -ets -fd"
    Write-Debug $Command
    Invoke-Expression $Command 2>&1 | Out-Null
}

if ($ConvertEtl -ne "") {
    # Convert the ETL to text.
    $OutputPath = Join-Path $env:temp "temp.log"
    $Command = "netsh trace convert $($ConvertEtl) output=$($OutputPath) overwrite=yes report=no"
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
