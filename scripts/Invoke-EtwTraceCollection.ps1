<#

.SYNOPSIS
This script invokes an ETW trace collection

.PARAMETER Sanitize
    If set, sanitizes IP addresses
#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$Sanitize,

    # Temp variables for testing
    [string]$In,
    [string]$Out
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

# To use, Just have your data in an array, and pass through.
Get-Content -Path $In | Format-IPAddresses -Sanitize $Sanitize | Set-Content -Path $Out
