function Run-Secnetperf($testIds, $commands, $exe, $json, $LogProfile) {

    Write-Host "Running Secnetperf tests..."

    $SQL = @"
"@
    $json = @{}

    for ($i = 0; $i -lt $commands.Count; $i++) {
    for ($tcp = 0; $tcp -lt 2; $tcp++) {

    if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # Start logging.
        Write-Host "Starting logging with log profile: $LogProfile..."
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    for ($try = 0; $try -lt 3; $try++) {
        $command = "$exe -target:netperf-peer $($commands[$i]) -tcp:$tcp -trimout"
        Write-Host "Running test: $command"
        try {
            $rawOutput = Invoke-Expression $command
        } catch {
            Write-GHError "Failed to run test: $($commands[$i])"
            Write-GHError $_
            $script:encounterFailures = $true
            continue
        }

        if ($rawOutput -eq $null) {
            Write-GHError "RawOutput is null. Failed to run test: $($commands[$i])"
            $script:encounterFailures = $true
            continue
        }

        if ($rawOutput.Contains("Error")) {
            $rawOutput = $rawOutput.Substring(7) # Skip over the 'Error: ' prefix
            Write-GHError $rawOutput
            $script:encounterFailures = $true
            continue
        }
        
        $rawOutput

        if ($testIds[$i].Contains("rps")) {
            $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
            $Perc = [regex]::Matches($rawOutput, $latency_percentiles) | ForEach-Object {$_.Value}
            $json[$testIds[$i]] = $Perc
            # TODO: SQL += ...
            continue
        }

        $throughput = '@ (\d+) kbps'

        $testId = $testIds[$i]
        if ($tcp -eq 1) {
            $testId += "-tcp"
        } else {
            $testId += "quic"
        }
        $testId += "-$MsQuicCommit"

        foreach ($line in $rawOutput) {
            if ($line -match $throughput) {

                $num = $matches[1]

                # Generate SQL statement
                $SQL += @"

INSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Client_environment_ID, Server_environment_ID, Result, Latency_stats_ID, Units)
VALUES ('$($testIds[$i])', 'azure_vm', 'azure_vm', $num, NULL, 'kbps');

"@

                # Generate JSON
                $json[$testIds[$i]] = $num
                break
            }
        }

        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # Stop logging.
            Write-Host "Stopping logging..."
            Invoke-Expression ".\scripts\log.ps1 -Stop -OutputPath .\artifacts\logs\$command"
        }

        Start-Sleep -Seconds 1
    }
    

    
    }}

    return $SQL
}
