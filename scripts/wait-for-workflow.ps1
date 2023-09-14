param (
    [Parameter(Mandatory = $true)]
    [string]$name,

    [Parameter(Mandatory = $true)]
    [string]$sha
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Get-WorkflowRunId {
    param([string]$name, [string]$sha)
    $results =
      gh run list -R microsoft/netperf -e repository_dispatch `
        | Select-String -Pattern 'repository_dispatch\s+(\d+)' -AllMatches `
        | Foreach-Object { $_.Matches } `
        | Foreach-Object { $_.Groups[1].Value }
    foreach ($result in $results) {
      if (gh run view -R microsoft/netperf $result | Select-String -Pattern "$name-$sha") {
          return $result
      }
    }
    return $null
}

function Get-WorkflowRunIdWithRetry {
    param([string]$name, [string]$sha)
    $i = 0
    while ($i -lt 3) {
        $id = Get-WorkflowRunId $name $sha
        if ($null -ne $id) {
            return $id
        }
        Write-Host "Workflow not found, retrying in 1 second..."
        Start-Sleep -Seconds 1
        $i++
    }
    Write-Error "Workflow not found!"
    return $null
}

function Get-WorkflowStatus {
    param([string]$id)
    $output = gh run view -R microsoft/netperf $id --exit-status
    if ($output | Select-String -Pattern "X Complete") {
        Write-Error "Workflow failed!"
        return $true
    }
    if ($output | Select-String -Pattern "Γ£ô Complete") {
        Write-Host "Workflow succeeded!"
        return $true
    }
    return $false
}

function Wait-ForWorkflow {
    param([string]$id)
    $i = 0
    while ($i -lt 30) {
        if (Get-WorkflowStatus $id) {
            return
        }
        Start-Sleep -Seconds 30
        $i++
    }
    Write-Error "Workflow timed out!"
}

# Get the workflow run id
Write-Host "Looking for workflow run..."
$id = Get-WorkflowRunIdWithRetry $name $sha
Write-Host "Workflow found: https://github.com/microsoft/netperf/actions/runs/$id"

# Wait for the workflow to complete
Write-Host "Waiting for workflow to complete..."
Wait-ForWorkflow $id