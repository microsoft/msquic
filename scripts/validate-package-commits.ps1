param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceCommit,

    [Parameter(Mandatory = $true)]
    [string]$ResourceBranch,

    [Parameter(Mandatory = $true)]
    [string]$PipelineCommit,

    [Parameter(Mandatory = $true)]
    [string]$PipelineBranch
)

$Failed = $false

if ($ResourceCommit -ne $PipelineCommit) {
    Write-Host "##vso[task.LogIssue type=error;]Mismatched commits. Resource: $ResourceCommit Pipeline: $PipelineCommit"
    $Failed = $true
}

if ($ResourceBranch -ne $PipelineBranch) {
    Write-Host "##vso[task.LogIssue type=error;]Mismatched branches. Resource: $ResourceBranch Pipeline: $PipelineBranch"
    $Failed = $true
}

if ($Failed) {
    exit 1
}
