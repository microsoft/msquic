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

Write-Host $ResourceCommit
Write-Host $ResourceBranch

Write-Host $PipelineCommit
Write-Host $PipelineBranch

exit 1
