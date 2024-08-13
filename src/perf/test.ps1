function NetperfWaitServerFinishExecution {
    param (
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 30,
        [Parameter(Mandatory = $false)]
        [int]$WaitPerAttempt = 8,
        [Parameter(Mandatory = $false)]
        [scriptblock]$UnblockRoutine = {}
    )
    $UnblockRoutine.Invoke()
}


function main {
    param (
        [Parameter(Mandatory = $false)]
        [string]$global = ""
    )

    NetperfWaitServerFinishExecution -UnblockRoutine {
        $local = "hello local"
        Write-Host "$local $global"
    }
}

main "hello global"