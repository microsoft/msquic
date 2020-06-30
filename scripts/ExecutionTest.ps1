
$RemoteAddressPair = "User@172.21.202.141"
$session = New-PSSession -HostName "$RemoteAddressPair"

$RemoteAddress = $session.ComputerName

if ($null -eq $session) {
    exit
}

try {
Invoke-Command -Session $session -ScriptBlock {
    $StoredVal = "Hello World"
}

Invoke-Command -Session $session -ScriptBlock {
    Write-Host $StoredVal
} 

} finally {
    Remove-PSSession -Session $session 
}
