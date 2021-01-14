Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$TestList = [System.Collections.Generic.Dictionary[Int32, Int32]]::new()
$TestList.Add(1, 3);
$TestList.Add(4,76);

foreach ($Test in $TestList.GetEnumerator()) {
    Write-Output $Test.GetType()
    Write-Output $Test.Value
}