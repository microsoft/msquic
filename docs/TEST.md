# Testing MsQuic

### Additional Windows Configuration

There is a one time registry setup required before the tests can be run when using
SChannel TLS. These registry keys allow QUIC to use TLS 1.3
```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
```

## Running the Tests

To run the tests, simply run:

```PowerShell
./scripts/test.ps1
```

By default this will run all tests in series. To run in parallel, use the `-Parallel` switch. Running in parallel is much faster than in series, but it sometimes can cause additional test failures because of the increased (likely maximum) CPU load it creates. Additionally, while running in parallel, you cannot collect the logs.

So, for a reliable run, that also includes logs for failed tests, run:

```PowerShell
./scripts/test.ps1 -LogProfile Full.Light
```

If there are any failed tests, this will generate a directory for each failed test that incldues the console output from running the test and any logs collected.

**Example Output**
```
PS G:\msquic> ./scripts/test.ps1 -LogProfile Full.Light
[01/21/2020 07:20:29] Executing 967 tests in series...
[01/21/2020 07:46:42] 963 test(s) passed.
[01/21/2020 07:46:42] 4 test(s) failed:
[01/21/2020 07:46:42]   Basic/WithFamilyArgs.BadALPN/0
[01/21/2020 07:46:42]   Basic/WithFamilyArgs.BadALPN/1
[01/21/2020 07:46:42]   Basic/WithFamilyArgs.BadSNI/0
[01/21/2020 07:46:42]   Basic/WithFamilyArgs.BadSNI/1
[01/21/2020 07:46:42] Logs can be found in G:\msquic\artifacts\logs\01.21.2020.07.20.29
```

**TODO** - Document additional configuration options.
