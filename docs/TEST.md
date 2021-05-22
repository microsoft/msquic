# Testing MsQuic

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

Note that in windows you will need to use Powershell 7 in administrator mode to create the builds and test.

Also, note that schannel requires the latest Windows versions (Windows Server 2022 or Insider Preview) to function. If you don't have `schannel` use `openssl` to build and test.

```
./scripts/test.ps1 -Tls openssl -LogProfile Full.Light
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
