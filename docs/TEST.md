# Testing MsQuic

## Running the Tests

First [build](./BUILD.md). Then prepare the machine:

```PowerShell
.\scripts\prepare-machine.ps1 -ForTest
```

Then all the tests can be run with:

```PowerShell
./scripts/test.ps1
```

> **Note**
> On Windows, `schannel` is the default TLS provider, but requires the latest Windows OS versions (Windows Server 2022 or Insider Preview) to function. If you don't have `schannel` use `openssl` to build and test.

```PowerShell
./scripts/test.ps1 -Tls openssl
```

By default this will run all tests in series, with no log collection. To include log collection for failed tests, run:

```PowerShell
./scripts/test.ps1 -LogProfile Full.Light
```

> **Note**
> On Windows, you will need to run Powershell as **Administrator** to get the logs.

If there are any failed tests, this will generate a directory for each failed test that includes the console output from running the test and any logs collected.

**Example Output** (Windows)
```PowerShell
PS F:\msquic> .\scripts\test.ps1
[05/24/2021 08:17:35] F:\msquic\artifacts\bin\windows\x64_Debug_schannel\msquiccoretest.exe (208 test case(s))
...
[05/24/2021 08:17:48] 208 test(s) run.
[05/24/2021 08:17:48] F:\msquic\artifacts\bin\windows\x64_Debug_schannel\msquicplatformtest.exe (66 test case(s))
...
[05/24/2021 08:17:55] 66 test(s) run.
[05/24/2021 08:17:56] F:\msquic\artifacts\bin\windows\x64_Debug_schannel\msquictest.exe (1681 test case(s))
...
[05/24/2021 08:26:58] 1681 test(s) run.
[05/24/2021 08:26:58] Output can be found in F:\msquic\artifacts\logs\msquictest.exe\05.24.2021.08.17.55
Write-Error: 4 test(s) failed.
```

## PowerShell Script Arguments

There are a number of other useful arguments for `test.ps1`.

`Config <Debug/Release>` - The build configuration (**default**: `debug`) to test. Must have been built first.

`Arch <x86/x64/arm/arm64>` - The CPU architecture (**default**: `x64`) to test. Must have been built first.

`Tls <openssl/schannel>` - The TLS provider to use (**Windows default**: `schannel`, **Posix default**: `openssl`) to test. Must have been built first.

`Filter <GoogleTest filter>` - A filter for which tests to run. More details [here](https://google.github.io/googletest/advanced.html#running-a-subset-of-the-tests) on the syntax.

`ListTestCases` - Lists all the (optionally filtered) tests instead of running them.

`NoProgress` - Don't display progress during test execution.

`LogProfile <profile>` - The profile to use for logging. **TODO** - Add more here.

`KeepOutputOnSuccess` - Keep logs even if tests pass.

`Debugger` - Run with the debugger attached.

`InitialBreak` - Break in the debugger on initial attach/start.

`BreakOnFailure` - Break into the debugger for any test failures.
