# Testing MsQuic

## Running the Tests

To run the all the tests, (after [building](./BUILD.md)) simply run:

```PowerShell
./scripts/test.ps1
```

> **Note** - On Windows, `schannel` is the default TLS provider, but requires the latest Windows OS versions (Windows Server 2022 or Insider Preview) to function. If you don't have `schannel` use `openssl` to build and test.

```PowerShell
./scripts/test.ps1 -Tls openssl
```

By default this will run all tests in series, with no log to collection. To include log collection for failed tests, run:

```PowerShell
./scripts/test.ps1 -LogProfile Full.Light
```

> **Note** - On Windows, you will need to run Powershell as **Administrator** to get the logs.

If there are any failed tests, this will generate a directory for each failed test that incldues the console output from running the test and any logs collected.

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

# Using DPDK

Copy all DPDK binaries (from both .\dpdk\bin and .\dpdk\lib\dpdk\pmds-21.3) to the output location, along with the MsQuic binaries.

Enable test signing (and reboot as necessary).

Follow the steps [here](http://doc.dpdk.org/guides/windows_gsg/run_apps.html) to configure the correct privileges and install virt2phys (note, you may have to sign virt2phys if you don't have a kd).

Download the Mellanox runtime and install it: https://www.mellanox.com/products/adapter-software/ethernet/windows/winof-2

Follow the instructions [here](https://microsoft.sharepoint.com/teams/STACKTeam-CoreNetworkingMobileConnectivityPeripheralsStackSe/_layouts/15/Doc.aspx?sourcedoc=%7b51a801c3-0d8e-4c41-bdd4-958f6ed84c41%7d&action=edit&wd=target%28UVMS.one%7C2606bb27-b3c6-4831-9458-6fd9c9c7b89e%2FUVMS%20%2B%20CX5%20PMD%7Cefcce2a4-d701-4bb3-94a0-b4fb3a3703e6%2F%29&wdorigin=703) to find and set the necessary (DevcEnabled and DevxFsRules) registry key for the adapter you will be using.
