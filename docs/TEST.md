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

Copy all DPDK binaries (from both `.\dpdk\bin` and `.\dpdk\lib\dpdk\pmds-21.3`) to the output location, along with the MsQuic binaries.

Follow the steps [here](http://doc.dpdk.org/guides/windows_gsg/run_apps.html) to configure the correct privileges.

Download the [Mellanox runtime](https://www.mellanox.com/products/adapter-software/ethernet/windows/winof-2) and install it.

Enable DevX on the Mellanox (CX4 or CX5) NIC that you want to use for testing. You need to add 2 new registry keys: `DevxEnabled` and `DevxFsRules`:

1. Open `Device manager` and locate the Mellanox device.
2. Right click and open the `Properties`.
3. Go to the `Details` tab.
4. Select the `Driver` key in the `Property` list.
5. Save the value you received.
   -  For example: `{4d36e972-e325-11ce-bfc1-08002be10318}\0003`
6. Open the registry editor (in console type `regedit`).
7. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class`
8. Select the class as shown in the driver key you extracted in step 5.
   - For example: `{4d36e972-e325-11ce-bfc1-08002be10318}`.
9. Select the device number as in `step 5`.
   - For example: `0003`.
10. Create a new `DWORD` with name `DevxEnabled` and set the value `1`.
11. Create a new `DWORD` with name `DevxFsRules` and set the value `0x28`.
12. Restart the driver. DevX Lib will be able to detect your device now.
13. Verify `DevX=True` for the enabled adapter, run `cmd mlx5cmd -stat`.
