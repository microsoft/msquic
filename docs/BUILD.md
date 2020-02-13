# Building MsQuic

MsQuic uses [CMake](https://cmake.org/) to generate build files.

> **Note** - clone the repo recursively or run `git submodule update --init --recursive`
to get all the submodules.

# PowerShell (6 or greater) Requirement

MsQuic uses several cross platform PowerShell build scripts to simplify build and test operations. PowerShell 6 or greater will need to be installed for them to work.

## Install on Windows

You can install PowerShell 7.0 on Windows by running the following **PowerShell** script:

```PowerShell
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Preview"
```

Then you will need to manually launch "PowerShell 7" to continue.

## Install on Linux

You find the full installation instructions for PowerShell on Linux [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?). For Ubuntu you can run the following:

```PowerShell
# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb

# Update the list of products
sudo apt-get update

# Enable the "universe" repositories
sudo add-apt-repository universe

# Install PowerShell
sudo apt-get install -y powershell

# Start PowerShell
pwsh
```

**Note** - If you get this error trying to install PowerShell:

```
powershell : Depends: libicu55 but it is not installable
```

Then you will need to run the following first (as a work around):

```
sudo apt-get remove libicu57
wget http://security.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7ubuntu0.4_amd64.deb
sudo dpkg -i libicu55_55.1-7ubuntu0.4_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4.15_amd64.deb
sudo dpkg -i libssl1.0.0_1.0.2g-1ubuntu4.15_amd64.deb
```

# Build Instructions

## Install Dependencies

For the very first time you build, it's recommend to make sure you have all the dependencies installed. You can ensure this by running:

```PowerShell
./scripts/build.ps1 -InstallDependencies
```

### Additional Requirements on Windows
  * [Visual Studio 2019](https://www.visualstudio.com/vs/) or higher
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds.

## Running a Build

To actually build the code, you just need to run:

```PowerShell
./scripts/build.ps1
```

The script has a lot of additional configuration options, but the default should be fine for most.

**TODO** - Document additional configuration options.

# Test Instructions

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

## Using Log Files

**TODO** - Instructions for converting logs to text.
