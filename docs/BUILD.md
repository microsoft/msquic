# Building MsQuic

First, clone the repo recursively or run `git submodule update --init --recursive`
to get all the submodules.

# Source Code

The source (found in the `src` directory) is divided into several directories:

  * `bin` - Packages up all static libraries into the platform specific binaries.
  * `core` - Platform independent code that implements the QUIC protocol.
  * `inc` - Header files used by all the other directories.
  * `manifest` - Windows [ETW manifest](https://docs.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest) and related files.
  * `platform` - Platform specific code for OS types, sockets and TLS.
  * `test` - Test code for the MsQuic API / protocol.
  * `tools` - Tools for exercising MsQuic.

# PowerShell Usage

MsQuic uses several cross-platform PowerShell scripts to simplify build and test operations. The latest PowerShell will need to be installed for them to work. These scripts are the **recommended** way to build and test MsQuic, but they are **not required**. If you prefer to use CMake directly, please scroll down to the end of this page and start with the **Building with CMake** instructions.

## Install on Windows

You can install the latest PowerShell on Windows by running the following **PowerShell** script or read the complete instructions [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows).

```PowerShell
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
```

Then you will need to **manually** launch "PowerShell 7" to continue. This install does not replace the built-in version of PowerShell.

## Install on Linux

You can find the full installation instructions for PowerShell on Linux [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?). For Ubuntu you can run the following:

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

> **Note**
> If you get this error trying to install PowerShell:

```
powershell : Depends: libicu55 but it is not installable
```

Then you will need to run the following first (as a workaround):

```
sudo apt-get remove libicu57
wget http://security.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7ubuntu0.5_amd64.deb
sudo dpkg -i libicu55_55.1-7ubuntu0.5_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4.18_amd64.deb
sudo dpkg -i libssl1.0.0_1.0.2g-1ubuntu4.18_amd64.deb
```

Then you will need to manually run "pwsh" to continue.

## Install on macOS
```
brew install powershell
```


Then you will need to manually run "pwsh" to continue.


# Building with PowerShell

## Install Dependencies

In order to install the necessary dependencies, a copy of the .NET Core 3.1 SDK is required. Go to the following location and find the install page for your platform.

 * [.NET Core](https://docs.microsoft.com/en-us/dotnet/core/install/)

After installing .NET Core, you will need to restart your terminal.

For the very first time you build, it's recommend to make sure you have all the dependencies installed. You can ensure this by running:

```PowerShell
./scripts/prepare-machine.ps1
```

Note at minimum CMake 3.20 on windows and 3.16 on other platforms is required. Instructions for installing the newest version on Ubuntu can be found here. https://apt.kitware.com/. The prepare-machine script will not do this for you.

### Additional Requirements on Windows

  * [CMake](https://cmake.org/) (The version installed with Visual Studio will likely not be new enough)
  * [Perl](https://www.perl.org/get.html) optional (required for OpenSSL build)
  * [Visual Studio 2019 or 2022](https://www.visualstudio.com/vs/) (or Build Tools for Visual Studio 2019/2022) with
    - C++ CMake tools for Windows
    - MSVC v142 - VS 2019 (or 2022) C++ (_Arch_) build tools
    - Windows SDK
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds (required for SChannel build)

## Running a Build

To build the code, you just need to run `build.ps1` in the `scripts` folder:

```PowerShell
./scripts/build.ps1
```

Note that `schannel` TLS provider requires the latest Windows versions (Windows Server 2022 or Insider Preview) to function. If you don't have `schannel` use `openssl` to build and test.

```
./scripts/build.ps1 -Tls openssl
```

The script has a lot of additional configuration options, but the default should be fine for most.

### Config options

`-Config <Debug/Release>` Allows for building in debug or release mode. **Debug** is the default configuration.

`-Arch <x86/x64/arm/arm64>` Allow for building for different architectures. **x64** is the defualt architecture.

`-Static` Compiles msquic as a monolithic statically linkable library.
Supported only by Windows currently.

`-Tls <schannel/openssl>` Allows for building with different TLS providers. The default is platform dependent (Windows = schannel, Linux = openssl).

`-Clean` Forces a clean build of everything.

For more info, take a look at the [build.ps1](../scripts/build.ps1) script.

## Build Output

By default the build output will go in the `build` folder and the final build binaries in the `artifacts` folder. Under that it will create per-platform folders with subfolders for architecture/tls combinations. This allows for building different platforms and configurations at the same time.

# Building with CMake

The following section details how to build MsQuic purely with CMake commands.

> **Please note** that since using CMake directly is not the recommended way of building MsQuic, it's likely that these instructions may fall out of date more often than the **Building with PowerShell** ones.

Note that you will need to disable logging if building with CMake exclusively. Logging enabled requires .NET Core and at least the configuration from prepare-machine.ps1 in order to build.

Note at minimum CMake 3.16 is required. Instructions for installing a the newest version on Ubuntu can be found here. https://apt.kitware.com/

## Install Dependencies

### Linux

The following are generally required. Actual installations may vary.

```
sudo apt-add-repository ppa:lttng/stable-2.12
sudo apt-get update
sudo apt-get install cmake
sudo apt-get install build-essential
sudo apt-get install liblttng-ust-dev
sudo apt-get install lttng-tools
```

On RHEL 8, you'll need to manually install CMake to get the latest version.
Download the x86_64 Linux installation script from cmake.org, and run the following
`sudo sh cmake.sh --prefix=/usr/local/ --exclude-subdir`
to install CMake.

RHEL 8 also requires the following:

```
sudo dnf install openssl-devel
sudo dnf install libatomic
```

### macOS
The build needs CMake and compiler.

```
brew install cmake
```
Minimally, build needs Xcode 'Command Line Tools`. That can be done via XCode in App Store or from command line
```
xcode-select --install
```

## Generating Build Files

### Windows

Ensure the corresponding "MSVC v142 - VS 2019 (or 2022) C++ (_Arch_) build tools" are installed for the target arch, e.g. selecting "Desktop development with C++" only includes x64/x86 but not ARM64 by default.

VS 2019
```
mkdir build && cd build
cmake -G 'Visual Studio 16 2019' -A x64 ..
```

VS 2022
```
mkdir build && cd build
cmake -G 'Visual Studio 17 2022' -A x64 ..
```

### Linux

```
mkdir build && cd build
cmake -G 'Unix Makefiles' ..
```

## Running a Build

```
cmake --build .
```

# Building for Rust

> **Rust support is currently experimental, and not officially supported.**

To build MsQuic for Rust, you still must install the dependencies listed above for the various platforms. Then simply run:

```cmd
cargo build
```

To run the tests:

```
cargo test
```
