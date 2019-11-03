# Building MsQuic

MsQuic uses [CMake](https://cmake.org/) to generate build files.

## Building on Windows

**Requirements**
  * [Visual Studio 2019](https://www.visualstudio.com/vs/) or higher
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds.

- Run `mkdir bld && cd bld`.
- Run `cmake -G "Visual Studio 16 2019" -A x64 ..`.
- Open `msquic.sln` in Visual Studio 2019.
- Build the solution.

### Running the tests

- Run `msquictest.exe` (found under artifacts/bin).

## Building on Linux (or [WSL](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install))

- Run `mkdir bld && cd bld`.
- Run `cmake -G "Unix Makefiles" ..`.
- Run `make`.

### Running the tests

- Run `msquictest` (found under artifacts/bin).
