# Building MsQuic

MsQuic uses [CMake](https://cmake.org/) to generate build files.

**Note** clone the repo recursively or run `git submodule update --init --recursive`
to get all the submodules.

## Building on Windows

**Requirements**
  * [Visual Studio 2019](https://www.visualstudio.com/vs/) or higher
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds.

- Run `mkdir bld && cd bld`.
- Run `cmake -G "Visual Studio 16 2019" -A x64 ..`.
- Run `cmake --build . --config RELEASE`

### Running the tests

There is a one time registry setup required before the tests can be run when using
SChannel TLS. These registry keys allow QUIC to use TLS 1.3:
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f
```

- Run `..\artifacts\bin\Release\msquictest.exe`.

## Building on Linux (or [WSL](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install))

- Run `mkdir bld && cd bld`.
- Run `cmake -G "Unix Makefiles" ..`.
- Run `cmake --build . --config RELEASE`.

### Running the tests

- Run `../artifacts/bin/msquictest`.
