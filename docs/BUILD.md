# Building MsQuic

MsQuic uses [CMake](https://cmake.org/) to generate build files.

**Note** clone the repo recursively or run `git submodule update --init --recursive`
to get all the submodules.

## Building on Windows

**Requirements**
  * [Visual Studio 2019](https://www.visualstudio.com/vs/) or higher
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds.

- Run `mkdir bld && cd bld`
- Run `cmake -G "Visual Studio 16 2019" -A x64 ..`
- Run `cmake --build . --config RELEASE`

### Building with OpenSSL

**Requirements**
  * [Perl](https://www.perl.org/)
  * [NMAKE](https://docs.microsoft.com/en-us/cpp/build/reference/nmake-reference?view=vs-2019)

**TODO** - Figure out the correct set of steps.

### Running the tests

There is a one time registry setup required before the tests can be run when using
SChannel TLS. These registry keys allow QUIC to use TLS 1.3:
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f
```

- Run `..\artifacts\bin\Release\msquictest.exe`

### Collecting logs

- To start a trace, run `netsh trace start overwrite=yes report=dis correlation=dis traceFile=quic.etl maxSize=1024 provider={ff15e657-4f26-570e-88ab-0796b258d11c} level=0x5`
- Run the repro.
- To stop the trace, run `netsh trace stop`
- To decode the `quic.etl` file, run **TODO**

## Building on Linux (or [WSL](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install))
- Install tooling (WSL2 or Ubuntu)
    - `sudo apt-get install cmake`
    - `sudo apt-get install build-essentials`
- Run `mkdir bld && cd bld`
- Run `cmake -G "Unix Makefiles" ..`
- Run `cmake --build . --config RELEASE`

### Running the tests

- Run `../artifacts/bin/msquictest`

### Collecting logs

On Linux, MsQuic uses [syslog](http://man7.org/linux/man-pages/man3/syslog.3.html) for logging by default. To view the logs:

- On **WSL**, run `sudo service rsyslog start` to make sure syslog is configured.
- **Optionally**, run `sudo truncate -s 0 /var/log/syslog` to clear out the current log file.
- Run the repro.
- You can view the logs from the `/var/log/syslog` file.
