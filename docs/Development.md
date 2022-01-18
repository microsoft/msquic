# Developing MsQuic

This document contains tips and tricks for configuring known editors to make MsQuic development easier.

## Configuring Visual Studio Code for MsQuic

Using the VS Code C/C++ Tools extension (https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
getting intellisense working for MsQuic is easy, but requires a small amount of configuration. The configuration UI
can be started by going to the command palette (View -> Command Palette) and running `C/C++: Edit Configurations (UI)`.
This UI is a bit awkward to use, to set a field you have to click on another field. If you click out of the window it
won't save.

For User Mode (Windows, Linux or macOS), the following defines need to be added to the configuration.

```
"_DEBUG",
"UNICODE",
"_UNICODE",
"QUIC_EVENTS_STUB",
"QUIC_LOGS_STUB"
```

Additionally, `cStandard` and `cppStandard` need to be set to `c17` and `c++17` respectively.


For Kernel Mode, create a new configuration with the `Add Configuration` button and call it Kernel.

Add a Compiler argument `/kernel` to force kernel mode in the compiler.

Add the following defines

```
_DEBUG
UNICODE
_UNICODE
QUIC_EVENTS_STUB
QUIC_LOGS_STUB
_AMD64_
_WIN32_WINNT=0x0A00
```

Set `cStandard` and `cppStandard` to `c17` and `c++17` respectively.

Finally, you'll need to add the kernel mode header paths to `Include path`. On my system they're

```
C:\Program Files (x86)\Windows Kits\10\Include\10.0.22000.0\km
C:\Program Files (x86)\Windows Kits\10\Include\wdf\kmdf\1.33
```
Depending on which WDK you have installed, the versions might change, but the relative folder paths should be similar.

You will have to switch between configurations depending on if you want kernel mode or user mode context. To do this,
while youre in a c or cpp file the status bar on the buttom right will have the configuration mode. For user it will
be called `Win32` and for kernel it will be called `Kernel`. To switch contexts, click the text, and you'll get a drop
down to select other configurations.



In the end, your c_cpp_properties.json file (in the .vscode folder) should look similar to the following. Some paths might be different, but they're trivially fixable.

```
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE",
                "QUIC_EVENTS_STUB",
                "QUIC_LOGS_STUB"
            ],
            "windowsSdkVersion": "10.0.22000.0",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64",
            "compilerPath": "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.30.30705/bin/Hostx64/x64/cl.exe"
        },
        {
            "name": "Kernel",
            "includePath": [
                "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22000.0\\km",
                "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\wdf\\kmdf\\1.33",
                "${workspaceFolder}/**"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE",
                "QUIC_EVENTS_STUB",
                "QUIC_LOGS_STUB",
                "_AMD64_",
                "_WIN32_WINNT=0x0A00"
            ],
            "compilerPath": "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.30.30705/bin/Hostx64/x64/cl.exe",
            "windowsSdkVersion": "10.0.22000.0",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64",
            "compilerArgs": [
                "/kernel"
            ]
        }
    ],
    "version": 4
}
```
