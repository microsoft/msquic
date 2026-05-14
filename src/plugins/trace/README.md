# Windows Performance Analyzer Plugin

![](images/wpa.png)

This page provides the install, setup and usage instructions for Windows Performance Analyzer (WPA) and use it to analyze MsQuic traces.

# Install Instructions

The following are currently only possible on Windows. Other platforms may be supported by WPA in the future.

## Install WPA

Download the preview version from [the Windows Store](https://www.microsoft.com/store/productId/9N58QRW40DFW) or (for MSFT internal) from http://aka.ms/getwpa.

## Download MsQuic WPA Plugin

1. Navigate to our [GitHub Action](https://github.com/microsoft/msquic/actions/workflows/plugins.yml?query=branch%3Amain) for building the plugin.
2. Click on the latest build.
3. Scroll to the bottom and download the `ptix_quictrace_Release` artifact.
4. Extract the `.ptix` file.

## Install the Plugin

1. Open WPA and use the `Install Plugin` dialog to install the MsQuic WPA plugin.
2. Restart WPA.

# Usage Instructions

WPA is extremely powerful. It can operate very quickly on multi-gigabyte trace files and let you slice & dice the data many different ways to really drill down into what's going on.

## Load trace file
### ETW trace
Select and Open .etl file

### LTTng trace
- Directory
    - Select directory which includes traces. WPA automatically traverses and find trace files.
- File
  1. Compress the directory as zip
  2. change the extension to .ctf
  3. Select the .ctf file


## Call stacks and CPU Usage

### Windows
![](images/flame.png)

One of the built-in capabilities of WPA is the ability to analyze CPU trace information to see the CPU usage of the various call stacks in the code. For instance, in the above Flame Graph you can easily see that the most expensive function (58% of total CPU usage!) is `CxPlatEncrypt`.

### Linux
Linux perf command is one of the way to collect such information.  
```sh
# on Linux (kernel > 5.10)
sudo apt-get install -y linux-perf
# on Linux (kernel <= 5.10)
sudo apt-get install -y linux-tools-`uname -r`
# use your own options
perf record -a -g -F 10 -o out.perf.data
# ".perf.data.txt" extension is required for later visualize on WPA
perf script -i out.perf.data > out.perf.data.txt
```

#### Visualize perf artifact on WPA
The perf command's artifact can be visualized on Windows through WPA.  
Follow steps below to load perf extension on WPA.

```pwsh
# on Windows
cd ${WORKDIR}
git clone https://github.com/microsoft/Microsoft-Performance-Tools-Linux-Android
cd .\Microsoft-Performance-Tools-Linux-Android\PerfDataExtensions
dotnet build
# use absolute path
wpa.exe -addsearchdir ${WORKDIR}\Microsoft-Performance-Tools-Linux-Android\PerfDataExtensions\bin\Debug\netstandard2.1\
# Open out.perf.data.txt on WPA. You might need to open multiple time if you see error at opening (known issue?)
```
Change visualization type by drop down menu as shown in image below. Also you can filter in data for each CPU etc.
![](images/wpa_perf_line.png)
![](images/wpa_perf_flamegraph.png)


**TODO** - Add more details/instructions.

## QUIC Charts and Tables

![](images/quic_network.png)

**TODO**
