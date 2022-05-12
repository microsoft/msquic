
// The different test types
var testTypes = [
    "Up",
    "Down",
    "Rps",
    "Hps"
]

// The different platform types and their properties
var platformTypes = [
    { name:"winKernelSchannel", friendly:"Windows Kernel", color:"#11a718" },
    { name:"winUserSchannel", friendly:"Windows User Schannel", color:"#0062ff" },
    { name:"winSharedECSchannel", friendly:"Windows User Schannel (ShareEC)", color:"#ffcc00" },
    { name:"winXDPSchannel", friendly:"Windows User Schannel (XDP)", color:"#858796" },
    { name:"winUserOpenSsl", friendly:"Windows User OpenSSL", color:"#ff3c00" },
    { name:"linuxOpenSsl", friendly:"Linux OpenSSL", color:"#17a2b8" },
    { name:"linuxSharedECOpenSsl", friendly:"Linux OpenSSL (SharedEC)", color:"#262626" }
]

let latestValueFormartter = function(dv) {
    return (pointsToValue(dv.raw[0].d) / dv.div).toFixed(2) + " " + dv.unit;
}

let latestValueLatencyFormartter = function(dv) {
    return (dv.raw[0].y / dv.div).toFixed(2) + " " + dv.unit;
}

// The set of data and available properties
var dataView = [
    { name:"winKernelSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_WinKernel_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winKernelSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_WinKernel_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winKernelSchannelRps", unit:"KHz", div:1000, raw:dataRps_WinKernel_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winKernelSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_WinKernel_x64_Schannel.filter(d=>d.c==1), lvformat:latestValueLatencyFormartter},
    { name:"winKernelSchannelRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_WinKernel_x64_Schannel.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"winKernelSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_WinKernel_x64_Schannel, lvformat:latestValueLatencyFormartter},
    { name:"winKernelSchannelHps", unit:"Hz", div:1, raw:dataHps_WinKernel_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winUserSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_Windows_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winUserSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_Windows_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winUserSchannelRps", unit:"KHz", div:1000, raw:dataRps_Windows_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winUserSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_Schannel.filter(d => d.c == 1), lvformat:latestValueLatencyFormartter},
    { name:"winUserSchannelRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_Schannel.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"winUserSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Windows_x64_Schannel, lvformat:latestValueLatencyFormartter},
    { name:"winUserSchannelHps", unit:"Hz", div:1, raw:dataHps_Windows_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winSharedECSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_WinSharedEC_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winSharedECSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_WinSharedEC_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winSharedECSchannelRps", unit:"KHz", div:1000, raw:dataRps_WinSharedEC_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winSharedECSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_WinSharedEC_x64_Schannel.filter(d=>d.c==1), lvformat:latestValueLatencyFormartter},
    { name:"winSharedECSchannelRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_WinSharedEC_x64_Schannel.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"winSharedECSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_WinSharedEC_x64_Schannel, lvformat:latestValueLatencyFormartter},
    { name:"winSharedECSchannelHps", unit:"Hz", div:1, raw:dataHps_WinSharedEC_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winXDPSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_WinXDP_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winXDPSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_WinXDP_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winXDPSchannelRps", unit:"KHz", div:1000, raw:dataRps_WinXDP_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winXDPSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_WinXDP_x64_Schannel.filter(d=>d.c==1), lvformat:latestValueLatencyFormartter},
    { name:"winXDPSchannelRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_WinXDP_x64_Schannel.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"winXDPSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_WinXDP_x64_Schannel, lvformat:latestValueLatencyFormartter},
    { name:"winXDPSchannelHps", unit:"Hz", div:1, raw:dataHps_WinXDP_x64_Schannel, lvformat:latestValueFormartter},
    { name:"winUserOpenSslUp", unit:"Gbps", div:1000000, raw:dataUp_Windows_x64_Openssl, lvformat:latestValueFormartter},
    { name:"winUserOpenSslDown", unit:"Gbps", div:1000000, raw:dataDown_Windows_x64_Openssl, lvformat:latestValueFormartter},
    { name:"winUserOpenSslRps", unit:"KHz", div:1000, raw:dataRps_Windows_x64_Openssl, lvformat:latestValueFormartter},
    { name:"winUserOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_OpenSsl.filter(d => d.c == 1), lvformat:latestValueLatencyFormartter},
    { name:"winUserOpenSslRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_OpenSsl.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"winUserOpenSslRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Windows_x64_OpenSsl, lvformat:latestValueLatencyFormartter},
    { name:"winUserOpenSslHps", unit:"Hz", div:1, raw:dataHps_Windows_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxOpenSslUp", unit:"Gbps", div:1000000, raw:dataUp_Linux_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxOpenSslDown", unit:"Gbps", div:1000000, raw:dataDown_Linux_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxOpenSslRps", unit:"KHz", div:1000, raw:dataRps_Linux_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Linux_x64_OpenSsl.filter(d => d.c == 1), lvformat:latestValueLatencyFormartter},
    { name:"linuxOpenSslRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_Linux_x64_OpenSsl.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"linuxOpenSslRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Linux_x64_OpenSsl, lvformat:latestValueLatencyFormartter},
    { name:"linuxOpenSslHps", unit:"Hz", div:1, raw:dataHps_Linux_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxSharedECOpenSslUp", unit:"Gbps", div:1000000, raw:dataUp_LinuxSharedEC_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxSharedECOpenSslDown", unit:"Gbps", div:1000000, raw:dataDown_LinuxSharedEC_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxSharedECOpenSslRps", unit:"KHz", div:1000, raw:dataRps_LinuxSharedEC_x64_Openssl, lvformat:latestValueFormartter},
    { name:"linuxSharedECOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_LinuxSharedEC_x64_OpenSsl.filter(d => d.c == 1), lvformat:latestValueLatencyFormartter},
    { name:"linuxSharedECOpenSslRpsLatencyMultiConn", unit:"μs", div:1, raw:dataRpsLatency_LinuxSharedEC_x64_OpenSsl.filter(d=>d.c==40), lvformat:latestValueLatencyFormartter},
    { name:"linuxSharedECOpenSslRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_LinuxSharedEC_x64_OpenSsl, lvformat:latestValueLatencyFormartter},
    { name:"linuxSharedECOpenSslHps", unit:"Hz", div:1, raw:dataHps_LinuxSharedEC_x64_Openssl, lvformat:latestValueFormartter},
]

// Fixed charting values
var dataLineWidth = 2
var dataRawPointRadius = 3

function average(array) {
    return array.reduce((a, b) => a + b) / array.length
}

function median(array){
    if (array.length === 0) return 0;
    array.sort(function(a,b){ return a-b; });
    var half = Math.floor(array.length / 2);
    if (array.length % 2) return array[half];
    return (array[half - 1] + array[half]) / 2.0;
}

function max(array){
    if (array.length === 0) return 0;
    return array.sort(function(a,b){ return b-a; })[0];
}

function min(array){
    if (array.length === 0) return 0;
    return array.sort(function(a,b){ return a-b; })[0];
}

// Controls how we represent a single value for an array of data points
pointsToValue = median
pointsToValueName = "median"

// Helper functions for generating chart data sets
function generatePointDataset(dataset, maxIndex, commitCount) {
    // Filter the number of commits to use in the dataset
    dataset = dataset.filter(p => (maxIndex - 1 - p.c) < commitCount)

    // Generate output in the correct format
    var output = []
    dataset.forEach(
        p => p.d.forEach(
            r => output.push({x:p.c, y:r, m:p.m, b:p.b})))

    return output
}

function generateLineDataset(dataset, maxIndex, commitCount) {
    // Filter the number of commits to use in the dataset
    dataset = dataset.filter(p => (maxIndex - 1 - p.c) < commitCount)

    // Generate output in the correct format
    var output = []
    dataset.forEach(
        p => output.push({x:p.c, y:pointsToValue(p.d), m:p.m, b:p.b}))

    return output
}

rpsLatencyMax = 500

function processSearchParams() {
    var url = new URL(window.location.href);

    var param = url.searchParams.get("count")
    if (param) {
        commitCount = param
        if (maxIndex < commitCount) {
            commitCount = maxIndex
        }
    }

    var param = url.searchParams.get("width")
    if (param) {
        dataLineWidth = param
    }

    var param = url.searchParams.get("radius")
    if (param) {
        dataRawPointRadius = param
    }

    var param = url.searchParams.get("mode")
    if (param == "max") {
        pointsToValue = max
        pointsToValueName = "max"
    } else if (param == "min") {
        pointsToValue = min
        pointsToValueName = "average"
    } else if (param == "average") {
        pointsToValue = average
        pointsToValueName = "average"
    }

    var param = url.searchParams.get("latmax")
    if (param) {
        rpsLatencyMax = Number(param)
    }
}
