
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
    { name:"winUserOpenSsl", friendly:"Windows User OpenSSL", color:"#ff3c00" },
    { name:"linuxOpenSsl", friendly:"Linux OpenSSL", color:"#17a2b8" }
]

// The set of data and available properties
var dataView = [
    { name:"winKernelSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_WinKernel_x64_Schannel },
    { name:"winKernelSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_WinKernel_x64_Schannel },
    { name:"winKernelSchannelRps", unit:"KHz", div:1000, raw:dataRps_WinKernel_x64_Schannel },
    { name:"winKernelSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_WinKernel_x64_Schannel },
    { name:"winKernelSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_WinKernel_x64_Schannel },
    { name:"winKernelSchannelHps", unit:"Hz", div:1, raw:dataHps_WinKernel_x64_Schannel },
    { name:"winUserSchannelUp", unit:"Gbps", div:1000000, raw:dataUp_Windows_x64_Schannel },
    { name:"winUserSchannelDown", unit:"Gbps", div:1000000, raw:dataDown_Windows_x64_Schannel },
    { name:"winUserSchannelRps", unit:"KHz", div:1000, raw:dataRps_Windows_x64_Schannel },
    { name:"winUserSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_Schannel },
    { name:"winUserSchannelRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Windows_x64_Schannel },
    { name:"winUserSchannelHps", unit:"Hz", div:1, raw:dataHps_Windows_x64_Schannel },
    { name:"winUserOpenSslUp", unit:"Gbps", div:1000000, raw:dataUp_Windows_x64_Openssl },
    { name:"winUserOpenSslDown", unit:"Gbps", div:1000000, raw:dataDown_Windows_x64_Openssl },
    { name:"winUserOpenSslRps", unit:"KHz", div:1000, raw:dataRps_Windows_x64_Openssl },
    { name:"winUserOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Windows_x64_OpenSsl },
    { name:"winUserOpenSslRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Windows_x64_OpenSsl },
    { name:"winUserOpenSslHps", unit:"Hz", div:1, raw:dataHps_Windows_x64_Openssl },
    { name:"linuxOpenSslUp", unit:"Gbps", div:1000000, raw:dataUp_Linux_x64_Openssl },
    { name:"linuxOpenSslDown", unit:"Gbps", div:1000000, raw:dataDown_Linux_x64_Openssl },
    { name:"linuxOpenSslRps", unit:"KHz", div:1000, raw:dataRps_Linux_x64_Openssl },
    { name:"linuxOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatency_Linux_x64_OpenSsl },
    { name:"linuxOpenSslRpsLatencyLatest", unit:"μs", div:1, raw:dataRpsLatencyLatest_Linux_x64_OpenSsl },
    { name:"linuxOpenSslHps", unit:"Hz", div:1, raw:dataHps_Linux_x64_Openssl },
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
