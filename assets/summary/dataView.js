
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
    { name:"winUserOpenSsl", friendly:"Windows User OpenSSL", color:"#ff3c00" }
]

// The set of data and available properties
var dataView = [
    { name:"winKernelSchannelUp", unit:"Gbps", div:1000000, raw:dataRawWinKernelx64SchannelThroughput, avg:dataAverageWinKernelx64SchannelThroughput},
    { name:"winKernelSchannelDown", unit:"Gbps", div:1000000, raw:dataRawWinKernelx64SchannelThroughputDown, avg:dataAverageWinKernelx64SchannelThroughputDown},
    { name:"winKernelSchannelRps", unit:"KHz", div:1000, raw:dataRawWinKernelx64SchannelRps, avg:dataAverageWinKernelx64SchannelRps},
    { name:"winKernelSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatencyWinKernel, avg:null},
    { name:"winKernelSchannelHps", unit:"Hz", div:1, raw:dataRawWinKernelx64SchannelHps, avg:dataAverageWinKernelx64SchannelHps},
    { name:"winUserSchannelUp", unit:"Gbps", div:1000000, raw:dataRawWindowsx64SchannelThroughput, avg:dataAverageWindowsx64SchannelThroughput},
    { name:"winUserSchannelDown", unit:"Gbps", div:1000000, raw:dataRawWindowsx64SchannelThroughputDown, avg:dataAverageWindowsx64SchannelThroughputDown},
    { name:"winUserSchannelRps", unit:"KHz", div:1000, raw:dataRawWindowsx64SchannelRps, avg:dataAverageWindowsx64SchannelRps},
    { name:"winUserSchannelRpsLatency", unit:"μs", div:1, raw:dataRpsLatencyWindowsSchannel, avg:null},
    { name:"winUserSchannelHps", unit:"Hz", div:1, raw:dataRawWindowsx64SchannelHps, avg:dataAverageWindowsx64SchannelHps},
    { name:"winUserOpenSslUp", unit:"Gbps", div:1000000, raw:dataRawWindowsx64OpensslThroughput, avg:dataAverageWindowsx64OpensslThroughput},
    { name:"winUserOpenSslDown", unit:"Gbps", div:1000000, raw:dataRawWindowsx64OpensslThroughputDown, avg:dataAverageWindowsx64OpensslThroughputDown},
    { name:"winUserOpenSslRps", unit:"KHz", div:1000, raw:dataRawWindowsx64OpensslRps, avg:dataAverageWindowsx64OpensslRps},
    { name:"winUserOpenSslRpsLatency", unit:"μs", div:1, raw:dataRpsLatencyWindowsOpenSsl, avg:null},
    { name:"winUserOpenSslHps", unit:"KHz", div:1000, raw:dataRawWindowsx64OpensslHps, avg:dataAverageWindowsx64OpensslHps},
]

// Fixed charting values
var dataLineWidth = 2
var dataRawPointRadius = 3

// Percentile scale dictionary
var percentileScaleDict = {
    1: '0%',
    10: '90%',
    100: '99%',
    1000: '99.9%',
    10000: '99.99%',
    100000: '99.999%',
    1000000: '99.9999%',
    10000000: '99.99999%',
    100000000: '99.999999%'
}
