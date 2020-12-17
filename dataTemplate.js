// Different data point colors
var dataColorWinKernelx64Schannel = "rgb(0, 255, 0)"
var dataColorWindownsx64Schannel = "rgb(0, 0, 255)"
var dataColorWindowsx64Openssl = "rgb(255, 0, 0)"

// Useful configuration values
var dataLineWidth = 2
var dataRawPointRadius = 4

function tooltipSort(a, b, data) {
    return data.datasets[a.datasetIndex].sortOrder - data.datasets[b.datasetIndex].sortOrder;
}

function beforeBodyPlacement(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem[0].datasetIndex]
    var datapoint = dataset.data[tooltipItem[0].index]
    return "Commit Hash: " + commitDatePairs[datapoint.rawTime]
}

function labelChange(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem.datasetIndex]
    if (dataset.label.includes('(average)')) {
        return "Average: " + tooltipItem.value
    } else {
        return "Raw:       " + tooltipItem.value
    }
}

// Global option configuration
Chart.defaults.global.responsive = true
Chart.defaults.global.title.display = true
Chart.defaults.global.title.fontSize = 16
Chart.defaults.global.tooltips.mode = 'x'
Chart.defaults.global.tooltips.intersect = true
Chart.defaults.global.tooltips.position = 'nearest'
Chart.defaults.global.tooltips.itemSort = tooltipSort

var tooltipsObject = {
    callbacks : {
        beforeBody: beforeBodyPlacement,
        label: labelChange
    }
}

var pluginObject = {
    zoom: {
        pan: {
            enabled: true,
            mode: 'x',
            rangeMin: {
                x: oldestDate
            },
            rangeMax: {
                x: newestDate
            }
        },
        zoom: {
            enabled: true,
            mode: 'x',
            rangeMin: {
                x: oldestDate
            },
            rangeMax: {
                x: newestDate
            }
        }
    }
}

// Time axis used for all charts
var timeAxis = {
    type: 'time',
    offset: true,
    time: {
        unit: 'day'
    },
    display: true,
    scaleLabel: {
        display: true,
        labelString: 'Commit Date',
        fontSize: 14,
        fontStyle: 'bold'
    }
};

var chartDataThroughput = {
    datasets: [{
        type: "scatter",
        label: "Windows Kernel (raw)",
        backgroundColor: dataColorWinKernelx64Schannel,
        pointBorderColor: dataColorWinKernelx64Schannel,
        borderColor: dataColorWinKernelx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWinKernelx64SchannelThroughput,
        sortOrder: 2,
        hidden: true,
    }, {
        type: "line",
        label: "Windows Kernel (average)",
        backgroundColor: dataColorWinKernelx64Schannel,
        borderColor: dataColorWinKernelx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWinKernelx64SchannelThroughput,
        fill: false,
        sortOrder: 1
    }, {
        type: "scatter",
        label: "Windows User - Schannel (raw)",
        backgroundColor: dataColorWindownsx64Schannel,
        pointBorderColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64SchannelThroughput,
        sortOrder: 11,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - Schannel (average)",
        backgroundColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64SchannelThroughput,
        fill: false,
        sortOrder: 10
    }, {
        type: "scatter",
        label: "Windows User - OpenSSL (raw)",
        backgroundColor: dataColorWindowsx64Openssl,
        pointBorderColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64OpensslThroughput,
        sortOrder: 21,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - OpenSSL (average)",
        backgroundColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64OpensslThroughput,
        fill: false,
        sortOrder: 20
    }]
};

var chartOptionsThroughput = {
    title: {
        text: 'Single Connection Throughput',
    },
    tooltips: tooltipsObject,
    scales: {
        xAxes: [timeAxis],
        yAxes: [{
            display: true,
            scaleLabel: {
                display: true,
                labelString: 'Throughput (kbps)'
            }
        }]
    },
    plugins: pluginObject
};

var chartDataRPS = {
    datasets: [{
        type: "scatter",
        label: "Windows Kernel (raw)",
        backgroundColor: dataColorWinKernelx64Schannel,
        pointBorderColor: dataColorWinKernelx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWinKernelx64SchannelRps,
        sortOrder: 2,
        hidden: true,
    }, {
        type: "line",
        label: "Windows Kernel (average)",
        backgroundColor: dataColorWinKernelx64Schannel,
        borderColor: dataColorWinKernelx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWinKernelx64SchannelRps,
        fill: false,
        sortOrder: 1
    }, {
        type: "scatter",
        label: "Windows User - Schannel (raw)",
        backgroundColor: dataColorWindownsx64Schannel,
        pointBorderColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64SchannelRps,
        sortOrder: 11,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - Schannel (average)",
        backgroundColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64SchannelRps,
        fill: false,
        sortOrder: 10
    }, {
        type: "scatter",
        label: "Windows User - OpenSSL (raw)",
        backgroundColor: dataColorWindowsx64Openssl,
        pointBorderColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64OpensslRps,
        sortOrder: 21,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - OpenSSL (average)",
        backgroundColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64OpensslRps,
        fill: false,
        sortOrder: 20
    }]
};

var chartOptionsRPS = {
    title: {
        text: 'Requests per Second',
    },
    tooltips: tooltipsObject,
    scales: {
        xAxes: [timeAxis],
        yAxes: [{
            display: true,
            scaleLabel: {
                display: true,
                labelString: 'RPS',
                fontSize: 14,
                fontStyle: 'bold'
            }
        }]
    },
    plugins: pluginObject
};

var chartDataHPS = {
    datasets: [{
        type: "scatter",
        label: "Windows Kernel (raw)",
        backgroundColor: dataColorWinKernelx64Schannel,
        pointBorderColor: dataColorWinKernelx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWinKernelx64SchannelHps,
        sortOrder: 2,
        hidden: true,
    }, {
        type: "line",
        label: "Windows Kernel (average)",
        backgroundColor: dataColorWinKernelx64Schannel,
        borderColor: dataColorWinKernelx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWinKernelx64SchannelHps,
        fill: false,
        sortOrder: 1
    }, {
        type: "scatter",
        label: "Windows User - Schannel (raw)",
        backgroundColor: dataColorWindownsx64Schannel,
        pointBorderColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64SchannelHps,
        sortOrder: 11,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - Schannel (average)",
        backgroundColor: dataColorWindownsx64Schannel,
        borderColor: dataColorWindownsx64Schannel,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64SchannelHps,
        fill: false,
        sortOrder: 10
    }, {
        type: "scatter",
        label: "Windows User - OpenSSL (raw)",
        backgroundColor: dataColorWindowsx64Openssl,
        pointBorderColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataRawWindowsx64OpensslHps,
        sortOrder: 21,
        hidden: true,
    }, {
        type: "line",
        label: "Windows User - OpenSSL (average)",
        backgroundColor: dataColorWindowsx64Openssl,
        borderColor: dataColorWindowsx64Openssl,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataAverageWindowsx64OpensslHps,
        fill: false,
        sortOrder: 20
    }]
};

var chartOptionsHPS = {
    title: {
        text: 'Handshakes per Second',
    },
    tooltips: tooltipsObject,
    scales: {
        xAxes: [timeAxis],
        yAxes: [{
            display: true,
            scaleLabel: {
                display: true,
                labelString: 'HPS',
                fontSize: 14,
                fontStyle: 'bold'
            }
        }]
    },
    plugins: pluginObject
};