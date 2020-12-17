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

var chartOptionsThroughput = {
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

var chartOptionsRPS = {
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

var chartOptionsHPS = {
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

function createDatasets(rawKernel, avgKernel, rawUserSchannel, avgUserSchannel, rawUserOpenssl, avgUserOpenssl) {
    return {
        datasets: [{
            type: "scatter",
            label: "Windows Kernel (raw)",
            backgroundColor: dataColorWinKernelx64Schannel,
            pointBorderColor: dataColorWinKernelx64Schannel,
            pointStyle: "crossRot",
            pointRadius: dataRawPointRadius,
            pointBorderWidth: 2,
            data: rawKernel,
            sortOrder: 2,
            hidden: true,
            hiddenType: true,
            hiddenPlatform: false,
            isRaw: true,
            platform: 'kernel'
        }, {
            type: "line",
            label: "Windows Kernel (average)",
            backgroundColor: dataColorWinKernelx64Schannel,
            borderColor: dataColorWinKernelx64Schannel,
            borderWidth: dataLineWidth,
            pointRadius: dataRawPointRadius,
            tension: 0,
            data: avgKernel,
            fill: false,
            sortOrder: 1,
            hidden: false,
            hiddenType: false,
            hiddenPlatform: false,
            isRaw: false,
            platform: 'kernel'
        }, {
            type: "scatter",
            label: "Windows User - Schannel (raw)",
            backgroundColor: dataColorWindownsx64Schannel,
            pointBorderColor: dataColorWindownsx64Schannel,
            borderColor: dataColorWindownsx64Schannel,
            pointStyle: "crossRot",
            pointRadius: dataRawPointRadius,
            pointBorderWidth: 2,
            data: rawUserSchannel,
            sortOrder: 11,
            hidden: true,
            hiddenType: true,
            hiddenPlatform: false,
            isRaw: true,
            platform: 'winschannel'
        }, {
            type: "line",
            label: "Windows User - Schannel (average)",
            backgroundColor: dataColorWindownsx64Schannel,
            borderColor: dataColorWindownsx64Schannel,
            borderWidth: dataLineWidth,
            pointRadius: dataRawPointRadius,
            tension: 0,
            data: avgUserSchannel,
            fill: false,
            sortOrder: 10,
            hidden: false,
            hiddenType: false,
            hiddenPlatform: false,
            isRaw: false,
            platform: 'winschannel'
        }, {
            type: "scatter",
            label: "Windows User - OpenSSL (raw)",
            backgroundColor: dataColorWindowsx64Openssl,
            pointBorderColor: dataColorWindowsx64Openssl,
            borderColor: dataColorWindowsx64Openssl,
            pointStyle: "crossRot",
            pointRadius: dataRawPointRadius,
            pointBorderWidth: 2,
            data: rawUserOpenssl,
            sortOrder: 21,
            hidden: true,
            hiddenType: true,
            hiddenPlatform: false,
            isRaw: true,
            platform: 'winopenssl'
        }, {
            type: "line",
            label: "Windows User - OpenSSL (average)",
            backgroundColor: dataColorWindowsx64Openssl,
            borderColor: dataColorWindowsx64Openssl,
            borderWidth: dataLineWidth,
            pointRadius: dataRawPointRadius,
            tension: 0,
            data: avgUserOpenssl,
            fill: false,
            sortOrder: 20,
            hidden: false,
            hiddenType: false,
            hiddenPlatform: false,
            isRaw: false,
            platform: 'winopenssl'
        }]
    };
}

var chartDataThroughput = null;
var chartDataRPS = null;
var chartDataHPS = null;

var tputChart = null;
var rpsChart = null;
var hpsChart = null;

function updateDataset(dataset) {
    dataset.hidden = dataset.hiddenType | dataset.hiddenPlatform
}

function updateChartDisplayPoints(chart, value) {
    var setRaw = true
    var setAvg = true
    if (value === 'both') {
        setRaw = false
        setAvg = false
    } else if (value === 'raw') {
        setRaw = false
    } else if (value === 'avg') {
        setAvg = false
    }
    for (const val of chart.data.datasets) {
        if (val.isRaw) {
            val.hiddenType = setRaw
        } else {
            val.hiddenType = setAvg
        }
        updateDataset(val)
    }
    chart.update()
}

function updateChartPlatforms(chart, platform, checked) {
    for (const val of chart.data.datasets) {
        if (val.platform === platform) {
            val.hiddenPlatform = !checked
        }
        updateDataset(val)
    }
    chart.update()
}

function onRadioChange(event) {
    var value = event.srcElement.value;
    updateChartDisplayPoints(tputChart, value)
    updateChartDisplayPoints(rpsChart, value)
    updateChartDisplayPoints(hpsChart, value)
}

function onPlatformChange(event) {
    var platform = event.srcElement.id
    var checked = event.srcElement.checked
    updateChartPlatforms(tputChart, platform, checked)
    updateChartPlatforms(rpsChart, platform, checked)
    updateChartPlatforms(hpsChart, platform, checked)
}

window.onload = function() {
    chartDataThroughput = createDatasets(dataRawWinKernelx64SchannelThroughput, dataAverageWinKernelx64SchannelThroughput, dataRawWindowsx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataRawWindowsx64OpensslThroughput, dataAverageWindowsx64OpensslThroughput)
    chartDataRPS = createDatasets(dataRawWinKernelx64SchannelRps, dataAverageWinKernelx64SchannelRps, dataRawWindowsx64SchannelRps, dataAverageWindowsx64SchannelRps, dataRawWindowsx64OpensslRps, dataAverageWindowsx64OpensslRps)
    chartDataHPS = createDatasets(dataRawWinKernelx64SchannelHps, dataAverageWinKernelx64SchannelHps, dataRawWindowsx64SchannelHps, dataAverageWindowsx64SchannelHps, dataRawWindowsx64OpensslHps, dataAverageWindowsx64OpensslHps)

    tputChart = new Chart(document.getElementById('canvasThroughput').getContext('2d'), {
        data: chartDataThroughput,
        options: chartOptionsThroughput
    });
    rpsChart = new Chart(document.getElementById('canvasRPS').getContext('2d'), {
        data: chartDataRPS,
        options: chartOptionsRPS
    });
    hpsChart = new Chart(document.getElementById('canvasHPS').getContext('2d'), {
        data: chartDataHPS,
        options: chartOptionsHPS
    });

    document.getElementById('rawpdt').onclick = onRadioChange
    document.getElementById('avgpdt').onclick = onRadioChange
    document.getElementById('bothpdt').onclick = onRadioChange

    document.getElementById('kernel').onclick = onPlatformChange
    document.getElementById('winschannel').onclick = onPlatformChange
    document.getElementById('winopenssl').onclick = onPlatformChange
};
