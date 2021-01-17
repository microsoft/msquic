// Different data point colors
var dataColorWinKernelx64Schannel = "#11a718"
var dataColorWindowsx64Schannel = "#0062ff"
var dataColorWindowsx64Openssl = "#ff3c00"

// Useful configuration values
var dataLineWidth = 2
var dataRawPointRadius = 4

// Global option configuration
Chart.defaults.global.responsive = true
Chart.defaults.global.tooltips.position = 'nearest'
Chart.defaults.global.tooltips.itemSort = tooltipSort
Chart.defaults.global.legend.display = false
Chart.defaults.scale.display = true

// Chart variables used in onClick handler
var tputChart = null;
var tputDownChart = null;
var rpsChart = null;
var hpsChart = null;
var rpsLatencyChart = null;

function tooltipSort(a, b, data) {
    return data.datasets[a.datasetIndex].sortOrder - data.datasets[b.datasetIndex].sortOrder;
}

function titlePlacement(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem[0].datasetIndex]
    var datapoint = dataset.data[tooltipItem[0].index]
    // TODO Fix this, this is very hacky
    return Chart._adapters._date.prototype.format(datapoint.t, Chart._adapters._date.prototype.formats().datetime)
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

function chartOnCick(a, activeElements) {
    if (activeElements.length === 0) return
    var dataset = this.config.data.datasets[activeElements[0]._datasetIndex]
    var rawTime = dataset.data[activeElements[0]._index].rawTime
    var commitHash = commitDatePairs[rawTime]
    window.open("./percommit/main/" + commitHash + "/index.html", "_self")
}

function filterDataset(dataset, afterDate) {
    return dataset.filter(p => p.t > afterDate);
}

var tooltipsObject = {
    callbacks : {
        title: titlePlacement,
        beforeBody: beforeBodyPlacement,
        label: labelChange
    },
    mode: "x",
    intersect: true
}

var tooltipsSummaryObject = {
    callbacks : {
        title: titlePlacement,
        beforeBody: beforeBodyPlacement
    },
    mode: "nearest",
    intersect: false
}

var timeAxis = {
    type: 'linear',
    offset: true,
    ticks: {
        maxTicksLimit: maxIndex + 10,
        stepSize: 1,
        callback: function(value) {
            if (value % 1 !== 0) {
                return "";
            } else {
                return maxIndex - 1 - value;
            }
        }
    },
    scaleLabel: createScaleLabel('Commits Back From Current')
};

var pluginObject = {
    zoom: {
        pan: {
            enabled: true,
            mode: 'x',
            rangeMin: { x: 0 },
            rangeMax: { x: maxIndex - 1 }
        },
        zoom: {
            enabled: true,
            mode: 'x',
            rangeMin: { x: 0 },
            rangeMax: { x: maxIndex - 1 }
        }
    }
}

function createScaleLabel(name) {
    return {
        display: true,
        labelString: name,
        fontSize: 14,
        fontStyle: 'bold'
    };
}

function createSummaryChartOptions(title, yName) {
    return {
        title: {
            display: true,
            text: title,
            fontSize: 16
        },
        tooltips: tooltipsSummaryObject,
        scales: {
            xAxes: [timeAxis],
            yAxes: [{
                scaleLabel: createScaleLabel(yName),
                ticks: { min: 0 }
            }]
        },
        maintainAspectRatio: false
    };
}

var scaleDict = {
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

function createLatencyChartOptions(name) {
    return {
        scales: {
            xAxes: [{
                display: true,
                type: 'logarithmic',
                afterBuildTicks: function(scale) {
                    scale.ticks = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000]
                },
                ticks: {
                    callback: function(value) {
                        return scaleDict[value]
                    }
                },
                scaleLabel: createScaleLabel('Percentile')
            }],
            yAxes: [{
                display: true,

                scaleLabel: createScaleLabel(name),
            }]
        }
    }
}

function createChartOptions(name) {
    return {
        tooltips: tooltipsObject,
        onClick: chartOnCick,
        scales: {
            xAxes: [timeAxis],
            yAxes: [{
                scaleLabel: createScaleLabel(name)
            }]
        },
        plugins: pluginObject
    };
}

function createRawDataset(platform, color, dataset) {
    return {
        type: "scatter",
        label: platform + " (raw)",
        backgroundColor: color,
        pointBorderColor: color,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: dataset,
        sortOrder: 2,
        hidden: true,
        hiddenType: true,
        hiddenPlatform: false,
        isRaw: true,
        platform: platform
    };
}

function createAverageDataset(platform, color, dataset) {
    return {
        type: "line",
        label: platform + " (average)",
        backgroundColor: color,
        borderColor: color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: dataset,
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform
    };
}

function createAverageSummaryDataset(platform, color, dataset) {
    return {
        type: "line",
        label: platform + " (average)",
        backgroundColor: color,
        borderColor: color,
        borderWidth: dataLineWidth,
        pointRadius: 0,
        tension: 0,
        data: filterDataset(dataset, new Date(Date.now() - 12096e5)), // Last 2 weeks
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform
    };
}

function createLatencyDataset(platform, color, dataset) {
    return {
        type: "line",
        label: platform,
        backgroundColor: color,
        borderColor: color,
        borderWidth: dataLineWidth,
        pointRadius: 0,
        tension: 0,
        fill: false,
        data: dataset,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform
    }
}

function createLatencyDatasets(winOpenssl, winSchannel, winKernel) {
    return {
        datasets: [
            createLatencyDataset("Windows Kernel", dataColorWinKernelx64Schannel, winKernel),
            createLatencyDataset("Windows User Schannel", dataColorWindowsx64Schannel, winSchannel),
            createLatencyDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, winOpenssl)
        ]
    }
}

function createDatasets(rawKernel, avgKernel, rawUserSchannel, avgUserSchannel, rawUserOpenssl, avgUserOpenssl) {
    return {
        datasets: [
            createRawDataset("Windows Kernel", dataColorWinKernelx64Schannel, rawKernel),
            createAverageDataset("Windows Kernel", dataColorWinKernelx64Schannel, avgKernel),
            createRawDataset("Windows User Schannel", dataColorWindowsx64Schannel, rawUserSchannel),
            createAverageDataset("Windows User Schannel", dataColorWindowsx64Schannel, avgUserSchannel),
            createRawDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, rawUserOpenssl),
            createAverageDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, avgUserOpenssl)
        ]
    };
}

function createSummaryDatasets(avgKernel, avgUserSchannel, avgUserOpenssl) {
    return {
        datasets: [
            createAverageSummaryDataset("Windows Kernel", dataColorWinKernelx64Schannel, avgKernel),
            createAverageSummaryDataset("Windows User Schannel", dataColorWindowsx64Schannel, avgUserSchannel),
            createAverageSummaryDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, avgUserOpenssl)
        ]
    };
}

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
    updateChartDisplayPoints(tputDownChart, value)
    updateChartDisplayPoints(rpsChart, value)
    updateChartDisplayPoints(hpsChart, value)
    updateChartDisplayPoints(rpsLatencyChart, value)
}

function onPlatformChange(event) {
    var platform = event.srcElement.id
    var checked = event.srcElement.checked
    updateChartPlatforms(tputChart, platform, checked)
    updateChartPlatforms(tputDownChart, platform, checked)
    updateChartPlatforms(rpsChart, platform, checked)
    updateChartPlatforms(hpsChart, platform, checked)
    updateChartPlatforms(rpsLatencyChart, platform, checked)
}

window.onload = function() {
    // Summary charts
    new Chart(document.getElementById('canvasThroughputSummary').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataAverageWindowsx64OpensslThroughput),
        options: createSummaryChartOptions('Single Connection Throughput', 'Throughput (kbps)')
    });
    new Chart(document.getElementById('canvasRPSSummary').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelRps, dataAverageWindowsx64SchannelRps, dataAverageWindowsx64OpensslRps),
        options: createSummaryChartOptions('Requests per Second', 'RPS')
    });
    new Chart(document.getElementById('canvasHPSSummary').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelHps, dataAverageWindowsx64SchannelHps, dataAverageWindowsx64OpensslHps),
        options: createSummaryChartOptions('Handshakes per Second', 'HPS')
    });

    // Detailed charts
    tputChart = new Chart(document.getElementById('canvasThroughput').getContext('2d'), {
        data: createDatasets(dataRawWinKernelx64SchannelThroughput, dataAverageWinKernelx64SchannelThroughput, dataRawWindowsx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataRawWindowsx64OpensslThroughput, dataAverageWindowsx64OpensslThroughput),
        options: createChartOptions('Throughput (kbps)')
    });
    tputDownChart = new Chart(document.getElementById('canvasThroughputDown').getContext('2d'), {
        data: createDatasets(dataRawWinKernelx64SchannelThroughputDown, dataAverageWinKernelx64SchannelThroughputDown, dataRawWindowsx64SchannelThroughputDown, dataAverageWindowsx64SchannelThroughputDown, dataRawWindowsx64OpensslThroughputDown, dataAverageWindowsx64OpensslThroughputDown),
        options: createChartOptions('Throughput (kbps)')
    });
    rpsChart = new Chart(document.getElementById('canvasRPS').getContext('2d'), {
        data: createDatasets(dataRawWinKernelx64SchannelRps, dataAverageWinKernelx64SchannelRps, dataRawWindowsx64SchannelRps, dataAverageWindowsx64SchannelRps, dataRawWindowsx64OpensslRps, dataAverageWindowsx64OpensslRps),
        options: createChartOptions('RPS')
    });
    hpsChart = new Chart(document.getElementById('canvasHPS').getContext('2d'), {
        data: createDatasets(dataRawWinKernelx64SchannelHps, dataAverageWinKernelx64SchannelHps, dataRawWindowsx64SchannelHps, dataAverageWindowsx64SchannelHps, dataRawWindowsx64OpensslHps, dataAverageWindowsx64OpensslHps),
        options: createChartOptions('HPS')
    });

    rpsLatencyChart = new Chart(document.getElementById('canvasRPSLatency').getContext('2d'), {
        data: createLatencyDatasets(dataRpsLatencyWindowsOpenSsl, dataRpsLatencyWindowsSchannel, dataRpsLatencyWinKernel),
        options: createLatencyChartOptions('RPS Latency (μs)')
    });

    document.getElementById('rawpdt').onclick = onRadioChange
    document.getElementById('avgpdt').onclick = onRadioChange
    document.getElementById('bothpdt').onclick = onRadioChange

    document.getElementById('Windows Kernel').onclick = onPlatformChange
    document.getElementById('Windows User Schannel').onclick = onPlatformChange
    document.getElementById('Windows User OpenSSL').onclick = onPlatformChange
};
