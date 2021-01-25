// Different data point colors
var dataColorWinKernelx64Schannel = "#11a718"
var dataColorWindowsx64Schannel = "#0062ff"
var dataColorWindowsx64Openssl = "#ff3c00"

// Useful configuration values
var dataLineWidth = 2
var dataRawPointRadius = 3

// Default number of commits to slice for each chart type.
var chartCommits = 31
if (maxIndex < chartCommits) {
    chartCommits = maxIndex
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

function filterDataset(dataset, commitCount) {
    return dataset.filter(p => (maxIndex - 1 - p.x) < commitCount);
}

function labelChange(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem.datasetIndex]
    if (dataset.label.includes('(average)')) {
        var datapoint = dataset.data[tooltipItem.index]
        var shortMachine = datapoint.machine.substring(datapoint.machine.length - 2)
        return "Average (M" + shortMachine + "):" + tooltipItem.value
    } else {
        return "Raw:       " + tooltipItem.value
    }
}

function chartOnClick(a, activeElements) {
    if (activeElements.length === 0) return
    var dataset = this.config.data.datasets[activeElements[0]._datasetIndex]
    var rawTime = dataset.data[activeElements[0]._index].rawTime
    var commitHash = commitDatePairs[rawTime]
    window.open("./percommit/main/" + commitHash + "/index.html", "_blank")
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
        data: filterDataset(dataset, chartCommits),
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
        data: filterDataset(dataset, chartCommits),
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform
    };
}

function createCommitDatasets(rawKernel, avgKernel, rawUserSchannel, avgUserSchannel, rawUserOpenssl, avgUserOpenssl) {
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

var commitChartOptions = {
    maintainAspectRatio: false,
    scales: {
        xAxes: [{
            type: 'linear',
            offset: true,
            gridLines: {
              display: false,
              drawBorder: false
            },
            ticks: {
                maxTicksLimit: chartCommits + 10,
                stepSize: 1,
                callback: function(value) {
                    if (value % 1 !== 0) {
                        return "";
                    } else {
                        return maxIndex - 1 - value;
                    }
                }
            }
        }],
        yAxes: [{
            ticks: {
                padding: 10
            },
            gridLines: {
                color: "rgb(234, 236, 244)",
                zeroLineColor: "rgb(234, 236, 244)",
                drawBorder: false,
                borderDash: [2],
                zeroLineBorderDash: [2]
            }
        }]
    },
    legend: {
      display: false
    },
    onClick: chartOnClick,
    tooltips: {
        backgroundColor: "rgb(255,255,255)",
        bodyFontColor: "#858796",
        titleMarginBottom: 10,
        titleFontColor: '#6e707e',
        titleFontSize: 14,
        borderColor: '#dddfeb',
        borderWidth: 1,
        xPadding: 15,
        yPadding: 15,
        mode: "x",
        intersect: false,
        callbacks : {
            title: titlePlacement,
            beforeBody: beforeBodyPlacement,
            label: labelChange
        }
    }
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

var percentileChartOptions = {
    maintainAspectRatio: false,
    scales: {
        xAxes: [{
            type: 'logarithmic',
            afterBuildTicks: function(scale) {
                scale.ticks = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000]
            },
            gridLines: {
              display: false,
              drawBorder: false
            },
            ticks: {
                callback: function(value) {
                    return scaleDict[value]
                }
            }
        }],
        yAxes: [{
            display: true,
            ticks: {
                padding: 10
            },
            gridLines: {
                color: "rgb(234, 236, 244)",
                zeroLineColor: "rgb(234, 236, 244)",
                drawBorder: false,
                borderDash: [2],
                zeroLineBorderDash: [2]
            }
        }]
    },
    legend: {
      display: false
    },
    tooltips: {
        backgroundColor: "rgb(255,255,255)",
        bodyFontColor: "#858796",
        titleMarginBottom: 10,
        titleFontColor: '#6e707e',
        titleFontSize: 14,
        borderColor: '#dddfeb',
        borderWidth: 1,
        xPadding: 15,
        yPadding: 15,
        mode: "nearest",
        intersect: false
    }
}

window.onload = function() {
    // Latest values
    setLatestData()

    // Summary charts
    new Chart(document.getElementById('canvasUp').getContext('2d'), {
        data: createCommitDatasets(dataRawWinKernelx64SchannelThroughput, dataAverageWinKernelx64SchannelThroughput, dataRawWindowsx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataRawWindowsx64OpensslThroughput, dataAverageWindowsx64OpensslThroughput),
        options: commitChartOptions
    });
    new Chart(document.getElementById('canvasDown').getContext('2d'), {
        data: createCommitDatasets(dataRawWinKernelx64SchannelThroughputDown, dataAverageWinKernelx64SchannelThroughputDown, dataRawWindowsx64SchannelThroughputDown, dataAverageWindowsx64SchannelThroughputDown, dataRawWindowsx64OpensslThroughputDown, dataAverageWindowsx64OpensslThroughputDown),
        options: commitChartOptions
    });
    new Chart(document.getElementById('canvasRps').getContext('2d'), {
        data: createCommitDatasets(dataRawWinKernelx64SchannelRps, dataAverageWinKernelx64SchannelRps, dataRawWindowsx64SchannelRps, dataAverageWindowsx64SchannelRps, dataRawWindowsx64OpensslRps, dataAverageWindowsx64OpensslRps),
        options: commitChartOptions
    });
    rpsLatencyChart = new Chart(document.getElementById('canvasRpsLatency').getContext('2d'), {
        data: createLatencyDatasets(dataRpsLatencyWindowsOpenSsl, dataRpsLatencyWindowsSchannel, dataRpsLatencyWinKernel),
        options: percentileChartOptions
    });
    new Chart(document.getElementById('canvasHps').getContext('2d'), {
        data: createCommitDatasets(dataRawWinKernelx64SchannelHps, dataAverageWinKernelx64SchannelHps, dataRawWindowsx64SchannelHps, dataAverageWindowsx64SchannelHps, dataRawWindowsx64OpensslHps, dataAverageWindowsx64OpensslHps),
        options: commitChartOptions
    });
};
