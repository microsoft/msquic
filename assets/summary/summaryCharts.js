// Different data point colors
var dataColorWinKernelx64Schannel = "#11a718"
var dataColorWindowsx64Schannel = "#0062ff"
var dataColorWindowsx64Openssl = "#ff3c00"

// Useful configuration values
var dataLineWidth = 2
var dataRawPointRadius = 3

// Default number of commits to slice for each chart type.
var summaryChartCommits = 11
if (maxIndex < summaryChartCommits) {
    summaryChartCommits = maxIndex
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

function chartOnClick(a, activeElements) {
    if (activeElements.length === 0) return
    var dataset = this.config.data.datasets[activeElements[0]._datasetIndex]
    var rawTime = dataset.data[activeElements[0]._index].rawTime
    var commitHash = commitDatePairs[rawTime]
    window.open("./percommit/main/" + commitHash + "/index.html", "_blank")
}

function createAverageSummaryDataset(platform, color, dataset) {
    return {
        type: "line",
        label: platform + " (average)",
        backgroundColor: color,
        borderColor: color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: filterDataset(dataset, summaryChartCommits),
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform
    };
}

function createCommitDatasets(avgKernel, avgUserSchannel, avgUserOpenssl) {
    return {
        datasets: [
            createAverageSummaryDataset("Windows Kernel", dataColorWinKernelx64Schannel, avgKernel),
            createAverageSummaryDataset("Windows User Schannel", dataColorWindowsx64Schannel, avgUserSchannel),
            createAverageSummaryDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, avgUserOpenssl)
        ]
    };
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
                maxTicksLimit: summaryChartCommits + 10,
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
                min: 0,
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
        mode: "nearest",
        intersect: false,
        callbacks : {
            title: titlePlacement,
            beforeBody: beforeBodyPlacement
        }
    }
}

window.onload = function() {
    // Latest values
    setLatestData()

    // Summary charts
    new Chart(document.getElementById('canvasUp').getContext('2d'), {
        data: createCommitDatasets(dataAverageWinKernelx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataAverageWindowsx64OpensslThroughput),
        options: commitChartOptions
    });
    new Chart(document.getElementById('canvasDown').getContext('2d'), {
        data: createCommitDatasets(dataAverageWinKernelx64SchannelThroughputDown, dataAverageWindowsx64SchannelThroughputDown, dataAverageWindowsx64OpensslThroughputDown),
        options: commitChartOptions
    });
    new Chart(document.getElementById('canvasRps').getContext('2d'), {
        data: createCommitDatasets(dataAverageWinKernelx64SchannelRps, dataAverageWindowsx64SchannelRps, dataAverageWindowsx64OpensslRps),
        options: commitChartOptions
    });
    new Chart(document.getElementById('canvasHps').getContext('2d'), {
        data: createCommitDatasets(dataAverageWinKernelx64SchannelHps, dataAverageWindowsx64SchannelHps, dataAverageWindowsx64OpensslHps),
        options: commitChartOptions
    });
};
