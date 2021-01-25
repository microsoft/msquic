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

function chartOnCick(a, activeElements) {
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

function createSummaryDatasets(avgKernel, avgUserSchannel, avgUserOpenssl) {
    return {
        datasets: [
            createAverageSummaryDataset("Windows Kernel", dataColorWinKernelx64Schannel, avgKernel),
            createAverageSummaryDataset("Windows User Schannel", dataColorWindowsx64Schannel, avgUserSchannel),
            createAverageSummaryDataset("Windows User OpenSSL", dataColorWindowsx64Openssl, avgUserOpenssl)
        ]
    };
}

var summaryChartOptions = {
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
    onClick: chartOnCick,
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
    document.getElementById("winKernelSchannelUp").textContent = "5,911 Mbps"
    document.getElementById("winKernelSchannelDown").textContent = "5,711 Mbps"
    document.getElementById("winKernelSchannelRps").textContent = "257 KHz"
    document.getElementById("winKernelSchannelHps").textContent = "1,924 Hz"
    document.getElementById("winUserSchannelUp").textContent = "5,779 Mbps"
    document.getElementById("winUserSchannelDown").textContent = "2,121 Mbps"
    document.getElementById("winUserSchannelRps").textContent = "869 KHz"
    document.getElementById("winUserSchannelHps").textContent = "1,832 Hz"
    document.getElementById("winUserOpenSslUp").textContent = "5,672 Mbps"
    document.getElementById("winUserOpenSslDown").textContent = "3,631 Mbps"
    document.getElementById("winUserOpenSslRps").textContent = "919 KHz"
    document.getElementById("winUserOpenSslHps").textContent = "2,326 Hz"

    // Summary charts
    new Chart(document.getElementById('canvasUp').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataAverageWindowsx64OpensslThroughput),
        options: summaryChartOptions
    });
    new Chart(document.getElementById('canvasDown').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelThroughputDown, dataAverageWindowsx64SchannelThroughputDown, dataAverageWindowsx64OpensslThroughputDown),
        options: summaryChartOptions
    });
    new Chart(document.getElementById('canvasRps').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelRps, dataAverageWindowsx64SchannelRps, dataAverageWindowsx64OpensslRps),
        options: summaryChartOptions
    });
    new Chart(document.getElementById('canvasHps').getContext('2d'), {
        data: createSummaryDatasets(dataAverageWinKernelx64SchannelHps, dataAverageWindowsx64SchannelHps, dataAverageWindowsx64OpensslHps),
        options: summaryChartOptions
    });
};
