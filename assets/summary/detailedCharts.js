
// Default number of commits to slice for each chart type.
var commitCount = 31
if (maxIndex < commitCount) {
    commitCount = maxIndex
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

function filterDataset(dataset, commitCount) {
    return dataset.filter(p => (maxIndex - 1 - p.x) < commitCount);
}

function createAvgDataset(test, platform) {
    var data = dataView.find(x => x.name === (platform.name + test))
    return {
        type: "line",
        label: platform.friendly + " (average)",
        backgroundColor: platform.color,
        borderColor: platform.color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: filterDataset(data.avg, commitCount),
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform.friendly
    };
}

function createRawDataset(test, platform) {
    var data = dataView.find(x => x.name === (platform.name + test))
    return {
        type: "scatter",
        label: platform.friendly + " (raw)",
        backgroundColor: platform.color,
        pointBorderColor: platform.color,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: filterDataset(data.raw, commitCount),
        sortOrder: 2,
        hidden: true,
        hiddenType: true,
        hiddenPlatform: false,
        isRaw: true,
        platform: platform.friendly
    };
}

function createLatencyDataset(test, platform) {
    var data = dataView.find(x => x.name === (platform.name + test))
    return {
        type: "line",
        label: platform.friendly,
        backgroundColor: platform.color,
        borderColor: platform.color,
        borderWidth: dataLineWidth,
        pointRadius: 1,
        tension: 0,
        fill: false,
        data: data.raw,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        isRaw: false,
        platform: platform.friendly
    }
}

function createChart(test) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createAvgDataset(test, x)))
    platformTypes.forEach(x => datasets.push(createRawDataset(test, x)))

    new Chart(document.getElementById("canvas" + test).getContext('2d'), {
        data: { datasets: datasets},
        options: {
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
                        maxTicksLimit: commitCount + 10,
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
    })
}

function createLatencyChart(test) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createLatencyDataset(test, x)))

    new Chart(document.getElementById("canvas" + test).getContext('2d'), {
        data: { datasets: datasets},
        options: {
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
                            return percentileScaleDict[value]
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
    })
}

window.onload = function() {
    // Latest values
    setLatestData()

    // Summary charts
    testTypes.forEach(x => createChart(x))
    createLatencyChart("RpsLatency")
};
