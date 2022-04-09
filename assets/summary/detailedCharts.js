
// Default number of commits to slice for each chart type.
var commitCount = 31
if (maxIndex < commitCount) {
    commitCount = maxIndex
}

function titlePlacement(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem[0].datasetIndex]
    var datapoint = dataset.data[tooltipItem[0].index]
    var time = recentCommits[datapoint.x].t
    // TODO Fix this, this is very hacky
    return Chart._adapters._date.prototype.format(time, Chart._adapters._date.prototype.formats().datetime)
}

function beforeBodyPlacement(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem[0].datasetIndex]
    var datapoint = dataset.data[tooltipItem[0].index]
    return "Commit Hash: " + recentCommits[datapoint.x].h
}

function labelChange(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem.datasetIndex]
    if (dataset.label.includes(pointsToValueName)) {
        var datapoint = dataset.data[tooltipItem.index]
        var machine = datapoint.m
        if (datapoint.b != 0) {
            machine = machine + "|" + datapoint.b
        }
        return pointsToValueName + " (M" + machine + "):" + tooltipItem.value
    } else {
        return "Raw:       " + tooltipItem.value
    }
}

function chartOnClick(a, activeElements) {
    if (activeElements.length === 0) return
    var dataset = this.config.data.datasets[activeElements[0]._datasetIndex]
    var commitIndex = dataset.data[activeElements[0]._index].x
    var commitHash = recentCommits[commitIndex].h
    window.open("https://github.com/microsoft/msquic/commit/" + commitHash, "_blank")
}

function createLineDataset(test, platform) {
    var data = dataView.find(x => x.name === (platform.name + test))
    return {
        type: "line",
        label: platform.friendly + " (" + pointsToValueName + ")",
        backgroundColor: platform.color,
        borderColor: platform.color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        data: generateLineDataset(data.raw, maxIndex, commitCount),
        fill: false,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        platform: platform.name
    };
}

function createPointDataset(test, platform) {
    var data = dataView.find(x => x.name === (platform.name + test))
    return {
        type: "scatter",
        label: platform.friendly + " (raw)",
        backgroundColor: platform.color,
        pointBorderColor: platform.color,
        pointStyle: "crossRot",
        pointRadius: dataRawPointRadius,
        pointBorderWidth: 2,
        data: generatePointDataset(data.raw, maxIndex, commitCount),
        sortOrder: 2,
        hidden: true,
        hiddenType: true,
        hiddenPlatform: false,
        platform: platform.name
    };
}

function onPlatformToggled(event) {
    var chart = event.srcElement.chart
    for (const val of chart.data.datasets) {
        if (val.platform === event.srcElement.platform) {
            val.hiddenPlatform = !val.hiddenPlatform
            val.hidden = val.hiddenPlatform | val.hiddenType
        }
    }
    chart.update()
}

function onTypeToggled(event) {
    var chart = event.srcElement.chart
    for (const val of chart.data.datasets) {
        if (val.type === event.srcElement.type) {
            val.hiddenType = !val.hiddenType
            val.hidden = val.hiddenPlatform | val.hiddenType
        }
    }
    chart.update()
}

function addPlatformToggle(test, platform, chart) {
    var elem = document.getElementById(platform.name + test + "Toggle")
    if (elem) {
        elem.onclick = onPlatformToggled
        elem.chart = chart
        elem.platform = platform.name
    }
}

function addTypeToggle(test, type, chart) {
    var elem = document.getElementById(type + test + "Toggle")
    if (elem) {
        elem.onclick = onTypeToggled
        elem.chart = chart
        elem.type = type
    }
}

function createChart(test) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createLineDataset(test, x)))
    platformTypes.forEach(x => datasets.push(createPointDataset(test, x)))

    var div = dataView.find(x => x.name === platformTypes[0].name + test).div

    chart = new Chart(document.getElementById("canvas" + test).getContext('2d'), {
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
                            value = maxIndex - 1 - value
                            if (value % 10 !== 0) {
                                return "";
                            } else {
                                return value;
                            }
                        }
                    }
                }],
                yAxes: [{
                    ticks: {
                        padding: 10,
                        callback: function(value) {
                            return (value/div).toFixed(2)
                        }
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

    platformTypes.forEach(x => addPlatformToggle(test, x, chart))
    addTypeToggle(test, "scatter", chart)
    addTypeToggle(test, "line", chart)
}

window.onload = function() {
    // Check for custom parameters
    processSearchParams()

    // Latest values
    setLatestData()

    // Summary charts
    testTypes.forEach(x => createChart(x))
    createLatencyChart("RpsLatency", (data) => maxIndex - 1 - data.x < commitCount);
    createLatencyChart("RpsLatencyMultiConn", (data) => maxIndex - 1 - data.x < commitCount);
    createLatestLatencyChart("RpsLatencyLatest");
};
