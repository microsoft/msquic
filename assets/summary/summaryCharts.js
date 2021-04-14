
// Default number of commits to slice for each chart type.
var commitCount = 11
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

function chartOnClick(a, activeElements) {
    if (activeElements.length === 0) return
    var dataset = this.config.data.datasets[activeElements[0]._datasetIndex]
    var commitIndex = dataset.data[activeElements[0]._index].x
    var commitHash = recentCommits[commitIndex].h
    window.open("https://github.com/microsoft/msquic/commit/" + commitHash, "_blank")
}

function filterDataset(dataset, commitCount) {
    return dataset.filter(p => (maxIndex - 1 - p.x) < commitCount);
}

function createDataset(test, platform) {
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
        isRaw: false,
        platform: platform.friendly
    };
}

function createChart(test) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createDataset(test, x)))

    var div = dataView.find(x => x.name === platformTypes[0].name + test).div

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
                        min: 0,
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
                mode: "nearest",
                intersect: false,
                callbacks : {
                    title: titlePlacement,
                    beforeBody: beforeBodyPlacement
                }
            }
        }
    })
}

window.onload = function() {
    // Latest values
    setLatestData()

    // Summary charts
    testTypes.forEach(x => createChart(x))
};
