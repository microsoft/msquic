function createLatencyDataset(test, platform, dataFilter) {
    var data = dataView.find(x => x.name === (platform.name + test))
    var dataFiltered = data.raw.filter(dataFilter);
    return {
        type: "line",
        label: platform.friendly,
        backgroundColor: platform.color,
        borderColor: platform.color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
        tension: 0,
        fill: false,
        data: dataFiltered,
        sortOrder: 1,
        hidden: false,
        hiddenType: false,
        hiddenPlatform: false,
        platform: platform.name
    }
}

function createLatencyChart(test, dataFilter) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createLatencyDataset(test, x, dataFilter)))

    var div = dataView.find(x => x.name === platformTypes[0].name + test).div;

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
                mode: "nearest",
                intersect: false,
                callbacks : {
                    title: titlePlacement,
                    beforeBody: beforeBodyPlacement
                }
            }
        }
    });

    platformTypes.forEach(x => addPlatformToggle(test, x, chart))
}

function computePercentile(value, moreDetail) {
    var logScale = Math.log10(value);
    var mulPower = logScale - 2;
    var percentBase = value - 1;
    var res = percentBase / Math.pow(10, mulPower);
    var offset = -1;
    if (res >= 99) {
        if (moreDetail) {
            offset = -1
        } else {
            offset = -2
        }
    } else {
        if (moreDetail) {
            offset = 0
        } else {
            offset = -1
        }
    }
    return res.toFixed(logScale+offset) + "%";
}

function latencyTitleChange(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem[0].datasetIndex]
    var datapoint = dataset.data[tooltipItem[0].index]
    return computePercentile(datapoint.x, true);
}

function createLatestLatencyDataset(test, platform) {
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
        platform: platform.name
    }
}

function createLatestLatencyChart(test) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createLatestLatencyDataset(test, x)))

    chart = new Chart(document.getElementById("canvas" + test).getContext('2d'), {
        data: { datasets: datasets},
        options: {
            maintainAspectRatio: false,
            scales: {
                xAxes: [{
                    type: 'logarithmic',
                    afterBuildTicks: function(scale) {
                        scale.ticks = [2, 4, 10, 20, 100, 1000, 10000, 100000]
                    },
                    gridLines: {
                        color: "rgb(200, 200, 200)",
                        zeroLineColor: "rgb(200, 200, 200)",
                        drawBorder: false,
                        borderDash: [2],
                        zeroLineBorderDash: [2]
                    },
                    ticks: {
                        callback: function(value) {
                            return computePercentile(value, false)
                        }
                    }
                }],
                yAxes: [{
                    display: true,
                    ticks: {
                        padding: 10,
                        max: rpsLatencyMax
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
                intersect: false,
                callbacks: {
                    title: latencyTitleChange
                }
            }
        }
    })

    platformTypes.forEach(x => addPlatformToggle(test, x, chart))
}
