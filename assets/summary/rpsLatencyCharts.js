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
        platform: platform.name
    }
}

function createLatencyChart(test, toggleEnabled) {
    var datasets = []
    platformTypes.forEach(x => datasets.push(createLatencyDataset(test, x)))

    var div = dataView.find(x => x.name === platformTypes[0].name + test).div;
    console.log(datasets);

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
    });

    if (toggleEnabled) {
        platformTypes.forEach(x => addPlatformToggle(test, x, chart))
    }
}