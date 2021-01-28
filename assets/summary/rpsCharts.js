var colors = ["#3498db", "#2ecc71", "#f1c40f", "#8e44ad", "#e74c3c", "#34495e", "#e67e22", "#7f8c8d"];

// Fixed charting values
var dataLineWidth = 2
var dataRawPointRadius = 3

function createScaleLabel(name) {
    return {
        display: true,
        labelString: name,
        fontSize: 14,
        fontStyle: 'bold'
    };
}

function createRpsDataset(dataset, color) {
    return {
        type: "scatter",
        label: dataset.LegendValue,
        data: dataset.DataPairs,
        showLine: true,
        fill: false,
        tension: 0,
        backgroundColor: color,
        borderColor: color,
        borderWidth: dataLineWidth,
        pointRadius: dataRawPointRadius,
    }
}

function createChart(chartData) {
    var datasets = []
    var index = 0
    for (var data of chartData[1].Data) {
        datasets.push(createRpsDataset(data, colors[index++]))
        if (index >= colors.length) {
            index = 0;
        }
    }

    new Chart(chartData[0].getContext('2d'), {
        data: { datasets: datasets },
        options: {
            maintainAspectRatio: false,
            scales: {
                xAxes: [{
                    type: 'linear',
                    position: 'bottom',
                    offset: true,
                    gridLines: {
                      display: false,
                      drawBorder: false
                    },
                    scaleLabel: createScaleLabel(chartData[1].XName),
                }],
                yAxes: [{
                    ticks: {
                        padding: 10,
                        min: 0
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
                intersect: false
            }
        }
    })
}

window.onload = function() {
    var templateDiv = document.getElementById("Template");
    var chartsDiv = document.getElementById("ChartsDiv");
    chartsDiv.innerHTML = ""

    var chartList = [];

    var index = 0;
    for (var chartToMake of periodicRpsGraphs) {
        var newNode = templateDiv.cloneNode(true);
        newNode.id = newNode.id + index;
        var canvasNode = newNode.querySelector("#canvas");
        canvasNode.id = canvasNode.id + index;

        var headerNode = newNode.querySelector("#HeaderName");
        headerNode.innerText = `RPS per ${chartToMake.LegendName}, ${chartToMake.XName}`
        headerNode.id = headerNode.id + index;

        var summaryTextNode = newNode.querySelector("#SummaryText");
        summaryTextNode.innerText = "This test measures average requests completed per second while simulating HTTP-style traffic between the client and server."
        summaryTextNode.id = summaryTextNode.id + index;

        var createData = [canvasNode, chartToMake];
        chartList.push(createData);

        chartsDiv.appendChild(newNode);
        index++;
    }

    for (var chartData of chartList) {
        createChart(chartData)
    }
}