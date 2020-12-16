/*!
 * Automatically generated data
 */
var dataRawThroughput = [{
    x: 1,
    y: 5097984
}, {
    x: 1,
    y: 5190477
}, {
    x: 1,
    y: 5114621
}, {
    x: 1,
    y: 5150847
}, {
    x: 1,
    y: 5060383
}, {
    x: 2,
    y: 5172262
}, {
    x: 2,
    y: 5113858
}, {
    x: 2,
    y: 5221557
}, {
    x: 2,
    y: 5143136
}, {
    x: 2,
    y: 5213932
}, {
    x: 3,
    y: 5012033
}, {
    x: 3,
    y: 5171683
}, {
    x: 3,
    y: 5206668
}, {
    x: 3,
    y: 5185257
}, {
    x: 3,
    y: 5193963
}, {
    x: 4,
    y: 5148048
}, {
    x: 4,
    y: 5230482
}, {
    x: 4,
    y: 5214532
}, {
    x: 4,
    y: 5144984
}, {
    x: 4,
    y: 5183002
}, {
    x: 5,
    y: 4768418
}, {
    x: 5,
    y: 5169544
}, {
    x: 5,
    y: 5147090
}, {
    x: 5,
    y: 5195739
}, {
    x: 5,
    y: 5221207
}, {
    x: 6,
    y: 4688155
}, {
    x: 6,
    y: 5183935
}, {
    x: 6,
    y: 5142092
}, {
    x: 6,
    y: 5195933
}, {
    x: 6,
    y: 4729882
}];

var dataAverageThroughput = [{
    x: 1,
    y: 5122862.4
}, {
    x: 2,
    y: 5172949
}, {
    x: 3,
    y: 5153920.8
}, {
    x: 4,
    y: 5184209.6
}, {
    x: 5,
    y: 5100399.6
}, {
    x: 6,
    y: 4987999.4
}];

var chartDataThroughput = {
    labels: [1, 2, 3, 4, 5, 6],
    datasets: [{
        type: "scatter",
        label: "Windows Kernel (raw)",
        backgroundColor: "rgb(0, 255, 0)",
        pointBorderColor: "rgb(0, 255, 0)",
        pointStyle: "crossRot",
        pointRadius: 5,
        pointBorderWidth: 2,
        data: dataRawThroughput,
    }, {
        type: "line",
        label: "Windows Kernel (average)",
        backgroundColor: "rgb(0, 255, 0)",
        borderColor: "rgb(0, 255, 0)",
        tension: 0,
        data: dataAverageThroughput,
        fill: false
    }]
};

var chartOptionsThroughput = {
    responsive: true,
    title: {
        display: true,
        text: 'Throughput'
    },
    tooltips: {
        mode: 'index',
        intersect: true
    },
    scales: {
        xAxes: [{
            display: true,
            scaleLabel: {
                display: true,
                labelString: 'Date'
            }
        }],
        yAxes: [{
            display: true,
            scaleLabel: {
                display: true,
                labelString: 'Throughput (kbps)'
            }
        }]
    }
};
