var colors = ["#3498db", "#2ecc71", "#f1c40f", "#8e44ad", "#e74c3c", "#34495e", "#e67e22", "#7f8c8d"];

// Useful configuration values
var dataLineWidth = 2
var dataRawPointRadius = 4

// Global option configuration
Chart.defaults.global.responsive = true
Chart.defaults.global.tooltips.position = 'nearest'
Chart.defaults.global.tooltips.mode = 'x'

function createScaleLabel(name) {
    return {
        display: true,
        labelString: name,
        fontSize: 14,
        fontStyle: 'bold'
    };
}

function createRpsOptions(chartToMake) {
    return {
        scales: {
            xAxes: [{
                type: 'linear',
                position: 'bottom',
                scaleLabel: createScaleLabel(chartToMake.XName),
            }],
            yAxes: [{
                display: true,
                scaleLabel: createScaleLabel("Requests Per Second"),
                ticks: { min: 0 }
            }]
        }
    }
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

function createRpsDatasets(chartData) {
    var arr = []
    var index = 0
    for (var dataset of chartData) {
        arr.push(createRpsDataset(dataset, colors[index]))
        index++;
        if (index >= colors.length) {
            index = 0;
        }
    }
    return {
        datasets: arr
    };
}

window.onload = function() {
    document.getElementById('PageTitle').innerText = 'MsQuic Periodic Performance Dashboard - ' + pageCommitHash;
    var commitLinkElement = document.getElementById('CommitLink');
    commitLinkElement.innerText = 'GitHub: ' + pageCommitHash;
    commitLinkElement.href = 'https://github.com/microsoft/msquic/commit/' + pageCommitHash;

    var formattedDate = Chart._adapters._date.prototype.format(runDate, "MMM d, yyyy");

    document.getElementById("RunDate").innerText = formattedDate

    // Generate Charts
    var chartsDiv = document.getElementById('ChartsDiv')

    for (var chartToMake of periodicRpsGraphs) {
        var headerElement = document.createElement('h3');
        headerElement.innerText = `RPS per ${chartToMake.LegendName}, ${chartToMake.XName}`
        chartsDiv.appendChild(headerElement);
        var singleChartDiv = document.createElement('div');
        singleChartDiv.className = 'graph'

        var canvas = document.createElement('canvas');
        canvas.className = 'chartjs-render-monitor'
        singleChartDiv.appendChild(canvas);

        var c2d = canvas.getContext('2d')
        console.log(c2d)

        new Chart(canvas.getContext('2d'), {
            data: createRpsDatasets(chartToMake.Data),
            options: createRpsOptions(chartToMake)
        });


        chartsDiv.appendChild(singleChartDiv);
    }

    // // Summary charts
    // new Chart(document.getElementById('canvasThroughputSummary').getContext('2d'), {
    //     data: createSummaryDatasets(dataAverageWinKernelx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataAverageWindowsx64OpensslThroughput),
    //     options: createSummaryChartOptions('Single Connection Throughput', 'Throughput (kbps)')
    // });
    // new Chart(document.getElementById('canvasRPSSummary').getContext('2d'), {
    //     data: createSummaryDatasets(dataAverageWinKernelx64SchannelRps, dataAverageWindowsx64SchannelRps, dataAverageWindowsx64OpensslRps),
    //     options: createSummaryChartOptions('Requests per Second', 'RPS')
    // });
    // new Chart(document.getElementById('canvasHPSSummary').getContext('2d'), {
    //     data: createSummaryDatasets(dataAverageWinKernelx64SchannelHps, dataAverageWindowsx64SchannelHps, dataAverageWindowsx64OpensslHps),
    //     options: createSummaryChartOptions('Handshakes per Second', 'HPS')
    // });

    // // Detailed charts
    // tputChart = new Chart(document.getElementById('canvasThroughput').getContext('2d'), {
    //     data: createDatasets(dataRawWinKernelx64SchannelThroughput, dataAverageWinKernelx64SchannelThroughput, dataRawWindowsx64SchannelThroughput, dataAverageWindowsx64SchannelThroughput, dataRawWindowsx64OpensslThroughput, dataAverageWindowsx64OpensslThroughput),
    //     options: createChartOptions('Throughput (kbps)')
    // });
    // rpsChart = new Chart(document.getElementById('canvasRPS').getContext('2d'), {
    //     data: createDatasets(dataRawWinKernelx64SchannelRps, dataAverageWinKernelx64SchannelRps, dataRawWindowsx64SchannelRps, dataAverageWindowsx64SchannelRps, dataRawWindowsx64OpensslRps, dataAverageWindowsx64OpensslRps),
    //     options: createChartOptions('RPS')
    // });
    // hpsChart = new Chart(document.getElementById('canvasHPS').getContext('2d'), {
    //     data: createDatasets(dataRawWinKernelx64SchannelHps, dataAverageWinKernelx64SchannelHps, dataRawWindowsx64SchannelHps, dataAverageWindowsx64SchannelHps, dataRawWindowsx64OpensslHps, dataAverageWindowsx64OpensslHps),
    //     options: createChartOptions('HPS')
    // });

    // rpsLatencyChart = new Chart(document.getElementById('canvasRPSLatency').getContext('2d'), {
    //     data: createLatencyDatasets(dataRpsLatencyWindowsOpenSsl, dataRpsLatencyWindowsSchannel, dataRpsLatencyWinKernel),
    //     options: createLatencyChartOptions('RPS Latency (μs)')
    // });

    // document.getElementById('rawpdt').onclick = onRadioChange
    // document.getElementById('avgpdt').onclick = onRadioChange
    // document.getElementById('bothpdt').onclick = onRadioChange

    // document.getElementById('Windows Kernel').onclick = onPlatformChange
    // document.getElementById('Windows User Schannel').onclick = onPlatformChange
    // document.getElementById('Windows User OpenSSL').onclick = onPlatformChange
};
