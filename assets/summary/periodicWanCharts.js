
var filteredWanPerfData = []

function generateWanPerfData() {
    var baseData = wanPerfData[platformList[0]]
    for (let i = 0; i < baseData.length; i +=2) {
        var tcpData = wanPerfData[platformList[0]][i]
        var quicData = wanPerfData[platformList[0]][i+1]
        filteredWanPerfData.push({
            "BottleneckMbps": tcpData.BottleneckMbps,
            "RttMs": tcpData.RttMs,
            "BottleneckBufferPackets": tcpData.BottleneckBufferPackets,
            "RandomLossDenominator": tcpData.RandomLossDenominator,
            "RandomReorderDenominator": tcpData.RandomReorderDenominator,
            "ReorderDelayDeltaMs": tcpData.ReorderDelayDeltaMs,
            "DurationMs": tcpData.DurationMs,
            "TcpRateKbps": tcpData.RateKbps,
            "QuicRateKbps": quicData.RateKbps,
            "TcpDiffPercent": (quicData.RateKbps - tcpData.RateKbps) / (tcpData.BottleneckMbps * 10),
            "MaxDiffPercent": quicData.RateKbps / (tcpData.BottleneckMbps * 10)
        })
    }
}

function generateWanTable() {
    var table = document.getElementById("WanTable");
    var thead = document.createElement('thead');
    var tr = document.createElement('tr');
    thead.appendChild(tr);
    table.appendChild(thead)
    var columnNames = [
        "Network (Mbps)",
        "RTT (ms)",
        "Queue (pkts)",
        "Loss (1/N)",
        "Reorder (1/N)",
        "Reorder Delay (ms)",
        //"Duration (ms)",
        "STCP Goodput (Kbps)",
        "QUIC Goodput (Kbps)",
        "Diff from TCP (%)",
        "Diff from Max (%)"
    ].forEach (
        name => {
            var element = document.createElement("th");
            element.innerText = name;
            tr.appendChild(element);
        }
    )
    $('#WanTable').DataTable({
        data: filteredWanPerfData,
        columns: [
            { data: "BottleneckMbps" },
            { data: "RttMs" },
            { data: "BottleneckBufferPackets" },
            { data: "RandomLossDenominator" },
            { data: "RandomReorderDenominator" },
            { data: "ReorderDelayDeltaMs" },
            //{ data: "DurationMs" },
            { data: "TcpRateKbps" },
            { data: "QuicRateKbps" },
            { data: "TcpDiffPercent" },
            { data: "MaxDiffPercent" }
        ]
    })
}

window.onload = function() {
    generateWanPerfData()
    generateWanTable()
}
