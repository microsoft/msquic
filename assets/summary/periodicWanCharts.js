
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
    "Percent of Max"
]

var filterable = [
    [ "BottleneckMbps", "Network (Mbps)" ],
    [ "RttMs", "RTT (ms)" ],
    [ "BottleneckBufferPackets", "Queue (pkts)" ],
    [ "RandomLossDenominator", "Loss (1/N)" ],
    [ "RandomReorderDenominator", "Reorder (1/N)" ],
    [ "ReorderDelayDeltaMs", "Reorder Delay (ms)" ],
];

var filteredWanPerfData = []

var dataTableStore;

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
            "MaxPercent": quicData.RateKbps / (tcpData.BottleneckMbps * 10)
        })
    }
}

function filterTable(settings, data, dataIndex) {
    var idx = 0;
    for (var flt of filterable) {
        var name = "Filter" + flt[0];
        var value = document.getElementById(name).value;
        if (value === 'all') {
            idx++;
            continue;
        }
        if (value === data[idx]) {
            idx++;
            continue;
        }
        return false;
    }

    return true;
}

function compareNumbers(a, b) {
    return a - b;
}

function selectorChanged() {
    dataTableStore.draw();
}

function generateWanFilter() {
    var filterdiv = document.getElementById('filterdiv');

    var filterInnerDiv = document.createElement('div');
    filterInnerDiv.style = "float:left";
    filterdiv.appendChild(filterInnerDiv);

    var filterLabel = document.createElement('label');
    filterLabel.innerText = "Filter: ";
    filterLabel.style = "font-weight: bold";
    filterInnerDiv.appendChild(filterLabel);

    for (const filtername of filterable) {

        var innerDiv = document.createElement('div');
        innerDiv.style = "float:left";
        filterdiv.appendChild(innerDiv);

        var label = document.createElement('label');
        label.innerText = "\xa0\xa0\xa0\xa0\xa0\xa0\xa0" + filtername[1] + "\xa0";
        label.for = filtername[0];
        innerDiv.appendChild(label);

        var select = document.createElement('select');
        select.name = filtername[0];
        select.id = "Filter" + filtername[0];

        var elements = new Set();
        for (var element of filteredWanPerfData) {
            elements.add(parseInt(element[filtername[0]], 10));
        }

        var allOption = document.createElement('option');
        allOption.value = 'all';
        allOption.innerText = "All";
        select.appendChild(allOption);

        var sortedSet = Array.from(elements).sort(compareNumbers);

        for (var element of sortedSet) {
            var option = document.createElement('option');
            option.value = element;
            option.innerText = element;
            select.appendChild(option);
            select.appendChild(document.createElement('p'));
        }

        innerDiv.appendChild(select);
        innerDiv.appendChild(document.createElement('p'));

        select.onchange = selectorChanged;
    }
}

function generateWanTable() {
    var table = document.getElementById("WanTable");
    var thead = document.createElement('thead');
    var tr = document.createElement('tr');
    thead.appendChild(tr);
    table.appendChild(thead)
    columnNames.forEach(
        name => {
            var element = document.createElement("th");
            element.innerText = name;
            tr.appendChild(element);
        }
    )

    $.fn.dataTable.ext.search.push(filterTable);

    dataTableStore = $('#WanTable').DataTable({
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
            { data: "MaxPercent" }
        ]
    })
}

window.onload = function() {
    generateWanPerfData()
    generateWanFilter()
    generateWanTable()
}
