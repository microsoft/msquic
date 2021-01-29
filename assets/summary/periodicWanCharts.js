window.onload = function() {
    var table = document.getElementById("WanTable");
    var thead = document.createElement('thead');
    var tr = document.createElement('tr');
    thead.appendChild(tr);
    table.appendChild(thead)
    var dataList = []
    // Load each field, get its name
    for (var name in wanPerfData[platformList[0]][0]) {
        // Ignore RawRateKbps
        if (name == "RawRateKbps") continue
        var element = document.createElement("th");
        element.innerText = name;
        tr.appendChild(element);
        dataList.push({ data: name });
    }
    $('#WanTable').DataTable({
        data: wanPerfData[platformList[0]],
        columns: dataList
    })
}