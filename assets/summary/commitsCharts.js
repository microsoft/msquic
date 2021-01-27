function dateFormatting(row, type, val, meta) {
    if (type === 'set') {
        var date = new Date(Number(val))
        var formattedDate = Chart._adapters._date.prototype.format(date, Chart._adapters._date.prototype.formats().datetime)
        row.display = formattedDate
        row.raw = val
        return
    } else if (type === 'sort') {
        return row.raw
    }
    return row.display
}

window.onload = function() {
    // Generate Table
    var table = document.getElementById('CommitsTable');
    var tableBody = document.createElement('tbody');
    
    for (var commit of commitData) {
        var tableElement = document.createElement('tr')

        var commitDateElement = document.createElement('td')
        commitDateElement.innerText = commit.commitDate
        tableElement.appendChild(commitDateElement)

        var commitHashElement = document.createElement('td')
        commitHashElement.innerText = commit.commitHash
        tableElement.appendChild(commitHashElement);

        var commitPerfLinkElement = document.createElement('td');
        var commitRef = document.createElement('a');
        commitRef.href = "percommit/main/" + commit.commitHash + "/index.html"
        commitRef.innerText = "Performance: " + commit.commitHash
        commitPerfLinkElement.appendChild(commitRef);
        tableElement.appendChild(commitPerfLinkElement);

        var commitSourceLinkElement = document.createElement('td');
        var commitRef = document.createElement('a');
        commitRef.href = "https://github.com/microsoft/msquic/commit/" + commit.commitHash
        commitRef.innerText = "GitHub: " + commit.commitHash
        commitSourceLinkElement.appendChild(commitRef);
        tableElement.appendChild(commitSourceLinkElement);

        tableBody.appendChild(tableElement);
    }
    table.appendChild(tableBody);

    $('#CommitsTable').DataTable({
        pageLength: 25,
        columnDefs: [
            { targets: 0, data: dateFormatting},
            { orderable: false, targets: 1},
            { orderable: false, targets: 2},
        ],
        order: [[0, 'desc']],
    });
}