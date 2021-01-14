window.onload = function() {
    document.getElementById('PageTitle').innerText = 'MsQuic Performance Dashboard - ' + pageCommitHash;
    var commitLinkElement = document.getElementById('CommitLink');
    commitLinkElement.innerText = 'GitHub: ' + pageCommitHash;
    commitLinkElement.href = 'https://github.com/microsoft/msquic/commit/' + pageCommitHash;
};
