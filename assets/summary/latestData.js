function setLatestData() {
    dataView.forEach(
        x => {
        if (!x.name.includes("Latency")) {
            document.getElementById(x.name).textContent = (x.avg[0].y / x.div).toFixed(2) + " " + x.unit
        }})
};
