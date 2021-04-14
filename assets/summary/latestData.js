function setLatestData() {
    dataView.forEach(
        x => {
        if (!x.name.includes("Latency")) {
            document.getElementById(x.name).textContent = (pointsToValue(x.raw[0].d) / x.div).toFixed(2) + " " + x.unit
        }})
};
