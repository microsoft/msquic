function setLatestData() {
    dataView.forEach(
        x => {
        if (!x.name.includes("Latency")) {
            document.getElementById(x.name).textContent = (pointsToValue(x.raw[0].d) / x.div).toFixed(2) + " " + x.unit
        } else if (!x.name.includes("Latest")) {
            document.getElementById(x.name).textContent = (x.raw[0].y / x.div).toFixed(2) + " " + x.unit
        }})
};
