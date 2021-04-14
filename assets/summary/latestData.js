function setLatestData() {
    dataView.forEach(
        x => {
        if (!x.name.includes("Latency")) {
            document.getElementById(x.name).textContent = (median(x.raw[0].d) / x.div).toFixed(2) + " " + x.unit
        }})
};
