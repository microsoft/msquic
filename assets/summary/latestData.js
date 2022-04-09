function setLatestData() {
    let latestValueDoms = document.querySelectorAll("div[data='latestValue']");
    latestValueDoms.forEach((dom) => {
        let data = dataView.find(x => x.name == dom.id);
        if (data) {
            dom.innerHTML = data.lvformat(data);
        }
    });
};
