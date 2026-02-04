import docsearch from "@docsearch/js";

docsearch({
    container: '#docsearch',
    appId: '1JP5JYFGFC',
    indexName: 'DefectDojo Docs',
    apiKey: '213cc809a92717cffe6ffbe804d13fd1'
});

const onClick = function () {
    document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;