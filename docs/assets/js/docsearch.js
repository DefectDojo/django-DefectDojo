import docsearch from "@docsearch/js";

// Scope results to the language of the page the reader is on. Every record in
// the index carries a `lang` facet and every page emits <html lang>, so without
// this filter an English reader gets German, Spanish, French and Japanese hits
// mixed into every search.
docsearch({
    container: '#docsearch',
    appId: '1JP5JYFGFC',
    indexName: 'DefectDojo Docs',
    apiKey: '213cc809a92717cffe6ffbe804d13fd1',
    searchParameters: {
        facetFilters: ['lang:' + (document.documentElement.lang || 'en')]
    }
});

const onClick = function () {
    document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;