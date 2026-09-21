import docsearch from "@docsearch/js";

// Keep at most two hits from any one page. DocSearch groups results by section
// rather than by page, so a single long page can fill every slot: searching
// "reimport" returned five hits that were all subsections of the Reimport page,
// crowding out every other page in the docs.
const MAX_HITS_PER_PAGE = 2;

function limitHitsPerPage(items) {
    const seen = new Map();
    return items.filter(function (item) {
        const page = item.url_without_anchor || item.url;
        const n = (seen.get(page) || 0) + 1;
        seen.set(page, n);
        return n <= MAX_HITS_PER_PAGE;
    });
}

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
    },
    transformItems: limitHitsPerPage
});

const onClick = function () {
    document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;