// custom js

// Mobile navigation: the site sets doks.bootstrapJavascript = false, so no
// Bootstrap plugins load and the header's offcanvas toggles are dead markup.
// Importing the Offcanvas plugin evaluates its module, which registers the
// data-bs-toggle="offcanvas" click handling; the window reference keeps the
// import (and its side effects) from being tree-shaken.
import { Offcanvas } from 'bootstrap';

window.ddOffcanvas = Offcanvas;


// Edition toggler (Open Source / Pro)
//
// The sidebar renders both edition menus (.version-opensource / .version-pro).
// Which menu shows — and which segmented-control button reads as selected —
// is pure CSS keyed off html[data-dd-version] (see _custom.scss). An inline
// script in custom-head.html stamps that attribute from localStorage before
// first paint, so every page load renders the stored edition immediately with
// no hide-then-reveal flicker. This module only handles toggling: update the
// attribute, persist the choice, sync aria-checked for assistive tech.
(() => {
    "use strict";

    // Edition-specific landing pages per top-nav tab. The top nav is otherwise
    // static, so a single URL can't be correct for both editions: we keep these
    // nav links in sync with the selected version, and — when the user is
    // already viewing one of these pages — navigate to the matching edition's
    // page so the main content follows the toggle. Keyed by nav-link label.
    const editionNavUrls = {
        "Model Your Assets": {
            opensource: "/asset_modelling/engagements_tests/os__assets/",
            pro: "/asset_modelling/pro_hierarchy/asset_hierarchy/",
        },
        // Sensei is Pro-only: Open Source shows a short "Pro feature" page,
        // Pro shows the full guide.
        "Sensei": {
            opensource: "/sensei/os__sensei/",
            pro: "/sensei/about_sensei/",
        },
    };

    const switchPageForVersion = (version) => {
        Object.values(editionNavUrls).forEach((urls) => {
            const target = urls[version];
            const other = urls[version === "pro" ? "opensource" : "pro"];
            // Only redirect when currently on the *other* edition's page, so
            // this never fires on unrelated pages or loops on the target page.
            if (target && location.pathname === other) {
                location.assign(target);
            }
        });
    };

    const setVersion = (version) => {
        // CSS shows the matching menu and highlights the matching button
        document.documentElement.dataset.ddVersion = version;

        try {
            localStorage.setItem("version", version);
        } catch (e) {
            // Storage blocked (private browsing) — toggle still works this page
        }

        // aria-checked is for assistive tech only; visuals come from the
        // html[data-dd-version] attribute above
        document.querySelectorAll(".dd-version-seg button[data-version-value]").forEach(btn => {
            btn.setAttribute("aria-checked", btn.dataset.versionValue === version ? "true" : "false");
        });

        // Edition-aware top nav: route these tabs to the page that matches the
        // selected version (see editionNavUrls above).
        document.querySelectorAll("a.nav-link").forEach(link => {
            const urls = editionNavUrls[link.textContent.trim()];
            if (urls) {
                link.setAttribute("href", urls[version] || urls.opensource);
            }
        });
    };

    const initVersionToggle = () => {
        // custom-head.html already stamped the stored edition on <html> before
        // paint; re-applying it here syncs aria-checked and the nav link on
        // freshly parsed (or dynamically replaced) markup.
        setVersion(document.documentElement.dataset.ddVersion || "opensource");
    };

    // Delegated listener on body — catches every control instance
    document.body.addEventListener("click", (e) => {
        const btn = e.target.closest("button[data-version-value]");
        if (btn) {
            setVersion(btn.dataset.versionValue);
            // Only on an explicit user toggle (not on load) follow the page to
            // the matching edition when viewing one of the edition-specific pages.
            switchPageForVersion(btn.dataset.versionValue);
        }
    });

    // Run on DOM ready
    window.addEventListener("DOMContentLoaded", initVersionToggle);

    // MutationObserver to detect dynamically replaced sidebar
    const observer = new MutationObserver(() => {
        // Re-run init to make sure menus match stored version
        initVersionToggle();
    });
    observer.observe(document.body, { childList: true, subtree: true });

})();


// Code block language labels — stamp the fence language onto each
// expressive-code frame's (empty) title span so CSS can render it in the
// header band via attr(data-lang). Frames whose fence "language" is really
// an editor artifact (paths, line ranges) get a generic "code" label.
(() => {
    "use strict";

    const CLEAN_LANG = /^[a-z0-9_+#.-]{1,16}$/i;

    const init = () => {
        document.querySelectorAll(".docs-content .expressive-code .frame").forEach(frame => {
            const title = frame.querySelector(".header .title");
            if (!title || title.textContent.trim() !== "" || title.dataset.lang) return;
            const code = frame.querySelector("pre code[data-lang]");
            let lang = code ? code.dataset.lang : "";
            if (!lang || lang === "fallback" || !CLEAN_LANG.test(lang)) lang = "code";
            title.dataset.lang = lang;
            frame.classList.add("dd-has-lang");
        });
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();


// Homepage hero search field — forwards to the DocSearch modal
(() => {
    "use strict";

    const init = () => {
        const trigger = document.getElementById("ddHomeSearch");
        if (!trigger) return;
        trigger.addEventListener("click", () => {
            const btn = document.getElementsByClassName("DocSearch-Button")[0];
            if (btn) btn.click();
        });
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();


// Scroll progress bar — shows reading progress on doc pages
(() => {
    "use strict";

    const init = () => {
        // Only add on doc pages (pages with .docs-content)
        if (!document.querySelector('.docs-content')) return;

        const bar = document.createElement('div');
        bar.className = 'scroll-progress';
        bar.style.width = '0%';
        document.body.appendChild(bar);

        const update = () => {
            const scrollTop = window.scrollY;
            const docHeight = document.documentElement.scrollHeight - window.innerHeight;
            const progress = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
            bar.style.width = progress + '%';
        };

        window.addEventListener('scroll', update, { passive: true });
        update();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
