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
// The sidebar renders both edition menus (.version-opensource / .version-pro);
// this shows one, persists the choice, and keeps every segmented control on
// the page (desktop sidebar + mobile offcanvas) in sync. The sidebar and the
// control start hidden (see _custom.scss) and are revealed only after the
// stored edition is applied, so there is no flash of the wrong menu.
(() => {
    "use strict";

    // Asset-modelling landing pages per edition. The top nav is otherwise
    // static, so a single URL can't be correct for both editions: we keep the
    // "Model Your Assets" nav link in sync with the selected version, and —
    // when the user is already viewing one of these pages — navigate to the
    // matching edition's page so the main content follows the toggle.
    const assetNavUrls = {
        opensource: "/asset_modelling/engagements_tests/os__assets/",
        pro: "/asset_modelling/pro_hierarchy/assets_organizations/",
    };

    const switchAssetPageForVersion = (version) => {
        const target = assetNavUrls[version];
        const other = assetNavUrls[version === "pro" ? "opensource" : "pro"];
        // Only redirect when currently on the *other* edition's asset page,
        // so this never fires on unrelated pages or loops on the target page.
        if (target && location.pathname === other) {
            location.assign(target);
        }
    };

    const setVersion = (version) => {
        document.querySelectorAll(".version-opensource, .version-pro").forEach(el => {
            el.style.display = el.classList.contains(`version-${version}`) ? "block" : "none";
        });

        localStorage.setItem("version", version);

        // Sync every segmented control instance, then reveal it
        document.querySelectorAll(".dd-version-seg").forEach(seg => {
            seg.querySelectorAll("button[data-version-value]").forEach(btn => {
                btn.setAttribute("aria-checked", btn.dataset.versionValue === version ? "true" : "false");
            });
            seg.style.visibility = "visible";
        });

        // Unhide sidebar after version is applied
        const sidebar = document.querySelector(".docs-sidebar");
        if (sidebar) {
            sidebar.style.visibility = "visible";
        }

        // Edition-aware top nav: route "Model Your Assets" to the page that
        // matches the selected version (see assetNavUrls above).
        document.querySelectorAll("a.nav-link").forEach(link => {
            if (link.textContent.trim() === "Model Your Assets") {
                link.setAttribute("href", assetNavUrls[version] || assetNavUrls.opensource);
            }
        });
    };

    const initVersionToggle = () => {
        const storedVersion = localStorage.getItem("version") || "opensource";
        setVersion(storedVersion);
    };

    // Delegated listener on body — catches every control instance
    document.body.addEventListener("click", (e) => {
        const btn = e.target.closest("button[data-version-value]");
        if (btn) {
            setVersion(btn.dataset.versionValue);
            // Only on an explicit user toggle (not on load) follow the page to
            // the matching edition when viewing an asset-modelling page.
            switchAssetPageForVersion(btn.dataset.versionValue);
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
