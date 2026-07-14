// custom js


// version toggler
(() => {
    "use strict";

    console.log("[VersionToggle] custom.js loaded");

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
        console.log("[VersionToggle] Setting version to:", version);

        document.querySelectorAll(".version-opensource, .version-pro").forEach(el => {
            el.style.display = el.classList.contains(`version-${version}`) ? "block" : "none";
        });

        localStorage.setItem("version", version);
        console.log("[VersionToggle] localStorage updated:", localStorage.getItem("version"));

        // Update dropdown
        const selects = document.querySelectorAll("#version-select");
        selects.forEach(sel => {
            sel.value = version;
            sel.dataset.version = version;
            sel.style.visibility = "visible";
        });

        // unhide sidebar after version is applied
        const sidebar = document.querySelector(".docs-sidebar");
        if (sidebar) {
            sidebar.style.visibility = "visible";
            console.log("[VersionToggle] Sidebar revealed");
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
        console.log("[VersionToggle] Stored version:", storedVersion);
        setVersion(storedVersion);
    };

    // Delegated listener on body
    document.body.addEventListener("change", (e) => {
        if (e.target && e.target.id === "version-select") {
            console.log("[VersionToggle] Dropdown changed to:", e.target.value);
            setVersion(e.target.value);
            // Only on an explicit user toggle (not on load) follow the page to
            // the matching edition when viewing an asset-modelling page.
            switchAssetPageForVersion(e.target.value);
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
