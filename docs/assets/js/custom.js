// custom js


// version toggler
(() => {
  "use strict";

  console.log("[VersionToggle] custom.js loaded");

  const setVersion = (version) => {
    console.log("[VersionToggle] Setting version to:", version);

    document.querySelectorAll(".version-opensource, .version-pro").forEach(el => {
      el.style.display = el.classList.contains(`version-${version}`) ? "" : "none";
    });

    localStorage.setItem("version", version);
    console.log("[VersionToggle] localStorage updated:", localStorage.getItem("version"));

    // Update any visible dropdowns
    const selects = document.querySelectorAll("#version-select");
    selects.forEach(sel => sel.value = version);
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
