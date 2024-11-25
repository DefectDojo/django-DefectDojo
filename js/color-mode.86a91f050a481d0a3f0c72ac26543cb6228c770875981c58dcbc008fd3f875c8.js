(()=>{(()=>{"use strict";let t=localStorage.getItem("theme"),r=()=>t||(window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"),a=function(e){e==="auto"&&window.matchMedia("(prefers-color-scheme: dark)").matches?document.documentElement.setAttribute("data-bs-theme","dark"):document.documentElement.setAttribute("data-bs-theme",e)};a(r()),window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>{(t!=="light"||t!=="dark")&&a(r())}),window.addEventListener("DOMContentLoaded",()=>{document.querySelectorAll("[data-bs-theme-value]").forEach(e=>{e.addEventListener("click",()=>{let d=e.getAttribute("data-bs-theme-value");localStorage.setItem("theme",d),a(d)})})})})();})();
/*!
 * Modified from
 * Color mode toggler for Bootstrap's docs (https://getbootstrap.com/)
 * Copyright 2011-2022 The Bootstrap Authors
 * Licensed under the Creative Commons Attribution 3.0 Unported License.
 */
