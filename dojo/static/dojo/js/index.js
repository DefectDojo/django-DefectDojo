/* ============================================================
   Bootstrap JS replacement shims (vanilla JS)
   Replaces bootstrap.min.js for: dropdowns, collapses, tooltips
   ============================================================ */

/* ---- Dropdown shim ----
   Handles [data-toggle="dropdown"] by toggling .open on parent.
   Bootstrap CSS rule  .open > .dropdown-menu { display: block }  does the rest.
   Also fires jQuery events (show/shown/hide/hidden.bs.dropdown) so existing
   table-responsive overflow handlers keep working.
*/
(function () {
    function fireJQueryEvent(el, name) {
        if (typeof jQuery !== 'undefined') {
            jQuery(el).trigger(name);
        }
    }

    function closeAllDropdowns(except) {
        document.querySelectorAll('.open').forEach(function (el) {
            if (el !== except) {
                el.classList.remove('open');
                fireJQueryEvent(el, 'hide.bs.dropdown');
                fireJQueryEvent(el, 'hidden.bs.dropdown');
            }
        });
    }

    document.addEventListener('click', function (e) {
        var toggle = e.target.closest('[data-toggle="dropdown"]');
        if (toggle) {
            e.preventDefault();
            e.stopPropagation();
            var parent = toggle.closest('.dropdown, .btn-group, .dropup') || toggle.parentElement;
            var wasOpen = parent.classList.contains('open');

            // Close all other open dropdowns
            closeAllDropdowns(parent);

            if (wasOpen) {
                parent.classList.remove('open');
                fireJQueryEvent(parent, 'hide.bs.dropdown');
                fireJQueryEvent(parent, 'hidden.bs.dropdown');
            } else {
                parent.classList.add('open');
                fireJQueryEvent(parent, 'show.bs.dropdown');
                fireJQueryEvent(parent, 'shown.bs.dropdown');
            }
            return;
        }

        // Clicks inside an open dropdown menu (e.g. selecting options in the
        // bulk edit form) must not collapse the menu. Only clicks outside any
        // open dropdown — or on a submit button, which navigates anyway —
        // should close it.
        if (e.target.closest('.open > .dropdown-menu')) return;

        // Click outside any dropdown → close all
        closeAllDropdowns(null);
    });

    // Escape key closes dropdowns
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeAllDropdowns(null);
    });
})();

/* ---- Collapse shim ----
   Handles [data-toggle="collapse"] by toggling .in on the target element.
   CSS in tailwind.css:  .collapse { display:none }  .collapse.in { display:block }
*/
/* Animate a collapse target open/closed by sliding its height between 0 and
   its natural size, then settling to auto (open) or display:none via .in
   (closed). Falls back to an instant toggle when reduced motion is requested. */
function animateCollapse(target, toggle) {
    if (target._ddCollapsing) return;  // ignore clicks while mid-animation
    var willOpen = !target.classList.contains('in');
    if (toggle) toggle.setAttribute('aria-expanded', willOpen ? 'true' : 'false');

    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        target.classList.toggle('in', willOpen);
        return;
    }

    var DURATION = 250;
    var finished = false;
    target._ddCollapsing = true;

    if (willOpen) target.classList.add('in');     // make it measurable / visible

    // Animate height AND vertical padding together, so the panel collapses all
    // the way to 0 instead of stalling at the panel-body's padding "floor".
    var cs = getComputedStyle(target);
    var padTop = cs.paddingTop, padBottom = cs.paddingBottom;
    // In border-box (Tailwind's default) the height property already includes
    // padding, so animate to the full scrollHeight; only subtract in content-box.
    var fullH = cs.boxSizing === 'border-box'
        ? target.scrollHeight
        : target.scrollHeight - parseFloat(padTop) - parseFloat(padBottom);
    var contentH = fullH + 'px';
    var collapsed = { height: '0px', paddingTop: '0px', paddingBottom: '0px' };
    var expanded = { height: contentH, paddingTop: padTop, paddingBottom: padBottom };
    var from = willOpen ? collapsed : expanded;
    var to = willOpen ? expanded : collapsed;

    target.style.overflow = 'hidden';
    target.style.height = from.height;
    target.style.paddingTop = from.paddingTop;
    target.style.paddingBottom = from.paddingBottom;
    void target.offsetHeight;                     // force reflow so the transition runs
    target.style.transition = 'height ' + DURATION + 'ms ease, padding ' + DURATION + 'ms ease';
    target.style.height = to.height;
    target.style.paddingTop = to.paddingTop;
    target.style.paddingBottom = to.paddingBottom;

    function done() {
        if (finished) return;
        finished = true;
        if (!willOpen) target.classList.remove('in');  // hide before clearing styles
        target.style.transition = '';
        target.style.height = '';
        target.style.paddingTop = '';
        target.style.paddingBottom = '';
        target.style.overflow = '';
        target._ddCollapsing = false;
        target.removeEventListener('transitionend', onEnd);
    }
    function onEnd(ev) { if (ev.target === target && ev.propertyName === 'height') done(); }
    target.addEventListener('transitionend', onEnd);
    setTimeout(done, DURATION + 80);          // fallback if transitionend doesn't fire
}

document.addEventListener('click', function (e) {
    var toggle = e.target.closest('[data-toggle="collapse"]');
    if (!toggle) return;

    // Don't prevent default for links with real href (non-collapse)
    var targetSel = toggle.getAttribute('data-target')
                  || toggle.getAttribute('href');
    if (!targetSel || targetSel === '#') return;

    e.preventDefault();

    // Handle comma-separated targets (rare but possible)
    targetSel.split(',').forEach(function (sel) {
        sel = sel.trim();
        if (!sel) return;
        var target = document.querySelector(sel);
        if (target) {
            animateCollapse(target, toggle);
        }
    });
});

/* ---- Tooltip / Popover jQuery shims ----
   Replace Bootstrap tooltip/popover plugins with lightweight implementations.
   For has-popover elements, CSS ::after shows data-content on hover.
*/
(function waitForJQuery() {
    if (typeof jQuery === 'undefined') {
        // jQuery not loaded yet (unlikely since it's in <head>), retry
        return setTimeout(waitForJQuery, 50);
    }

    // $.fn.tooltip — Bootstrap-compatible shim replacing both Bootstrap and jQuery UI tooltip.
    // Supports: init (no-arg or options), 'show', 'hide', 'destroy', 'fixTitle'
    // Always override — jQuery UI tooltip doesn't support Bootstrap's string-action API.
    (function () {
        var TOOLTIP_CLASS = 'dd-tooltip';

        function createTooltipEl(text) {
            var tip = document.createElement('div');
            tip.className = TOOLTIP_CLASS;
            tip.textContent = text;
            tip.style.cssText =
                'position:absolute;z-index:1070;background:#333;color:#fff;' +
                'border-radius:4px;padding:4px 8px;font-size:12px;line-height:1.4;' +
                'white-space:nowrap;pointer-events:none;opacity:0;transition:opacity .15s;';
            document.body.appendChild(tip);
            return tip;
        }

        function positionTooltip(el, tip, placement) {
            var rect = el.getBoundingClientRect();
            tip.style.display = 'block';
            tip.style.opacity = '1';
            var tw = tip.offsetWidth, th = tip.offsetHeight;
            var gap = 6;
            if (placement === 'bottom') {
                tip.style.top = (rect.bottom + window.scrollY + gap) + 'px';
                tip.style.left = (rect.left + window.scrollX + rect.width / 2 - tw / 2) + 'px';
            } else if (placement === 'left') {
                tip.style.top = (rect.top + window.scrollY + rect.height / 2 - th / 2) + 'px';
                tip.style.left = (rect.left + window.scrollX - tw - gap) + 'px';
            } else if (placement === 'right') {
                tip.style.top = (rect.top + window.scrollY + rect.height / 2 - th / 2) + 'px';
                tip.style.left = (rect.right + window.scrollX + gap) + 'px';
            } else {
                // default: top
                tip.style.top = (rect.top + window.scrollY - th - gap) + 'px';
                tip.style.left = (rect.left + window.scrollX + rect.width / 2 - tw / 2) + 'px';
            }
        }

        function initTooltip(el, opts) {
            if (el._ddTooltip) return; // already initialized
            var placement = (opts && opts.placement) || el.getAttribute('data-placement') || 'top';
            // Save title and remove native tooltip to avoid double display
            var title = el.getAttribute('title') || el.getAttribute('data-original-title') || '';
            if (el.getAttribute('title')) {
                el.setAttribute('data-original-title', title);
                el.removeAttribute('title');
            }
            el._ddTooltip = { placement: placement, tip: null };
            el._ddTooltipShow = function () {
                var text = el.getAttribute('data-original-title') || '';
                if (!text) return;
                if (!el._ddTooltip.tip) {
                    el._ddTooltip.tip = createTooltipEl(text);
                } else {
                    el._ddTooltip.tip.textContent = text;
                }
                positionTooltip(el, el._ddTooltip.tip, el._ddTooltip.placement);
            };
            el._ddTooltipHide = function () {
                if (el._ddTooltip && el._ddTooltip.tip) {
                    el._ddTooltip.tip.style.opacity = '0';
                    el._ddTooltip.tip.style.display = 'none';
                }
            };
            el.addEventListener('mouseenter', el._ddTooltipShow);
            el.addEventListener('mouseleave', el._ddTooltipHide);
        }

        jQuery.fn.tooltip = function (action) {
            if (typeof action === 'object' || action === undefined) {
                // Init
                var opts = action || {};
                return this.each(function () { initTooltip(this, opts); });
            }
            return this.each(function () {
                var el = this;
                if (action === 'show') {
                    if (!el._ddTooltip) initTooltip(el, {});
                    if (el._ddTooltipShow) el._ddTooltipShow();
                } else if (action === 'hide') {
                    if (el._ddTooltipHide) el._ddTooltipHide();
                } else if (action === 'destroy') {
                    if (el._ddTooltip && el._ddTooltip.tip) {
                        el._ddTooltip.tip.remove();
                    }
                    if (el._ddTooltipShow) el.removeEventListener('mouseenter', el._ddTooltipShow);
                    if (el._ddTooltipHide) el.removeEventListener('mouseleave', el._ddTooltipHide);
                    // Restore native title
                    var orig = el.getAttribute('data-original-title');
                    if (orig) {
                        el.setAttribute('title', orig);
                        el.removeAttribute('data-original-title');
                    }
                    delete el._ddTooltip;
                    delete el._ddTooltipShow;
                    delete el._ddTooltipHide;
                } else if (action === 'fixTitle') {
                    // Re-read title attr (may have been changed by JS) into data-original-title
                    var t = el.getAttribute('title');
                    if (t) {
                        el.setAttribute('data-original-title', t);
                        el.removeAttribute('title');
                    }
                }
            });
        };
    })();

    // $.fn.popover — lightweight shim that shows/hides data-content
    if (!jQuery.fn.popover) {
        jQuery.fn.popover = function (action) {
            return this.each(function () {
                var el = this;
                var content = el.getAttribute('data-content');
                if (!content) return;

                if (action === 'show') {
                    // Create or show the popover element
                    var pop = el._ddPopover;
                    if (!pop) {
                        pop = document.createElement('div');
                        pop.className = 'dd-popover';
                        pop.textContent = content;
                        pop.style.cssText =
                            'position:absolute;z-index:1070;background:#fff;border:1px solid #ccc;' +
                            'border-radius:4px;padding:6px 10px;font-size:12px;box-shadow:0 2px 6px rgba(0,0,0,.15);' +
                            'white-space:nowrap;pointer-events:none;';
                        document.body.appendChild(pop);
                        el._ddPopover = pop;
                    }
                    // Position near the element
                    var rect = el.getBoundingClientRect();
                    var placement = el.getAttribute('data-placement') || 'right';
                    pop.style.display = 'block';
                    if (placement === 'right') {
                        pop.style.top = (rect.top + window.scrollY + rect.height / 2 - 14) + 'px';
                        pop.style.left = (rect.right + window.scrollX + 6) + 'px';
                    } else if (placement === 'left') {
                        pop.style.top = (rect.top + window.scrollY + rect.height / 2 - 14) + 'px';
                        pop.style.left = (rect.left + window.scrollX - pop.offsetWidth - 6) + 'px';
                    } else if (placement === 'top') {
                        pop.style.top = (rect.top + window.scrollY - pop.offsetHeight - 6) + 'px';
                        pop.style.left = (rect.left + window.scrollX + rect.width / 2 - pop.offsetWidth / 2) + 'px';
                    } else {
                        pop.style.top = (rect.bottom + window.scrollY + 6) + 'px';
                        pop.style.left = (rect.left + window.scrollX + rect.width / 2 - pop.offsetWidth / 2) + 'px';
                    }
                } else if (action === 'hide') {
                    if (el._ddPopover) el._ddPopover.style.display = 'none';
                } else if (action === 'destroy') {
                    if (el._ddPopover) {
                        el._ddPopover.remove();
                        el._ddPopover = null;
                    }
                }
            });
        };
    }

    // $.fn.highlight — no-op shim (jquery-highlight plugin removed)
    // Templates still call $('body').highlight(term); this prevents errors.
    if (!jQuery.fn.highlight) {
        jQuery.fn.highlight = function () { return this; };
    }

})();


/* ============================================================
   Vanilla JS initialization (no jQuery dependency)
   ============================================================ */
document.addEventListener('DOMContentLoaded', function () {

    // ---- Accessibility: make .has-popover help icons keyboard-focusable ----
    document.querySelectorAll('.has-popover[data-content]').forEach(function (el) {
        if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
        if (!el.hasAttribute('role')) el.setAttribute('role', 'img');
        if (!el.getAttribute('aria-label') && el.getAttribute('data-content')) {
            el.setAttribute('aria-label', el.getAttribute('data-content'));
        }
    });

    // ---- Back-to-top button ----
    var toTop = document.createElement('a');
    toTop.id = 'toTop';
    toTop.title = 'Back to Top';
    toTop.setAttribute('aria-label', 'Back to Top');
    toTop.className = 'btn btn-primary btn-circle';
    toTop.innerHTML = '<i class="fa-solid fa-arrow-up fa-fw"></i>';
    toTop.style.display = 'none';
    document.body.appendChild(toTop);

    window.addEventListener('scroll', function () {
        toTop.style.display = window.scrollY > 300 ? '' : 'none';
    });

    toTop.addEventListener('click', function (e) {
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // ---- File upload auto-submit ----
    document.querySelectorAll('form#replace_risk_file input[type="file"], div.controls.file input').forEach(function (el) {
        el.addEventListener('change', function () {
            this.closest('form').submit();
        });
    });

    // ---- Accept all findings checkboxes ----
    document.querySelectorAll('a.accept-all-findings').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelectorAll('ul#id_accepted_findings input').forEach(function (cb) {
                cb.checked = true;
            });
        });
    });

    // ---- Alert auto-dismiss (fade out after 20s) ----
    setTimeout(function () {
        document.querySelectorAll('.alert-dismissible:not(.announcement-banner)').forEach(function (el) {
            el.classList.add('fade-out');
            setTimeout(function () { el.remove(); }, 350);
        });
    }, 20000);

    // ---- Auto-focus first form field ----
    var content = document.getElementById('base-content');
    if (content) {
        var form = content.querySelector('form');
        if (form) {
            var focusable = form.querySelector(
                'input:not([type=hidden]):not([type=submit]):not([type=checkbox]):not(.datepicker), select, textarea'
            );
            // Skip filter inputs, quick-add inputs, and specific textareas
            if (focusable &&
                !focusable.closest('.filters') &&
                focusable.id !== 'id_entry' &&
                focusable.id !== 'quick_add_finding' &&
                focusable.tagName !== 'BUTTON') {
                focusable.focus();
            }
        }
    }

    // ---- Progress crumbs smooth scroll ----
    var progressCrumbs = document.getElementById('progress-crumbs');
    if (progressCrumbs) {
        progressCrumbs.addEventListener('click', function (e) {
            var link = e.target.closest('a');
            if (link) {
                e.preventDefault();
                var href = link.getAttribute('href');
                var target = document.querySelector(href);
                if (target) {
                    window.scrollTo({
                        top: target.offsetTop - 55,
                        behavior: 'smooth'
                    });
                }
            }
        });
    }

    // ---- Flatpickr datepicker init ----
    if (typeof flatpickr !== 'undefined') {
        flatpickr('.datepicker', { dateFormat: 'Y-m-d', allowInput: true });
    }

    // ---- Re-initialize third-party plugins after htmx content swaps ----
    document.body.addEventListener('htmx:afterSwap', function (evt) {
        // Re-init datepickers in swapped content
        var pickers = evt.detail.target.querySelectorAll('.datepicker');
        if (pickers.length && typeof flatpickr !== 'undefined') {
            flatpickr(pickers, { dateFormat: 'Y-m-d', allowInput: true });
        }
        // Re-init DataTables in swapped content
        var tables = evt.detail.target.querySelectorAll('table.dataTable');
        if (tables.length && typeof jQuery !== 'undefined' && jQuery.fn.DataTable) {
            tables.forEach(function (t) { jQuery(t).DataTable(); });
        }
    });
});

$.fn.serializeObject = function()
{
    var o = {};
    var a = this.serializeArray();
    $.each(a, function() {
        if (o[this.name] !== undefined && o[this.name] != 'csrfmiddlewaretoken') {
            if (!o[this.name].push) {
                o[this.name] = [o[this.name]];
            }
            o[this.name].push(this.value || '');
        } else {
            o[this.name] = this.value || '';
        }
    });
    return o;
};

//methods removed in django 3.1. we copy them here to keep this popup thing working
// but this definately needs a rework, but with UI v2 in the works this is acceptable
function id_to_windowname(text) {
    text = text.replace(/\./g, '__dot__');
    text = text.replace(/\-/g, '__dash__');
    return text;
}

function windowname_to_id(text) {
    text = text.replace(/__dot__/g, '.');
    text = text.replace(/__dash__/g, '-');
    return text;
}

function emptyEndpoints(win) {
    var name = windowname_to_id(win.name);
    var elem = document.getElementById(name);
    if (elem) elem.innerHTML = '';
}

function html_unescape(text) {
    // Unescape a string that was escaped using django.utils.html.escape.
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&amp;/g, '&');
    return text;
}

function dismissAddAnotherPopupDojo(win, newId, newRepr) {
    // newId and newRepr are expected to have previously been escaped by
    // django.utils.html.escape.
    newId = html_unescape(newId);
    newRepr = html_unescape(newRepr);
    var name = windowname_to_id(win.name);
    var elem = document.getElementById(name);
    var o;
    if (elem) {
        var elemName = elem.nodeName.toUpperCase();
        if (elemName === 'SELECT') {
            var existing = elem.querySelector("option[value='" + newId + "']");
            if (!existing) {
                o = new Option(newRepr, newId);
                elem.options[elem.options.length] = o;
                o.selected = true;
            } else {
                existing.selected = true;
            }
        } else if (elemName === 'INPUT') {
            if (elem.className.indexOf('vManyToManyRawIdAdminField') !== -1 && elem.value) {
                elem.value += ',' + newId;
            } else {
                elem.value = newId;
            }
        }
    } else {
        var toId = name + "_to";
        o = new Option(newRepr, newId);
        SelectBox.add_to_cache(toId, o);
        SelectBox.redisplay(toId);
    }
}

// punchcard() function moved to metrics.js (Chart.js bubble chart)

function togglePassVisibility() {
    var passwdInput = document.getElementById("id_password");
    var toggleBox = document.getElementById("toggleBox");

    // swap password
    if (passwdInput.type === "password") {
        passwdInput.type = "text";
        toggleBox.innerHTML = "<i class='fa-solid fa-eye-slash'></i>\
        <span>Hide Password</span>";
    } else {
        passwdInput.type = "password";
        toggleBox.innerHTML = "<i class='fa-solid fa-eye'></i>\
        <span>Show Password</span>";
    }
}


// Parse a string that contains HTML to retrieve value from the HTML tag or Attribute, returning only a TEXT version.
// The htmlTagAttributValye is optional, and if supplied, then this function will look within the HTML tag attributes to
// return the value. Example htmlTagAttributValye ( data-content=****** )
// This function is used in the product.html,  view_product_details adn engagements_all for proper DataTables exports.
function getDojoExportValueFromTag(htmlString, tag, htmlTagAttribValue){
    parser = new DOMParser();
    doc = parser.parseFromString(htmlString.toString(), "text/html");
    var tags = doc.getElementsByTagName(tag.toString());
    var l = tags.length;
    var tagsValueArray = [];
    var exportValue = "";
    if (htmlTagAttribValue) {
        for (i = 0; i < l; i++) {
            var tempAttribValue = tags[i].getAttribute(htmlTagAttribValue.toString());
            // Only append values if they are not null, empty or NaN
            if (tempAttribValue) {
                tagsValueArray.push(tempAttribValue);
            }
        }
        exportValue = tagsValueArray;
    }
    else {
        if (l >= 1) {
            // Iterate through all HTML tags and append the return values to the array
            for (i = 0; i < l; i++) {
                tagsValueArray.push(tags[i].textContent);
            }
            exportValue = tagsValueArray;
        }
    else {
        exportValue = htmlString;
    }}

    // Replace by a space any HTML tags that might still be in the string
    return exportValue.toString().replace(/<\/?[^>]+(>|$)/g, " ");
}

generateGUID = (typeof(window.crypto) != 'undefined' &&
                typeof(window.crypto.getRandomValues) != 'undefined') ?
    function() {
        // If we have a cryptographically secure PRNG, use that
        // https://stackoverflow.com/questions/6906916/collisions-when-generating-uuids-in-javascript
        var buf = new Uint16Array(8);
        window.crypto.getRandomValues(buf);
        var S4 = function(num) {
            var ret = num.toString(16);
            while(ret.length < 4){
                ret = "0"+ret;
            }
            return ret;
        };
        return (S4(buf[0])+S4(buf[1])+"-"+S4(buf[2])+"-"+S4(buf[3])+"-"+S4(buf[4])+"-"+S4(buf[5])+S4(buf[6])+S4(buf[7]));
    }

    :

    function() {
        // Otherwise, just use Math.random
        // https://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/2117523#2117523
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
            return v.toString(16);
        });
    };

    var absolutePath = function(href) {
        var link = document.createElement("a");
        link.href = href;
        return link.href;
    }

function clear_form(form){
    var formEl = (form instanceof HTMLElement) ? form : form[0]; // Handle both DOM and jQuery
    formEl.querySelectorAll('input, select, textarea').forEach(function(el) {
        switch(el.type) {
            case 'number':
            case 'password':
            case 'select-one':
            case 'text':
            case 'textarea':
                el.value = '';
                break;
            case 'checkbox':
            case 'radio':
                el.checked = false;
                break;
            case 'select-multiple':
                // Clear select2 widgets (requires jQuery for select2 API)
                if (typeof jQuery !== 'undefined' && jQuery(el).hasClass('select2-hidden-accessible')) {
                    jQuery(el).data('select2').$container.find('.select2-selection__choice').remove();
                }
                // Clear selected options
                Array.from(el.options).forEach(function(opt) { opt.selected = false; });
                el.dispatchEvent(new Event('change'));
                break;
        }
    });
}
