/*
 * components.js -- Alpine.js component registrations for VulnAdvisor.
 *
 * Uses the @alpinejs/csp build (not the standard alpinejs build). The CSP
 * build replaces Function() expression evaluation with a restricted parser,
 * which is required because our CSP policy does not include unsafe-eval.
 *
 * CSP build constraints (all code here must comply):
 *   - No arrow functions in x-data expressions (use function() {} syntax)
 *   - No template literals in x-data expressions (use string concatenation)
 *   - No console.log() or globals like Math/JSON in inline x-data
 *   - All logic must live in Alpine.data() method bodies (not inline HTML attrs)
 *
 * Load order (enforced by defer in layout.html):
 *   1. Alpine CDN script (declares window.Alpine, fires alpine:init)
 *   2. This file (registers Alpine.data components before Alpine initializes DOM)
 *   3. Bootstrap JS (unrelated, after Alpine)
 *
 * Why defer on all scripts: defer preserves document order and runs after
 * HTML parsing. Without defer, this file might execute before Alpine is
 * available and the Alpine.data() call would fail.
 */

/*
 * assetTable component -- client-side search, sort, and filter for the
 * asset list table.
 *
 * Pattern: Data-down / Events-up (DDEU). The server renders the full table
 * as plain HTML on page load. Alpine reads the rendered rows into this.rows
 * and drives visibility via filteredRows. No server round-trips needed for
 * filtering -- the constraint (< ~500 rows) is documented in STATE.md.
 *
 * State keys:
 *   search     -- text filter applied to name, hostname, and ip columns
 *   sortCol    -- column key currently sorted on ('' = none)
 *   sortDir    -- 'asc' or 'desc'
 *   rows       -- array of row objects read from DOM data-* attributes
 *
 * URL sync: search and sort state is mirrored to the query string via
 * history.replaceState() so the browser Back button and page refresh
 * preserve the user's filter state.
 */
document.addEventListener('alpine:init', function () {
    Alpine.data('assetTable', function () {
        return {
            search: '',
            sortCol: '',
            sortDir: 'asc',
            rows: [],
            init: function () {
                var tbody = this.$el.querySelector('tbody');
                if (!tbody) { return; }
                this.rows = Array.from(tbody.querySelectorAll('tr[data-row]')).map(function (tr) {
                    return {
                        el: tr,
                        name: (tr.dataset.name || '').toLowerCase(),
                        hostname: (tr.dataset.hostname || '').toLowerCase(),
                        ip: (tr.dataset.ip || '').toLowerCase(),
                        criticality: tr.dataset.criticality || '',
                        environment: tr.dataset.environment || '',
                        vulnCount: parseInt(tr.dataset.vulnCount || '0', 10),
                    };
                });
                // Restore filter state from URL query params so refresh and
                // the browser Back button preserve the user's previous filter.
                var params = new URLSearchParams(window.location.search);
                this.search = params.get('search') || '';
                this.sortCol = params.get('sort') || '';
                this.sortDir = params.get('dir') || 'asc';
            },
            get filteredRows() {
                var q = this.search.toLowerCase();
                return this.rows.filter(function (r) {
                    return !q || r.name.indexOf(q) !== -1 || r.hostname.indexOf(q) !== -1 || r.ip.indexOf(q) !== -1;
                });
            },
            updateUrl: function () {
                var params = new URLSearchParams(window.location.search);
                if (this.search) { params.set('search', this.search); }
                else { params.delete('search'); }
                if (this.sortCol) {
                    params.set('sort', this.sortCol);
                    params.set('dir', this.sortDir);
                } else {
                    params.delete('sort');
                    params.delete('dir');
                }
                var qs = params.toString();
                history.replaceState(null, '', qs ? '?' + qs : window.location.pathname);
            },
        };
    });
});

/*
 * HTMX + Alpine bridge -- re-initialize Alpine on HTMX-swapped subtrees.
 *
 * Problem: HTMX replaces DOM nodes on swap. Alpine's MutationObserver sees
 * the new nodes but does not automatically call init() on Alpine.data()
 * components in freshly swapped content.
 *
 * Solution: Call Alpine.initTree(swappedElement) after every HTMX swap.
 * This re-runs Alpine's initialization pass on just the swapped subtree,
 * wiring up x-data, x-bind, x-on, etc. without resetting components
 * elsewhere on the page.
 *
 * Why event.detail.elt (not document.body): Scoping to the swapped element
 * avoids re-initializing all Alpine components on the page (which would
 * reset their state). Only the replaced subtree needs re-initialization.
 */
document.addEventListener('htmx:afterSwap', function (event) {
    if (typeof Alpine !== 'undefined') {
        Alpine.initTree(event.detail.elt);
    }
});
