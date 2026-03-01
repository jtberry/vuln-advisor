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
 * as plain HTML on page load. Alpine reads the rendered rows via data-*
 * attributes into this.rows and drives visibility/ordering client-side.
 * No server round-trips are needed for filtering or sorting.
 *
 * Scale constraint: client-side filtering is intentional and documented.
 * This component targets < ~500 assets. Above that threshold, server-side
 * pagination would be required. This constraint is logged in STATE.md.
 *
 * State keys:
 *   search      -- text filter applied to hostname, name, and ip columns
 *   criticality -- exact-match filter on criticality ('' = all)
 *   environment -- exact-match filter on environment ('' = all)
 *   sortCol     -- column key currently sorted on ('hostname' default)
 *   sortDir     -- 'asc' or 'desc'
 *   rows        -- array of row objects read from DOM data-* attributes
 *   _debounceTimer  -- timer handle for search debounce
 *   _critOrdinal    -- criticality -> numeric rank map for semantic sort
 *
 * URL sync: all filter and sort state is mirrored to the query string via
 * history.replaceState() so the browser Back button and page refresh
 * preserve the user's filter state.
 *
 * Input handlers use :value + @input instead of x-model. This is required
 * because the CSP build's restricted parser does not support x-model, and
 * using it would generate CSP violations at runtime.
 */
document.addEventListener('alpine:init', function () {
    /*
     * vulnTable component -- client-side search, filter, sort, and URL sync
     * for the vulnerability table on the asset detail page.
     *
     * Architecture: The component root (x-data) is on the outer vulnerability
     * card div, NOT on the <tbody>. This is required because the HTMX add-CVE
     * form targets #vuln-table-body with hx-swap="innerHTML". If Alpine owned
     * the tbody, HTMX's DOM replacement would destroy the component.
     * By placing x-data on the outer card, the tbody swap happens inside
     * Alpine's scope without touching the component boundary.
     *
     * After HTMX swaps new rows, the htmx:afterSwap listener at the bottom
     * calls refreshRows() to re-read the updated DOM into this.rows.
     *
     * Checkbox coexistence: The vanilla JS checkbox code (getCheckboxes()) is
     * patched in the template to filter out hidden rows so "Select All" only
     * selects visible rows. Alpine does NOT own the checkboxes -- they stay
     * in vanilla JS territory.
     *
     * State keys:
     *   search          -- text filter on CVE ID + description
     *   severity        -- exact-match filter on severity ('' = all)
     *   status          -- exact-match filter on status ('' = all)
     *   sortCol         -- column key currently sorted on ('severity' default)
     *   sortDir         -- 'asc' or 'desc'
     *   rows            -- array of row objects read from DOM data-* attributes
     *   _debounceTimer  -- timer handle for search debounce
     *   _severityOrdinal -- severity -> numeric rank map (P1=0 ... P4=3)
     *   _statusOrdinal   -- status -> numeric rank map for semantic sort
     *
     * Scale constraint: client-side filtering targets < ~500 vulnerabilities
     * per asset. Above that threshold, server-side pagination would be needed.
     */
    Alpine.data('vulnTable', function () {
        return {
            search: '',
            severity: '',
            status: '',
            sortCol: 'severity',
            sortDir: 'desc',
            rows: [],
            _debounceTimer: null,
            _severityOrdinal: null,
            _statusOrdinal: null,

            init: function () {
                // Ordinal maps for semantic sort.
                // P1 (Critical) ranks 0 so ascending sort puts most-critical first.
                // With default sortDir='desc', P4 (lowest) would appear first --
                // so we use sortDir='desc' with the ordinal inverted: higher ordinal
                // = lower severity, and desc puts lower ordinal (more critical) first.
                this._severityOrdinal = { p1: 0, p2: 1, p3: 2, p4: 3, critical: 0, high: 1, medium: 2, low: 3 };
                this._statusOrdinal = { open: 0, in_review: 1, remediated: 2, deferred: 3, closed: 4 };

                this.readRows();

                // Restore filter/sort state from URL query params.
                var params = new URLSearchParams(window.location.search);
                this.search = params.get('search') || '';
                var sev = params.get('severity') || '';
                // Validate severity against known values to prevent garbage from URL.
                this.severity = (this._severityOrdinal[sev] !== undefined) ? sev : '';
                var st = params.get('status') || '';
                // Validate status against known values.
                this.status = (this._statusOrdinal[st] !== undefined) ? st : '';

                if (params.get('sort')) {
                    this.sortCol = params.get('sort');
                    this.sortDir = params.get('dir') || 'desc';
                } else {
                    // Default: severity descending (P1 / Critical first).
                    this.sortCol = 'severity';
                    this.sortDir = 'desc';
                }

                this._applyVisibility();
            },

            // readRows scans the tbody for tr[data-row] elements and maps each
            // to a plain JS object. Called on init AND after HTMX swaps.
            // Uses tr[data-row] selector to exclude the empty-state row (data-empty-state).
            readRows: function () {
                var tbody = this.$el.querySelector('tbody');
                if (!tbody) { return; }
                this.rows = Array.from(tbody.querySelectorAll('tr[data-row]')).map(function (tr) {
                    return {
                        el: tr,
                        cve: (tr.dataset.cve || '').toLowerCase(),
                        description: (tr.dataset.description || '').toLowerCase(),
                        severity: (tr.dataset.severity || '').toLowerCase(),
                        cvss: parseFloat(tr.dataset.cvss || '0'),
                        status: (tr.dataset.status || '').toLowerCase(),
                    };
                });
            },

            // refreshRows is called by the htmx:afterSwap listener when HTMX
            // swaps new rows into #vuln-table-body. It re-reads the updated DOM
            // and re-applies the current filter/sort state.
            refreshRows: function () {
                this.readRows();
                this._applyVisibility();
            },

            // ----------------------------------------------------------------
            // Input handlers (CSP-safe: no x-model, no arrow functions)
            // ----------------------------------------------------------------

            // setSearch is called on @input from the search text box.
            setSearch: function (event) {
                this.search = event.target.value;
                this._scheduleUrlUpdate();
                this._applyVisibility();
            },

            // setSeverity is called on @change from the severity select.
            setSeverity: function (event) {
                this.severity = event.target.value;
                this.updateUrl();
                this._applyVisibility();
            },

            // setStatus is called on @change from the status select.
            setStatus: function (event) {
                this.status = event.target.value;
                this.updateUrl();
                this._applyVisibility();
            },

            // clearSearch resets the text search and reapplies filters.
            clearSearch: function () {
                this.search = '';
                this.updateUrl();
                this._applyVisibility();
            },

            // clearFilters resets all filters and sort to defaults.
            clearFilters: function () {
                this.search = '';
                this.severity = '';
                this.status = '';
                this.sortCol = 'severity';
                this.sortDir = 'desc';
                this.updateUrl();
                this._applyVisibility();
            },

            // ----------------------------------------------------------------
            // Computed getters
            // ----------------------------------------------------------------

            // hasActiveFilters: true when any filter differs from default.
            // Used to conditionally show the "Clear filters" link.
            get hasActiveFilters() {
                return this.search !== '' || this.severity !== '' || this.status !== '';
            },

            // matchCount: number of rows currently visible.
            get matchCount() {
                var count = 0;
                for (var i = 0; i < this.rows.length; i++) {
                    if (this.rows[i].el.style.display !== 'none') {
                        count++;
                    }
                }
                return count;
            },

            // totalCount: total number of server-rendered rows (unfiltered).
            get totalCount() {
                return this.rows.length;
            },

            // ----------------------------------------------------------------
            // Core filter + sort engine
            // ----------------------------------------------------------------

            _applyVisibility: function () {
                var self = this;
                var q = self.search.toLowerCase();

                // Step 1: build the filtered subset.
                var visible = self.rows.filter(function (r) {
                    // Text search on CVE ID + description (both pre-lowercased in readRows).
                    if (q && r.cve.indexOf(q) === -1 && r.description.indexOf(q) === -1) {
                        return false;
                    }
                    // Exact severity filter.
                    if (self.severity && r.severity !== self.severity) {
                        return false;
                    }
                    // Exact status filter.
                    if (self.status && r.status !== self.status) {
                        return false;
                    }
                    return true;
                });

                // Step 2: sort the filtered subset.
                if (self.sortCol) {
                    var col = self.sortCol;
                    var dir = self.sortDir === 'asc' ? 1 : -1;
                    var sevOrd = self._severityOrdinal;
                    var stOrd = self._statusOrdinal;
                    visible.sort(function (a, b) {
                        var av, bv;
                        if (col === 'severity') {
                            // Semantic sort: use ordinal map. Unknown values rank last (99).
                            av = sevOrd[a.severity] !== undefined ? sevOrd[a.severity] : 99;
                            bv = sevOrd[b.severity] !== undefined ? sevOrd[b.severity] : 99;
                            return dir * (av - bv);
                        }
                        if (col === 'status') {
                            av = stOrd[a.status] !== undefined ? stOrd[a.status] : 99;
                            bv = stOrd[b.status] !== undefined ? stOrd[b.status] : 99;
                            return dir * (av - bv);
                        }
                        if (col === 'cvss') {
                            // Numeric comparison for CVSS score.
                            return dir * (a.cvss - b.cvss);
                        }
                        // String sort for CVE ID.
                        av = a[col] || '';
                        bv = b[col] || '';
                        if (av < bv) { return -1 * dir; }
                        if (av > bv) { return 1 * dir; }
                        return 0;
                    });
                }

                // Step 3: hide all rows, then show and reorder the visible set.
                // DOM reorder via appendChild moves existing nodes -- no clone needed.
                var tbody = self.$el.querySelector('tbody');
                for (var i = 0; i < self.rows.length; i++) {
                    self.rows[i].el.style.display = 'none';
                }
                for (var j = 0; j < visible.length; j++) {
                    visible[j].el.style.display = '';
                    tbody.appendChild(visible[j].el);
                }
            },

            // ----------------------------------------------------------------
            // Sort toggle
            // ----------------------------------------------------------------

            // toggleSort cycles: different col -> asc; same+asc -> desc; same+desc -> severity default.
            toggleSort: function (col) {
                if (this.sortCol !== col) {
                    this.sortCol = col;
                    this.sortDir = 'asc';
                } else if (this.sortDir === 'asc') {
                    this.sortDir = 'desc';
                } else {
                    // Third click resets to default: severity descending (Critical first).
                    this.sortCol = 'severity';
                    this.sortDir = 'desc';
                }
                this.updateUrl();
                this._applyVisibility();
            },

            // sortActive returns true when the given column is the active sort key.
            sortActive: function (col) {
                return this.sortCol === col;
            },

            // sortAsc returns true when sorted ascending on this column.
            sortAsc: function (col) {
                return this.sortCol === col && this.sortDir === 'asc';
            },

            // ----------------------------------------------------------------
            // URL sync
            // ----------------------------------------------------------------

            _scheduleUrlUpdate: function () {
                var self = this;
                clearTimeout(self._debounceTimer);
                self._debounceTimer = setTimeout(function () {
                    self.updateUrl();
                }, 300);
            },

            // updateUrl mirrors the current filter/sort state to the query string.
            // Uses history.replaceState (no page reload, no new history entry).
            updateUrl: function () {
                var params = new URLSearchParams(window.location.search);
                if (this.search) { params.set('search', this.search); } else { params.delete('search'); }
                if (this.severity) { params.set('severity', this.severity); } else { params.delete('severity'); }
                if (this.status) { params.set('status', this.status); } else { params.delete('status'); }
                // Omit sort/dir when state matches the default (severity desc).
                if (this.sortCol && !(this.sortCol === 'severity' && this.sortDir === 'desc')) {
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

    Alpine.data('assetTable', function () {
        return {
            search: '',
            criticality: '',
            environment: '',
            sortCol: 'hostname',
            sortDir: 'asc',
            rows: [],
            _debounceTimer: null,
            _critOrdinal: null,

            init: function () {
                var tbody = this.$el.querySelector('tbody');
                if (!tbody) { return; }

                // Map each server-rendered <tr data-row> to a plain object.
                // Lowercasing hostname/ip/name here avoids repeated .toLowerCase()
                // calls in _applyVisibility on every keypress.
                this.rows = Array.from(tbody.querySelectorAll('tr[data-row]')).map(function (tr) {
                    return {
                        el: tr,
                        hostname: (tr.dataset.hostname || '').toLowerCase(),
                        ip: (tr.dataset.ip || '').toLowerCase(),
                        name: (tr.dataset.name || '').toLowerCase(),
                        criticality: (tr.dataset.criticality || ''),
                        environment: (tr.dataset.environment || ''),
                        vulnCount: parseInt(tr.dataset.vulnCount || '0', 10),
                    };
                });

                // Ordinal map for semantic criticality sort:
                // Critical (0) > High (1) > Medium (2) > Low (3)
                // Ascending sort shows most-critical first.
                this._critOrdinal = { critical: 0, high: 1, medium: 2, low: 3 };

                // Restore filter state from URL query params so that page
                // refresh and the browser Back button restore the user's
                // previous filter/sort configuration.
                var params = new URLSearchParams(window.location.search);
                this.search = params.get('search') || '';
                this.criticality = params.get('criticality') || '';
                this.environment = params.get('environment') || '';
                if (params.get('sort')) {
                    this.sortCol = params.get('sort');
                    this.sortDir = params.get('dir') || 'asc';
                } else {
                    // Default: sort by hostname A-Z on page load.
                    this.sortCol = 'hostname';
                    this.sortDir = 'asc';
                }

                this._applyVisibility();
            },

            // ----------------------------------------------------------------
            // Input handlers (CSP-safe: no x-model)
            // ----------------------------------------------------------------

            // setSearch is called on @input from the search text box.
            // Debounced 300ms so we do not refilter on every keystroke.
            setSearch: function (event) {
                this.search = event.target.value;
                this._scheduleUrlUpdate();
                this._applyVisibility();
            },

            // setCriticality is called on @change from the criticality select.
            setCriticality: function (event) {
                this.criticality = event.target.value;
                this.updateUrl();
                this._applyVisibility();
            },

            // setEnvironment is called on @change from the environment select.
            setEnvironment: function (event) {
                this.environment = event.target.value;
                this.updateUrl();
                this._applyVisibility();
            },

            // clearSearch resets the text search and reapplies filters.
            clearSearch: function () {
                this.search = '';
                this.updateUrl();
                this._applyVisibility();
            },

            // clearFilters resets all filters and sort to defaults.
            clearFilters: function () {
                this.search = '';
                this.criticality = '';
                this.environment = '';
                this.sortCol = 'hostname';
                this.sortDir = 'asc';
                this.updateUrl();
                this._applyVisibility();
            },

            // ----------------------------------------------------------------
            // Computed getters
            // ----------------------------------------------------------------

            // hasActiveFilters: true when any filter/sort differs from default.
            // Used to conditionally show the "Clear filters" link.
            get hasActiveFilters() {
                return this.search !== '' || this.criticality !== '' || this.environment !== '';
            },

            // matchCount: number of rows currently visible.
            // Reads from DOM style.display rather than maintaining a separate
            // counter to stay in sync with _applyVisibility().
            get matchCount() {
                var count = 0;
                for (var i = 0; i < this.rows.length; i++) {
                    if (this.rows[i].el.style.display !== 'none') {
                        count++;
                    }
                }
                return count;
            },

            // totalCount: total number of server-rendered rows (unfiltered).
            get totalCount() {
                return this.rows.length;
            },

            // ----------------------------------------------------------------
            // Core filter + sort engine
            // ----------------------------------------------------------------

            _applyVisibility: function () {
                var self = this;
                var q = self.search.toLowerCase();

                // Step 1: build the filtered subset.
                var visible = self.rows.filter(function (r) {
                    if (q && r.hostname.indexOf(q) === -1 && r.ip.indexOf(q) === -1 && r.name.indexOf(q) === -1) {
                        return false;
                    }
                    if (self.criticality && r.criticality !== self.criticality) {
                        return false;
                    }
                    if (self.environment && r.environment !== self.environment) {
                        return false;
                    }
                    return true;
                });

                // Step 2: sort the filtered subset.
                if (self.sortCol) {
                    var col = self.sortCol;
                    var dir = self.sortDir === 'asc' ? 1 : -1;
                    var ord = self._critOrdinal;
                    visible.sort(function (a, b) {
                        var av, bv;
                        if (col === 'criticality') {
                            // Semantic sort: use ordinal map, unknown values rank last (99).
                            av = ord[a.criticality] !== undefined ? ord[a.criticality] : 99;
                            bv = ord[b.criticality] !== undefined ? ord[b.criticality] : 99;
                            return dir * (av - bv);
                        }
                        // String sort for hostname and environment.
                        av = a[col] || '';
                        bv = b[col] || '';
                        if (av < bv) { return -1 * dir; }
                        if (av > bv) { return 1 * dir; }
                        return 0;
                    });
                }

                // Step 3: hide all rows, then show and reorder the visible set.
                // DOM reorder via appendChild moves existing nodes -- no clone needed.
                var tbody = self.$el.querySelector('tbody');
                for (var i = 0; i < self.rows.length; i++) {
                    self.rows[i].el.style.display = 'none';
                }
                for (var j = 0; j < visible.length; j++) {
                    visible[j].el.style.display = '';
                    tbody.appendChild(visible[j].el);
                }
            },

            // ----------------------------------------------------------------
            // Sort toggle
            // ----------------------------------------------------------------

            // toggleSort cycles through three states for each column:
            //   different column  -> sort asc on that column
            //   same column asc   -> sort desc
            //   same column desc  -> clear sort (revert to hostname default)
            //
            // Three-state sort is a common UX pattern (think: Gmail inbox sort).
            // The third state (clear) lets users return to the default order.
            toggleSort: function (col) {
                if (this.sortCol !== col) {
                    this.sortCol = col;
                    this.sortDir = 'asc';
                } else if (this.sortDir === 'asc') {
                    this.sortDir = 'desc';
                } else {
                    // Third click on the same column resets to hostname default.
                    this.sortCol = 'hostname';
                    this.sortDir = 'asc';
                }
                this.updateUrl();
                this._applyVisibility();
            },

            // sortActive returns true when the given column is the active sort key.
            // Used by the template to show/hide sort indicator arrows.
            sortActive: function (col) {
                return this.sortCol === col;
            },

            // sortAsc returns true when the given column is sorted ascending.
            sortAsc: function (col) {
                return this.sortCol === col && this.sortDir === 'asc';
            },

            // ----------------------------------------------------------------
            // URL sync
            // ----------------------------------------------------------------

            // _scheduleUrlUpdate debounces URL sync for the search input.
            // Without debounce, history.replaceState fires on every keystroke
            // which can cause performance issues in some browsers.
            _scheduleUrlUpdate: function () {
                var self = this;
                clearTimeout(self._debounceTimer);
                self._debounceTimer = setTimeout(function () {
                    self.updateUrl();
                }, 300);
            },

            // updateUrl mirrors the current filter/sort state to the URL query
            // string using history.replaceState (no page reload, no new history
            // entry). This allows page refresh to restore filter state and the
            // Back button to work correctly.
            updateUrl: function () {
                var params = new URLSearchParams(window.location.search);
                if (this.search) { params.set('search', this.search); } else { params.delete('search'); }
                if (this.criticality) { params.set('criticality', this.criticality); } else { params.delete('criticality'); }
                if (this.environment) { params.set('environment', this.environment); } else { params.delete('environment'); }
                if (this.sortCol && this.sortCol !== 'hostname') {
                    params.set('sort', this.sortCol);
                    params.set('dir', this.sortDir);
                } else if (this.sortCol === 'hostname' && this.sortDir === 'desc') {
                    // Hostname desc is a non-default state -- preserve it in the URL.
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

/*
 * vulnTable HTMX bridge -- re-read rows after HTMX swaps #vuln-table-body.
 *
 * Why a second htmx:afterSwap listener: The generic bridge above calls
 * Alpine.initTree() to re-wire x-bind/x-on attributes on newly swapped nodes.
 * That is sufficient for stateless Alpine bindings. However, vulnTable keeps
 * a this.rows array derived from the DOM. When HTMX replaces tbody content,
 * the array still points at the old (detached) <tr> elements. This listener
 * calls refreshRows() to re-scan the live DOM and re-apply filter/sort.
 *
 * Both listeners fire on the same htmx:afterSwap event. Order of execution
 * follows listener registration order: Alpine.initTree() first (wires attrs),
 * then refreshRows() (reads the freshly wired DOM). This order matters.
 */
document.addEventListener('htmx:afterSwap', function (event) {
    if (event.detail.target && event.detail.target.id === 'vuln-table-body') {
        var card = document.querySelector('[x-data="vulnTable"]');
        if (card && card._x_dataStack && card._x_dataStack[0] && card._x_dataStack[0].refreshRows) {
            card._x_dataStack[0].refreshRows();
        }
    }
});
