/*
 * components.js -- Vanilla JS component classes for VulnAdvisor.
 *
 * All components use plain DOM APIs -- no framework dependency, 100% CSP-safe.
 * Vanilla JS eliminates all framework overhead and is safe by default
 * (no eval, no new Function()).
 *
 * Load order (enforced by defer in layout.html):
 *   1. HTMX (unrelated to these components)
 *   2. This file (registers DOMContentLoaded listeners)
 *   3. Bootstrap JS (unrelated)
 *
 * Why defer on all scripts: defer preserves document order and runs after
 * HTML parsing. Without defer, this file might execute before the DOM is
 * ready and getElementById() would return null.
 */

/*
 * AssetTableFilter -- client-side search, sort, and filter for the asset
 * list table.
 *
 * Pattern: Data-down / Events-up (DDEU). Server renders the full table as
 * HTML. JS reads data-* attributes from rows and drives visibility/ordering.
 * No framework dependency, 100% CSP-safe.
 *
 * Scale constraint: client-side filtering targets < ~500 assets.
 * Above that threshold, server-side pagination would be required.
 *
 * State:
 *   search          -- text filter applied to hostname, name, and ip columns
 *   criticality     -- exact-match filter on criticality ('' = all)
 *   environment     -- exact-match filter on environment ('' = all)
 *   sortCol         -- column key currently sorted on ('hostname' default)
 *   sortDir         -- 'asc' or 'desc'
 *   _sortCycleStage -- explicit three-state counter (0=default, 1=asc, 2=desc)
 *                      Stage 0 is the reset/default state. Using an explicit
 *                      counter avoids the inference bug where reset and initial
 *                      state have the same (col, dir) output values.
 *   rows            -- array of row objects read from DOM data-* attributes
 *   _debounceTimer  -- timer handle for search debounce
 *   _critOrdinal    -- criticality -> numeric rank map for semantic sort
 *
 * URL sync: all filter and sort state is mirrored to the query string via
 * history.replaceState() so page refresh and the browser Back button preserve
 * the user's filter state.
 */
function AssetTableFilter(cardEl) {
    this.cardEl = cardEl;

    // State
    this.search = '';
    this.criticality = '';
    this.environment = '';
    this.sortCol = 'hostname';
    this.sortDir = 'asc';
    // _sortCycleStage: 0 = default/reset, 1 = asc, 2 = desc.
    // Explicit counter avoids the implicit-state-machine bug where default
    // state has the same (col, dir) values as the post-reset state.
    this._sortCycleStage = 0;
    this.rows = [];
    this._debounceTimer = null;
    this._critOrdinal = { critical: 0, high: 1, medium: 2, low: 3 };

    // DOM element references
    this.searchInput = document.getElementById('asset-search-input');
    this.clearSearchBtn = document.getElementById('asset-clear-search');
    this.countLabel = document.getElementById('asset-count-label');
    this.critSelect = document.getElementById('asset-crit-select');
    this.envSelect = document.getElementById('asset-env-select');
    this.clearFiltersLink = document.getElementById('asset-clear-filters');
    this.noResultsRow = document.getElementById('asset-no-results');
    this.noResultsClearLink = document.getElementById('asset-no-results-clear');

    // Read rows from DOM, restore state from URL, sync inputs, wire events
    this._readRows();
    this._restoreFromUrl();

    // Sync DOM inputs to restored URL state
    if (this.searchInput) { this.searchInput.value = this.search; }
    if (this.critSelect) { this.critSelect.value = this.criticality; }
    if (this.envSelect) { this.envSelect.value = this.environment; }

    this._wireEvents();
    this._applyVisibility();
}

// _readRows scans tbody for tr[data-row] elements and maps each to a plain
// object. Hostname/ip/name are lowercased at read time to avoid repeated
// .toLowerCase() calls in _applyVisibility on every keypress.
AssetTableFilter.prototype._readRows = function () {
    var tbody = this.cardEl.querySelector('tbody');
    if (!tbody) { return; }
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
};

// _restoreFromUrl reads URL query params and sets component state.
// Allows page refresh and the browser Back button to restore filter state.
// _sortCycleStage is always reset to 0 on URL restore -- we cannot persist
// cycle stage in the URL without clutter, and stage 0 matches "just loaded" semantics.
AssetTableFilter.prototype._restoreFromUrl = function () {
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
    this._sortCycleStage = 0;
};

// _wireEvents attaches event listeners to all toolbar elements.
// Uses var self pattern (not arrow functions) for broad browser compatibility.
AssetTableFilter.prototype._wireEvents = function () {
    var self = this;
    if (self.searchInput) {
        self.searchInput.addEventListener('input', function () { self._onSearchInput(); });
    }
    if (self.clearSearchBtn) {
        self.clearSearchBtn.addEventListener('click', function () { self._onClearSearch(); });
    }
    if (self.critSelect) {
        self.critSelect.addEventListener('change', function () { self._onCritChange(); });
    }
    if (self.envSelect) {
        self.envSelect.addEventListener('change', function () { self._onEnvChange(); });
    }
    if (self.clearFiltersLink) {
        self.clearFiltersLink.addEventListener('click', function () { self._onClearFilters(); });
    }
    if (self.noResultsClearLink) {
        self.noResultsClearLink.addEventListener('click', function () { self._onClearFilters(); });
    }

    // Sort header click handlers
    var sortHostname = document.getElementById('sort-hostname');
    if (sortHostname) {
        sortHostname.addEventListener('click', function () { self.toggleSort('hostname'); });
    }
    var sortEnvironment = document.getElementById('sort-environment');
    if (sortEnvironment) {
        sortEnvironment.addEventListener('click', function () { self.toggleSort('environment'); });
    }
    var sortCriticality = document.getElementById('sort-criticality');
    if (sortCriticality) {
        sortCriticality.addEventListener('click', function () { self.toggleSort('criticality'); });
    }
};

// -------------------------------------------------------------------------
// Input handlers
// -------------------------------------------------------------------------

AssetTableFilter.prototype._onSearchInput = function () {
    this.search = this.searchInput.value;
    this._scheduleUrlUpdate();
    this._applyVisibility();
};

AssetTableFilter.prototype._onClearSearch = function () {
    this.search = '';
    this.searchInput.value = '';
    this.updateUrl();
    this._applyVisibility();
};

AssetTableFilter.prototype._onCritChange = function () {
    this.criticality = this.critSelect.value;
    this.updateUrl();
    this._applyVisibility();
};

AssetTableFilter.prototype._onEnvChange = function () {
    this.environment = this.envSelect.value;
    this.updateUrl();
    this._applyVisibility();
};

// _onClearFilters resets all state to defaults: clears text, dropdowns, sort.
// _sortCycleStage resets to 0 -- default state where the cycle can restart cleanly.
AssetTableFilter.prototype._onClearFilters = function () {
    this.search = '';
    this.criticality = '';
    this.environment = '';
    this.sortCol = 'hostname';
    this.sortDir = 'asc';
    this._sortCycleStage = 0;
    if (this.searchInput) { this.searchInput.value = ''; }
    if (this.critSelect) { this.critSelect.value = ''; }
    if (this.envSelect) { this.envSelect.value = ''; }
    this.updateUrl();
    this._applyVisibility();
};

// -------------------------------------------------------------------------
// Core filter + sort engine
// -------------------------------------------------------------------------

AssetTableFilter.prototype._applyVisibility = function () {
    var self = this;
    var q = self.search.toLowerCase();

    // Step 1: build the filtered subset.
    var visible = self.rows.filter(function (r) {
        // Text search: substring match on hostname, ip, name (pre-lowercased).
        if (q && r.hostname.indexOf(q) === -1 && r.ip.indexOf(q) === -1 && r.name.indexOf(q) === -1) {
            return false;
        }
        // Exact criticality filter.
        if (self.criticality && r.criticality !== self.criticality) {
            return false;
        }
        // Exact environment filter.
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
                // Semantic sort: ordinal map, unknown values rank last (99).
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
    var tbody = self.cardEl.querySelector('tbody');
    for (var i = 0; i < self.rows.length; i++) {
        self.rows[i].el.style.display = 'none';
    }
    for (var j = 0; j < visible.length; j++) {
        visible[j].el.style.display = '';
        tbody.appendChild(visible[j].el);
    }

    // Step 4: update sort indicator arrows (imperative, CSP-safe).
    self._updateSortIndicators();

    // Step 5: update UI state (counts, button visibility).
    self._updateUiState(visible.length);
};

// _updateSortIndicators manages sort arrow visibility imperatively.
// Each indicator span carries data-sort-col and data-sort-type attributes.
// This avoids framework-dependent expressions and keeps the code 100% CSP-safe.
AssetTableFilter.prototype._updateSortIndicators = function () {
    var indicators = this.cardEl.querySelectorAll('[data-sort-type]');
    for (var i = 0; i < indicators.length; i++) {
        var col = indicators[i].dataset.sortCol;
        var type = indicators[i].dataset.sortType;
        var show = false;
        if (type === 'inactive') {
            show = col !== this.sortCol;
        } else if (type === 'asc') {
            show = col === this.sortCol && this.sortDir === 'asc';
        } else if (type === 'desc') {
            show = col === this.sortCol && this.sortDir !== 'asc';
        }
        indicators[i].style.display = show ? '' : 'none';
    }
};

// _updateUiState refreshes count label, clear button, and no-results row.
AssetTableFilter.prototype._updateUiState = function (matchCount) {
    var totalCount = this.rows.length;
    if (this.countLabel) {
        this.countLabel.textContent = matchCount + ' of ' + totalCount + ' assets';
    }
    if (this.clearSearchBtn) {
        this.clearSearchBtn.style.display = this.search ? '' : 'none';
    }
    if (this.clearFiltersLink) {
        this.clearFiltersLink.style.display = this._hasActiveFilters() ? '' : 'none';
    }
    if (this.noResultsRow) {
        this.noResultsRow.style.display = (matchCount === 0 && totalCount > 0) ? '' : 'none';
    }
};

// _hasActiveFilters returns true when any filter differs from the default state.
AssetTableFilter.prototype._hasActiveFilters = function () {
    return this.search !== '' || this.criticality !== '' || this.environment !== '';
};

// -------------------------------------------------------------------------
// Sort
// -------------------------------------------------------------------------

// toggleSort cycles through three explicit stages via _sortCycleStage counter.
//
// Pattern: Explicit State Machine. The stage counter tracks cycle position
// directly, breaking the ambiguity where the reset state has the same
// (col, dir) output values as the initial state (both are hostname/asc).
//
// Stages: 0 = default/reset, 1 = asc, 2 = desc.
// Switching to a new column always starts at stage 1 (asc).
AssetTableFilter.prototype.toggleSort = function (col) {
    if (this.sortCol !== col) {
        // New column: start at stage 1 (asc).
        this.sortCol = col;
        this.sortDir = 'asc';
        this._sortCycleStage = 1;
    } else {
        // Same column: advance stage with modulo-3 wrap.
        this._sortCycleStage = (this._sortCycleStage + 1) % 3;
        if (this._sortCycleStage === 1) {
            this.sortCol = col;
            this.sortDir = 'asc';
        } else if (this._sortCycleStage === 2) {
            this.sortDir = 'desc';
        } else {
            // Stage 0: reset to default (hostname asc).
            this.sortCol = 'hostname';
            this.sortDir = 'asc';
        }
    }
    this.updateUrl();
    this._applyVisibility();
};

// -------------------------------------------------------------------------
// URL sync
// -------------------------------------------------------------------------

// _scheduleUrlUpdate debounces URL sync for the search input (300ms).
// Without debounce, history.replaceState fires on every keystroke.
AssetTableFilter.prototype._scheduleUrlUpdate = function () {
    var self = this;
    clearTimeout(self._debounceTimer);
    self._debounceTimer = setTimeout(function () {
        self.updateUrl();
    }, 300);
};

// updateUrl mirrors current filter/sort state to the URL query string.
// Uses history.replaceState (no page reload, no new history entry).
// Omits sort/dir when state matches the default (hostname asc) to keep URLs clean.
AssetTableFilter.prototype.updateUrl = function () {
    var params = new URLSearchParams(window.location.search);
    if (this.search) { params.set('search', this.search); } else { params.delete('search'); }
    if (this.criticality) { params.set('criticality', this.criticality); } else { params.delete('criticality'); }
    if (this.environment) { params.set('environment', this.environment); } else { params.delete('environment'); }
    // Omit sort/dir when state matches the default (hostname asc).
    if (this.sortCol && !(this.sortCol === 'hostname' && this.sortDir === 'asc')) {
        params.set('sort', this.sortCol);
        params.set('dir', this.sortDir);
    } else {
        params.delete('sort');
        params.delete('dir');
    }
    var qs = params.toString();
    history.replaceState(null, '', qs ? '?' + qs : window.location.pathname);
};

// Self-initialize on DOMContentLoaded if the card element is present.
// Stores the instance on window so Plan 02's HTMX bridge can call methods on it.
document.addEventListener('DOMContentLoaded', function () {
    var card = document.getElementById('asset-table-card');
    if (card) {
        window._assetTableFilter = new AssetTableFilter(card);
    }
});

/*
 * VulnTableFilter -- client-side search, filter, sort for the vulnerability
 * table on the asset detail page. Replaces the previous Alpine.js vulnTable
 * component.
 *
 * Architecture: The component anchors on the outer vulnerability card div
 * (id="vuln-table-card"), NOT on the tbody. HTMX targets #vuln-table-body
 * for innerHTML swap. If JS owned the tbody, HTMX's replacement would orphan
 * the component's DOM references. The outer-card anchor keeps the component
 * alive during HTMX swaps.
 *
 * After HTMX swaps new rows, the htmx:afterSwap listener calls refreshRows()
 * to re-read the updated DOM.
 *
 * Checkbox coexistence: The vanilla JS checkbox code filters hidden rows via
 * cb.closest('tr').style.display !== 'none'. This component does NOT own the
 * checkboxes.
 *
 * Scale constraint: client-side filtering targets < ~500 vulnerabilities.
 */
function VulnTableFilter(cardEl) {
    this.cardEl = cardEl;

    // State
    this.search = '';
    this.severity = '';
    this.status = '';
    this.sortCol = 'severity';
    this.sortDir = 'desc';
    // _sortCycleStage: 0 = default/reset, 1 = asc, 2 = desc.
    // Explicit counter avoids the implicit-state-machine bug where clicking the
    // default column (severity desc) immediately triggers the reset branch.
    this._sortCycleStage = 0;
    this.rows = [];
    this._debounceTimer = null;

    // Semantic ordinals for severity sort (lower ordinal = higher priority).
    // Supports both priority labels (p1-p4) and CVSS-style labels (critical/high/medium/low).
    this._severityOrdinal = { p1: 0, p2: 1, p3: 2, p4: 3, critical: 0, high: 1, medium: 2, low: 3 };

    // Semantic ordinals for status sort.
    this._statusOrdinal = { open: 0, in_review: 1, remediated: 2, deferred: 3, closed: 4 };

    // DOM element references (by id -- matching ids set in asset_detail.html)
    this.searchInput = document.getElementById('vuln-search-input');
    this.clearSearchBtn = document.getElementById('vuln-clear-search');
    this.countLabel = document.getElementById('vuln-count-label');
    this.severitySelect = document.getElementById('vuln-severity-select');
    this.statusSelect = document.getElementById('vuln-status-select');
    this.clearFiltersLink = document.getElementById('vuln-clear-filters');
    this.noResultsRow = document.getElementById('vuln-no-results');
    this.noResultsClearLink = document.getElementById('vuln-no-results-clear');

    // Read rows from DOM, restore state from URL, sync inputs, wire events
    this._readRows();
    this._restoreFromUrl();

    // Sync DOM inputs to restored URL state
    if (this.searchInput) { this.searchInput.value = this.search; }
    if (this.severitySelect) { this.severitySelect.value = this.severity; }
    if (this.statusSelect) { this.statusSelect.value = this.status; }

    this._wireEvents();
    this._applyVisibility();
}

// _readRows scans tbody for tr[data-row] elements (excludes data-empty-state row)
// and maps each to a plain object. Text fields are lowercased at read time to
// avoid repeated .toLowerCase() calls in _applyVisibility on every keypress.
VulnTableFilter.prototype._readRows = function () {
    var tbody = this.cardEl.querySelector('tbody');
    if (!tbody) { return; }
    this.rows = Array.from(tbody.querySelectorAll('tr[data-row]')).map(function (tr) {
        return {
            el: tr,
            cve: (tr.dataset.cve || '').toLowerCase(),
            description: (tr.dataset.description || '').toLowerCase(),
            severity: (tr.dataset.severity || ''),
            cvss: parseFloat(tr.dataset.cvss || '0'),
            status: (tr.dataset.status || ''),
        };
    });
};

// refreshRows is called by the HTMX afterSwap bridge after #vuln-table-body
// innerHTML is replaced. It re-reads the live DOM and re-applies the current
// filter/sort state so newly-added rows are included.
VulnTableFilter.prototype.refreshRows = function () {
    this._readRows();
    this._applyVisibility();
};

// _restoreFromUrl reads URL query params and sets component state.
// Validates severity/status params against ordinal maps -- invalid values are cleared.
// _sortCycleStage is always reset to 0 on URL restore -- we cannot persist
// cycle stage in the URL without clutter, and stage 0 matches "just loaded" semantics.
VulnTableFilter.prototype._restoreFromUrl = function () {
    var params = new URLSearchParams(window.location.search);
    this.search = params.get('search') || '';

    var sev = params.get('severity') || '';
    this.severity = (sev && this._severityOrdinal[sev] !== undefined) ? sev : '';

    var sta = params.get('status') || '';
    this.status = (sta && this._statusOrdinal[sta] !== undefined) ? sta : '';

    if (params.get('sort')) {
        this.sortCol = params.get('sort');
        this.sortDir = params.get('dir') || 'asc';
    } else {
        // Default: sort by severity descending (P1/Critical first) on page load.
        this.sortCol = 'severity';
        this.sortDir = 'desc';
    }
    this._sortCycleStage = 0;
};

// _wireEvents attaches event listeners to all toolbar elements.
// Uses var self pattern (not arrow functions) for broad browser compatibility.
VulnTableFilter.prototype._wireEvents = function () {
    var self = this;
    if (self.searchInput) {
        self.searchInput.addEventListener('input', function () { self._onSearchInput(); });
    }
    if (self.clearSearchBtn) {
        self.clearSearchBtn.addEventListener('click', function () { self._onClearSearch(); });
    }
    if (self.severitySelect) {
        self.severitySelect.addEventListener('change', function () { self._onSeverityChange(); });
    }
    if (self.statusSelect) {
        self.statusSelect.addEventListener('change', function () { self._onStatusChange(); });
    }
    if (self.clearFiltersLink) {
        self.clearFiltersLink.addEventListener('click', function () { self._onClearFilters(); });
    }
    if (self.noResultsClearLink) {
        self.noResultsClearLink.addEventListener('click', function () { self._onClearFilters(); });
    }

    // Sort header click handlers -- each th has an id matching sort-{col}
    var sortCve = document.getElementById('sort-cve');
    if (sortCve) {
        sortCve.addEventListener('click', function () { self.toggleSort('cve'); });
    }
    var sortSeverity = document.getElementById('sort-severity');
    if (sortSeverity) {
        sortSeverity.addEventListener('click', function () { self.toggleSort('severity'); });
    }
    var sortCvss = document.getElementById('sort-cvss');
    if (sortCvss) {
        sortCvss.addEventListener('click', function () { self.toggleSort('cvss'); });
    }
    var sortStatus = document.getElementById('sort-status');
    if (sortStatus) {
        sortStatus.addEventListener('click', function () { self.toggleSort('status'); });
    }
};

// -------------------------------------------------------------------------
// Input handlers
// -------------------------------------------------------------------------

VulnTableFilter.prototype._onSearchInput = function () {
    this.search = this.searchInput.value;
    this._scheduleUrlUpdate();
    this._applyVisibility();
};

VulnTableFilter.prototype._onClearSearch = function () {
    this.search = '';
    this.searchInput.value = '';
    this.updateUrl();
    this._applyVisibility();
};

VulnTableFilter.prototype._onSeverityChange = function () {
    this.severity = this.severitySelect.value;
    this.updateUrl();
    this._applyVisibility();
};

VulnTableFilter.prototype._onStatusChange = function () {
    this.status = this.statusSelect.value;
    this.updateUrl();
    this._applyVisibility();
};

// _onClearFilters resets all state to defaults: clears text, dropdowns, sort.
// _sortCycleStage resets to 0 -- default state where the cycle can restart cleanly.
VulnTableFilter.prototype._onClearFilters = function () {
    this.search = '';
    this.severity = '';
    this.status = '';
    this.sortCol = 'severity';
    this.sortDir = 'desc';
    this._sortCycleStage = 0;
    if (this.searchInput) { this.searchInput.value = ''; }
    if (this.severitySelect) { this.severitySelect.value = ''; }
    if (this.statusSelect) { this.statusSelect.value = ''; }
    this.updateUrl();
    this._applyVisibility();
};

// -------------------------------------------------------------------------
// Core filter + sort engine
// -------------------------------------------------------------------------

VulnTableFilter.prototype._applyVisibility = function () {
    var self = this;
    var q = self.search.toLowerCase();

    // Step 1: build the filtered subset.
    var visible = self.rows.filter(function (r) {
        // Text search: substring match on cve + description (pre-lowercased).
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
    var col = self.sortCol;
    var dir = self.sortDir === 'asc' ? 1 : -1;
    var sevOrd = self._severityOrdinal;
    var staOrd = self._statusOrdinal;
    visible.sort(function (a, b) {
        var av, bv;
        if (col === 'severity') {
            // Semantic sort: ordinal map, unknown values rank last (99).
            av = sevOrd[a.severity] !== undefined ? sevOrd[a.severity] : 99;
            bv = sevOrd[b.severity] !== undefined ? sevOrd[b.severity] : 99;
            return dir * (av - bv);
        }
        if (col === 'status') {
            // Semantic sort: ordinal map, unknown values rank last (99).
            av = staOrd[a.status] !== undefined ? staOrd[a.status] : 99;
            bv = staOrd[b.status] !== undefined ? staOrd[b.status] : 99;
            return dir * (av - bv);
        }
        if (col === 'cvss') {
            // Numeric sort on parsed float (parseFloat done at _readRows time).
            return dir * (a.cvss - b.cvss);
        }
        // String sort for cve (already lowercased).
        av = a[col] || '';
        bv = b[col] || '';
        if (av < bv) { return -1 * dir; }
        if (av > bv) { return 1 * dir; }
        return 0;
    });

    // Step 3: hide all rows, then show and reorder the visible set.
    // DOM reorder via appendChild moves existing nodes -- no clone needed.
    var tbody = self.cardEl.querySelector('tbody');
    for (var i = 0; i < self.rows.length; i++) {
        self.rows[i].el.style.display = 'none';
    }
    for (var j = 0; j < visible.length; j++) {
        visible[j].el.style.display = '';
        tbody.appendChild(visible[j].el);
    }

    // Step 4: update sort indicator arrows (imperative, CSP-safe).
    self._updateSortIndicators();

    // Step 5: update UI state (counts, button visibility).
    self._updateUiState(visible.length);
};

// _updateSortIndicators manages sort arrow visibility imperatively.
// Each indicator span carries data-sort-col and data-sort-type attributes.
VulnTableFilter.prototype._updateSortIndicators = function () {
    var indicators = this.cardEl.querySelectorAll('[data-sort-type]');
    for (var i = 0; i < indicators.length; i++) {
        var col = indicators[i].dataset.sortCol;
        var type = indicators[i].dataset.sortType;
        var show = false;
        if (type === 'inactive') {
            show = col !== this.sortCol;
        } else if (type === 'asc') {
            show = col === this.sortCol && this.sortDir === 'asc';
        } else if (type === 'desc') {
            show = col === this.sortCol && this.sortDir !== 'asc';
        }
        indicators[i].style.display = show ? '' : 'none';
    }
};

// _updateUiState refreshes count label, clear button visibility, and no-results row.
VulnTableFilter.prototype._updateUiState = function (matchCount) {
    var totalCount = this.rows.length;
    if (this.countLabel) {
        this.countLabel.textContent = matchCount + ' of ' + totalCount + ' vulnerabilities';
    }
    if (this.clearSearchBtn) {
        this.clearSearchBtn.style.display = this.search ? '' : 'none';
    }
    if (this.clearFiltersLink) {
        this.clearFiltersLink.style.display = this._hasActiveFilters() ? '' : 'none';
    }
    if (this.noResultsRow) {
        this.noResultsRow.style.display = (matchCount === 0 && totalCount > 0) ? '' : 'none';
    }
};

// _hasActiveFilters returns true when any filter or sort differs from the default state.
VulnTableFilter.prototype._hasActiveFilters = function () {
    return this.search !== '' || this.severity !== '' || this.status !== '' ||
        this.sortCol !== 'severity' || this.sortDir !== 'desc';
};

// -------------------------------------------------------------------------
// Sort
// -------------------------------------------------------------------------

// toggleSort cycles through three explicit stages via _sortCycleStage counter.
//
// Pattern: Explicit State Machine. The stage counter tracks cycle position
// directly, breaking the ambiguity where clicking the default column (severity
// desc) at stage 0 would immediately match the "else" branch and reset with
// no visible change.
//
// Stages: 0 = default/reset, 1 = asc, 2 = desc.
// Switching to a new column always starts at stage 1 (asc).
VulnTableFilter.prototype.toggleSort = function (col) {
    if (this.sortCol !== col) {
        // New column: start at stage 1 (asc).
        this.sortCol = col;
        this.sortDir = 'asc';
        this._sortCycleStage = 1;
    } else {
        // Same column: advance stage with modulo-3 wrap.
        this._sortCycleStage = (this._sortCycleStage + 1) % 3;
        if (this._sortCycleStage === 1) {
            this.sortCol = col;
            this.sortDir = 'asc';
        } else if (this._sortCycleStage === 2) {
            this.sortDir = 'desc';
        } else {
            // Stage 0: reset to default (severity desc, P1/Critical first).
            this.sortCol = 'severity';
            this.sortDir = 'desc';
        }
    }
    this.updateUrl();
    this._applyVisibility();
};

// -------------------------------------------------------------------------
// URL sync
// -------------------------------------------------------------------------

// _scheduleUrlUpdate debounces URL sync for the search input (300ms).
VulnTableFilter.prototype._scheduleUrlUpdate = function () {
    var self = this;
    clearTimeout(self._debounceTimer);
    self._debounceTimer = setTimeout(function () {
        self.updateUrl();
    }, 300);
};

// updateUrl mirrors current filter/sort state to the URL query string.
// Uses history.replaceState (no page reload, no new history entry).
// Omits sort/dir when state matches the default (severity desc) to keep URLs clean.
VulnTableFilter.prototype.updateUrl = function () {
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
};

// Self-initialize on DOMContentLoaded if the card element is present.
// Stores the instance on window so the HTMX bridge can call refreshRows() on it.
document.addEventListener('DOMContentLoaded', function () {
    var card = document.getElementById('vuln-table-card');
    if (card) {
        window._vulnTableFilter = new VulnTableFilter(card);
    }
});

/*
 * HTMX afterSwap bridge -- re-read vuln rows after HTMX swaps #vuln-table-body.
 *
 * When the add-CVE form submits, HTMX replaces #vuln-table-body innerHTML.
 * The VulnTableFilter's this.rows array still points at old (detached) <tr>
 * elements. This listener calls refreshRows() to re-scan the live DOM and
 * re-apply the current filter/sort state to include newly added rows.
 *
 * Simpler than the Alpine version -- no _x_dataStack lookup needed.
 * The window global reference is direct and explicit.
 */
document.addEventListener('htmx:afterSwap', function (event) {
    if (event.detail.target && event.detail.target.id === 'vuln-table-body') {
        if (window._vulnTableFilter && window._vulnTableFilter.refreshRows) {
            window._vulnTableFilter.refreshRows();
        }
    }
});
