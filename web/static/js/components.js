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
AssetTableFilter.prototype._onClearFilters = function () {
    this.search = '';
    this.criticality = '';
    this.environment = '';
    this.sortCol = 'hostname';
    this.sortDir = 'asc';
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

// toggleSort cycles: different col -> asc; same+asc -> desc; same+desc -> reset to default (hostname asc).
AssetTableFilter.prototype.toggleSort = function (col) {
    if (this.sortCol !== col) {
        this.sortCol = col;
        this.sortDir = 'asc';
    } else if (this.sortDir === 'asc') {
        this.sortDir = 'desc';
    } else {
        this.sortCol = 'hostname';
        this.sortDir = 'asc';
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
 * VulnTableFilter -- will be added in Plan 02.
 * Plan 02 adds a vanilla JS class following the same pattern as AssetTableFilter.
 */

/*
 * HTMX afterSwap bridge -- placeholder for Plan 02's VulnTableFilter.
 * When VulnTableFilter is added, this listener will call refreshRows()
 * on the component when HTMX swaps #vuln-table-body.
 */
document.addEventListener('htmx:afterSwap', function (event) {
    // Plan 02 will add: if target is vuln-table-body, call refreshRows()
});
