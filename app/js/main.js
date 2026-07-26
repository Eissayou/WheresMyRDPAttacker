// ========================================
// SITE CONFIG — single swap-point for hosts
// ========================================
// If you move to a custom domain, the ONLY places that reference external hosts
// are: (1) the constants below, (2) `connect-src` in staticwebapp.config.json,
// and (3) the canonical/OG/sitemap/robots URLs. See README "Moving to a custom domain".
const STORAGE_ACCOUNT = 'honeypotpublicdata';   // Azure Storage account holding attacks_*.json
const BLOB_CONTAINER = 'public-data';           // Public blob container name
const BLOB_BASE_URL = `https://${STORAGE_ACCOUNT}.blob.core.windows.net/${BLOB_CONTAINER}`;

// AI trend-analysis endpoint (Azure Function). Must also be allowed by the CSP connect-src.
const AI_FUNCTION_URL = 'https://aianalysis-hmhudebecwhebrhv.westus2-01.azurewebsites.net/api/compare';

const REFRESH_PERIOD_MS = 30 * 60 * 1000;  // Logic App cadence (:00 and :30)
const REFRESH_BUFFER_MS = 2 * 60 * 1000;   // wait for the new blob to actually land
const REFRESH_TICK_MS = 60 * 1000;         // how often we check whether a refresh is due

const PACIFIC_TZ = 'America/Los_Angeles';
const LEADERBOARD_SIZE = 5;
const MAX_POPUP_ACCOUNTS = 5;

// Marker severity bands. `fill` is the SVG fill Leaflet applies; `cls` sets
// `color` in CSS so the glow (which uses currentColor) matches — that used to
// need a per-marker 'add' listener writing element.style.color by hand.
const SEVERITY_BANDS = [
    { min: 50, fill: '#ff0000', cls: 'sev-critical' },
    { min: 20, fill: '#ff6600', cls: 'sev-high' },
    { min: 5, fill: '#ffaa00', cls: 'sev-medium' },
    { min: -Infinity, fill: '#00ff00', cls: 'sev-low' }
];

// The five string fields the Azure Function contract guarantees, minus the
// summary which gets its own highlighted block.
const AI_SECTIONS = [
    { key: 'attack_volume', label: 'Attack Volume', fallback: 'No significant changes.' },
    { key: 'geographic_shifts', label: 'Geographic Shifts', fallback: 'No significant changes.' },
    { key: 'notable_ips', label: 'Notable IPs', fallback: 'None detected.' },
    { key: 'target_behavior', label: 'Target Behavior', fallback: 'No significant changes.' }
];

// ========================================
// APP STATE
// ========================================
let map;
let markerClusterGroup;
let attackData = [];          // always holds *normalized* rows (see normalizeAttack)
let isLiveMode = true;
let refreshTimer = null;
let countdownTimer = null;
let nextAutoRefreshAt = 0;
let analyzeIconHtml = '';     // captured from the markup once, restored after loading
let mapUnavailable = false;   // Leaflet CDN blocked — everything else still runs

// ========================================
// DOM HELPERS
// ========================================
const $ = (id) => document.getElementById(id);

// Build an element in one call. Using textContent everywhere means no data ever
// reaches an HTML parser, so attacker-controlled strings (usernames, city names)
// cannot inject markup — there is no escaping step to forget.
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

// Standard "nothing to show" paragraph used by every panel.
const notice = (message) => el('p', 'loading', message);

// ========================================
// DATE / TIME (all Pacific, all via cached Intl formatters)
// ========================================
// Intl formatters are expensive to construct; these are built once instead of
// per call (formatTimestamp alone runs twice per attack row).
const isoDateFmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: PACIFIC_TZ, year: 'numeric', month: '2-digit', day: '2-digit'
});
const clockFmt = new Intl.DateTimeFormat('en-US', {
    timeZone: PACIFIC_TZ, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
});
const stampFmt = new Intl.DateTimeFormat('en-US', {
    timeZone: PACIFIC_TZ, month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
});

// Current Pacific date (or an offset in whole days) as YYYY-MM-DD. Used for both
// the date pickers and the blob file names so they never disagree near midnight.
// en-CA formats as YYYY-MM-DD natively, so no manual part assembly is needed.
function getDateInPacific(offsetDays = 0) {
    const today = isoDateFmt.format(new Date());
    if (!offsetDays) return today;
    // Shift whole days in UTC so the arithmetic never crosses a local DST
    // boundary (adding 86_400_000 ms to a wall-clock time can land on the
    // wrong date on transition days).
    const [y, m, d] = today.split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, d + offsetDays)).toISOString().slice(0, 10);
}

const getTodayDate = () => getDateInPacific(0);

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return Number.isNaN(date.getTime()) ? 'N/A' : stampFmt.format(date);
}

// ========================================
// DATA NORMALIZATION
// ========================================
// The blob has been written by two different pipeline versions, so every field
// has a snake_case and a PascalCase spelling. Reconciling that ONCE at fetch
// time means no renderer below ever repeats `attack.city || attack.City`.
function toCount(value) {
    if (value == null) return 0;
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
    const parsed = Number(String(value).replace(/,/g, '').trim());
    return Number.isFinite(parsed) ? parsed : 0;
}

function toCoord(value) {
    if (value == null) return NaN;
    return typeof value === 'number' ? value : parseFloat(value);
}

// Parse the target_accounts field (a JSON string from KQL make_set, or an array).
function parseAccounts(attack) {
    let accounts = attack.target_accounts;
    if (typeof accounts === 'string') {
        try {
            accounts = JSON.parse(accounts);
        } catch (e) {
            accounts = [];
        }
    }
    return Array.isArray(accounts) ? accounts : [];
}

// Normalize a raw "DOMAIN\\user" account string to just the uppercased username.
function cleanUsername(raw) {
    const parts = String(raw).split(/\\+/);
    return parts[parts.length - 1].toUpperCase().trim();
}

function normalizeAttack(raw) {
    return {
        ip: raw.ip || raw.IpAddress || 'Unknown',
        city: raw.city || raw.City || 'Unknown',
        state: raw.state || raw.State || '',
        country: raw.country || raw.Country || 'Unknown',
        lat: toCoord(raw.lat ?? raw.Latitude),
        lon: toCoord(raw.lon ?? raw.Longitude),
        count: toCount(raw.attack_count ?? raw.FailureCount),
        firstSeen: raw.first_seen || null,
        lastSeen: raw.last_seen || raw.timestamp || null,
        // Cleaned and de-duplicated here, so "unique usernames per IP" is a
        // property of the data rather than something each renderer re-derives.
        accounts: [...new Set(parseAccounts(raw).map(cleanUsername).filter(Boolean))]
    };
}

// ========================================
// MAP
// ========================================
// Zoom at which the whole world fits the map's width (tiles are 256px at zoom 0
// and double each level). Hardcoding minZoom: 2 meant a 375px phone could only
// ever show ~37% of the map, with no way to zoom out to the rest.
function getWorldFitZoom() {
    const width = map ? map.getSize().x : window.innerWidth;
    if (width < 1) return 0;
    return Math.max(0, Math.floor(Math.log2(width / 256)));
}

// True once the container has actually been laid out. A map in a hidden tab or
// a display:none ancestor measures 0x0, and every zoom calculation against that
// produces garbage.
function mapHasSize() {
    if (!map) return false;
    const size = map.getSize();
    return size.x > 0 && size.y > 0;
}

// Frame the viewport on the attacks themselves, once, after the first load.
// A fixed center/zoom meant a phone opened on an arbitrary slice of ocean;
// this always opens on where the traffic actually is. Only on the first load,
// so a later auto-refresh never yanks the view out from under someone.
let hasFitToData = false;

function fitMapToData() {
    // Deliberately does NOT set hasFitToData when the container has no size —
    // fitting against a 0x0 map yields a nonsense zoom, so leave it pending and
    // let the ResizeObserver below retry once the real size is known.
    if (hasFitToData || !mapHasSize()) return;

    const points = attackData
        .filter((a) => !Number.isNaN(a.lat) && !Number.isNaN(a.lon))
        .map((a) => [a.lat, a.lon]);
    if (points.length === 0) return;

    hasFitToData = true;
    map.fitBounds(L.latLngBounds(points), { padding: [30, 30], maxZoom: 5, animate: false });
}

function initMap() {
    const fitZoom = getWorldFitZoom();

    map = L.map('map', {
        center: [20, 0],
        zoom: fitZoom,
        minZoom: fitZoom,
        maxZoom: 18,
        worldCopyJump: true,
        maxBounds: L.latLngBounds(L.latLng(-85, -180), L.latLng(85, 180)),
        maxBoundsViscosity: 1.0
    });

    // Dark theme basemap (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);

    markerClusterGroup = L.markerClusterGroup({
        spiderfyOnMaxZoom: true,         // Enable spider when fully zoomed (shows stacked markers)
        showCoverageOnHover: false,      // Cleaner hover (no blue overlay)
        zoomToBoundsOnClick: true,       // Zoom in when clicking cluster
        maxClusterRadius: 60,            // Tighter clustering for cleaner look
        disableClusteringAtZoom: 12,     // Stop clustering at city-level zoom
        spiderfyDistanceMultiplier: 2,   // Larger spread for easier clicking
        spiderfyDistanceSurplus: 40,     // Extra distance between markers
        spiderLegPolylineOptions: { weight: 2, color: '#00ffff', opacity: 0.6 },
        animate: true,
        animateAddingMarkers: false,     // Disable to avoid errors with circle markers
        chunkedLoading: true,            // Yield to the main thread while adding in bulk
        iconCreateFunction: (cluster) => {
            const count = cluster.getChildCount();
            const size = count < 10 ? 'small' : count < 50 ? 'medium' : 'large';
            return new L.DivIcon({
                html: `<div><span>${count}</span></div>`,
                className: `marker-cluster marker-cluster-${size}`,
                iconSize: new L.Point(40, 40)
            });
        }
    });
    map.addLayer(markerClusterGroup);

    observeMapSize();
}

// Keep minZoom honest as the container changes size, and recover from the case
// where the map was built with no size at all. A ResizeObserver on the
// container catches all of it — device rotation, window resize, and a hidden
// tab becoming visible (which fires no window 'resize' event).
function observeMapSize() {
    let timer;
    const onResize = () => {
        if (!mapHasSize()) return;
        map.invalidateSize({ animate: false });

        const zoom = getWorldFitZoom();
        map.setMinZoom(zoom);
        if (map.getZoom() < zoom) map.setZoom(zoom);

        fitMapToData();  // no-op once it has successfully run
    };

    new ResizeObserver(() => {
        clearTimeout(timer);
        timer = setTimeout(onResize, 150);
    }).observe($('map'));
}

// ========================================
// MARKERS
// ========================================
const severityFor = (count) => SEVERITY_BANDS.find((band) => count > band.min);

// Built on demand: Leaflet accepts a function for popup content, so this only
// runs for the handful of markers a visitor actually clicks instead of eagerly
// producing ~45KB of markup for every refresh.
function buildPopup(attack) {
    const location = [attack.city, attack.state, attack.country].filter(Boolean).join(', ');
    const accounts = attack.accounts.length
        ? attack.accounts.slice(0, MAX_POPUP_ACCOUNTS).join(', ')
        : 'N/A';

    const body = el('div', 'popup-body');
    body.appendChild(el('strong', 'popup-title', 'ATTACK DETECTED'));
    body.appendChild(document.createElement('br'));

    const rows = [
        ['IP', attack.ip],
        ['Location', location],
        ['Failed Attempts', attack.count.toLocaleString()],
        ['First Seen', formatTimestamp(attack.firstSeen)],
        ['Last Seen', formatTimestamp(attack.lastSeen)],
        ['Usernames Tried', accounts]
    ];

    for (const [label, value] of rows) {
        body.appendChild(el('strong', null, `${label}: `));
        body.appendChild(document.createTextNode(String(value)));
        body.appendChild(document.createElement('br'));
    }
    return body;
}

function plotMarkers() {
    if (!markerClusterGroup) return;
    const layers = [];

    for (const attack of attackData) {
        if (Number.isNaN(attack.lat) || Number.isNaN(attack.lon)) continue;

        const band = severityFor(attack.count);
        const marker = L.circleMarker([attack.lat, attack.lon], {
            // Clamped at both ends: a negative count in the source JSON would
            // otherwise produce a negative radius, which is an invalid SVG
            // circle and throws inside Leaflet.
            radius: Math.max(5, Math.min(5 + attack.count / 5, 20)),
            fillColor: band.fill,
            color: '#fff',
            weight: 1,
            opacity: 1,
            fillOpacity: 0.8,
            className: `attack-marker ${band.cls}`
        });

        marker.bindPopup(() => buildPopup(attack));
        layers.push(marker);
    }

    // One bulk insert instead of N addLayer calls — MarkerCluster can build the
    // whole cluster tree in a single pass this way.
    markerClusterGroup.addLayers(layers);
}

function clearMarkers() {
    if (markerClusterGroup) markerClusterGroup.clearLayers();
}

// ========================================
// FETCH
// ========================================
function blobUrlForDate(date) {
    return `${BLOB_BASE_URL}/attacks_${date}.json`;
}

async function fetchDataForDate(date) {
    // 'no-cache' revalidates via ETag so new blobs appear promptly, without the
    // CDN cache pollution a unique ?v= query string would cause.
    const response = await fetch(blobUrlForDate(date), { cache: 'no-cache' });
    if (!response.ok) {
        if (response.status === 404) throw new Error(`No attack data found for ${date}`);
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response.json();
}

// Guards against a slow response for an earlier date landing after a newer one
// and repainting the dashboard with the wrong day (easy to trigger by clicking
// through the date picker). Only the most recent request may write state.
let latestRequestId = 0;

async function fetchAttackData(date = null) {
    const targetDate = date || getTodayDate();
    const requestId = ++latestRequestId;

    try {
        const data = await fetchDataForDate(targetDate);
        if (requestId !== latestRequestId) return;  // superseded

        if (!Array.isArray(data) || data.length === 0) {
            throw new Error(`No attacks recorded for ${targetDate}`);
        }

        attackData = data.map(normalizeAttack);
        updateDashboard();
        hideError();
    } catch (error) {
        if (requestId !== latestRequestId) return;  // superseded
        console.error('Fetch error:', error);
        // "No data yet" is a normal early-in-the-day state, not a failure.
        const noData = /No attack data|No attacks recorded/i.test(error.message);
        if (noData) {
            showError(`${error.message}. Data is generated periodically — the map will populate automatically once attacks are recorded.`);
            clearDashboard('No attacks recorded yet — check back soon');
        } else {
            showError(`Could not load attack data: ${error.message}`);
            clearDashboard('Unable to load data');
        }
    }
}

// ========================================
// DASHBOARD RENDERING
// ========================================
function updateDashboard() {
    clearMarkers();
    updateLeaderboard();
    updateUsernameLeaderboard();
    plotMarkers();
    fitMapToData();
    updateLastUpdateTime();
}

function updateLeaderboard() {
    const container = $('leaderboard-container');

    const byCountry = new Map();
    for (const attack of attackData) {
        byCountry.set(attack.country, (byCountry.get(attack.country) || 0) + attack.count);
    }

    const top = [...byCountry.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, LEADERBOARD_SIZE);

    // Keep the screen-reader map summary in sync with the visible leaderboard.
    $('map-summary').textContent = top.length
        ? `Top attacking countries: ${top.map(([c, n]) => `${c} (${n.toLocaleString()})`).join(', ')}.`
        : 'No attack data is currently available.';

    if (top.length === 0) {
        container.replaceChildren(notice('No data available'));
        return;
    }

    const maxCount = top[0][1] || 1;
    const items = top.map(([country, count], index) => {
        const item = el('div', 'leaderboard-item');
        item.appendChild(el('span', 'leaderboard-rank', `#${index + 1}`));

        const name = el('div', 'leaderboard-country', country);
        const bar = el('div', 'leaderboard-bar');
        bar.style.width = `${(count / maxCount) * 100}%`;
        name.appendChild(bar);

        item.appendChild(name);
        item.appendChild(el('span', 'leaderboard-count', count.toLocaleString()));
        return item;
    });

    container.replaceChildren(...items);
}

function updateUsernameLeaderboard() {
    const container = $('username-container');

    // How many unique IPs tried each username — the clearest answer to
    // "which usernames are attackers targeting?". `accounts` is already
    // de-duplicated per attack row, so each IP counts once per username.
    const ipsByUsername = new Map();
    for (const attack of attackData) {
        for (const username of attack.accounts) {
            if (!ipsByUsername.has(username)) ipsByUsername.set(username, new Set());
            ipsByUsername.get(username).add(attack.ip);
        }
    }

    const top = [...ipsByUsername.entries()]
        .map(([username, ips]) => [username, ips.size])
        .sort((a, b) => b[1] - a[1])
        .slice(0, LEADERBOARD_SIZE);

    if (top.length === 0) {
        container.replaceChildren(notice('No usernames detected'));
        return;
    }

    const items = top.map(([username, ipCount]) => {
        const item = el('div', 'username-item');
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', `Show the IP addresses that tried the username ${username}`);
        item.appendChild(el('span', 'username-name', username));
        item.appendChild(el('span', 'username-count', `${ipCount} IPs`));

        // Clickable AND keyboard-operable (Enter/Space) to show the IP breakdown.
        item.addEventListener('click', () => showUsernameDetail(username));
        item.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                showUsernameDetail(username);
            }
        });
        return item;
    });

    container.replaceChildren(...items);
}

function clearDashboard(message = 'No data available') {
    attackData = [];
    clearMarkers();
    $('leaderboard-container').replaceChildren(notice(message));
    $('username-container').replaceChildren(notice(message));
    // Clear the live region too, or a screen reader keeps announcing the
    // previous day's countries for a view that now shows nothing.
    $('map-summary').textContent = message;
}

function updateLastUpdateTime() {
    $('last-update').textContent = `${clockFmt.format(new Date())} PT`;
}

// ========================================
// MODAL CONTROLLER (focus management + Escape + focus trap)
// ========================================
let lastFocusedElement = null;

function getFocusable(container) {
    return [...container.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])'
    )].filter((node) => node.offsetParent !== null);
}

// Keydown handler active only while a modal is open: Escape closes it, Tab is
// trapped inside the dialog (standard accessible-dialog behavior).
function trapFocus(e) {
    const modal = document.querySelector('.modal.is-open');
    if (!modal) return;
    if (e.key === 'Escape') {
        closeModal(modal);
        return;
    }
    if (e.key !== 'Tab') return;

    const focusable = getFocusable(modal);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
    }
}

function openModal(modal) {
    lastFocusedElement = document.activeElement;
    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    // Focus the dialog container (tabindex="-1") rather than its first control,
    // so screen readers announce the dialog title before its fields.
    (modal.querySelector('.modal-content') || modal).focus();
    document.addEventListener('keydown', trapFocus);
}

function closeModal(modal) {
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    document.removeEventListener('keydown', trapFocus);

    // Focus must never be left sitting on the dialog we just set to
    // display:none — keyboard users end up with no focus ring anywhere and the
    // next Tab restarts from the top of the document.
    const active = document.activeElement;
    if (active && modal.contains(active) && typeof active.blur === 'function') {
        active.blur();
    }

    const target = lastFocusedElement;
    lastFocusedElement = null;
    // Only restore to something still in the document and actually focusable;
    // <body> is the "nothing was focused" case and is not a useful target.
    if (target && target !== document.body && target.isConnected &&
        typeof target.focus === 'function') {
        target.focus();
    }
}

function showUsernameDetail(username) {
    $('username-modal-title').textContent = `IPs that tried "${username}"`;

    const matching = attackData
        .filter((attack) => attack.accounts.includes(username))
        .sort((a, b) => b.count - a.count);

    const list = $('username-modal-list');
    if (matching.length === 0) {
        list.replaceChildren(el('p', 'empty-note', 'No IPs found'));
    } else {
        list.replaceChildren(...matching.map((attack) => {
            const item = el('div', 'username-detail-item');
            item.appendChild(el('div', 'ip', attack.ip));
            item.appendChild(el('div', 'location', `${attack.city}, ${attack.country}`));
            item.appendChild(el('div', 'attempts', `${attack.count.toLocaleString()} total attacks`));
            return item;
        }));
    }

    openModal($('username-modal'));
}

// ========================================
// ERROR BANNER
// ========================================
// The banner stays up until the next successful fetch, so the map is never
// blank without an explanation. role/aria-live are declared in the markup.
function showError(message) {
    $('error-text').textContent = message;
    $('error-message').style.display = 'block';
}

function hideError() {
    // A successful data fetch doesn't make a blocked map library work again, so
    // that particular notice is never dismissed.
    if (mapUnavailable) return;
    $('error-message').style.display = 'none';
}

// ========================================
// MODE SWITCHING
// ========================================
function setMode(live, date) {
    isLiveMode = live;

    const indicator = $('mode-indicator');
    indicator.textContent = live ? 'LIVE' : 'HISTORY';
    indicator.className = `mode-indicator ${live ? 'live' : 'history'}`;

    // `max` is refreshed here as well as at load: a tab left open across
    // Pacific midnight would otherwise cap the picker at yesterday.
    const picker = $('date-picker');
    picker.max = getTodayDate();
    picker.value = date;

    if (live) {
        fetchAttackData();
        startAutoRefresh();
    } else {
        stopAutoRefresh();
        // Paint the countdown once more after the timer stops, otherwise it
        // keeps showing whatever second it froze on instead of PAUSED.
        renderCountdown();
        fetchAttackData(date);
    }
}

const switchToLiveMode = () => setMode(true, getTodayDate());
const switchToHistoryMode = (date) => setMode(false, date);

function handleDateChange(e) {
    const selected = e.target.value;
    if (!selected || selected === getTodayDate()) {
        switchToLiveMode();
    } else {
        switchToHistoryMode(selected);
    }
}

// ========================================
// AUTO REFRESH
// ========================================
// The Logic App writes a new blob every REFRESH_PERIOD_MS on wall-clock
// boundaries (:00 and :30). Epoch milliseconds line up with those boundaries in
// any whole-hour timezone, so this needs no timezone conversion at all — the
// previous version round-tripped through toLocaleString to read the minute hand.
// REFRESH_BUFFER_MS holds the refetch back until the blob has actually landed.
function getNextScheduledRefreshTime() {
    const now = Date.now();
    // ceil() already lands on or after `now`, so adding the buffer always puts
    // the target in the future — no further adjustment is reachable.
    return Math.ceil(now / REFRESH_PERIOD_MS) * REFRESH_PERIOD_MS + REFRESH_BUFFER_MS;
}

// Refetch if the scheduled moment has passed. Called both by the slow interval
// and by the countdown as it reaches zero, so the display never sits at 00:00
// waiting up to a full tick for the next poll.
function refreshIfDue() {
    if (!isLiveMode || Date.now() < nextAutoRefreshAt) return false;
    fetchAttackData();
    nextAutoRefreshAt = getNextScheduledRefreshTime();
    return true;
}

function startAutoRefresh() {
    stopAutoRefresh();
    nextAutoRefreshAt = getNextScheduledRefreshTime();
    refreshTimer = setInterval(refreshIfDue, REFRESH_TICK_MS);
    startCountdown();
}

function stopAutoRefresh() {
    clearInterval(refreshTimer);
    refreshTimer = null;
    stopCountdown();
}

function renderCountdown() {
    const target = $('auto-refresh-countdown');
    if (!isLiveMode) {
        target.textContent = 'PAUSED';
        return;
    }
    // Hitting zero is the trigger, not just a display state.
    if (refreshIfDue()) return renderCountdown();

    const remainingSec = Math.ceil(Math.max(0, nextAutoRefreshAt - Date.now()) / 1000);
    const mm = String(Math.floor(remainingSec / 60)).padStart(2, '0');
    const ss = String(remainingSec % 60).padStart(2, '0');
    target.textContent = `${mm}:${ss}`;
}

function startCountdown() {
    stopCountdown();
    renderCountdown();
    countdownTimer = setInterval(renderCountdown, 1000);
}

function stopCountdown() {
    clearInterval(countdownTimer);
    countdownTimer = null;
}

// A once-per-second timer is pure battery drain while the tab is backgrounded
// (and phones background tabs constantly). Suspend it and catch up on return.
function handleVisibilityChange() {
    if (document.hidden) {
        stopCountdown();
        return;
    }
    if (!isLiveMode) return;

    // A tab can be backgrounded across Pacific midnight, which changes both the
    // blob we should be requesting and the picker's ceiling.
    $('date-picker').max = getTodayDate();
    refreshIfDue();
    startCountdown();
}

// ========================================
// MOBILE TOGGLE
// ========================================
// No cloning: the single set of HUD panels is reflowed into a full-screen
// overlay by CSS when <body> has the .mobile-open class (see main.css). This
// avoids duplicate element IDs and keeps a single source of truth in the DOM.
function setupMobileToggle() {
    const toggle = $('mobile-toggle');
    if (!toggle) return;

    const setOpen = (open) => {
        document.body.classList.toggle('mobile-open', open);
        toggle.setAttribute('aria-expanded', String(open));
    };

    toggle.addEventListener('click', () => {
        setOpen(!document.body.classList.contains('mobile-open'));
    });

    // Close the mobile menu with Escape — but let an open modal claim Escape first.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (document.querySelector('.modal.is-open')) return;
        if (document.body.classList.contains('mobile-open')) setOpen(false);
    });
}

// ========================================
// AI COMPARISON
// ========================================
function setAnalyzeLoading(btn, loading) {
    btn.disabled = loading;
    btn.classList.toggle('is-loading', loading);
    // Swap only the icon slot; the button's markup lives in index.html so it
    // never has to be duplicated as a string here.
    btn.querySelector('.btn-icon').innerHTML = loading
        ? '<div class="ai-spinner"></div>'
        : analyzeIconHtml;
}

function renderAiError(message, full = false) {
    const box = el('div', full ? 'ai-error ai-error-full' : 'ai-error');
    box.setAttribute('role', 'alert');
    if (full) {
        box.appendChild(el('strong', null, 'Analysis Failed'));
        box.appendChild(document.createElement('br'));
    }
    box.appendChild(document.createTextNode(message));
    $('ai-results-area').replaceChildren(box);
}

// Model fields are contractually strings, but coerce defensively so an object
// renders as readable JSON instead of "[object Object]".
function asText(value, fallback) {
    if (value == null || value === '') return fallback;
    if (typeof value === 'string') return value;
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
}

function renderAiResult(result) {
    const summary = el('div', 'ai-summary');
    summary.appendChild(el('h4', null, 'Executive Summary'));
    summary.appendChild(el('p', null, asText(result.summary, 'Analysis complete.')));

    const sections = el('div', 'ai-sections');
    for (const { key, label, fallback } of AI_SECTIONS) {
        const section = el('div', 'ai-section');
        section.appendChild(el('h4', null, label));
        section.appendChild(el('p', null, asText(result[key], fallback)));
        sections.appendChild(section);
    }

    $('ai-results-area').replaceChildren(summary, sections);
}

async function compareWithAI() {
    const date1 = $('ai-date1').value;
    const date2 = $('ai-date2').value;
    const btn = $('ai-compare-btn');

    if (!date1 || !date2) {
        renderAiError('Please select both a baseline and a comparison date.');
        return;
    }
    if (date1 === date2) {
        renderAiError('Please choose two different dates to compare.');
        return;
    }

    setAnalyzeLoading(btn, true);
    const loading = el('div', 'ai-loading ai-loading-full');
    loading.appendChild(el('div', 'ai-spinner'));
    loading.appendChild(el('div', 'ai-loading-label', 'Analyzing attack telemetry...'));
    $('ai-results-area').replaceChildren(loading);

    try {
        const [data1, data2] = await Promise.all([
            fetchDataForDate(date1),
            fetchDataForDate(date2)
        ]);

        let response;
        try {
            response = await fetch(AI_FUNCTION_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ date1, date2, data1, data2 })
            });
        } catch (_) {
            // fetch() rejects with a bare "Failed to fetch" TypeError for every
            // network-level failure, which tells the user nothing. By far the
            // most common cause here is the Function's CORS allowlist not
            // containing this page's origin (serving from localhost or a new
            // custom domain), so name that explicitly.
            throw new Error(
                `Could not reach the analysis service from ${location.origin}. ` +
                `This is usually the origin missing from the Function's ALLOWED_ORIGIN setting, ` +
                `or the service being offline.`
            );
        }

        if (!response.ok) {
            // Error bodies aren't always JSON (e.g. a 404 from an undeployed
            // function is empty) — never choke while reporting; always
            // surface the HTTP status.
            let message = `Analysis failed (HTTP ${response.status})`;
            try {
                const err = await response.json();
                if (err && err.error) message = `${err.error} (HTTP ${response.status})`;
            } catch (_) {
                if (response.status === 404) {
                    message = 'Analysis service unreachable (HTTP 404) — the Azure Function may not be deployed.';
                }
            }
            throw new Error(message);
        }

        let result;
        try {
            result = await response.json();
        } catch (_) {
            throw new Error('The analysis service returned an empty or invalid response.');
        }

        renderAiResult(result);
    } catch (error) {
        renderAiError(error.message, true);
    } finally {
        setAnalyzeLoading(btn, false);
    }
}

// ========================================
// INITIALIZATION
// ========================================
function bindEvents() {
    $('date-picker').addEventListener('change', handleDateChange);

    const usernameModal = $('username-modal');
    $('username-modal-close').addEventListener('click', () => closeModal(usernameModal));
    usernameModal.addEventListener('click', (e) => {
        if (e.target === usernameModal) closeModal(usernameModal);
    });

    const aiModal = $('ai-modal');
    $('ai-panel-open-btn').addEventListener('click', () => openModal(aiModal));
    $('ai-modal-close').addEventListener('click', () => closeModal(aiModal));
    aiModal.addEventListener('click', (e) => {
        if (e.target === aiModal) closeModal(aiModal);
    });
    $('ai-compare-btn').addEventListener('click', compareWithAI);

    document.addEventListener('visibilitychange', handleVisibilityChange);
}

function initDatePickers() {
    const today = getTodayDate();

    const picker = $('date-picker');
    picker.max = today;
    picker.value = today;

    const aiDate1 = $('ai-date1');
    const aiDate2 = $('ai-date2');
    aiDate1.max = today;
    aiDate2.max = today;
    // Default to yesterday vs today (both in Pacific Time for consistency).
    aiDate1.value = getDateInPacific(-1);
    aiDate2.value = today;
}

function init() {
    // None of this depends on Leaflet, so it is wired up before the map check:
    // if the CDN is blocked (offline, content blocker, SRI mismatch) the
    // leaderboards, date picker, mobile menu and AI tool all still work rather
    // than the whole page dying alongside the map.
    analyzeIconHtml = $('ai-compare-btn').querySelector('.btn-icon').innerHTML;
    initDatePickers();
    setupMobileToggle();
    bindEvents();

    if (typeof L === 'undefined' || typeof L.markerClusterGroup !== 'function') {
        mapUnavailable = true;
        showError('The map library failed to load, so the map is unavailable — the leaderboards below still update. Check your connection or content blockers, then refresh.');
    } else {
        initMap();
    }

    switchToLiveMode();
}

// Run as soon as the DOM is parsed. Waiting for 'load' also waited on every
// CDN stylesheet, script and map tile before the first fetch even started.
// (No 'beforeunload' handler: it blocks the back/forward cache, and the
//  interval timers this page owns are torn down by the browser anyway.)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
    init();
}
