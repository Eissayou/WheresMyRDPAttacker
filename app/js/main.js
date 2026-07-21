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

const AUTO_REFRESH_INTERVAL = 30 * 60 * 1000; // 30 minutes (matches Logic App)
const AUTO_REFRESH_BUFFER_MS = 2 * 60 * 1000; // UI buffer to allow blob/pipeline delay

// ========================================
// GLOBAL VARIABLES
// ========================================
let map;
let markers = [];
let markerClusterGroup;
let attackData = [];
let isLiveMode = true;
let autoRefreshTimer;
let autoRefreshCountdownTimer;
let nextAutoRefreshAt;

function toCount(value) {
    if (value == null) return 0;
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
    if (typeof value === 'string') {
        const cleaned = value.replace(/,/g, '').trim();
        const parsed = Number(cleaned);
        return Number.isFinite(parsed) ? parsed : 0;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
}

// Escape untrusted strings before inserting into HTML.
// Honeypot data (usernames, city/country from logs) is attacker-influenced,
// so every data-derived value MUST pass through this before any innerHTML/popup.
function escapeHtml(value) {
    if (value == null) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ========================================
// DATA HELPERS
// ========================================
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

// Current date (or an offset in days) as YYYY-MM-DD in Pacific Time. Used for both
// the date pickers and the blob file names so they never disagree near midnight.
function getDateInPacific(offsetDays = 0) {
    const now = new Date();
    const pacific = new Date(now.toLocaleString('en-US', { timeZone: 'America/Los_Angeles' }));
    pacific.setDate(pacific.getDate() + offsetDays);
    const year = pacific.getFullYear();
    const month = String(pacific.getMonth() + 1).padStart(2, '0');
    const day = String(pacific.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

// ========================================
// INITIALIZE MAP
// ========================================
function initMap() {
    map = L.map('map', {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
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

    // Initialize marker cluster group
    markerClusterGroup = L.markerClusterGroup({
        spiderfyOnMaxZoom: true,         // Enable spider when fully zoomed (shows stacked markers)
        showCoverageOnHover: false,      // Cleaner hover (no blue overlay)
        zoomToBoundsOnClick: true,       // Zoom in when clicking cluster
        maxClusterRadius: 60,            // Tighter clustering for cleaner look
        disableClusteringAtZoom: 12,     // Stop clustering at city-level zoom
        spiderfyDistanceMultiplier: 2,   // Larger spread for easier clicking
        spiderfyDistanceSurplus: 40,     // Extra distance between markers
        spiderLegPolylineOptions: {      // Make spider legs more visible
            weight: 2,
            color: '#00ffff',
            opacity: 0.6
        },
        animate: true,                   // Smooth animations
        animateAddingMarkers: false,     // Disable to avoid errors with circle markers
        iconCreateFunction: function (cluster) {
            const childCount = cluster.getChildCount();
            let c = ' marker-cluster-';
            if (childCount < 10) {
                c += 'small';
            } else if (childCount < 50) {
                c += 'medium';
            } else {
                c += 'large';
            }
            return new L.DivIcon({
                html: '<div><span>' + childCount + '</span></div>',
                className: 'marker-cluster' + c,
                iconSize: new L.Point(40, 40)
            });
        }
    });
    map.addLayer(markerClusterGroup);
}

// ========================================
// FETCH ATTACK DATA
// ========================================
async function fetchAttackData(date = null) {
    const targetDate = date || getTodayDate();
    const fileName = `attacks_${targetDate}.json`;
    const url = `${BLOB_BASE_URL}/${fileName}`;

    try {
        // 'no-cache' revalidates via ETag so new blobs appear promptly, without the
        // CDN cache pollution a unique ?v= query string would cause.
        const response = await fetch(url, { cache: 'no-cache' });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error(`No attack data found for ${targetDate}`);
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (!Array.isArray(data) || data.length === 0) {
            throw new Error(`No attacks recorded for ${targetDate}`);
        }

        attackData = data;
        updateDashboard();
        hideError();

    } catch (error) {
        console.error('Fetch error:', error);
        // "No data yet" is a normal early-in-the-day state, not a failure.
        const noData = /No attack data|No attacks recorded/i.test(error.message);
        if (noData) {
            showError(`${error.message}. Data is generated periodically — the map will populate automatically once attacks are recorded.`, { persistent: true });
            clearDashboard('No attacks recorded yet — check back soon');
        } else {
            showError(`Could not load attack data: ${error.message}`, { persistent: true });
            clearDashboard('Unable to load data');
        }
    }
}

// ========================================
// UPDATE DASHBOARD
// ========================================
function updateDashboard() {
    clearMarkers();
    updateLeaderboard();
    updateUsernameLeaderboard();
    plotMarkers();
    updateLastUpdateTime();
}

// ========================================
// PLOT MARKERS ON MAP
// ========================================
function plotMarkers() {
    attackData.forEach(attack => {
        const lat = (attack.lat ?? (attack.Latitude != null ? parseFloat(attack.Latitude) : NaN));
        const lon = (attack.lon ?? (attack.Longitude != null ? parseFloat(attack.Longitude) : NaN));

        if (isNaN(lat) || isNaN(lon)) {
            return; // Skip invalid coordinates
        }

        const attackCount = toCount(attack.attack_count ?? attack.FailureCount);

        // Marker color based on failure count
        let markerColor = '#00ff00'; // Green (low)
        if (attackCount > 50) {
            markerColor = '#ff0000'; // Red (high)
        } else if (attackCount > 20) {
            markerColor = '#ff6600'; // Orange (medium)
        } else if (attackCount > 5) {
            markerColor = '#ffaa00'; // Yellow (low-medium)
        }

        const marker = L.circleMarker([lat, lon], {
            radius: Math.min(5 + (attackCount / 5), 20),
            fillColor: markerColor,
            color: '#fff',
            weight: 1,
            opacity: 1,
            fillOpacity: 0.8,
            className: 'attack-marker'
        });

        // Ensure CSS glow uses the marker's own severity color (currentColor)
        marker.on('add', () => {
            const el = marker.getElement ? marker.getElement() : marker._path;
            if (el) {
                el.style.color = markerColor;
            }
        });

        // Popup with attack details
        const ip = attack.ip || attack.IpAddress;
        const city = attack.city || attack.City || 'Unknown';
        const state = attack.state || attack.State || '';
        const country = attack.country || attack.Country || 'Unknown';
        const firstSeen = attack.first_seen ? formatTimestamp(attack.first_seen) : 'N/A';
        const lastSeen = attack.last_seen || attack.timestamp;

        // Parse target_accounts (may be a JSON string from KQL) and show up to 5.
        const accounts = parseAccounts(attack);
        const accountsDisplay = accounts.length
            ? accounts.slice(0, 5).map(cleanUsername).join(', ')
            : 'N/A';

        const popupContent = `
            <div style="font-family: 'Courier New', monospace; color: #000;">
                <strong style="color: #ff0000;">ATTACK DETECTED</strong><br>
                <strong>IP:</strong> ${escapeHtml(ip)}<br>
                <strong>Location:</strong> ${escapeHtml(city)}${state ? ', ' + escapeHtml(state) : ''}, ${escapeHtml(country)}<br>
                <strong>Failed Attempts:</strong> ${attackCount}<br>
                <strong>First Seen:</strong> ${escapeHtml(firstSeen)}<br>
                <strong>Last Seen:</strong> ${escapeHtml(formatTimestamp(lastSeen))}<br>
                <strong>Usernames Tried:</strong> ${escapeHtml(accountsDisplay)}
            </div>
        `;
        marker.bindPopup(popupContent);

        markers.push(marker);
        markerClusterGroup.addLayer(marker);
    });
}

// ========================================
// UPDATE LEADERBOARD PANEL
// ========================================
function updateLeaderboard() {
    // Update ALL leaderboard containers (desktop + mobile clone)
    const leaderboardContainers = document.querySelectorAll('#leaderboard-container');

    // Aggregate attacks by country
    const countryCount = {};
    attackData.forEach(attack => {
        const country = attack.country || attack.Country || 'Unknown';
        const count = toCount(attack.attack_count ?? attack.FailureCount);
        countryCount[country] = (countryCount[country] || 0) + count;
    });

    // Get top 5 countries
    const topCountries = Object.entries(countryCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    // Keep the screen-reader map summary in sync with the visible leaderboard.
    const summaryEl = document.getElementById('map-summary');
    if (summaryEl) {
        summaryEl.textContent = topCountries.length
            ? `Top attacking countries: ${topCountries.map(([c, n]) => `${c} (${n.toLocaleString()})`).join(', ')}.`
            : 'No attack data is currently available.';
    }

    if (topCountries.length === 0) {
        leaderboardContainers.forEach(container => {
            container.innerHTML = '<p class="loading">No data available</p>';
        });
        return;
    }

    const maxCount = topCountries[0][1] || 1;

    leaderboardContainers.forEach(leaderboardContainer => {
        leaderboardContainer.innerHTML = '';

        topCountries.forEach(([country, count], index) => {
            const item = document.createElement('div');
            item.className = 'leaderboard-item';

            const barWidth = (count / maxCount) * 100;

            item.innerHTML = `
                <span class="leaderboard-rank">#${index + 1}</span>
                <div class="leaderboard-country">
                    ${escapeHtml(country)}
                    <div class="leaderboard-bar" style="width: ${barWidth}%"></div>
                </div>
                <span class="leaderboard-count">${count.toLocaleString()}</span>
            `;

            leaderboardContainer.appendChild(item);
        });
    });
}

// ========================================
// UPDATE USERNAME LEADERBOARD
// ========================================
function updateUsernameLeaderboard() {
    // Update ALL username containers (desktop + mobile clone)
    const usernameContainers = document.querySelectorAll('#username-container');

    // Count how many unique IPs tried each username
    // This is the clearest metric: "Which usernames are attackers targeting?"
    const usernameIPs = {}; // username -> Set of IPs

    attackData.forEach(attack => {
        const ip = attack.ip || attack.IpAddress || 'unknown';

        // Count each unique cleaned username once per IP.
        const seenUsernames = new Set();
        parseAccounts(attack).forEach(rawUsername => {
            if (!rawUsername) return;
            const username = cleanUsername(rawUsername);
            if (!username || seenUsernames.has(username)) return;
            seenUsernames.add(username);
            if (!usernameIPs[username]) {
                usernameIPs[username] = new Set();
            }
            usernameIPs[username].add(ip);
        });
    });

    // Get top 5 usernames by number of unique IPs that tried them
    const topUsernames = Object.entries(usernameIPs)
        .map(([username, ips]) => [username, ips.size])
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    if (topUsernames.length === 0) {
        usernameContainers.forEach(container => {
            container.innerHTML = '<p class="loading">No usernames detected</p>';
        });
        return;
    }

    usernameContainers.forEach(usernameContainer => {
        usernameContainer.innerHTML = '';

        topUsernames.forEach(([username, ipCount]) => {
            const item = document.createElement('div');
            item.className = 'username-item';
            item.setAttribute('role', 'button');
            item.setAttribute('tabindex', '0');
            item.setAttribute('aria-label', `Show the IP addresses that tried the username ${username}`);
            item.innerHTML = `
                <span class="username-name">${escapeHtml(username)}</span>
                <span class="username-count">${ipCount} IPs</span>
            `;

            // Clickable AND keyboard-operable (Enter/Space) to show the IP breakdown.
            const open = () => showUsernameDetail(username);
            item.addEventListener('click', open);
            item.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    open();
                }
            });

            usernameContainer.appendChild(item);
        });
    });
}

// ========================================
// MODAL CONTROLLER (focus management + Escape + focus trap)
// ========================================
let lastFocusedElement = null;

function getFocusable(container) {
    return [...container.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])'
    )].filter(el => el.offsetParent !== null);
}

// Keydown handler active only while a modal is open: Escape closes it, Tab is
// trapped inside the dialog (standard accessible-dialog behavior).
function trapFocus(e) {
    const modal = document.querySelector('.modal-open');
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
    modal.style.display = 'flex';
    modal.classList.add('modal-open');
    modal.setAttribute('aria-hidden', 'false');
    const focusable = getFocusable(modal);
    (focusable[0] || modal).focus();
    document.addEventListener('keydown', trapFocus);
}

function closeModal(modal) {
    modal.style.display = 'none';
    modal.classList.remove('modal-open');
    modal.setAttribute('aria-hidden', 'true');
    document.removeEventListener('keydown', trapFocus);
    if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
        lastFocusedElement.focus();
    }
}

// ========================================
// SHOW USERNAME DETAIL MODAL
// ========================================
function showUsernameDetail(username) {
    const modal = document.getElementById('username-modal');
    const title = document.getElementById('username-modal-title');
    const list = document.getElementById('username-modal-list');

    title.textContent = `IPs that tried "${username}"`;
    list.innerHTML = '';

    // Find all IPs that tried this username with distributed counts
    const matchingAttacks = [];
    attackData.forEach(attack => {
        if (parseAccounts(attack).some(acc => cleanUsername(acc) === username)) {
            matchingAttacks.push(attack);
        }
    });

    // Sort by full attack count
    matchingAttacks.sort((a, b) => {
        const countA = toCount(a.attack_count ?? a.FailureCount);
        const countB = toCount(b.attack_count ?? b.FailureCount);
        return countB - countA;
    });

    if (matchingAttacks.length === 0) {
        list.innerHTML = '<p style="color: #888;">No IPs found</p>';
    } else {
        matchingAttacks.forEach(attack => {
            const ip = attack.ip || attack.IpAddress || 'Unknown';
            const city = attack.city || attack.City || 'Unknown';
            const country = attack.country || attack.Country || 'Unknown';
            const count = toCount(attack.attack_count ?? attack.FailureCount);

            const item = document.createElement('div');
            item.className = 'username-detail-item';
            item.innerHTML = `
                <div class="ip">${escapeHtml(ip)}</div>
                <div class="location">${escapeHtml(city)}, ${escapeHtml(country)}</div>
                <div class="attempts">${count.toLocaleString()} total attacks</div>
            `;
            list.appendChild(item);
        });
    }

    openModal(modal);
}

function closeUsernameModal() {
    closeModal(document.getElementById('username-modal'));
}

// ========================================
// CLEAR MARKERS
// ========================================
function clearMarkers() {
    markerClusterGroup.clearLayers();
    markers = [];
}

// ========================================
// CLEAR DASHBOARD
// ========================================
function clearDashboard(message = 'No data available') {
    clearMarkers();
    // Update all containers (desktop + mobile)
    document.querySelectorAll('#leaderboard-container').forEach(container => {
        container.innerHTML = `<p class="loading">${escapeHtml(message)}</p>`;
    });
    document.querySelectorAll('#username-container').forEach(container => {
        container.innerHTML = `<p class="loading">${escapeHtml(message)}</p>`;
    });
}

// ========================================
// ERROR HANDLING
// ========================================
let errorHideTimer = null;

// persistent: keep the message visible until the next successful fetch
// (used for "no data yet" and load failures, so the map is never blank
//  without explanation). Non-persistent messages auto-dismiss.
function showError(message, { persistent = false } = {}) {
    const box = document.getElementById('error-message');
    document.getElementById('error-text').textContent = message;
    box.style.display = 'block';
    box.setAttribute('role', 'alert');
    box.setAttribute('aria-live', 'assertive');

    if (errorHideTimer) { clearTimeout(errorHideTimer); errorHideTimer = null; }
    if (!persistent) {
        errorHideTimer = setTimeout(hideError, 6000);
    }
}

function hideError() {
    if (errorHideTimer) { clearTimeout(errorHideTimer); errorHideTimer = null; }
    document.getElementById('error-message').style.display = 'none';
}

// ========================================
// UTILITY FUNCTIONS
// ========================================
function getTodayDate() {
    return getDateInPacific(0);
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    // Convert to Pacific Time
    return date.toLocaleString('en-US', {
        timeZone: 'America/Los_Angeles',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function updateLastUpdateTime() {
    const now = new Date();
    // Display in Pacific Time
    const timeStr = now.toLocaleTimeString('en-US', {
        timeZone: 'America/Los_Angeles',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });

    // Update ALL last-update elements (desktop + mobile)
    document.querySelectorAll('#last-update').forEach(element => {
        element.textContent = timeStr + ' PT';
    });
}

// ========================================
// MODE SWITCHING
// ========================================
function switchToLiveMode() {
    isLiveMode = true;

    // Update ALL mode indicators (desktop + mobile)
    document.querySelectorAll('#mode-indicator').forEach(indicator => {
        indicator.textContent = 'LIVE';
        indicator.className = 'mode-indicator live';
    });

    // Set date picker to today
    const today = getTodayDate();
    document.querySelectorAll('#date-picker').forEach(picker => {
        picker.value = today;
    });

    fetchAttackData();
    startAutoRefresh();
}

function switchToHistoryMode(date) {
    isLiveMode = false;

    // Update ALL mode indicators (desktop + mobile)
    document.querySelectorAll('#mode-indicator').forEach(indicator => {
        indicator.textContent = 'HISTORY';
        indicator.className = 'mode-indicator history';
    });

    // Set date picker to selected date
    document.querySelectorAll('#date-picker').forEach(picker => {
        picker.value = date;
    });

    stopAutoRefresh();
    fetchAttackData(date);
}

// ========================================
// AUTO REFRESH
// ========================================
function getNextScheduledRefreshTime() {
    // Logic App runs every 30 minutes (on the hour and half-hour in Pacific Time)
    // Calculate next :00 or :30 mark in Pacific Time
    const now = new Date();
    const pacificTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Los_Angeles' }));

    const currentMinute = pacificTime.getMinutes();
    const currentSecond = pacificTime.getSeconds();

    let minutesUntilNext;
    if (currentMinute < 30) {
        // Next refresh at :30
        minutesUntilNext = 30 - currentMinute;
    } else {
        // Next refresh at next hour :00
        minutesUntilNext = 60 - currentMinute;
    }

    // Subtract current seconds to get exact time
    const secondsUntilNext = (minutesUntilNext * 60) - currentSecond;

    return Date.now() + (secondsUntilNext * 1000);
}

function startAutoRefresh() {
    stopAutoRefresh(); // Clear existing timer

    // Calculate next scheduled refresh time (synced to :00 and :30)
    nextAutoRefreshAt = getNextScheduledRefreshTime();
    startAutoRefreshCountdown();

    // Check every minute if we've passed the scheduled time
    autoRefreshTimer = setInterval(() => {
        if (isLiveMode && Date.now() >= nextAutoRefreshAt) {
            fetchAttackData();
            // Calculate next scheduled time after this refresh
            nextAutoRefreshAt = getNextScheduledRefreshTime();
        }
    }, 60000); // Check every minute instead of waiting full 30 min
}

function stopAutoRefresh() {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
    }

    stopAutoRefreshCountdown();
}

function startAutoRefreshCountdown() {
    stopAutoRefreshCountdown();

    const render = () => {
        // Update ALL countdown elements (desktop + mobile)
        document.querySelectorAll('#auto-refresh-countdown').forEach(countdownEl => {
            if (!isLiveMode) {
                countdownEl.textContent = 'PAUSED';
                return;
            }

            const remainingMs = Math.max(0, (nextAutoRefreshAt || Date.now()) - Date.now());
            const remainingSec = Math.ceil(remainingMs / 1000);
            const mm = String(Math.floor(remainingSec / 60)).padStart(2, '0');
            const ss = String(remainingSec % 60).padStart(2, '0');
            countdownEl.textContent = `${mm}:${ss}`;
        });
    };

    render();
    autoRefreshCountdownTimer = setInterval(render, 1000);
}

function stopAutoRefreshCountdown() {
    if (autoRefreshCountdownTimer) {
        clearInterval(autoRefreshCountdownTimer);
        autoRefreshCountdownTimer = null;
    }
}

// ========================================
// MOBILE TOGGLE
// ========================================
function setupMobileToggle() {
    const toggle = document.getElementById('mobile-toggle');
    if (!toggle) return;

    // No cloning: the single set of HUD panels is reflowed into a full-screen
    // overlay by CSS when <body> has the .mobile-open class (see main.css). This
    // avoids duplicate element IDs and keeps a single source of truth in the DOM.
    const setOpen = (open) => {
        document.body.classList.toggle('mobile-open', open);
        toggle.setAttribute('aria-expanded', String(open));
    };

    toggle.addEventListener('click', () => {
        setOpen(!document.body.classList.contains('mobile-open'));
    });

    // Close the mobile menu with Escape.
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.body.classList.contains('mobile-open')) {
            setOpen(false);
        }
    });
}

function handleDateChange(e) {
    const selectedDate = e.target.value;
    if (selectedDate) {
        // Check if selected date is today
        const today = getTodayDate();
        if (selectedDate === today) {
            switchToLiveMode();
        } else {
            switchToHistoryMode(selectedDate);
        }
    } else {
        switchToLiveMode();
    }
}

// ========================================
// AI COMPARISON
// ========================================
async function fetchDataForDate(date) {
    const fileName = `attacks_${date}.json`;
    const url = `${BLOB_BASE_URL}/${fileName}`;
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) {
        throw new Error(`No data for ${date}`);
    }
    return response.json();
}

async function compareWithAI() {
    const date1 = document.getElementById('ai-date1').value;
    const date2 = document.getElementById('ai-date2').value;
    const btn = document.getElementById('ai-compare-btn');
    const resultsArea = document.getElementById('ai-results-area');

    if (!date1 || !date2) {
        resultsArea.innerHTML = '<div class="ai-error" role="alert">Please select both a baseline and a comparison date.</div>';
        return;
    }

    if (date1 === date2) {
        resultsArea.innerHTML = '<div class="ai-error" role="alert">Please choose two different dates to compare.</div>';
        return;
    }

    // Show loading state
    btn.disabled = true;
    btn.innerHTML = '<div class="ai-spinner"></div>';
    resultsArea.innerHTML = `
        <div class="ai-loading" style="justify-content: center; height: 100%; flex-direction: column;">
            <div class="ai-spinner" style="width: 40px; height: 40px; border-width: 4px; margin-bottom: 15px;"></div>
            <div style="color: #a78bfa; font-size: 16px;">Analyzing attack telemetry...</div>
        </div>
    `;

    try {
        // Fetch data for both dates
        const [data1, data2] = await Promise.all([
            fetchDataForDate(date1),
            fetchDataForDate(date2)
        ]);

        // Call Azure Function
        const response = await fetch(AI_FUNCTION_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ date1, date2, data1, data2 })
        });

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

        // Helper to safely display any value (handles objects/arrays)
        const safeDisplay = (val, fallback = 'No data.') => {
            if (!val) return fallback;
            if (typeof val === 'string') return val;
            if (typeof val === 'object') return JSON.stringify(val, null, 2);
            return String(val);
        };

        // Format structured JSON output
        let html = `
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(99, 102, 241, 0.1); border-left: 4px solid #6366f1; border-radius: 4px;">
                <h4 style="margin: 0 0 5px 0; color: #a78bfa; text-transform: uppercase; font-size: 12px;">Executive Summary</h4>
                <p style="margin: 0; color: #fff; font-size: 15px; font-weight: 500;">${escapeHtml(safeDisplay(result.summary, 'Analysis complete.'))}</p>
            </div>

            <div style="display: grid; gap: 20px;">
                <div>
                    <h4 style="color: #00ffff; margin-bottom: 8px; border-bottom: 1px solid rgba(0,255,255,0.2); padding-bottom: 4px;">Attack Volume</h4>
                    <p>${escapeHtml(safeDisplay(result.attack_volume, 'No significant changes.'))}</p>
                </div>

                <div>
                    <h4 style="color: #00ffff; margin-bottom: 8px; border-bottom: 1px solid rgba(0,255,255,0.2); padding-bottom: 4px;">Geographic Shifts</h4>
                    <p>${escapeHtml(safeDisplay(result.geographic_shifts, 'No significant changes.'))}</p>
                </div>

                <div>
                    <h4 style="color: #00ffff; margin-bottom: 8px; border-bottom: 1px solid rgba(0,255,255,0.2); padding-bottom: 4px;">Notable IPs</h4>
                    <p>${escapeHtml(safeDisplay(result.notable_ips, 'None detected.'))}</p>
                </div>

                <div>
                    <h4 style="color: #00ffff; margin-bottom: 8px; border-bottom: 1px solid rgba(0,255,255,0.2); padding-bottom: 4px;">Target Behavior</h4>
                    <p>${escapeHtml(safeDisplay(result.target_behavior, 'No significant changes.'))}</p>
                </div>
            </div>
        `;

        resultsArea.innerHTML = html;

    } catch (error) {
        resultsArea.innerHTML = `
            <div class="ai-error" style="text-align: center; margin-top: 50px;">
                <strong>Analysis Failed</strong><br>
                ${escapeHtml(error.message)}
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Analyze`;
    }
}

// ========================================
// EVENT LISTENERS
// ========================================
// Close username modal
document.getElementById('username-modal-close').addEventListener('click', closeUsernameModal);
document.getElementById('username-modal').addEventListener('click', (e) => {
    if (e.target.id === 'username-modal') {
        closeUsernameModal();
    }
});

document.getElementById('date-picker').addEventListener('change', handleDateChange);

// AI Modal Controls
const aiModal = document.getElementById('ai-modal');

document.getElementById('ai-panel-open-btn').addEventListener('click', () => {
    openModal(aiModal);
});

document.getElementById('ai-modal-close').addEventListener('click', () => {
    closeModal(aiModal);
});

aiModal.addEventListener('click', (e) => {
    if (e.target === aiModal) closeModal(aiModal);
});

document.getElementById('ai-compare-btn').addEventListener('click', compareWithAI);

// ========================================
// INITIALIZATION
// ========================================
window.addEventListener('load', () => {
    // Fail gracefully if the map library CDN didn't load (offline, blocked, or an
    // SRI mismatch) instead of throwing a ReferenceError and showing a black screen.
    if (typeof L === 'undefined' || typeof L.markerClusterGroup !== 'function') {
        showError('The map library failed to load. Check your connection or content blockers, then refresh the page.', { persistent: true });
        return;
    }

    // Set max date for date picker to today
    const today = getTodayDate();
    document.querySelectorAll('#date-picker').forEach(picker => {
        picker.max = today;
        picker.value = today; // Set initial value to today
    });

    // Initialize AI date pickers
    const aiDate1 = document.getElementById('ai-date1');
    const aiDate2 = document.getElementById('ai-date2');
    if (aiDate1 && aiDate2) {
        aiDate1.max = today;
        aiDate2.max = today;
        // Default to yesterday vs today (both in Pacific Time for consistency).
        aiDate1.value = getDateInPacific(-1);
        aiDate2.value = today;
    }

    // Setup mobile toggle
    setupMobileToggle();

    // Initialize map
    initMap();

    // Start in live mode
    switchToLiveMode();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});
