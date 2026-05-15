
const APP_CONFIG = {
    version: '4.3.1',
    maxLogEntries: 1000,
    maxAuditEntries: 500,
    chartUpdateThrottle: 500,      // ✅ Increased from 100ms
    socketRetryAttempts: 15,       // ✅ Increased from 10
    socketRetryDelay: 1000,
    maxSocketQueueSize: 100,
    refreshInterval: 5000,
    requestTimeout: 30000,
    debounceDelay: 300,
    validation: {
        linkIdPattern: /^[a-f0-9]{32,64}$/i,
        ipPattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
        urlPattern: /^https?:\/\//i
    }
};

// ============================================
// ERROR BOUNDARY - Capture and Report Errors
// ============================================
class ErrorBoundary {
    constructor() {
        this.errors = [];
        this.maxErrors = 100;
    }

    capture(error, context = {}) {
        const errorData = {
            message: error?.message || String(error),
            stack: error?.stack || '',
            context,
            timestamp: new Date().toISOString()
        };

        this.errors.push(errorData);
        if (this.errors.length > this.maxErrors) {
            this.errors.shift();
        }

        console.error('💥 Error captured:', errorData);
        return errorData;
    }

    async report(error, context = {}) {
        this.capture(error, context);
        // Send to server if needed
        try {
            await fetch('/admin/errors', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: error?.message, context })
            }).catch(() => {});
        } catch (e) {
            console.error('Failed to report error:', e);
        }
    }
}

const errorBoundary = new ErrorBoundary();

// ============================================
// RESOURCE CLEANER - Prevent Memory Leaks
// ============================================
class ResourceCleaner {
    constructor() {
        this.intervals = [];
        this.timeouts = [];
        this.listeners = [];
    }

    registerInterval(interval) {
        this.intervals.push(interval);
        return interval;
    }

    registerTimeout(timeout) {
        this.timeouts.push(timeout);
        return timeout;
    }

    registerListener(element, event, handler) {
        if (!element) return;
        element.addEventListener(event, handler);
        this.listeners.push({ element, event, handler });
    }

    cleanup() {
        console.log('🧹 Cleaning up resources...');
        this.intervals.forEach(interval => clearInterval(interval));
        this.timeouts.forEach(timeout => clearTimeout(timeout));
        this.listeners.forEach(({ element, event, handler }) => {
            element.removeEventListener(event, handler);
        });
        this.intervals = [];
        this.timeouts = [];
        this.listeners = [];
        console.log('✅ Resources cleaned');
    }
}

const resourceCleaner = new ResourceCleaner();

// ============================================
// STATE MANAGEMENT
// ============================================
class AppState {
    constructor() {
        this.socket = null;
        this.charts = {
            requests: null,
            device: null,
            country: null,
            analytics: null,
            performance: null
        };
        this.allLinks = [];
        this.filteredLinks = [];
        this.requestsInFlight = new Set();
        this.currentPage = 1;
        this.pageSize = 20;
        this.logCount = 0;
        this.selectedLinkMode = typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short';
        this.startTime = Date.now();
    }

    addRequestInFlight(id) {
        this.requestsInFlight.add(id);
    }

    removeRequestInFlight(id) {
        this.requestsInFlight.delete(id);
    }

    isRequestInFlight(id) {
        return this.requestsInFlight.has(id);
    }

    cleanup() {
        // Destroy all charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                try {
                    chart.destroy();
                } catch (e) {
                    console.warn('Chart cleanup error:', e);
                }
            }
        });

        // Disconnect socket
        if (this.socket) {
            try {
                this.socket.disconnect();
            } catch (e) {
                console.warn('Socket disconnect error:', e);
            }
        }

        // Clear data
        this.allLinks = [];
        this.filteredLinks = [];
        this.requestsInFlight.clear();
    }
}

const appState = new AppState();

// ============================================
// VALIDATORS WITH XSS PREVENTION
// ============================================
const Validators = {
    linkId(id) {
        return id && APP_CONFIG.validation.linkIdPattern.test(id);
    },

    url(url) {
        if (!url) return false;
        try {
            const parsed = new URL(url);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    },

    ip(ip) {
        return ip && APP_CONFIG.validation.ipPattern.test(ip);
    },

    escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },

    sanitizeAttr(str) {
        if (!str) return '';
        return String(str)
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
function throttle(func, wait) {
    let timeout = null;
    let previous = 0;

    return function executedFunction(...args) {
        const now = Date.now();
        const remaining = wait - (now - previous);

        if (remaining <= 0 || remaining > wait) {
            if (timeout) {
                clearTimeout(timeout);
                timeout = null;
            }
            previous = now;
            func.apply(this, args);
        } else if (!timeout) {
            timeout = resourceCleaner.registerTimeout(
                setTimeout(() => {
                    previous = Date.now();
                    timeout = null;
                    func.apply(this, args);
                }, remaining)
            );
        }
    };
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        clearTimeout(timeout);
        timeout = resourceCleaner.registerTimeout(
            setTimeout(() => func.apply(this, args), wait)
        );
    };
}

function formatNumber(num) {
    if (num === undefined || num === null) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '0s';
    if (seconds < 60) return Math.floor(seconds) + 's';
    if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return mins + 'm ' + (secs > 0 ? secs + 's' : '');
    }
    if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return hours + 'h ' + (mins > 0 ? mins + 'm' : '');
    }
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return days + 'd ' + (hours > 0 ? hours + 'h' : '');
}

// ============================================
// ENHANCED SOCKET INITIALIZATION
// ============================================
function initSocket() {
    console.log('🔌 Initializing Socket.IO with enhanced error handling...');
    
    if (appState.socket) {
        appState.socket.disconnect();
    }

    const socketConfig = {
        auth: { token: METRICS_API_KEY },
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: APP_CONFIG.socketRetryAttempts,
        reconnectionDelay: APP_CONFIG.socketRetryDelay,
        reconnectionDelayMax: 5000,
        timeout: 20000,
        autoConnect: true
    };

    appState.socket = io(socketConfig);

    // Register all handlers
    registerSocketHandlers();

    // Cleanup on window unload
    resourceCleaner.registerListener(window, 'beforeunload', () => {
        if (appState.socket) appState.socket.disconnect();
    });
}

function registerSocketHandlers() {
    if (!appState.socket) return;

    appState.socket.on('connect', () => {
        console.log('✅ Socket connected');
        showAlert('Real-time connection established', 'success');
        updateConnectivityStatus('connected');
    });

    appState.socket.on('disconnect', (reason) => {
        console.log('❌ Socket disconnected:', reason);
        updateConnectivityStatus('disconnected');
    });

    appState.socket.on('connect_error', (error) => {
        console.error('Socket error:', error);
        updateConnectivityStatus('error');
        showAlert('Connection failed, retrying...', 'warning');
    });

    appState.socket.on('stats', throttle((data) => {
        if (data) {
            updateStats(data);
            updateCharts(data);
        }
    }, APP_CONFIG.chartUpdateThrottle));

    appState.socket.on('links', (links) => {
        if (Array.isArray(links)) {
            appState.allLinks = links;
            filterAndRenderLinks();
        }
    });

    appState.socket.on('log', (log) => {
        if (log) addLogEntry(log);
    });
}

// ============================================
// CONNECTIVITY STATUS
// ============================================
function updateConnectivityStatus(status) {
    const indicator = document.querySelector('[data-connectivity]');
    if (!indicator) return;

    const statusMap = {
        'connected': { class: 'status-connected', icon: '✅' },
        'disconnected': { class: 'status-disconnected', icon: '❌' },
        'error': { class: 'status-error', icon: '⚠️' },
        'offline': { class: 'status-offline', icon: '📡' }
    };

    const config = statusMap[status] || statusMap.disconnected;
    indicator.className = 'connectivity-indicator ' + config.class;
    indicator.title = `Status: ${status}`;
}

// ============================================
// ALERTS
// ============================================
function showAlert(message, type = 'info', duration = 5000) {
    if (!message) return;

    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;

    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };

    alert.innerHTML = `
        <div class="alert-icon">
            <i class="fas fa-${icons[type] || 'info-circle'}"></i>
        </div>
        <div class="alert-content">
            <div class="alert-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
            <div class="alert-message">${Validators.escapeHTML(message)}</div>
        </div>
        <button class="alert-close">
            <i class="fas fa-times"></i>
        </button>
    `;

    const alertContainer = document.getElementById('alertContainer') || document.body;
    alertContainer.appendChild(alert);

    const closeBtn = alert.querySelector('.alert-close');
    if (closeBtn) {
        resourceCleaner.registerListener(closeBtn, 'click', () => alert.remove());
    }

    if (duration > 0) {
        const timeout = resourceCleaner.registerTimeout(
            setTimeout(() => alert.remove(), duration)
        );
    }

    return alert;
}

// ============================================
// CHART MANAGEMENT
// ============================================
class ChartManager {
    static destroy(chartRef) {
        if (chartRef && typeof chartRef.destroy === 'function') {
            try {
                chartRef.destroy();
            } catch (e) {
                console.warn('Chart destruction error:', e);
            }
        }
    }

    static createChart(ctx, type, data, options = {}) {
        return new Chart(ctx, {
            type,
            data,
            options: { ...options }
        });
    }
}

// ============================================
// STATS AND UPDATES
// ============================================
function updateStats(data) {
    if (!data) return;

    const elements = {
        totalRequests: document.getElementById('totalRequests'),
        activeLinks: document.getElementById('activeLinks'),
        botBlocks: document.getElementById('botBlocks'),
        memoryUsage: document.getElementById('memoryUsage'),
        cpuUsage: document.getElementById('cpuUsage')
    };

    if (elements.totalRequests) {
        elements.totalRequests.textContent = formatNumber(data.totalRequests || 0);
    }
    if (elements.activeLinks) {
        elements.activeLinks.textContent = formatNumber(data.realtime?.activeLinks || 0);
    }
    if (elements.botBlocks) {
        elements.botBlocks.textContent = formatNumber(data.botBlocks || 0);
    }
    if (elements.memoryUsage && data.system?.memory) {
        elements.memoryUsage.textContent = formatBytes(data.system.memory);
    }
    if (elements.cpuUsage && data.system?.cpu) {
        elements.cpuUsage.textContent = (data.system.cpu || 0).toFixed(1) + '%';
    }
}

function updateCharts(data) {
    if (!data || !window.Chart) return;

    const ctx1 = document.getElementById('requestsChart')?.getContext('2d');
    const ctx2 = document.getElementById('deviceChart')?.getContext('2d');

    if (!ctx1 || !ctx2) return;

    // ✅ Destroy old charts first
    ChartManager.destroy(appState.charts.requests);
    ChartManager.destroy(appState.charts.device);

    const lastMinute = data.realtime?.lastMinute || [];
    const timestamps = lastMinute.map(d => {
        const date = new Date(d.time);
        return date.toLocaleTimeString();
    });

    const requests = lastMinute.map(d => d.requests || 0);

    // ✅ Create new charts
    appState.charts.requests = ChartManager.createChart(ctx1, 'line', {
        labels: timestamps,
        datasets: [{
            label: 'Requests',
            data: requests,
            borderColor: '#8a8a8a',
            backgroundColor: 'rgba(138, 138, 138, 0.1)',
            tension: 0.4,
            fill: true
        }]
    }, {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#aaa' } }
        },
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666' } },
            x: { grid: { display: false }, ticks: { color: '#666' } }
        }
    });

    appState.charts.device = ChartManager.createChart(ctx2, 'doughnut', {
        labels: ['Mobile', 'Desktop', 'Tablet', 'Bot'],
        datasets: [{
            data: [
                data.byDevice?.mobile || 0,
                data.byDevice?.desktop || 0,
                data.byDevice?.tablet || 0,
                data.byDevice?.bot || 0
            ],
            backgroundColor: ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444']
        }]
    }, {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: { legend: { position: 'bottom', labels: { color: '#aaa' } } }
    });
}

// ============================================
// LINKS MANAGEMENT
// ============================================
function filterAndRenderLinks() {
    const search = document.getElementById('linkSearch')?.value?.toLowerCase() || '';
    const filter = document.getElementById('linkFilter')?.value || 'all';

    appState.filteredLinks = appState.allLinks.filter(link => {
        if (filter !== 'all' && link.status !== filter) return false;
        if (search) {
            return (link.id?.toLowerCase().includes(search)) ||
                   (link.target_url?.toLowerCase().includes(search));
        }
        return true;
    });

    appState.currentPage = 1;
    renderLinksTable();
}

function renderLinksTable() {
    const tbody = document.getElementById('linksTableBody');
    if (!tbody) return;

    if (!appState.filteredLinks || appState.filteredLinks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9">No links found</td></tr>';
        return;
    }

    const start = (appState.currentPage - 1) * appState.pageSize;
    const end = Math.min(start + appState.pageSize, appState.filteredLinks.length);
    const pageLinks = appState.filteredLinks.slice(start, end);

    // ✅ Safe HTML generation
    let html = '';
    for (const link of pageLinks) {
        const id = Validators.escapeHTML(link.id);
        const url = Validators.sanitizeAttr(link.target_url);
        
        html += `
            <tr>
                <td><code>${id.substring(0, 8)}...</code></td>
                <td><span class="badge">${link.link_mode || 'short'}</span></td>
                <td><a href="${url}" target="_blank">${Validators.escapeHTML(link.target_url?.substring(0, 40))}</a></td>
                <td>${new Date(link.created_at).toLocaleString()}</td>
                <td>${new Date(link.expires_at).toLocaleString()}</td>
                <td>${formatNumber(link.current_clicks || 0)}</td>
                <td><span class="badge">${link.status}</span></td>
                <td>v${link.api_version || '1'}</td>
                <td>
                    <button class="btn btn-sm view-link" data-id="${Validators.sanitizeAttr(link.id)}">View</button>
                </td>
            </tr>
        `;
    }

    tbody.innerHTML = html;

    // ✅ Add event listeners to new buttons
    document.querySelectorAll('.view-link').forEach(btn => {
        resourceCleaner.registerListener(btn, 'click', async () => {
            try {
                const id = btn.dataset.id;
                if (Validators.linkId(id)) {
                    const res = await fetch(`/api/v1/stats/${encodeURIComponent(id)}`);
                    if (res.ok) {
                        const stats = await res.json();
                        const modal = document.getElementById('linkModal');
                        const content = document.getElementById('linkModalContent');
                        if (content) {
                            content.innerHTML = `
                                <p><strong>ID:</strong> <code>${Validators.escapeHTML(id)}</code></p>
                                <p><strong>Clicks:</strong> ${stats.clicks || 0}</p>
                                <p><strong>Created:</strong> ${new Date(stats.created).toLocaleString()}</p>
                            `;
                        }
                        if (modal) modal.style.display = 'flex';
                    }
                }
            } catch (error) {
                errorBoundary.report(error, { action: 'viewLink' });
                showAlert('Failed to load link details', 'error');
            }
        });
    });
}

// ============================================
// LOG ENTRIES
// ============================================
function addLogEntry(log) {
    if (!log) return;

    const logs = document.getElementById('logs');
    if (!logs) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = `[${new Date(log.t).toLocaleTimeString()}] ${log.type} ${Validators.escapeHTML(log.ip || '')} ${log.method} ${log.path}`;

    logs.insertBefore(entry, logs.firstChild);

    // Limit entries
    while (logs.children.length > APP_CONFIG.maxLogEntries) {
        logs.removeChild(logs.lastChild);
    }

    appState.logCount++;
    const counter = document.getElementById('logCounter');
    if (counter) counter.textContent = appState.logCount;
}

// ============================================
// LINK GENERATION
// ============================================
async function generateLink() {
    const requestId = `gen_${Date.now()}`;
    
    // ✅ Prevent duplicate requests
    if (appState.isRequestInFlight(requestId)) {
        showAlert('Request already in progress', 'warning');
        return;
    }

    appState.addRequestInFlight(requestId);
    const btn = document.getElementById('generateBtn');

    try {
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        }

        const url = document.getElementById('targetUrl')?.value;

        if (!url || !Validators.url(url)) {
            throw new Error('Invalid URL');
        }

        const csrf = document.querySelector('input[name="_csrf"]')?.value || CSRF_TOKEN;

        const res = await fetch('/api/v1/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf  // ✅ CSRF in header
            },
            body: JSON.stringify({ url }),
            credentials: 'include'
        });

        if (!res.ok) {
            const error = await res.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(error.error || `HTTP ${res.status}`);
        }

        const data = await res.json();

        // ✅ Safe DOM update
        const urlOutput = document.getElementById('generatedUrl');
        if (urlOutput) {
            urlOutput.value = Validators.sanitizeAttr(data.url);
        }

        showAlert('Link generated successfully!', 'success');
    } catch (error) {
        errorBoundary.report(error, { action: 'generateLink' });
        showAlert(error.message || 'Failed to generate link', 'error');
    } finally {
        appState.removeRequestInFlight(requestId);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-magic"></i> Generate Link';
        }
    }
}

// ============================================
// EVENT LISTENERS SETUP
// ============================================
function setupEventListeners() {
    console.log('🔧 Setting up event listeners...');

    const generateBtn = document.getElementById('generateBtn');
    if (generateBtn) {
        resourceCleaner.registerListener(generateBtn, 'click', generateLink);
    }

    const linkSearch = document.getElementById('linkSearch');
    if (linkSearch) {
        const debouncedFilter = debounce(filterAndRenderLinks, APP_CONFIG.debounceDelay);
        resourceCleaner.registerListener(linkSearch, 'input', debouncedFilter);
    }

    const linkFilter = document.getElementById('linkFilter');
    if (linkFilter) {
        resourceCleaner.registerListener(linkFilter, 'change', filterAndRenderLinks);
    }

    // Modal close buttons
    const modalClose = document.getElementById('modalClose');
    if (modalClose) {
        resourceCleaner.registerListener(modalClose, 'click', () => {
            const modal = document.getElementById('linkModal');
            if (modal) modal.style.display = 'none';
        });
    }

    // Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        resourceCleaner.registerListener(logoutBtn, 'click', () => {
            fetch('/admin/logout', {
                method: 'POST',
                credentials: 'include'
            }).then(() => {
                window.location.href = '/admin/login';
            }).catch(err => {
                console.error('Logout error:', err);
                window.location.href = '/admin/login';
            });
        });
    }

    console.log('✅ Event listeners setup complete');
}

// ============================================
// UPTIME COUNTER
// ============================================
function startUptimeCounter() {
    resourceCleaner.registerInterval(
        setInterval(() => {
            const uptime = Math.floor((Date.now() - appState.startTime) / 1000);
            const uptimeEl = document.getElementById('uptimeValue');
            if (uptimeEl) {
                uptimeEl.textContent = formatDuration(uptime);
            }
        }, 1000)
    );
}

// ============================================
// TAB NAVIGATION
// ============================================
function showTab(tabId) {
    if (!tabId) return;

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tabId);
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tabId);
    });
}

// ============================================
// INITIALIZATION
// ============================================
function init() {
    console.log('🚀 Initializing Redirector Pro Dashboard v' + APP_CONFIG.version);

    try {
        // Initialize socket
        initSocket();

        // Setup event listeners
        setupEventListeners();

        // Show dashboard tab
        showTab('dashboard');

        // Start uptime counter
        startUptimeCounter();

        console.log('✅ Dashboard initialized successfully');
    } catch (error) {
        console.error('❌ Initialization failed:', error);
        errorBoundary.report(error, { event: 'initialization' });
        showAlert('Failed to initialize dashboard', 'error');
    }
}

// ============================================
// CLEANUP ON UNLOAD
// ============================================
window.addEventListener('beforeunload', () => {
    console.log('🛑 Cleaning up...');
    resourceCleaner.cleanup();
    appState.cleanup();
});

// ============================================
// START
// ============================================
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Expose DEBUG object
window.DEBUG = {
    appState,
    errorBoundary,
    resourceCleaner,
    Validators,
    formatNumber,
    formatBytes,
    formatDuration
};

console.log('✨ Redirector Pro Dashboard v4.3.1 ready. Use DEBUG object for diagnostics.');
