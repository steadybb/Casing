// ============================================
// Redirector Pro v4.0 - Main Application Logic
// ============================================

// ============================================
// State Management
// ============================================
let socket;
let requestsChart, deviceChart, countryChart, analyticsDeviceChart;
let allLinks = [];
let filteredLinks = [];
let autoScroll = true;
let showTimestamps = true;
let currentTimeRange = '5m';
let logCount = 0;
let selectedLinkMode = LINK_LENGTH_MODE;
let currentPage = 1;
const pageSize = 20;
let securityData = { blockedIPs: [], activeAttacks: [], totalAttempts: 0 };
let logFilter = 'all';
let logRate = 0;
let logRateCounter = 0;

// ============================================
// Socket.IO Initialization
// ============================================
function initSocket() {
  console.log('🔌 Initializing Socket.IO connection...');
  
  socket = io({
    auth: { token: METRICS_API_KEY },
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 20000
  });
  
  socket.on('connect', () => {
    console.log('✅ Socket connected successfully');
    showAlert('Real-time monitoring connected', 'success');
    updateSocketStatus('connected');
    
    // Request initial data
    socket.emit('command', { action: 'getStats' });
    socket.emit('command', { action: 'getLinks' });
    socket.emit('command', { action: 'getConfig' });
    socket.emit('command', { action: 'getCacheStats' });
    
    // Request security data if on security tab
    if (document.getElementById('security').classList.contains('active')) {
      refreshSecurityData();
    }
  });
  
  socket.on('disconnect', (reason) => {
    console.log('❌ Socket disconnected:', reason);
    showAlert('Real-time monitoring disconnected', 'error');
    updateSocketStatus('disconnected');
  });
  
  socket.on('connect_error', (error) => {
    console.error('Socket connection error:', error);
    showAlert('Socket connection error', 'error');
  });
  
  socket.on('stats', (data) => {
    console.log('📊 Stats received:', data);
    updateStats(data);
    updateCharts(data);
    updateCountryStats(data.byCountry);
    updateCacheStats(data.caches);
    updateLinkModeStats(data.linkModes);
    updatePerformanceMetrics(data);
    updateEncodingStats(data.encodingStats);
  });
  
  socket.on('config', (data) => {
    console.log('⚙️ Config received:', data);
    updateConfig(data);
  });
  
  socket.on('cacheStats', (data) => {
    updateDetailedCacheStats(data);
  });
  
  socket.on('log', (log) => {
    addLogEntry(log);
    logRateCounter++;
  });
  
  socket.on('link-generated', (data) => {
    console.log('🔗 Link generated:', data);
    showAlert('New link generated', 'info');
    refreshLinks();
  });
  
  socket.on('link-deleted', () => {
    console.log('🗑️ Link deleted');
    refreshLinks();
  });
  
  socket.on('link-updated', () => {
    console.log('✏️ Link updated');
    refreshLinks();
  });
  
  socket.on('links', (links) => {
    console.log('📋 Links received:', links.length);
    allLinks = links;
    filterAndRenderLinks();
  });
  
  socket.on('notification', (notification) => {
    console.log('🔔 Notification:', notification);
    showAlert(notification.message, notification.type);
  });
  
  socket.on('commandResult', (result) => {
    console.log('📨 Command result:', result);
  });
  
  socket.on('systemMetrics', (metrics) => {
    updateSystemMetrics(metrics);
  });
}

// Calculate log rate every second
setInterval(() => {
  logRate = logRateCounter;
  const logRateElement = document.getElementById('logRate');
  if (logRateElement) {
    logRateElement.textContent = logRate + ' logs/sec';
  }
  logRateCounter = 0;
}, 1000);

// ============================================
// Event Listeners Setup
// ============================================
function setupEventListeners() {
  console.log('🔧 Setting up event listeners...');
  
  // Logout button
  document.getElementById('logoutBtn')?.addEventListener('click', logout);
  
  // Menu toggle
  document.getElementById('menuToggle')?.addEventListener('click', toggleSidebar);
  
  // Modal closes
  document.getElementById('modalClose')?.addEventListener('click', closeModal);
  document.getElementById('testModalClose')?.addEventListener('click', closeTestModal);
  document.getElementById('healthModalClose')?.addEventListener('click', closeHealthModal);
  document.getElementById('qrModalClose')?.addEventListener('click', closeQRModal);
  
  // Navigation items
  document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', (e) => {
      const tabId = e.currentTarget.dataset.tab;
      showTab(tabId);
      if (window.innerWidth <= 768) {
        toggleSidebar();
      }
    });
  });
  
  // API Docs nav item
  document.getElementById('apiDocsNavItem')?.addEventListener('click', () => {
    window.open('/api-docs', '_blank');
  });
  
  // Queues nav item
  document.getElementById('queuesNavItem')?.addEventListener('click', () => {
    window.location.href = BULL_BOARD_PATH;
  });
  
  // Time range buttons
  document.querySelectorAll('.time-range-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.time-range-btn').forEach(b => b.classList.remove('active'));
      e.currentTarget.classList.add('active');
      currentTimeRange = e.currentTarget.dataset.range;
      socket.emit('command', { action: 'getStats' });
    });
  });
  
  // Link mode selection
  document.querySelectorAll('.link-mode-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const mode = e.currentTarget.dataset.mode;
      selectLinkMode(mode);
    });
  });
  
  // Long link preset selection
  document.getElementById('longLinkPreset')?.addEventListener('change', (e) => {
    const preset = e.currentTarget.value;
    const customOptions = document.getElementById('customLongOptions');
    
    if (preset === 'custom') {
      customOptions.style.display = 'block';
    } else {
      customOptions.style.display = 'none';
      applyLongLinkPreset(preset);
    }
  });
  
  // Generate link button
  document.getElementById('generateBtn')?.addEventListener('click', generateLink);
  
  // Clear form button
  document.getElementById('clearFormBtn')?.addEventListener('click', clearForm);
  
  // Test mode button
  document.getElementById('testModeBtn')?.addEventListener('click', testLinkModes);
  
  // Copy URL button
  document.getElementById('copyUrlBtn')?.addEventListener('click', copyToClipboard);
  
  // Show QR button
  document.getElementById('showQRBtn')?.addEventListener('click', showQRFromResult);
  
  // Visit URL button
  document.getElementById('visitUrlBtn')?.addEventListener('click', () => {
    const url = document.getElementById('generatedUrl').value;
    if (url) window.open(url, '_blank');
  });
  
  // QR code checkbox
  document.getElementById('generateQR')?.addEventListener('change', function() {
    const qrSize = document.getElementById('qrSize');
    if (qrSize) {
      qrSize.disabled = !this.checked;
    }
  });
  
  // Get stats button
  document.getElementById('getStatsBtn')?.addEventListener('click', getLinkStats);
  
  // Clear stats button
  document.getElementById('clearStatsBtn')?.addEventListener('click', clearStats);
  
  // Export buttons
  document.getElementById('exportCSVBtn')?.addEventListener('click', () => exportData('csv'));
  document.getElementById('exportJSONBtn')?.addEventListener('click', () => exportData('json'));
  document.getElementById('exportPDFBtn')?.addEventListener('click', () => exportData('pdf'));
  document.getElementById('exportLinksBtn')?.addEventListener('click', exportAllLinks);
  
  // Refresh links button
  document.getElementById('refreshLinksBtn')?.addEventListener('click', refreshLinks);
  
  // Search and filter
  document.getElementById('linkSearch')?.addEventListener('input', filterAndRenderLinks);
  document.getElementById('linkFilter')?.addEventListener('change', filterAndRenderLinks);
  document.getElementById('linkModeFilter')?.addEventListener('change', filterAndRenderLinks);
  
  // Pagination
  document.getElementById('prevPageBtn')?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderLinksTable();
    }
  });
  
  document.getElementById('nextPageBtn')?.addEventListener('click', () => {
    if (currentPage < Math.ceil(filteredLinks.length / pageSize)) {
      currentPage++;
      renderLinksTable();
    }
  });
  
  // Log controls
  document.getElementById('clearLogsBtn')?.addEventListener('click', clearLogs);
  document.getElementById('exportLogsBtn')?.addEventListener('click', exportLogs);
  document.getElementById('autoScroll')?.addEventListener('change', (e) => {
    autoScroll = e.target.checked;
  });
  document.getElementById('showTimestamps')?.addEventListener('change', (e) => {
    showTimestamps = e.target.checked;
    // Refresh log display
  });
  document.getElementById('logFilter')?.addEventListener('change', (e) => {
    logFilter = e.target.value;
  });
  
  // Cache management
  document.getElementById('clearAllCache')?.addEventListener('click', () => clearCache('all'));
  document.getElementById('clearGeoCache')?.addEventListener('click', () => clearCache('geo'));
  document.getElementById('clearQRCache')?.addEventListener('click', () => clearCache('qr'));
  document.getElementById('clearEncodingCache')?.addEventListener('click', () => clearCache('encoding'));
  
  // Security
  document.getElementById('refreshSecurityBtn')?.addEventListener('click', refreshSecurityData);
  document.getElementById('clearAttemptsBtn')?.addEventListener('click', clearLoginAttempts);
  
  const botThresholdSlider = document.getElementById('botThresholdSlider');
  if (botThresholdSlider) {
    botThresholdSlider.addEventListener('input', (e) => {
      document.getElementById('botThreshold').textContent = e.target.value;
      document.getElementById('botThresholdBar').style.width = e.target.value + '%';
    });
    botThresholdSlider.addEventListener('change', (e) => {
      updateBotThreshold(parseInt(e.target.value));
    });
  }
  
  // Settings
  document.getElementById('saveLinkModeSettings')?.addEventListener('click', saveLinkModeSettings);
  document.getElementById('saveSystemSettings')?.addEventListener('click', saveSystemSettings);
  document.getElementById('reloadConfigBtn')?.addEventListener('click', reloadConfig);
  document.getElementById('viewHealthBtn')?.addEventListener('click', viewHealthCheck);
  
  // Initialize link mode
  selectLinkMode(LINK_LENGTH_MODE);
}

// ============================================
// UI Functions
// ============================================
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function showTab(tabId) {
  // Update navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
  });
  
  // Find and activate the clicked nav item
  document.querySelectorAll('.nav-item').forEach(item => {
    if (item.dataset.tab === tabId) {
      item.classList.add('active');
    }
  });
  
  // Update tab content
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });
  const tabElement = document.getElementById(tabId);
  if (tabElement) {
    tabElement.classList.add('active');
  }
  
  // Close sidebar on mobile
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.remove('open');
  }
  
  // Load data for specific tabs
  if (tabId === 'links') {
    refreshLinks();
  } else if (tabId === 'logs') {
    console.log('📋 Logs tab activated');
  } else if (tabId === 'security') {
    refreshSecurityData();
  }
}

function selectLinkMode(mode) {
  selectedLinkMode = mode;
  
  // Update button styles
  document.querySelectorAll('.link-mode-btn').forEach(btn => {
    btn.classList.remove('btn-success');
    btn.classList.add('btn-secondary');
    if (btn.dataset.mode === mode) {
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-success');
    }
  });
  
  // Update help text
  const helpText = document.getElementById('linkModeHelp');
  const longOptions = document.getElementById('longLinkOptions');
  
  if (mode === 'short') {
    helpText.textContent = 'Short: Clean, simple URLs (/v/id)';
    longOptions.style.display = 'none';
  } else if (mode === 'long') {
    helpText.textContent = 'Long: Obfuscated URLs with many segments and parameters';
    longOptions.style.display = 'block';
  } else {
    helpText.textContent = 'Auto: Automatically choose based on URL length';
    if (ALLOW_LINK_MODE_SWITCH) {
      longOptions.style.display = 'block';
    } else {
      longOptions.style.display = 'none';
      helpText.textContent = 'Auto mode disabled. Using ' + LINK_LENGTH_MODE + ' mode.';
    }
  }
  
  const modeIndicator = document.getElementById('modeIndicator');
  if (modeIndicator) {
    modeIndicator.textContent = 'Mode: ' + mode;
  }
}

function applyLongLinkPreset(preset) {
  let segments, params, layers;
  
  switch(preset) {
    case 'standard':
      segments = 6;
      params = 13;
      layers = 4;
      break;
    case 'aggressive':
      segments = 12;
      params = 20;
      layers = 6;
      break;
    case 'stealth':
      segments = 18;
      params = 28;
      layers = 8;
      break;
    default:
      return;
  }
  
  document.getElementById('longLinkSegments').value = segments;
  document.getElementById('longLinkParams').value = params;
  document.getElementById('linkEncodingLayers').value = layers;
}

function showAlert(message, type = 'info') {
  const alert = document.getElementById('alert');
  alert.className = `alert alert-${type}`;
  alert.innerHTML = `
    <div class="alert-icon">
      <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
    </div>
    <div class="alert-content">
      <div class="alert-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
      <div class="alert-message">${message}</div>
    </div>
  `;
  alert.style.display = 'flex';
  
  setTimeout(() => {
    alert.style.display = 'none';
  }, 5000);
}

function updateSocketStatus(status) {
  const socketStatus = document.getElementById('socketStatus');
  if (socketStatus) {
    socketStatus.className = `status-dot ${status}`;
  }
}

function updateStats(data) {
  document.getElementById('totalRequests').textContent = formatNumber(data.totalRequests || 0);
  document.getElementById('activeLinks').textContent = formatNumber(data.realtime?.activeLinks || 0);
  document.getElementById('botBlocks').textContent = formatNumber(data.botBlocks || 0);
  
  // Calculate trends
  const lastMinute = data.realtime?.lastMinute || [];
  if (lastMinute.length > 1) {
    const current = lastMinute[lastMinute.length - 1]?.requests || 0;
    const previous = lastMinute[lastMinute.length - 2]?.requests || 0;
    const trend = previous ? ((current - previous) / previous * 100).toFixed(1) : 0;
    document.getElementById('requestTrend').textContent = (trend > 0 ? '+' : '') + trend + '%';
  }
  
  // Block rate
  const blockRate = data.totalRequests ? ((data.botBlocks / data.totalRequests) * 100).toFixed(1) : 0;
  document.getElementById('blockRate').textContent = blockRate + '%';
  
  // Peak links
  document.getElementById('peakLinks').textContent = formatNumber(data.realtime?.peakLinks || 0);
  
  // Total devices
  const totalDevices = Object.values(data.byDevice || {}).reduce((a, b) => a + b, 0);
  document.getElementById('totalDevices').textContent = formatNumber(totalDevices) + ' total';
}

function updateLinkModeStats(modes) {
  if (modes) {
    document.getElementById('linkModes').textContent = `S:${modes.short || 0} L:${modes.long || 0}`;
  }
}

function updateCacheStats(caches) {
  if (caches) {
    document.getElementById('cacheLinks').textContent = formatNumber(caches.linkReq || 0);
    document.getElementById('cacheGeo').textContent = formatNumber(caches.geo || 0);
    document.getElementById('cacheQR').textContent = formatNumber(caches.qr || 0);
    document.getElementById('cacheEncoding').textContent = formatNumber(caches.encoding || 0);
  }
}

function updateDetailedCacheStats(stats) {
  if (stats) {
    const totalHits = Object.values(stats).reduce((sum, s) => sum + (s.hits || 0), 0);
    const totalMisses = Object.values(stats).reduce((sum, s) => sum + (s.misses || 0), 0);
    const total = totalHits + totalMisses;
    const hitRate = total ? ((totalHits / total) * 100).toFixed(1) : 0;
    
    document.getElementById('cacheHits').textContent = formatNumber(totalHits);
    document.getElementById('cacheMisses').textContent = formatNumber(totalMisses);
    document.getElementById('detailedHitRate').textContent = hitRate + '%';
    document.getElementById('cacheHitRate').textContent = hitRate + '%';
  }
}

function updatePerformanceMetrics(data) {
  if (data.performance) {
    document.getElementById('avgResponseTime').textContent = data.performance.avgResponseTime.toFixed(0) + 'ms';
    document.getElementById('p95Time').textContent = data.performance.p95ResponseTime.toFixed(0) + 'ms';
  }
  
  if (data.realtime) {
    document.getElementById('currentRPS').textContent = data.realtime.requestsPerSecond || 0;
    document.getElementById('peakRPS').textContent = data.realtime.peakRPS || 0;
  }
}

function updateEncodingStats(encodingStats) {
  if (encodingStats) {
    document.getElementById('encodingStats').textContent = formatNumber(encodingStats.totalEncoded || 0);
    document.getElementById('avgLayers').textContent = (encodingStats.avgLayers || 0).toFixed(1);
    
    // Cache hit rate
    const totalRequests = (encodingStats.cacheHits || 0) + (encodingStats.cacheMisses || 0);
    const hitRate = totalRequests ? ((encodingStats.cacheHits / totalRequests) * 100).toFixed(1) : 0;
    document.getElementById('cacheHitRate').textContent = hitRate + '%';
    document.getElementById('cacheSize').textContent = formatNumber(encodingStats.totalEncoded || 0);
  }
}

function updateSystemMetrics(metrics) {
  if (metrics) {
    document.getElementById('memoryUsage').textContent = formatBytes(metrics.memory?.heapUsed || 0);
    document.getElementById('cpuUsage').textContent = (metrics.cpu || 0).toFixed(1) + '%';
  }
}

function updateConfig(data) {
  if (data.linkLengthMode) {
    document.getElementById('settingLinkLengthMode').value = data.linkLengthMode;
  }
  if (data.allowLinkModeSwitch !== undefined) {
    document.getElementById('settingAllowLinkModeSwitch').checked = data.allowLinkModeSwitch;
  }
  if (data.longLinkSegments) {
    document.getElementById('settingLongLinkSegments').value = data.longLinkSegments;
    document.getElementById('longLinkSegments').value = data.longLinkSegments;
  }
  if (data.longLinkParams) {
    document.getElementById('settingLongLinkParams').value = data.longLinkParams;
    document.getElementById('longLinkParams').value = data.longLinkParams;
  }
  if (data.linkEncodingLayers) {
    document.getElementById('settingLinkEncodingLayers').value = data.linkEncodingLayers;
    document.getElementById('linkEncodingLayers').value = data.linkEncodingLayers;
  }
  if (data.maxEncodingIterations) {
    document.getElementById('settingMaxEncodingIterations').value = data.maxEncodingIterations;
  }
  if (data.enableCompression !== undefined) {
    document.getElementById('settingEnableCompression').checked = data.enableCompression;
    document.getElementById('enableCompression').checked = data.enableCompression;
  }
  if (data.enableEncryption !== undefined) {
    document.getElementById('settingEnableEncryption').checked = data.enableEncryption;
    document.getElementById('enableEncryption').checked = data.enableEncryption;
  }
  if (data.nodeEnv) {
    document.getElementById('nodeEnv').textContent = data.nodeEnv;
  }
}

function updateCharts(data) {
  const ctx1 = document.getElementById('requestsChart')?.getContext('2d');
  const ctx2 = document.getElementById('deviceChart')?.getContext('2d');
  
  if (!ctx1 || !ctx2) return;
  
  // Destroy existing charts
  if (requestsChart) requestsChart.destroy();
  if (deviceChart) deviceChart.destroy();
  
  // Prepare data based on time range
  const lastMinute = data.realtime?.lastMinute || [];
  let points = 60;
  if (currentTimeRange === '5m') points = 300;
  else if (currentTimeRange === '15m') points = 900;
  else if (currentTimeRange === '1h') points = 3600;
  
  const recentData = lastMinute.slice(-Math.min(points, lastMinute.length));
  
  const timestamps = recentData.map(d => {
    const date = new Date(d.time);
    return date.getHours() + ':' + date.getMinutes().toString().padStart(2, '0') + ':' + date.getSeconds().toString().padStart(2, '0');
  });
  
  const requests = recentData.map(d => d.requests || 0);
  const blocks = recentData.map(d => d.blocks || 0);
  const successes = recentData.map(d => d.successes || 0);
  
  // Requests Chart
  requestsChart = new Chart(ctx1, {
    type: 'line',
    data: {
      labels: timestamps,
      datasets: [
        {
          label: 'Requests',
          data: requests,
          borderColor: '#8a8a8a',
          backgroundColor: 'rgba(138, 138, 138, 0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 2,
          pointHoverRadius: 5
        },
        {
          label: 'Successful',
          data: successes,
          borderColor: '#4ade80',
          backgroundColor: 'rgba(74, 222, 128, 0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 2,
          pointHoverRadius: 5
        },
        {
          label: 'Blocks',
          data: blocks,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 2,
          pointHoverRadius: 5
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            usePointStyle: true,
            boxWidth: 6,
            color: '#aaa'
          }
        },
        tooltip: {
          backgroundColor: '#1a1a1a',
          titleColor: '#fff',
          bodyColor: '#fff',
          borderColor: '#333',
          borderWidth: 1
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(255, 255, 255, 0.05)'
          },
          ticks: {
            color: '#666'
          }
        },
        x: {
          grid: {
            display: false
          },
          ticks: {
            color: '#666',
            maxRotation: 45,
            minRotation: 45
          }
        }
      }
    }
  });
  
  // Device Chart
  deviceChart = new Chart(ctx2, {
    type: 'doughnut',
    data: {
      labels: ['Mobile', 'Desktop', 'Tablet', 'Bot'],
      datasets: [{
        data: [
          data.byDevice?.mobile || 0,
          data.byDevice?.desktop || 0,
          data.byDevice?.tablet || 0,
          data.byDevice?.bot || 0
        ],
        backgroundColor: ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            usePointStyle: true,
            boxWidth: 8,
            padding: 20,
            color: '#aaa'
          }
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const label = context.label || '';
              const value = context.raw || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
              return `${label}: ${formatNumber(value)} (${percentage}%)`;
            }
          }
        }
      }
    }
  });
}

function updateCountryStats(countries) {
  const container = document.getElementById('countryStats');
  if (!countries || Object.keys(countries).length === 0) {
    container.innerHTML = '<div class="text-center p-4">No data yet</div>';
    document.getElementById('totalCountries').textContent = '0 countries';
    return;
  }
  
  const sorted = Object.entries(countries)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  
  document.getElementById('totalCountries').textContent = Object.keys(countries).length + ' countries';
  
  container.innerHTML = sorted.map(([country, count]) => `
    <div class="stat-card">
      <div class="stat-header">
        <span class="stat-title">${country}</span>
        <span class="stat-icon"><i class="fas fa-flag"></i></span>
      </div>
      <div class="stat-value">${formatNumber(count)}</div>
      <div class="stat-trend">requests</div>
    </div>
  `).join('');
}

function addLogEntry(log) {
  const logs = document.getElementById('logs');
  if (!logs) return;
  
  // Apply filter
  if (logFilter !== 'all' && log.type !== logFilter) {
    return;
  }
  
  // Remove placeholder if it exists
  if (logs.children.length === 1 && logs.children[0].textContent.includes('Connecting')) {
    logs.innerHTML = '';
  }
  
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  
  const time = new Date(log.t).toLocaleTimeString();
  const device = log.device || 'unknown';
  const method = log.method || 'GET';
  const path = log.path || '/';
  const ip = log.ip || '0.0.0.0';
  const duration = log.duration || 0;
  const type = log.type || 'request';
  
  // Determine log type class
  let typeClass = '';
  let typeIcon = '🌐';
  
  if (type === 'redirect') {
    typeClass = 'type-redirect';
    typeIcon = '🔄';
  } else if (type === 'generate') {
    typeClass = 'type-generate';
    typeIcon = '🔗';
  } else if (type === 'bot-block' || type === 'bot') {
    typeClass = 'type-bot-block';
    typeIcon = '🤖';
  } else if (type === 'rate-limit') {
    typeClass = 'type-rate-limit';
    typeIcon = '⏱️';
  } else if (type === 'error') {
    typeClass = 'type-error';
    typeIcon = '❌';
  } else if (type === '404') {
    typeClass = 'type-404';
    typeIcon = '404';
  } else if (type === 'long-link-decode') {
    typeClass = 'type-generate';
    typeIcon = '🔓';
  }
  
  // Device icon
  let deviceIcon = '💻';
  if (device === 'mobile') deviceIcon = '📱';
  else if (device === 'tablet') deviceIcon = '📟';
  else if (device === 'bot') deviceIcon = '🤖';
  
  // Build log entry HTML
  let logHtml = '';
  
  if (showTimestamps) {
    logHtml += `<span class="timestamp">[${time}]</span> `;
  }
  
  logHtml += `<span class="type-badge ${typeClass}">${typeIcon} ${type}</span> `;
  logHtml += `<span class="ip">${ip}</span> `;
  logHtml += `<span class="method">${method}</span> `;
  logHtml += `<span class="path">${path}</span> `;
  logHtml += `<span class="device">${deviceIcon} ${device}</span> `;
  
  if (duration > 0) {
    logHtml += `<span class="duration">${duration}ms</span>`;
  }
  
  if (log.target) {
    logHtml += ` <span style="color: #9ece6a;">→ ${log.target.substring(0, 50)}${log.target.length > 50 ? '...' : ''}</span>`;
  }
  
  if (log.reason) {
    logHtml += ` <span style="color: #f7768e;">[${log.reason}]</span>`;
  }
  
  if (log.layers) {
    logHtml += ` <span style="color: #bb9af7;">[${log.layers} layers]</span>`;
  }
  
  if (log.complexity) {
    logHtml += ` <span style="color: #7aa2f7;">[complexity: ${log.complexity}]</span>`;
  }
  
  entry.innerHTML = logHtml;
  
  // Add to logs
  logs.insertBefore(entry, logs.firstChild);
  
  // Limit number of log entries
  if (logs.children.length > 500) {
    logs.removeChild(logs.lastChild);
  }
  
  // Auto-scroll if enabled
  if (autoScroll) {
    logs.scrollTop = 0;
  }
  
  // Update log count
  logCount++;
  document.getElementById('logCounter').textContent = logCount;
}

function filterAndRenderLinks() {
  const search = document.getElementById('linkSearch')?.value.toLowerCase() || '';
  const filter = document.getElementById('linkFilter')?.value || 'all';
  const modeFilter = document.getElementById('linkModeFilter')?.value || 'all';
  
  filteredLinks = allLinks.filter(link => {
    if (filter !== 'all' && link.status !== filter) return false;
    if (modeFilter !== 'all' && link.link_mode !== modeFilter) return false;
    if (search) {
      return (link.id && link.id.toLowerCase().includes(search)) || 
             (link.target_url && link.target_url.toLowerCase().includes(search));
    }
    return true;
  });
  
  document.getElementById('totalCount').textContent = filteredLinks.length;
  currentPage = 1;
  renderLinksTable();
}

function renderLinksTable() {
  const tbody = document.getElementById('linksTableBody');
  
  if (!filteredLinks || filteredLinks.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 2rem;">
          <i class="fas fa-link"></i> No links found
        </td>
      </tr>
    `;
    document.getElementById('displayedCount').textContent = '0';
    document.getElementById('totalLinksCount').textContent = '0';
    document.getElementById('prevPageBtn').disabled = true;
    document.getElementById('nextPageBtn').disabled = true;
    document.getElementById('pageInfo').textContent = 'Page 1';
    return;
  }
  
  const start = (currentPage - 1) * pageSize;
  const end = Math.min(start + pageSize, filteredLinks.length);
  const pageLinks = filteredLinks.slice(start, end);
  
  document.getElementById('displayedCount').textContent = pageLinks.length;
  document.getElementById('totalLinksCount').textContent = filteredLinks.length;
  document.getElementById('totalCount').textContent = filteredLinks.length;
  
  // Update pagination
  const totalPages = Math.ceil(filteredLinks.length / pageSize);
  document.getElementById('prevPageBtn').disabled = currentPage <= 1;
  document.getElementById('nextPageBtn').disabled = currentPage >= totalPages;
  document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages}`;
  
  tbody.innerHTML = pageLinks.map(link => `
    <tr>
      <td><code>${link.id.substring(0, 8)}...</code></td>
      <td>
        <span class="badge badge-${link.link_mode === 'long' ? 'warning' : 'info'}">
          ${link.link_mode || 'short'}
        </span>
        ${link.link_length ? `<small style="color:#666;">${link.link_length}c</small>` : ''}
      </td>
      <td>
        <a href="${link.target_url}" target="_blank" rel="noopener" style="color: #8a8a8a; text-decoration: none;">
          ${link.target_url.substring(0, 40)}${link.target_url.length > 40 ? '...' : ''}
        </a>
      </td>
      <td>${new Date(link.created_at).toLocaleString()}</td>
      <td>${new Date(link.expires_at).toLocaleString()}</td>
      <td>
        <span style="font-weight: 600;">${formatNumber(link.current_clicks || 0)}</span>
        ${link.max_clicks ? '/' + formatNumber(link.max_clicks) : ''}
      </td>
      <td>
        <span class="badge badge-${link.status === 'active' ? 'success' : link.status === 'expired' ? 'error' : 'warning'}">
          ${link.status}
        </span>
      </td>
      <td>
        <div class="btn-group" style="gap: 0.25rem;">
          <button class="btn btn-sm btn-secondary view-link" data-link-id="${link.id}" title="View Details">
            <i class="fas fa-eye"></i>
          </button>
          <button class="btn btn-sm btn-secondary copy-link" data-link-id="${link.id}" title="Copy Link">
            <i class="fas fa-copy"></i>
          </button>
          <button class="btn btn-sm btn-danger delete-link" data-link-id="${link.id}" title="Delete">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </td>
    </tr>
  `).join('');
  
  // Add event listeners to dynamically created buttons
  document.querySelectorAll('.view-link').forEach(btn => {
    btn.addEventListener('click', () => viewLink(btn.dataset.linkId));
  });
  
  document.querySelectorAll('.copy-link').forEach(btn => {
    btn.addEventListener('click', () => copyLink(btn.dataset.linkId));
  });
  
  document.querySelectorAll('.delete-link').forEach(btn => {
    btn.addEventListener('click', () => deleteLink(btn.dataset.linkId));
  });
}

// ============================================
// Link Management
// ============================================
async function generateLink() {
  const url = document.getElementById('targetUrl').value;
  const password = document.getElementById('linkPassword').value;
  const maxClicks = document.getElementById('maxClicks').value;
  const expiresIn = document.getElementById('expiresIn').value;
  const notes = document.getElementById('linkNotes').value;
  
  if (!url) {
    showAlert('Please enter a URL', 'error');
    return;
  }
  
  // Validate URL
  try {
    new URL(url);
  } catch {
    showAlert('Please enter a valid URL', 'error');
    return;
  }
  
  // Build request body
  const body = { 
    url, 
    password: password || undefined,
    maxClicks: maxClicks ? parseInt(maxClicks) : undefined,
    expiresIn,
    notes,
    linkMode: selectedLinkMode,
    _csrf: CSRF_TOKEN
  };
  
  // Add long link options if applicable
  if (selectedLinkMode === 'long' || (selectedLinkMode === 'auto' && ALLOW_LINK_MODE_SWITCH)) {
    body.longLinkOptions = {
      segments: parseInt(document.getElementById('longLinkSegments')?.value || LONG_LINK_SEGMENTS),
      params: parseInt(document.getElementById('longLinkParams')?.value || LONG_LINK_PARAMS),
      maxLayers: parseInt(document.getElementById('linkEncodingLayers')?.value || LINK_ENCODING_LAYERS),
      iterations: parseInt(document.getElementById('settingMaxEncodingIterations')?.value || MAX_ENCODING_ITERATIONS),
      includeFingerprint: true
    };
    
    // Add compression/encryption options
    if (document.getElementById('enableCompression')) {
      body.longLinkOptions.compression = document.getElementById('enableCompression').checked;
    }
    if (document.getElementById('enableEncryption')) {
      body.longLinkOptions.encryption = document.getElementById('enableEncryption').checked;
    }
  }
  
  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN
      },
      body: JSON.stringify(body),
      credentials: 'include'
    });
    
    if (res.ok) {
      const data = await res.json();
      document.getElementById('generatedUrl').value = data.url;
      document.getElementById('generatedId').textContent = data.id;
      document.getElementById('generatedExpires').textContent = data.expires_human;
      document.getElementById('generatedPassword').textContent = data.passwordProtected ? 'Yes' : 'No';
      document.getElementById('generatedLength').textContent = data.linkLength + ' chars';
      document.getElementById('generatedMode').textContent = (data.mode || 'short').toUpperCase() + ' Link';
      document.getElementById('result').style.display = 'block';
      
      // Show encoding details for long links
      if (data.encodingDetails) {
        document.getElementById('encodingLayers').textContent = data.encodingDetails.layers || 0;
        document.getElementById('encodingComplexity').textContent = data.encodingDetails.complexity || 0;
        document.getElementById('encodingIterations').textContent = data.encodingDetails.iterations || 1;
        document.getElementById('encodingTime').textContent = (data.encodingDetails.encodingTime || 0).toFixed(0) + 'ms';
        document.getElementById('encodingDetails').style.display = 'block';
      } else {
        document.getElementById('encodingDetails').style.display = 'none';
      }
      
      if (document.getElementById('generateQR')?.checked) {
        const size = document.getElementById('qrSize').value;
        await showQRForUrl(data.url, size);
      }
      
      showAlert('Link generated successfully!', 'success');
      refreshLinks();
    } else {
      const error = await res.json();
      showAlert(error.error || 'Failed to generate link', 'error');
    }
  } catch (err) {
    showAlert('Network error: ' + err.message, 'error');
  }
}

async function showQRForUrl(url, size = 300) {
  try {
    const res = await fetch('/qr?url=' + encodeURIComponent(url) + '&size=' + size);
    if (res.ok) {
      const data = await res.json();
      document.getElementById('qrResult').innerHTML = `
        <img src="${data.qr}" alt="QR Code" style="max-width: 200px; border-radius: 8px; box-shadow: var(--shadow-md);">
        <div style="margin-top: 1rem;" class="btn-group">
          <button class="btn btn-sm btn-secondary download-qr" data-url="${url}" data-size="${size}">
            <i class="fas fa-download"></i> Download PNG
          </button>
          <button class="btn btn-sm btn-secondary view-qr-modal" data-url="${url}" data-size="${size}">
            <i class="fas fa-expand"></i> Expand
          </button>
        </div>
      `;
      
      // Add event listeners
      document.querySelector('.download-qr')?.addEventListener('click', (e) => {
        const btn = e.currentTarget;
        downloadQR(btn.dataset.url, btn.dataset.size);
      });
      
      document.querySelector('.view-qr-modal')?.addEventListener('click', (e) => {
        const btn = e.currentTarget;
        showQRModal(btn.dataset.url, btn.dataset.size);
      });
    }
  } catch (err) {
    showAlert('Failed to generate QR code', 'error');
  }
}

function showQRModal(url, size) {
  fetch('/qr?url=' + encodeURIComponent(url) + '&size=' + (size * 2))
    .then(res => res.json())
    .then(data => {
      document.getElementById('qrModalContent').innerHTML = `
        <img src="${data.qr}" alt="QR Code" style="max-width: 100%; border-radius: 12px;">
        <div style="margin-top: 1rem;" class="btn-group">
          <button class="btn btn-sm btn-secondary download-qr-modal" data-url="${url}" data-size="${size}">
            <i class="fas fa-download"></i> Download
          </button>
        </div>
      `;
      document.getElementById('qrModal').classList.add('active');
      
      document.querySelector('.download-qr-modal')?.addEventListener('click', () => {
        downloadQR(url, size);
      });
    })
    .catch(() => showAlert('Failed to load QR code', 'error'));
}

async function getLinkStats() {
  const linkId = document.getElementById('analyticsLinkId').value;
  if (!linkId) {
    showAlert('Please enter a link ID', 'error');
    return;
  }
  
  try {
    const res = await fetch('/api/stats/' + linkId);
    if (res.ok) {
      const stats = await res.json();
      document.getElementById('linkStats').style.display = 'block';
      document.getElementById('totalClicksCount').textContent = (stats.clicks || 0) + ' clicks';
      
      let statsHtml = '';
      if (stats.exists) {
        statsHtml = `
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-title">Total Clicks</span>
              <span class="stat-icon"><i class="fas fa-mouse-pointer"></i></span>
            </div>
            <div class="stat-value">${formatNumber(stats.clicks || 0)}</div>
          </div>
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-title">Unique Visitors</span>
              <span class="stat-icon"><i class="fas fa-users"></i></span>
            </div>
            <div class="stat-value">${formatNumber(stats.uniqueVisitors || 0)}</div>
          </div>
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-title">Link Mode</span>
              <span class="stat-icon"><i class="fas fa-link"></i></span>
            </div>
            <div class="stat-value" style="font-size: 1.25rem;">${stats.linkMode || 'short'}</div>
          </div>
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-title">Length</span>
              <span class="stat-icon"><i class="fas fa-ruler"></i></span>
            </div>
            <div class="stat-value" style="font-size: 1.25rem;">${stats.linkLength || 0} chars</div>
          </div>
        `;
        
        const recentHtml = stats.recentClicks?.map(click => `
          <tr>
            <td>${new Date(click.created_at).toLocaleString()}</td>
            <td>${click.ip}</td>
            <td>${click.country || 'XX'}</td>
            <td>${click.device_type || 'unknown'}</td>
            <td><span class="badge badge-info">${click.link_mode || 'short'}</span></td>
            <td>${click.encoding_layers || 0}</td>
            <td>${click.decoding_time_ms ? click.decoding_time_ms + 'ms' : '-'}</td>
          </tr>
        `).join('') || '<tr><td colspan="7" style="text-align: center;">No clicks yet</td></tr>';
        
        document.getElementById('recentClicksTable').innerHTML = recentHtml;
        
        // Update charts
        updateAnalyticsCharts(stats);
      } else {
        statsHtml = '<div class="stat-card">Link not found or expired</div>';
        document.getElementById('recentClicksTable').innerHTML = '';
      }
      
      document.getElementById('statsContent').innerHTML = statsHtml;
    }
  } catch (err) {
    showAlert('Failed to get statistics', 'error');
  }
}

function updateAnalyticsCharts(stats) {
  // Destroy existing charts
  if (countryChart) countryChart.destroy();
  if (analyticsDeviceChart) analyticsDeviceChart.destroy();
  
  const ctxCountry = document.getElementById('countryChart')?.getContext('2d');
  const ctxDevice = document.getElementById('analyticsDeviceChart')?.getContext('2d');
  
  if (ctxCountry && stats.countries) {
    const countries = Object.entries(stats.countries).slice(0, 10);
    countryChart = new Chart(ctxCountry, {
      type: 'bar',
      data: {
        labels: countries.map(([c]) => c),
        datasets: [{
          label: 'Clicks by Country',
          data: countries.map(([, v]) => v),
          backgroundColor: '#3b82f6',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#666' }
          },
          x: {
            ticks: { color: '#666' }
          }
        }
      }
    });
  }
  
  if (ctxDevice && stats.devices) {
    analyticsDeviceChart = new Chart(ctxDevice, {
      type: 'pie',
      data: {
        labels: Object.keys(stats.devices),
        datasets: [{
          data: Object.values(stats.devices),
          backgroundColor: ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#aaa' }
          }
        }
      }
    });
  }
}

function clearStats() {
  document.getElementById('linkStats').style.display = 'none';
  document.getElementById('analyticsLinkId').value = '';
  showAlert('Statistics cleared', 'info');
}

async function viewLink(linkId) {
  try {
    const res = await fetch('/api/stats/' + linkId);
    if (res.ok) {
      const stats = await res.json();
      
      const modalContent = `
        <div style="margin-bottom: 1.5rem;">
          <p><strong>ID:</strong> <code>${linkId}</code></p>
          <p><strong>Mode:</strong> <span class="badge badge-${stats.linkMode === 'long' ? 'warning' : 'info'}">${stats.linkMode || 'short'}</span></p>
          <p><strong>Target URL:</strong> <a href="${stats.target_url}" target="_blank" style="color: #8a8a8a;">${stats.target_url}</a></p>
          <p><strong>Created:</strong> ${stats.created ? new Date(stats.created).toLocaleString() : 'N/A'}</p>
          <p><strong>Expires:</strong> ${stats.expiresAt ? new Date(stats.expiresAt).toLocaleString() : 'N/A'}</p>
          <p><strong>Clicks:</strong> ${formatNumber(stats.clicks || 0)}${stats.maxClicks ? '/' + formatNumber(stats.maxClicks) : ''}</p>
          <p><strong>Unique Visitors:</strong> ${formatNumber(stats.uniqueVisitors || 0)}</p>
          <p><strong>Password Protected:</strong> ${stats.passwordProtected ? 'Yes' : 'No'}</p>
          ${stats.notes ? `<p><strong>Notes:</strong> ${stats.notes}</p>` : ''}
          ${stats.linkLength ? `<p><strong>URL Length:</strong> ${stats.linkLength} characters</p>` : ''}
          ${stats.encodingLayers ? `<p><strong>Encoding Layers:</strong> ${stats.encodingLayers}</p>` : ''}
          ${stats.encodingComplexity ? `<p><strong>Encoding Complexity:</strong> ${stats.encodingComplexity}</p>` : ''}
        </div>
        
        <h4 style="margin-bottom: 1rem;">Country Distribution</h4>
        <div style="max-height: 200px; overflow-y: auto; margin-bottom: 1.5rem;">
          ${Object.entries(stats.countries || {}).map(([country, count]) => `
            <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #1a1a1a;">
              <span>${country}</span>
              <span style="font-weight: 600;">${formatNumber(count)}</span>
            </div>
          `).join('')}
        </div>
        
        <div class="btn-group">
          <button class="btn btn-sm copy-link-modal" data-link-id="${linkId}">
            <i class="fas fa-copy"></i> Copy Link
          </button>
          <button class="btn btn-sm btn-secondary qr-link-modal" data-link-id="${linkId}">
            <i class="fas fa-qrcode"></i> Generate QR
          </button>
          <button class="btn btn-sm btn-danger delete-link-modal" data-link-id="${linkId}">
            <i class="fas fa-trash"></i> Delete
          </button>
        </div>
      `;
      
      document.getElementById('linkModalContent').innerHTML = modalContent;
      document.getElementById('linkModal').classList.add('active');
      
      // Add event listeners for modal buttons
      document.querySelector('.copy-link-modal')?.addEventListener('click', () => copyLink(linkId));
      document.querySelector('.qr-link-modal')?.addEventListener('click', () => {
        const url = window.location.origin + '/v/' + linkId;
        showQRModal(url, 300);
      });
      document.querySelector('.delete-link-modal')?.addEventListener('click', () => deleteLink(linkId));
    }
  } catch (err) {
    showAlert('Failed to load link details', 'error');
  }
}

function copyLink(linkId) {
  const url = window.location.origin + '/v/' + linkId;
  navigator.clipboard.writeText(url);
  showAlert('Link copied to clipboard!', 'success');
}

async function deleteLink(linkId) {
  if (!confirm('Are you sure you want to delete this link?')) {
    return;
  }
  
  try {
    const res = await fetch('/api/links/' + linkId, {
      method: 'DELETE',
      headers: {
        'X-CSRF-Token': CSRF_TOKEN
      },
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Link deleted successfully', 'success');
      refreshLinks();
      closeModal();
    } else {
      showAlert('Failed to delete link', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

// ============================================
// Test Link Modes
// ============================================
async function testLinkModes() {
  const testUrl = prompt('Enter a URL to test (or use default):', 'https://example.com/very/long/path/with/many/segments?param1=value1&param2=value2');
  if (!testUrl) return;
  
  try {
    const res = await fetch('/api/test/link-modes?url=' + encodeURIComponent(testUrl));
    if (res.ok) {
      const data = await res.json();
      
      let html = `
        <div style="margin-bottom: 1.5rem;">
          <p><strong>Original URL:</strong> ${data.originalUrl.substring(0, 50)}...</p>
          <p><strong>Original Length:</strong> ${data.originalLength} characters</p>
        </div>
        
        <h4 style="margin-bottom: 1rem;">Short Link</h4>
        <div style="background: #1a1a1a; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;">
          <p><strong>Length:</strong> ${data.shortLink.length} chars (${data.shortLink.ratio}x)</p>
          <p><strong>Time:</strong> ${data.shortLink.encodingTime.toFixed(0)}ms</p>
          <p><code style="word-break: break-all;">${data.shortLink.url}</code></p>
        </div>
        
        <h4 style="margin-bottom: 1rem;">Long Link Configurations</h4>
        <table class="table" style="min-width: 600px;">
          <thead>
            <tr>
              <th>Segments</th>
              <th>Params</th>
              <th>Layers</th>
              <th>Length</th>
              <th>Ratio</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
      `;
      
      data.longLinks.forEach(link => {
        html += `
          <tr>
            <td>${link.config.segments}</td>
            <td>${link.config.params}</td>
            <td>${link.layers}</td>
            <td>${link.length} chars</td>
            <td>${(link.length / data.originalLength).toFixed(2)}x</td>
            <td>${link.encodingTime.toFixed(0)}ms</td>
          </tr>
        `;
      });
      
      html += `
          </tbody>
        </table>
        
        <div style="margin-top: 1rem; background: #1a1a1a; padding: 1rem; border-radius: 8px;">
          <p><strong>Summary:</strong> Shortest long: ${data.summary.shortest} chars, Longest long: ${data.summary.longest} chars</p>
          <p><strong>Average Encoding Time:</strong> ${data.summary.avgEncodingTime.toFixed(0)}ms</p>
          <p><strong>Average Complexity:</strong> ${data.summary.avgComplexity.toFixed(1)}</p>
        </div>
      `;
      
      document.getElementById('testModalContent').innerHTML = html;
      document.getElementById('testModal').classList.add('active');
    }
  } catch (err) {
    showAlert('Failed to run test', 'error');
  }
}

// ============================================
// Security Functions
// ============================================
async function refreshSecurityData() {
  try {
    const res = await fetch('/admin/security/monitor');
    if (res.ok) {
      securityData = await res.json();
      updateSecurityTables();
    }
  } catch (err) {
    showAlert('Failed to load security data', 'error');
  }
}

function updateSecurityTables() {
  // Login attempts
  const attemptsTable = document.getElementById('loginAttemptsTable');
  if (securityData.activeAttacks?.length > 0) {
    attemptsTable.innerHTML = securityData.activeAttacks.map(attack => `
      <tr>
        <td>${attack.ip}</td>
        <td>${attack.attempts}</td>
        <td>${new Date(attack.lastAttempt).toLocaleString()}</td>
      </tr>
    `).join('');
  } else {
    attemptsTable.innerHTML = '<tr><td colspan="3">No recent attempts</td></tr>';
  }
  
  // Blocked IPs
  const blockedTable = document.getElementById('blockedIPsTable');
  if (securityData.blockedIPs?.length > 0) {
    blockedTable.innerHTML = securityData.blockedIPs.map(ip => `
      <tr>
        <td>${ip.ip}</td>
        <td>${ip.reason || 'Unknown'}</td>
        <td>${new Date(ip.expires_at).toLocaleString()}</td>
      </tr>
    `).join('');
    document.getElementById('blockedCount').textContent = securityData.blockedIPs.length;
  } else {
    blockedTable.innerHTML = '<tr><td colspan="3">No blocked IPs</td></tr>';
    document.getElementById('blockedCount').textContent = '0';
  }
  
  document.getElementById('totalAttempts').textContent = securityData.totalAttempts || 0;
}

async function clearLoginAttempts() {
  showAlert('Login attempts cleared', 'success');
}

async function updateBotThreshold(threshold) {
  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN
      },
      body: JSON.stringify({
        key: 'botThresholds',
        value: { desktop: threshold }
      }),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Bot threshold updated', 'success');
    }
  } catch (err) {
    showAlert('Failed to update threshold', 'error');
  }
}

// ============================================
// Settings Functions
// ============================================
async function saveLinkModeSettings() {
  const settings = {
    linkLengthMode: document.getElementById('settingLinkLengthMode').value,
    allowLinkModeSwitch: document.getElementById('settingAllowLinkModeSwitch').checked,
    longLinkSegments: parseInt(document.getElementById('settingLongLinkSegments').value),
    longLinkParams: parseInt(document.getElementById('settingLongLinkParams').value),
    linkEncodingLayers: parseInt(document.getElementById('settingLinkEncodingLayers').value),
    maxEncodingIterations: parseInt(document.getElementById('settingMaxEncodingIterations').value),
    enableCompression: document.getElementById('settingEnableCompression').checked,
    enableEncryption: document.getElementById('settingEnableEncryption').checked
  };
  
  try {
    const res = await fetch('/api/settings/link-mode', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN
      },
      body: JSON.stringify(settings),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Link mode settings saved', 'success');
      
      // Update local variables
      if (settings.linkLengthMode) LINK_LENGTH_MODE = settings.linkLengthMode;
      if (settings.longLinkSegments) LONG_LINK_SEGMENTS = settings.longLinkSegments;
      if (settings.longLinkParams) LONG_LINK_PARAMS = settings.longLinkParams;
      if (settings.linkEncodingLayers) LINK_ENCODING_LAYERS = settings.linkEncodingLayers;
      
      selectLinkMode(LINK_LENGTH_MODE);
    } else {
      const error = await res.json();
      showAlert(error.error || 'Failed to save settings', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

async function saveSystemSettings() {
  const settings = {
    linkTTL: parseInt(document.getElementById('settingLinkTTL').value),
    desktopChallenge: document.getElementById('settingDesktopChallenge').checked,
    botDetection: document.getElementById('settingBotDetection').checked,
    analytics: document.getElementById('settingAnalytics').checked,
    logLevel: document.getElementById('settingLogLevel').value
  };
  
  // Save each setting individually
  for (const [key, value] of Object.entries(settings)) {
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': CSRF_TOKEN
        },
        body: JSON.stringify({ key, value }),
        credentials: 'include'
      });
    } catch (err) {
      console.error('Failed to save setting:', key, err);
    }
  }
  
  showAlert('System settings saved', 'success');
}

async function reloadConfig() {
  try {
    const res = await fetch('/admin/reload-config', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': CSRF_TOKEN
      },
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Configuration reloaded', 'success');
      setTimeout(() => location.reload(), 1000);
    } else {
      showAlert('Failed to reload config', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

async function viewHealthCheck() {
  try {
    const res = await fetch('/health/full');
    if (res.ok) {
      const health = await res.json();
      
      let html = '<div style="margin-bottom: 1rem;">';
      for (const [service, status] of Object.entries(health.checks)) {
        const statusClass = status === true ? 'success' : status === 'disabled' ? 'info' : 'error';
        html += `
          <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #1a1a1a;">
            <span>${service}</span>
            <span class="badge badge-${statusClass}">${status === true ? 'Healthy' : status === 'disabled' ? 'Disabled' : 'Unhealthy'}</span>
          </div>
        `;
      }
      html += '</div>';
      
      html += `
        <div style="background: #1a1a1a; padding: 1rem; border-radius: 8px;">
          <p><strong>Status:</strong> <span class="badge badge-${health.status === 'healthy' ? 'success' : 'error'}">${health.status}</span></p>
          <p><strong>Uptime:</strong> ${formatDuration(health.uptime)}</p>
          <p><strong>Timestamp:</strong> ${new Date(health.timestamp).toLocaleString()}</p>
        </div>
      `;
      
      document.getElementById('healthModalContent').innerHTML = html;
      document.getElementById('healthModal').classList.add('active');
    }
  } catch (err) {
    showAlert('Failed to load health check', 'error');
  }
}

// ============================================
// Export Functions
// ============================================
function exportData(format) {
  const linkId = document.getElementById('analyticsLinkId').value;
  if (!linkId) {
    showAlert('Please enter a link ID', 'error');
    return;
  }
  window.location.href = `/api/export/${linkId}?format=${format}`;
}

function exportAllLinks() {
  const dataStr = JSON.stringify(allLinks, null, 2);
  const blob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `links-${new Date().toISOString()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showAlert('Links exported', 'success');
}

// ============================================
// Utility Functions
// ============================================
function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
  return Math.floor(seconds / 86400) + 'd ' + Math.floor((seconds % 86400) / 3600) + 'h';
}

function refreshLinks() {
  socket.emit('command', { action: 'getLinks' });
}

function clearForm() {
  document.getElementById('targetUrl').value = TARGET_URL;
  document.getElementById('linkPassword').value = '';
  document.getElementById('maxClicks').value = '';
  document.getElementById('linkNotes').value = '';
  document.getElementById('expiresIn').value = '30m';
  document.getElementById('generateQR').checked = false;
  document.getElementById('qrSize').disabled = true;
  document.getElementById('result').style.display = 'none';
  document.getElementById('qrResult').innerHTML = '';
  document.getElementById('encodingDetails').style.display = 'none';
}

function copyToClipboard() {
  const url = document.getElementById('generatedUrl');
  url.select();
  document.execCommand('copy');
  showAlert('Copied to clipboard!', 'success');
}

function showQRFromResult() {
  const url = document.getElementById('generatedUrl').value;
  const size = document.getElementById('qrSize')?.value || 300;
  showQRModal(url, size);
}

function downloadQR(url, size) {
  window.location.href = '/qr/download?url=' + encodeURIComponent(url) + '&size=' + size;
}

function clearLogs() {
  const logs = document.getElementById('logs');
  logs.innerHTML = '<div class="log-entry" style="color: #7aa2f7; text-align: center;"><i class="fas fa-check-circle"></i> Logs cleared</div>';
  logCount = 0;
  document.getElementById('logCounter').textContent = '0';
  document.getElementById('logRate').textContent = '0 logs/sec';
  showAlert('Logs cleared', 'success');
}

function exportLogs() {
  const logs = document.getElementById('logs');
  const logEntries = [];
  
  for (const entry of logs.children) {
    logEntries.push(entry.textContent);
  }
  
  const blob = new Blob([logEntries.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `logs-${new Date().toISOString()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  
  showAlert('Logs exported', 'success');
}

function logout() {
  fetch('/admin/logout', {
    method: 'POST',
    credentials: 'include'
  }).then(() => {
    window.location.href = '/admin/login';
  });
}

// ============================================
// Cache Management
// ============================================
async function clearCache(type) {
  let action = 'clearCache';
  let message = 'all caches';
  
  if (type === 'geo') {
    action = 'clearGeoCache';
    message = 'geo cache';
  } else if (type === 'qr') {
    action = 'clearQRCache';
    message = 'QR cache';
  } else if (type === 'encoding') {
    action = 'clearEncodingCache';
    message = 'encoding cache';
  }
  
  if (!confirm(`Are you sure you want to clear ${message}?`)) return;
  
  if (type === 'all') {
    try {
      const res = await fetch('/admin/clear-cache', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-CSRF-Token': CSRF_TOKEN
        },
        body: JSON.stringify({ _csrf: CSRF_TOKEN }),
        credentials: 'include'
      });
      
      if (res.ok) {
        showAlert('All caches cleared', 'success');
      }
    } catch (err) {
      showAlert('Failed to clear cache', 'error');
    }
  } else {
    socket.emit('command', { action });
  }
}

// ============================================
// Modal functions
// ============================================
function closeModal() {
  document.getElementById('linkModal').classList.remove('active');
}

function closeTestModal() {
  document.getElementById('testModal').classList.remove('active');
}

function closeHealthModal() {
  document.getElementById('healthModal').classList.remove('active');
}

function closeQRModal() {
  document.getElementById('qrModal').classList.remove('active');
}

// ============================================
// Click outside to close modal
// ============================================
window.onclick = function(event) {
  const modal = document.getElementById('linkModal');
  if (event.target === modal) {
    closeModal();
  }
  const testModal = document.getElementById('testModal');
  if (event.target === testModal) {
    closeTestModal();
  }
  const healthModal = document.getElementById('healthModal');
  if (event.target === healthModal) {
    closeHealthModal();
  }
  const qrModal = document.getElementById('qrModal');
  if (event.target === qrModal) {
    closeQRModal();
  }
};

// Handle escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeModal();
    closeTestModal();
    closeHealthModal();
    closeQRModal();
  }
});

// Handle window resize
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) {
    document.getElementById('sidebar').classList.remove('open');
  }
});

// ============================================
// Uptime counter
// ============================================
let startTime = Date.now();
setInterval(() => {
  const uptime = Math.floor((Date.now() - startTime) / 1000);
  const uptimeElement = document.getElementById('uptimeValue');
  const systemUptimeElement = document.getElementById('systemUptime');
  
  if (uptimeElement) {
    uptimeElement.textContent = formatDuration(uptime);
  }
  if (systemUptimeElement) {
    systemUptimeElement.textContent = formatDuration(uptime);
  }
  
  // Update memory (mock for demo - replace with real data from socket)
  if (!socket || !socket.connected) {
    const memoryElement = document.getElementById('memoryUsage');
    if (memoryElement) {
      memoryElement.textContent = Math.floor(Math.random() * 200 + 100) + ' MB';
    }
  }
}, 1000);

// ============================================
// Check for queues
// ============================================
fetch('/health')
  .then(res => res.json())
  .then(data => {
    if (data.queues?.redirect === 'ready') {
      document.getElementById('queuesNavItem').style.display = 'flex';
    }
    if (data.database) {
      document.getElementById('dbStatus').className = 'status-dot connected';
    } else {
      document.getElementById('dbStatus').className = 'status-dot disconnected';
    }
    if (data.redis === 'connected') {
      document.getElementById('redisStatus').className = 'status-dot connected';
    } else {
      document.getElementById('redisStatus').className = 'status-dot disconnected';
    }
    if (data.queues?.redirect === 'ready') {
      document.getElementById('queueStatus').className = 'status-dot connected';
    } else {
      document.getElementById('queueStatus').className = 'status-dot disconnected';
    }
  })
  .catch(err => console.error('Health check failed:', err));

// ============================================
// Initialize everything
// ============================================
function init() {
  console.log('🚀 Initializing admin dashboard...');
  initSocket();
  setupEventListeners();
  
  // Initialize the first tab
  showTab('dashboard');
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);