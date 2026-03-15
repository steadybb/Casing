// ============================================
// Redirector Pro v4.1.0 - Enterprise Dashboard
// ============================================

// Global variables injected from server
/* global METRICS_API_KEY, TARGET_URL, CSRF_TOKEN, LINK_LENGTH_MODE, 
   ALLOW_LINK_MODE_SWITCH, LONG_LINK_SEGMENTS, LONG_LINK_PARAMS, 
   LINK_ENCODING_LAYERS, MAX_ENCODING_ITERATIONS, ENABLE_COMPRESSION,
   ENABLE_ENCRYPTION, BULL_BOARD_PATH, NODE_ENV, RATE_LIMIT_MAX, 
   ENCODING_RATE_LIMIT, MFA_ENABLED, WEBAUTHN_ENABLED, SESSION_TTL,
   AUDIT_LOG_ENABLED, BACKUP_ENCRYPTION_ENABLED */

// ============================================
// State Management
// ============================================
let socket;
let requestsChart, deviceChart, countryChart, analyticsDeviceChart, performanceChart;
let allLinks = [];
let filteredLinks = [];
let autoScroll = true;
let showTimestamps = true;
let currentTimeRange = '5m';
let logCount = 0;
let selectedLinkMode = typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short';
let currentPage = 1;
const pageSize = 20;
let securityData = { blockedIPs: [], activeAttacks: [], totalAttempts: 0, activeSessions: [] };
let logFilter = 'all';
let logRate = 0;
let logRateCounter = 0;
let encryptionKeys = [];
let auditLogs = [];
let backupStatus = {};
let mfaSetupRequired = false;
let activeAlerts = [];
let notificationSound = false;
let darkMode = true;
let refreshInterval = 5000;
let autoRefreshEnabled = true;

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
    socket.emit('command', { action: 'getSystemMetrics' });
    
    // Request encryption keys if on keys tab
    const keysTab = document.getElementById('encryption-keys');
    if (keysTab && keysTab.classList.contains('active')) {
      fetchEncryptionKeys();
    }
    
    // Request audit logs if on audit tab
    const auditTab = document.getElementById('audit-log');
    if (auditTab && auditTab.classList.contains('active')) {
      fetchAuditLogs();
    }
    
    // Request security data if on security tab
    const securityTab = document.getElementById('security');
    if (securityTab && securityTab.classList.contains('active')) {
      refreshSecurityData();
    }
    
    // Request backup status if on backup tab
    const backupTab = document.getElementById('backup');
    if (backupTab && backupTab.classList.contains('active')) {
      fetchBackupStatus();
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
    updateSecurityMetrics(data);
    updateRealtimeMetrics(data);
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
    
    // Check for alerts
    checkForAlerts(log);
  });
  
  socket.on('link-generated', (data) => {
    console.log('🔗 Link generated:', data);
    showAlert('New link generated', 'info');
    refreshLinks();
    playNotification('generated');
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
    playNotification(notification.type);
  });
  
  socket.on('commandResult', (result) => {
    console.log('📨 Command result:', result);
  });
  
  socket.on('systemMetrics', (metrics) => {
    updateSystemMetrics(metrics);
  });
  
  socket.on('keys', (keys) => {
    console.log('🔑 Encryption keys received:', keys);
    encryptionKeys = keys;
    renderEncryptionKeys();
  });
  
  socket.on('audit', (entry) => {
    console.log('📝 Audit log entry:', entry);
    addAuditEntry(entry);
  });
  
  socket.on('backup', (status) => {
    console.log('💾 Backup status:', status);
    backupStatus = status;
    updateBackupStatus();
  });
  
  socket.on('alert', (alert) => {
    console.log('⚠️ Alert:', alert);
    activeAlerts.push(alert);
    showAlert(alert.message, alert.severity);
    updateAlertBadge();
    playNotification('alert');
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

// Auto-refresh if enabled
setInterval(() => {
  if (autoRefreshEnabled && socket && socket.connected) {
    const activeTab = document.querySelector('.tab-content.active')?.id;
    if (activeTab === 'dashboard') {
      socket.emit('command', { action: 'getStats' });
    } else if (activeTab === 'links') {
      socket.emit('command', { action: 'getLinks' });
    } else if (activeTab === 'security') {
      refreshSecurityData();
    }
  }
}, refreshInterval);

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
  document.getElementById('keyModalClose')?.addEventListener('click', closeKeyModal);
  document.getElementById('auditModalClose')?.addEventListener('click', closeAuditModal);
  
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
    if (typeof BULL_BOARD_PATH !== 'undefined') {
      window.location.href = BULL_BOARD_PATH;
    } else {
      window.location.href = '/admin/queues';
    }
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
  
  const autoScrollCheckbox = document.getElementById('autoScroll');
  if (autoScrollCheckbox) {
    autoScrollCheckbox.addEventListener('change', (e) => {
      autoScroll = e.target.checked;
    });
  }
  
  const showTimestampsCheckbox = document.getElementById('showTimestamps');
  if (showTimestampsCheckbox) {
    showTimestampsCheckbox.addEventListener('change', (e) => {
      showTimestamps = e.target.checked;
    });
  }
  
  const logFilterSelect = document.getElementById('logFilter');
  if (logFilterSelect) {
    logFilterSelect.addEventListener('change', (e) => {
      logFilter = e.target.value;
    });
  }
  
  // Cache management
  document.getElementById('clearAllCache')?.addEventListener('click', () => clearCache('all'));
  document.getElementById('clearGeoCache')?.addEventListener('click', () => clearCache('geo'));
  document.getElementById('clearQRCache')?.addEventListener('click', () => clearCache('qr'));
  document.getElementById('clearEncodingCache')?.addEventListener('click', () => clearCache('encoding'));
  document.getElementById('clearDeviceCache')?.addEventListener('click', () => clearCache('device'));
  
  // Security
  document.getElementById('refreshSecurityBtn')?.addEventListener('click', refreshSecurityData);
  document.getElementById('clearAttemptsBtn')?.addEventListener('click', clearLoginAttempts);
  document.getElementById('unblockIPBtn')?.addEventListener('click', showUnblockIPModal);
  document.getElementById('revokeSessionBtn')?.addEventListener('click', showRevokeSessionModal);
  
  const botThresholdSlider = document.getElementById('botThresholdSlider');
  if (botThresholdSlider) {
    botThresholdSlider.addEventListener('input', (e) => {
      const botThreshold = document.getElementById('botThreshold');
      const botThresholdBar = document.getElementById('botThresholdBar');
      if (botThreshold) botThreshold.textContent = e.target.value;
      if (botThresholdBar) botThresholdBar.style.width = e.target.value + '%';
    });
    botThresholdSlider.addEventListener('change', (e) => {
      updateBotThreshold(parseInt(e.target.value));
    });
  }
  
  // Encryption keys
  document.getElementById('rotateKeysBtn')?.addEventListener('click', rotateEncryptionKeys);
  document.getElementById('backupKeysBtn')?.addEventListener('click', backupEncryptionKeys);
  document.getElementById('viewKeyBtn')?.addEventListener('click', () => showKeyDetails());
  
  // Audit logs
  document.getElementById('refreshAuditBtn')?.addEventListener('click', fetchAuditLogs);
  document.getElementById('exportAuditBtn')?.addEventListener('click', exportAuditLogs);
  document.getElementById('auditFilter')?.addEventListener('change', filterAuditLogs);
  document.getElementById('auditDateRange')?.addEventListener('change', filterAuditLogs);
  
  // Backup
  document.getElementById('runBackupBtn')?.addEventListener('click', runBackup);
  document.getElementById('restoreBackupBtn')?.addEventListener('click', showRestoreModal);
  document.getElementById('configureBackupBtn')?.addEventListener('click', showBackupConfig);
  
  // Settings
  document.getElementById('saveLinkModeSettings')?.addEventListener('click', saveLinkModeSettings);
  document.getElementById('saveSystemSettings')?.addEventListener('click', saveSystemSettings);
  document.getElementById('saveSecuritySettings')?.addEventListener('click', saveSecuritySettings);
  document.getElementById('saveNotificationSettings')?.addEventListener('click', saveNotificationSettings);
  document.getElementById('reloadConfigBtn')?.addEventListener('click', reloadConfig);
  document.getElementById('viewHealthBtn')?.addEventListener('click', viewHealthCheck);
  
  // Refresh interval
  document.getElementById('refreshInterval')?.addEventListener('change', (e) => {
    refreshInterval = parseInt(e.target.value) * 1000;
  });
  
  document.getElementById('autoRefresh')?.addEventListener('change', (e) => {
    autoRefreshEnabled = e.target.checked;
  });
  
  // Notification sound
  document.getElementById('notificationSound')?.addEventListener('change', (e) => {
    notificationSound = e.target.checked;
  });
  
  // Dark mode toggle
  document.getElementById('darkModeToggle')?.addEventListener('change', (e) => {
    darkMode = e.target.checked;
    document.body.classList.toggle('light-mode', !darkMode);
  });
  
  // Initialize link mode
  selectLinkMode(selectedLinkMode);
  
  // Initialize dark mode
  document.body.classList.toggle('light-mode', !darkMode);
  
  // Check for MFA setup
  if (typeof MFA_ENABLED !== 'undefined' && MFA_ENABLED === 'true' && !localStorage.getItem('mfa_setup_completed')) {
    mfaSetupRequired = true;
    showMFASetupPrompt();
  }
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
  } else if (tabId === 'encryption-keys') {
    fetchEncryptionKeys();
  } else if (tabId === 'audit-log') {
    fetchAuditLogs();
  } else if (tabId === 'backup') {
    fetchBackupStatus();
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
    if (helpText) helpText.textContent = 'Short: Clean, simple URLs (/v/id)';
    if (longOptions) longOptions.style.display = 'none';
  } else if (mode === 'long') {
    if (helpText) helpText.textContent = 'Long: Obfuscated URLs with many segments and parameters';
    if (longOptions) longOptions.style.display = 'block';
  } else {
    if (helpText) helpText.textContent = 'Auto: Automatically choose based on URL length';
    if (typeof ALLOW_LINK_MODE_SWITCH !== 'undefined' && ALLOW_LINK_MODE_SWITCH) {
      if (longOptions) longOptions.style.display = 'block';
    } else {
      if (longOptions) longOptions.style.display = 'none';
      if (helpText) helpText.textContent = 'Auto mode disabled. Using ' + (typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short') + ' mode.';
    }
  }
  
  const modeIndicator = document.getElementById('modeIndicator');
  if (modeIndicator) {
    modeIndicator.textContent = 'Mode: ' + mode;
  }
}

function applyLongLinkPreset(preset) {
  let segments, params, layers, iterations;
  
  switch(preset) {
    case 'standard':
      segments = 6;
      params = 13;
      layers = 4;
      iterations = 2;
      break;
    case 'aggressive':
      segments = 12;
      params = 20;
      layers = 6;
      iterations = 3;
      break;
    case 'stealth':
      segments = 18;
      params = 28;
      layers = 8;
      iterations = 4;
      break;
    case 'maximum':
      segments = 20;
      params = 30;
      layers = 12;
      iterations = 5;
      break;
    default:
      return;
  }
  
  const segmentsInput = document.getElementById('longLinkSegments');
  const paramsInput = document.getElementById('longLinkParams');
  const layersInput = document.getElementById('linkEncodingLayers');
  const iterationsInput = document.getElementById('maxEncodingIterations');
  
  if (segmentsInput) segmentsInput.value = segments;
  if (paramsInput) paramsInput.value = params;
  if (layersInput) layersInput.value = layers;
  if (iterationsInput) iterationsInput.value = iterations;
}

function showAlert(message, type = 'info') {
  const alert = document.getElementById('alert');
  if (!alert) return;
  
  const icons = {
    success: 'check-circle',
    error: 'exclamation-circle',
    warning: 'exclamation-triangle',
    info: 'info-circle'
  };
  
  alert.className = `alert alert-${type}`;
  alert.innerHTML = `
    <div class="alert-icon">
      <i class="fas fa-${icons[type] || 'info-circle'}"></i>
    </div>
    <div class="alert-content">
      <div class="alert-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
      <div class="alert-message">${message}</div>
    </div>
    <button class="alert-close" onclick="this.parentElement.style.display='none'">
      <i class="fas fa-times"></i>
    </button>
  `;
  alert.style.display = 'flex';
  
  // Auto-hide after 5 seconds for non-error messages
  if (type !== 'error') {
    setTimeout(() => {
      if (alert.style.display === 'flex') {
        alert.style.display = 'none';
      }
    }, 5000);
  }
}

function playNotification(type) {
  if (!notificationSound) return;
  
  const audio = new Audio();
  switch(type) {
    case 'generated':
      audio.src = 'data:audio/wav;base64,UklGRlwAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YVgAAABAAECAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAA';
      break;
    case 'alert':
      audio.src = 'data:audio/wav;base64,UklGRlwAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YVgAAABAAECAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAAAICAAACAgAAAgIAA';
      break;
    default:
      return;
  }
  audio.volume = 0.3;
  audio.play().catch(() => {});
}

function updateAlertBadge() {
  const alertBadge = document.getElementById('alertBadge');
  if (alertBadge) {
    alertBadge.textContent = activeAlerts.length;
    alertBadge.style.display = activeAlerts.length > 0 ? 'flex' : 'none';
  }
}

function checkForAlerts(log) {
  // Check for suspicious patterns
  if (log.type === 'rate-limit' && log.count > 10) {
    activeAlerts.push({
      id: Date.now(),
      type: 'rate-limit',
      severity: 'warning',
      message: `High rate limiting from ${log.ip}`,
      timestamp: new Date().toISOString()
    });
    updateAlertBadge();
  }
  
  if (log.type === 'bot-block' && log.reason === 'explicit_bot') {
    activeAlerts.push({
      id: Date.now(),
      type: 'bot',
      severity: 'info',
      message: `Bot detected: ${log.ip}`,
      timestamp: new Date().toISOString()
    });
    updateAlertBadge();
  }
  
  if (log.type === 'error' && log.error) {
    activeAlerts.push({
      id: Date.now(),
      type: 'error',
      severity: 'error',
      message: `Error: ${log.error.substring(0, 50)}`,
      timestamp: new Date().toISOString()
    });
    updateAlertBadge();
  }
}

function showMFASetupPrompt() {
  const prompt = document.createElement('div');
  prompt.className = 'alert alert-warning mfa-prompt';
  prompt.innerHTML = `
    <i class="fas fa-shield-alt"></i>
    <div class="mfa-prompt-content">
      <strong>Two-Factor Authentication Available</strong>
      <p>Enhance your account security by enabling 2FA</p>
    </div>
    <button class="btn btn-sm btn-primary" onclick="setupMFA()">Setup Now</button>
    <button class="btn btn-sm btn-secondary" onclick="this.parentElement.remove()">Dismiss</button>
  `;
  document.body.appendChild(prompt);
  
  setTimeout(() => {
    prompt.remove();
  }, 30000);
}

function setupMFA() {
  window.location.href = '/admin/setup-mfa';
}

function updateSocketStatus(status) {
  const socketStatus = document.getElementById('socketStatus');
  if (socketStatus) {
    socketStatus.className = `status-dot ${status}`;
    socketStatus.title = `Socket ${status}`;
  }
}

function updateStats(data) {
  const totalRequestsEl = document.getElementById('totalRequests');
  const activeLinksEl = document.getElementById('activeLinks');
  const botBlocksEl = document.getElementById('botBlocks');
  const requestTrendEl = document.getElementById('requestTrend');
  const blockRateEl = document.getElementById('blockRate');
  const peakLinksEl = document.getElementById('peakLinks');
  const totalDevicesEl = document.getElementById('totalDevices');
  
  if (totalRequestsEl) totalRequestsEl.textContent = formatNumber(data.totalRequests || 0);
  if (activeLinksEl) activeLinksEl.textContent = formatNumber(data.realtime?.activeLinks || 0);
  if (botBlocksEl) botBlocksEl.textContent = formatNumber(data.botBlocks || 0);
  
  // Calculate trends
  const lastMinute = data.realtime?.lastMinute || [];
  if (lastMinute.length > 1 && requestTrendEl) {
    const current = lastMinute[lastMinute.length - 1]?.requests || 0;
    const previous = lastMinute[lastMinute.length - 2]?.requests || 0;
    const trend = previous ? ((current - previous) / previous * 100).toFixed(1) : 0;
    requestTrendEl.textContent = (trend > 0 ? '+' : '') + trend + '%';
    requestTrendEl.className = trend >= 0 ? 'trend-up' : 'trend-down';
  }
  
  // Block rate
  if (blockRateEl) {
    const blockRate = data.totalRequests ? ((data.botBlocks / data.totalRequests) * 100).toFixed(1) : 0;
    blockRateEl.textContent = blockRate + '%';
  }
  
  // Peak links
  if (peakLinksEl) peakLinksEl.textContent = formatNumber(data.realtime?.peakLinks || 0);
  
  // Total devices
  if (totalDevicesEl) {
    const totalDevices = Object.values(data.byDevice || {}).reduce((a, b) => a + b, 0);
    totalDevicesEl.textContent = formatNumber(totalDevices) + ' total';
  }
}

function updateLinkModeStats(modes) {
  const linkModesEl = document.getElementById('linkModes');
  if (modes && linkModesEl) {
    linkModesEl.textContent = `S:${modes.short || 0} L:${modes.long || 0} A:${modes.auto || 0}`;
  }
}

function updateCacheStats(caches) {
  const cacheLinksEl = document.getElementById('cacheLinks');
  const cacheGeoEl = document.getElementById('cacheGeo');
  const cacheQREl = document.getElementById('cacheQR');
  const cacheEncodingEl = document.getElementById('cacheEncoding');
  const cacheDeviceEl = document.getElementById('cacheDevice');
  const cacheNonceEl = document.getElementById('cacheNonce');
  
  if (caches) {
    if (cacheLinksEl) cacheLinksEl.textContent = formatNumber(caches.linkReq || 0);
    if (cacheGeoEl) cacheGeoEl.textContent = formatNumber(caches.geo || 0);
    if (cacheQREl) cacheQREl.textContent = formatNumber(caches.qr || 0);
    if (cacheEncodingEl) cacheEncodingEl.textContent = formatNumber(caches.encoding || 0);
    if (cacheDeviceEl) cacheDeviceEl.textContent = formatNumber(caches.device || 0);
    if (cacheNonceEl) cacheNonceEl.textContent = formatNumber(caches.nonce || 0);
  }
}

function updateDetailedCacheStats(stats) {
  const cacheHitsEl = document.getElementById('cacheHits');
  const cacheMissesEl = document.getElementById('cacheMisses');
  const detailedHitRateEl = document.getElementById('detailedHitRate');
  const cacheHitRateEl = document.getElementById('cacheHitRate');
  
  if (stats) {
    const totalHits = Object.values(stats).reduce((sum, s) => sum + (s.hits || 0), 0);
    const totalMisses = Object.values(stats).reduce((sum, s) => sum + (s.misses || 0), 0);
    const total = totalHits + totalMisses;
    const hitRate = total ? ((totalHits / total) * 100).toFixed(1) : 0;
    
    if (cacheHitsEl) cacheHitsEl.textContent = formatNumber(totalHits);
    if (cacheMissesEl) cacheMissesEl.textContent = formatNumber(totalMisses);
    if (detailedHitRateEl) detailedHitRateEl.textContent = hitRate + '%';
    if (cacheHitRateEl) cacheHitRateEl.textContent = hitRate + '%';
  }
}

function updatePerformanceMetrics(data) {
  const avgResponseTimeEl = document.getElementById('avgResponseTime');
  const p95TimeEl = document.getElementById('p95Time');
  const p99TimeEl = document.getElementById('p99Time');
  const currentRPSEl = document.getElementById('currentRPS');
  const peakRPSEl = document.getElementById('peakRPS');
  const totalResponseTimeEl = document.getElementById('totalResponseTime');
  
  if (data.performance) {
    if (avgResponseTimeEl) avgResponseTimeEl.textContent = data.performance.avgResponseTime?.toFixed(0) + 'ms' || '0ms';
    if (p95TimeEl) p95TimeEl.textContent = data.performance.p95ResponseTime?.toFixed(0) + 'ms' || '0ms';
    if (p99TimeEl) p99TimeEl.textContent = data.performance.p99ResponseTime?.toFixed(0) + 'ms' || '0ms';
    if (totalResponseTimeEl) totalResponseTimeEl.textContent = formatDuration(data.performance.totalResponseTime || 0);
  }
  
  if (data.realtime) {
    if (currentRPSEl) currentRPSEl.textContent = data.realtime.requestsPerSecond || 0;
    if (peakRPSEl) peakRPSEl.textContent = data.realtime.peakRPS || 0;
  }
}

function updateEncodingStats(encodingStats) {
  const encodingStatsEl = document.getElementById('encodingStats');
  const avgLayersEl = document.getElementById('avgLayers');
  const cacheHitRateEl = document.getElementById('cacheHitRate');
  const cacheSizeEl = document.getElementById('cacheSize');
  const avgComplexityEl = document.getElementById('avgComplexity');
  const avgDecodeTimeEl = document.getElementById('avgDecodeTime');
  
  if (encodingStats) {
    if (encodingStatsEl) encodingStatsEl.textContent = formatNumber(encodingStats.totalEncoded || 0);
    if (avgLayersEl) avgLayersEl.textContent = (encodingStats.avgLayers || 0).toFixed(1);
    if (avgComplexityEl) avgComplexityEl.textContent = (encodingStats.avgComplexity || 0).toFixed(1);
    if (avgDecodeTimeEl) avgDecodeTimeEl.textContent = (encodingStats.avgDecodeTime || 0).toFixed(0) + 'ms';
    
    // Cache hit rate
    const totalRequests = (encodingStats.cacheHits || 0) + (encodingStats.cacheMisses || 0);
    const hitRate = totalRequests ? ((encodingStats.cacheHits / totalRequests) * 100).toFixed(1) : 0;
    if (cacheHitRateEl) cacheHitRateEl.textContent = hitRate + '%';
    if (cacheSizeEl) cacheSizeEl.textContent = formatNumber(encodingStats.totalEncoded || 0);
  }
}

function updateSecurityMetrics(data) {
  const botReasonsEl = document.getElementById('botReasons');
  if (botReasonsEl && data.byBotReason) {
    const reasons = Object.entries(data.byBotReason)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([reason, count]) => `<div><span>${reason}:</span> <span>${formatNumber(count)}</span></div>`)
      .join('');
    botReasonsEl.innerHTML = reasons || '<div>No data</div>';
  }
  
  const signaturesValidEl = document.getElementById('signaturesValid');
  const signaturesInvalidEl = document.getElementById('signaturesInvalid');
  
  if (data.signatures) {
    if (signaturesValidEl) signaturesValidEl.textContent = formatNumber(data.signatures.valid || 0);
    if (signaturesInvalidEl) signaturesInvalidEl.textContent = formatNumber(data.signatures.invalid || 0);
  }
}

function updateRealtimeMetrics(data) {
  const memoryUsageEl = document.getElementById('memoryUsage');
  const cpuUsageEl = document.getElementById('cpuUsage');
  const uptimeEl = document.getElementById('uptimeValue');
  const systemUptimeEl = document.getElementById('systemUptime');
  
  if (data.system) {
    if (memoryUsageEl) memoryUsageEl.textContent = formatBytes(data.system.memory || 0);
    if (cpuUsageEl) cpuUsageEl.textContent = (data.system.cpu || 0).toFixed(1) + '%';
    if (uptimeEl) uptimeEl.textContent = formatDuration(data.system.uptime || 0);
    if (systemUptimeEl) systemUptimeEl.textContent = formatDuration(data.system.uptime || 0);
  }
}

function updateSystemMetrics(metrics) {
  const memoryUsageEl = document.getElementById('memoryUsage');
  const cpuUsageEl = document.getElementById('cpuUsage');
  const uptimeEl = document.getElementById('uptimeValue');
  const systemUptimeEl = document.getElementById('systemUptime');
  
  if (metrics) {
    if (memoryUsageEl) memoryUsageEl.textContent = formatBytes(metrics.memory?.heapUsed || 0);
    if (cpuUsageEl) cpuUsageEl.textContent = (metrics.cpu || 0).toFixed(1) + '%';
    if (uptimeEl) uptimeEl.textContent = formatDuration(metrics.uptime || 0);
    if (systemUptimeEl) systemUptimeEl.textContent = formatDuration(metrics.uptime || 0);
    
    // Update connection metrics
    const connectionsEl = document.getElementById('activeConnections');
    if (connectionsEl) connectionsEl.textContent = metrics.connections || 0;
  }
}

function updateConfig(data) {
  const settingLinkLengthMode = document.getElementById('settingLinkLengthMode');
  const settingAllowLinkModeSwitch = document.getElementById('settingAllowLinkModeSwitch');
  const settingLongLinkSegments = document.getElementById('settingLongLinkSegments');
  const settingLongLinkParams = document.getElementById('settingLongLinkParams');
  const settingLinkEncodingLayers = document.getElementById('settingLinkEncodingLayers');
  const settingMaxEncodingIterations = document.getElementById('settingMaxEncodingIterations');
  const settingEnableCompression = document.getElementById('settingEnableCompression');
  const settingEnableEncryption = document.getElementById('settingEnableEncryption');
  const longLinkSegments = document.getElementById('longLinkSegments');
  const longLinkParams = document.getElementById('longLinkParams');
  const linkEncodingLayers = document.getElementById('linkEncodingLayers');
  const maxEncodingIterations = document.getElementById('maxEncodingIterations');
  const enableCompression = document.getElementById('enableCompression');
  const enableEncryption = document.getElementById('enableEncryption');
  const nodeEnv = document.getElementById('nodeEnv');
  const dbStatus = document.getElementById('dbStatus');
  const redisStatus = document.getElementById('redisStatus');
  const queueStatus = document.getElementById('queueStatus');
  const versionInfo = document.getElementById('versionInfo');
  
  if (data.linkLengthMode && settingLinkLengthMode) {
    settingLinkLengthMode.value = data.linkLengthMode;
  }
  if (data.allowLinkModeSwitch !== undefined && settingAllowLinkModeSwitch) {
    settingAllowLinkModeSwitch.checked = data.allowLinkModeSwitch;
  }
  if (data.longLinkSegments) {
    if (settingLongLinkSegments) settingLongLinkSegments.value = data.longLinkSegments;
    if (longLinkSegments) longLinkSegments.value = data.longLinkSegments;
  }
  if (data.longLinkParams) {
    if (settingLongLinkParams) settingLongLinkParams.value = data.longLinkParams;
    if (longLinkParams) longLinkParams.value = data.longLinkParams;
  }
  if (data.linkEncodingLayers) {
    if (settingLinkEncodingLayers) settingLinkEncodingLayers.value = data.linkEncodingLayers;
    if (linkEncodingLayers) linkEncodingLayers.value = data.linkEncodingLayers;
  }
  if (data.maxEncodingIterations && settingMaxEncodingIterations) {
    settingMaxEncodingIterations.value = data.maxEncodingIterations;
    if (maxEncodingIterations) maxEncodingIterations.value = data.maxEncodingIterations;
  }
  if (data.enableCompression !== undefined) {
    if (settingEnableCompression) settingEnableCompression.checked = data.enableCompression;
    if (enableCompression) enableCompression.checked = data.enableCompression;
  }
  if (data.enableEncryption !== undefined) {
    if (settingEnableEncryption) settingEnableEncryption.checked = data.enableEncryption;
    if (enableEncryption) enableEncryption.checked = data.enableEncryption;
  }
  if (data.nodeEnv && nodeEnv) {
    nodeEnv.textContent = data.nodeEnv;
  }
  if (data.databaseEnabled && dbStatus) {
    dbStatus.className = data.databaseEnabled ? 'status-dot connected' : 'status-dot disconnected';
  }
  if (data.redisEnabled && redisStatus) {
    redisStatus.className = data.redisEnabled ? 'status-dot connected' : 'status-dot disconnected';
  }
  if (data.queuesEnabled && queueStatus) {
    queueStatus.className = data.queuesEnabled ? 'status-dot connected' : 'status-dot disconnected';
  }
  if (data.version && versionInfo) {
    versionInfo.textContent = data.version;
  }
}

function updateCharts(data) {
  const ctx1 = document.getElementById('requestsChart')?.getContext('2d');
  const ctx2 = document.getElementById('deviceChart')?.getContext('2d');
  const ctx3 = document.getElementById('performanceChart')?.getContext('2d');
  
  if (!ctx1 || !ctx2) return;
  
  // Destroy existing charts
  if (requestsChart) requestsChart.destroy();
  if (deviceChart) deviceChart.destroy();
  if (performanceChart) performanceChart.destroy();
  
  // Prepare data based on time range
  const lastMinute = data.realtime?.lastMinute || [];
  let points = 60;
  if (currentTimeRange === '5m') points = 300;
  else if (currentTimeRange === '15m') points = 900;
  else if (currentTimeRange === '1h') points = 3600;
  else if (currentTimeRange === '6h') points = 21600;
  else if (currentTimeRange === '24h') points = 86400;
  
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
            minRotation: 45,
            maxTicksLimit: 10
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
  
  // Performance Chart (if available)
  if (ctx3 && data.performance?.responseTimes) {
    const responseTimes = data.performance.responseTimes.slice(-100);
    const responseLabels = responseTimes.map((_, i) => i);
    
    performanceChart = new Chart(ctx3, {
      type: 'line',
      data: {
        labels: responseLabels,
        datasets: [{
          label: 'Response Time (ms)',
          data: responseTimes,
          borderColor: '#7aa2f7',
          backgroundColor: 'rgba(122, 162, 247, 0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#666' }
          },
          x: {
            display: false
          }
        }
      }
    });
  }
}

function updateCountryStats(countries) {
  const container = document.getElementById('countryStats');
  const totalCountries = document.getElementById('totalCountries');
  
  if (!countries || Object.keys(countries).length === 0) {
    if (container) container.innerHTML = '<div class="text-center p-4">No data yet</div>';
    if (totalCountries) totalCountries.textContent = '0 countries';
    return;
  }
  
  const sorted = Object.entries(countries)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  
  if (totalCountries) totalCountries.textContent = Object.keys(countries).length + ' countries';
  
  if (container) {
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
  } else if (type === 'signature') {
    typeClass = 'type-success';
    typeIcon = '✅';
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
  
  if (log.version) {
    logHtml += ` <span style="color: #9ece6a;">[v${log.version}]</span>`;
  }
  
  entry.innerHTML = logHtml;
  
  // Add to logs
  logs.insertBefore(entry, logs.firstChild);
  
  // Limit number of log entries
  if (logs.children.length > 1000) {
    logs.removeChild(logs.lastChild);
  }
  
  // Auto-scroll if enabled
  if (autoScroll) {
    logs.scrollTop = 0;
  }
  
  // Update log count
  logCount++;
  const logCounter = document.getElementById('logCounter');
  if (logCounter) logCounter.textContent = logCount;
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
             (link.target_url && link.target_url.toLowerCase().includes(search)) ||
             (link.notes && link.notes.toLowerCase().includes(search));
    }
    return true;
  });
  
  const totalCount = document.getElementById('totalCount');
  if (totalCount) totalCount.textContent = filteredLinks.length;
  currentPage = 1;
  renderLinksTable();
}

function renderLinksTable() {
  const tbody = document.getElementById('linksTableBody');
  const displayedCount = document.getElementById('displayedCount');
  const totalLinksCount = document.getElementById('totalLinksCount');
  const totalCount = document.getElementById('totalCount');
  const prevPageBtn = document.getElementById('prevPageBtn');
  const nextPageBtn = document.getElementById('nextPageBtn');
  const pageInfo = document.getElementById('pageInfo');
  
  if (!filteredLinks || filteredLinks.length === 0) {
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; padding: 2rem;">
            <i class="fas fa-link"></i> No links found
          </td>
        </tr>
      `;
    }
    if (displayedCount) displayedCount.textContent = '0';
    if (totalLinksCount) totalLinksCount.textContent = '0';
    if (totalCount) totalCount.textContent = '0';
    if (prevPageBtn) prevPageBtn.disabled = true;
    if (nextPageBtn) nextPageBtn.disabled = true;
    if (pageInfo) pageInfo.textContent = 'Page 1';
    return;
  }
  
  const start = (currentPage - 1) * pageSize;
  const end = Math.min(start + pageSize, filteredLinks.length);
  const pageLinks = filteredLinks.slice(start, end);
  
  if (displayedCount) displayedCount.textContent = pageLinks.length;
  if (totalLinksCount) totalLinksCount.textContent = filteredLinks.length;
  if (totalCount) totalCount.textContent = filteredLinks.length;
  
  // Update pagination
  const totalPages = Math.ceil(filteredLinks.length / pageSize);
  if (prevPageBtn) prevPageBtn.disabled = currentPage <= 1;
  if (nextPageBtn) nextPageBtn.disabled = currentPage >= totalPages;
  if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
  
  if (tbody) {
    tbody.innerHTML = pageLinks.map(link => `
      <tr>
        <td><code>${link.id.substring(0, 8)}...</code></td>
        <td>
          <span class="badge badge-${link.link_mode === 'long' ? 'warning' : 'info'}">
            ${link.link_mode || 'short'}
          </span>
          ${link.link_length ? `<small style="color:#666;">${link.link_length}c</small>` : ''}
          ${link.encoding_layers ? `<small style="color:#666;"> (${link.encoding_layers} layers)</small>` : ''}
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
          <span class="badge badge-info">v${link.api_version || '1'}</span>
        </td>
        <td>
          <div class="btn-group" style="gap: 0.25rem;">
            <button class="btn btn-sm btn-secondary view-link" data-link-id="${link.id}" title="View Details">
              <i class="fas fa-eye"></i>
            </button>
            <button class="btn btn-sm btn-secondary copy-link" data-link-id="${link.id}" title="Copy Link">
              <i class="fas fa-copy"></i>
            </button>
            <button class="btn btn-sm btn-secondary qr-link" data-link-id="${link.id}" title="Generate QR">
              <i class="fas fa-qrcode"></i>
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
    
    document.querySelectorAll('.qr-link').forEach(btn => {
      btn.addEventListener('click', () => {
        const url = window.location.origin + '/v/' + btn.dataset.linkId;
        showQRModal(url, 300);
      });
    });
    
    document.querySelectorAll('.delete-link').forEach(btn => {
      btn.addEventListener('click', () => deleteLink(btn.dataset.linkId));
    });
  }
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
    _csrf: typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
  };
  
  // Add long link options if applicable
  if (selectedLinkMode === 'long' || (selectedLinkMode === 'auto' && typeof ALLOW_LINK_MODE_SWITCH !== 'undefined' && ALLOW_LINK_MODE_SWITCH)) {
    const longLinkSegments = document.getElementById('longLinkSegments')?.value;
    const longLinkParams = document.getElementById('longLinkParams')?.value;
    const linkEncodingLayers = document.getElementById('linkEncodingLayers')?.value;
    const maxEncodingIterations = document.getElementById('maxEncodingIterations')?.value;
    const enableCompression = document.getElementById('enableCompression');
    const enableEncryption = document.getElementById('enableEncryption');
    
    body.longLinkOptions = {
      segments: parseInt(longLinkSegments || (typeof LONG_LINK_SEGMENTS !== 'undefined' ? LONG_LINK_SEGMENTS : 6)),
      params: parseInt(longLinkParams || (typeof LONG_LINK_PARAMS !== 'undefined' ? LONG_LINK_PARAMS : 13)),
      maxLayers: parseInt(linkEncodingLayers || (typeof LINK_ENCODING_LAYERS !== 'undefined' ? LINK_ENCODING_LAYERS : 4)),
      iterations: parseInt(maxEncodingIterations || (typeof MAX_ENCODING_ITERATIONS !== 'undefined' ? MAX_ENCODING_ITERATIONS : 3)),
      includeFingerprint: true
    };
    
    // Add compression/encryption options
    if (enableCompression) {
      body.longLinkOptions.enableCompression = enableCompression.checked;
    }
    if (enableEncryption) {
      body.longLinkOptions.enableEncryption = enableEncryption.checked;
    }
  }
  
  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      body: JSON.stringify(body),
      credentials: 'include'
    });
    
    if (res.ok) {
      const data = await res.json();
      const generatedUrl = document.getElementById('generatedUrl');
      const generatedId = document.getElementById('generatedId');
      const generatedExpires = document.getElementById('generatedExpires');
      const generatedPassword = document.getElementById('generatedPassword');
      const generatedLength = document.getElementById('generatedLength');
      const generatedMode = document.getElementById('generatedMode');
      const result = document.getElementById('result');
      const encodingDetails = document.getElementById('encodingDetails');
      const encodingLayers = document.getElementById('encodingLayers');
      const encodingComplexity = document.getElementById('encodingComplexity');
      const encodingIterations = document.getElementById('encodingIterations');
      const encodingTime = document.getElementById('encodingTime');
      const apiVersion = document.getElementById('apiVersion');
      
      if (generatedUrl) generatedUrl.value = data.url;
      if (generatedId) generatedId.textContent = data.id;
      if (generatedExpires) generatedExpires.textContent = data.expires_human;
      if (generatedPassword) generatedPassword.textContent = data.passwordProtected ? 'Yes' : 'No';
      if (generatedLength) generatedLength.textContent = data.linkLength + ' chars';
      if (generatedMode) generatedMode.textContent = (data.mode || 'short').toUpperCase() + ' Link';
      if (apiVersion) apiVersion.textContent = data.metadata?.apiVersion || 'v1';
      if (result) result.style.display = 'block';
      
      // Show encoding details for long links
      if (data.encodingDetails && encodingDetails) {
        if (encodingLayers) encodingLayers.textContent = data.encodingDetails.layers || 0;
        if (encodingComplexity) encodingComplexity.textContent = data.encodingDetails.complexity || 0;
        if (encodingIterations) encodingIterations.textContent = data.encodingDetails.iterations || 1;
        if (encodingTime) encodingTime.textContent = (data.encodingDetails.encodingTime || 0).toFixed(0) + 'ms';
        encodingDetails.style.display = 'block';
      } else if (encodingDetails) {
        encodingDetails.style.display = 'none';
      }
      
      const generateQR = document.getElementById('generateQR');
      if (generateQR && generateQR.checked) {
        const size = document.getElementById('qrSize')?.value || 300;
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
      const qrResult = document.getElementById('qrResult');
      if (!qrResult) return;
      
      qrResult.innerHTML = `
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
      const qrModalContent = document.getElementById('qrModalContent');
      if (!qrModalContent) return;
      
      qrModalContent.innerHTML = `
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
      const linkStats = document.getElementById('linkStats');
      const totalClicksCount = document.getElementById('totalClicksCount');
      const statsContent = document.getElementById('statsContent');
      const recentClicksTable = document.getElementById('recentClicksTable');
      
      if (linkStats) linkStats.style.display = 'block';
      if (totalClicksCount) totalClicksCount.textContent = (stats.clicks || 0) + ' clicks';
      
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
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-title">Avg Decode Time</span>
              <span class="stat-icon"><i class="fas fa-clock"></i></span>
            </div>
            <div class="stat-value">${(stats.avg_decoding_time || 0).toFixed(0)}ms</div>
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
        
        if (recentClicksTable) recentClicksTable.innerHTML = recentHtml;
        
        // Update charts
        updateAnalyticsCharts(stats);
      } else {
        statsHtml = '<div class="stat-card">Link not found or expired</div>';
        if (recentClicksTable) recentClicksTable.innerHTML = '';
      }
      
      if (statsContent) statsContent.innerHTML = statsHtml;
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
          <p><strong>API Version:</strong> v${stats.apiVersion || '1'}</p>
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
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
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
              <th>Complexity</th>
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
            <td>${link.complexity || 'N/A'}</td>
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
  if (attemptsTable) {
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
  }
  
  // Blocked IPs
  const blockedTable = document.getElementById('blockedIPsTable');
  const blockedCount = document.getElementById('blockedCount');
  
  if (blockedTable) {
    if (securityData.blockedIPs?.length > 0) {
      blockedTable.innerHTML = securityData.blockedIPs.map(ip => `
        <tr>
          <td>${ip.ip}</td>
          <td>${ip.reason || 'Unknown'}</td>
          <td>${new Date(ip.expires_at).toLocaleString()}</td>
          <td>
            <button class="btn btn-sm btn-danger unblock-ip" data-ip="${ip.ip}">
              <i class="fas fa-ban"></i> Unblock
            </button>
          </td>
        </tr>
      `).join('');
      if (blockedCount) blockedCount.textContent = securityData.blockedIPs.length;
      
      document.querySelectorAll('.unblock-ip').forEach(btn => {
        btn.addEventListener('click', () => unblockIP(btn.dataset.ip));
      });
    } else {
      blockedTable.innerHTML = '<tr><td colspan="4">No blocked IPs</td></tr>';
      if (blockedCount) blockedCount.textContent = '0';
    }
  }
  
  // Active sessions
  const sessionsTable = document.getElementById('activeSessionsTable');
  if (sessionsTable) {
    if (securityData.activeSessions?.length > 0) {
      sessionsTable.innerHTML = securityData.activeSessions.map(session => `
        <tr>
          <td>${session.user_id || 'anonymous'}</td>
          <td>${session.ip}</td>
          <td>${new Date(session.created_at).toLocaleString()}</td>
          <td>
            <button class="btn btn-sm btn-danger revoke-session" data-session="${session.session_id}">
              <i class="fas fa-ban"></i> Revoke
            </button>
          </td>
        </tr>
      `).join('');
      
      document.querySelectorAll('.revoke-session').forEach(btn => {
        btn.addEventListener('click', () => revokeSession(btn.dataset.session));
      });
    } else {
      sessionsTable.innerHTML = '<tr><td colspan="4">No active sessions</td></tr>';
    }
  }
  
  const totalAttempts = document.getElementById('totalAttempts');
  if (totalAttempts) totalAttempts.textContent = securityData.totalAttempts || 0;
}

function clearLoginAttempts() {
  showAlert('Login attempts cleared', 'success');
}

function showUnblockIPModal() {
  const ip = prompt('Enter IP address to unblock:');
  if (ip) unblockIP(ip);
}

async function unblockIP(ip) {
  try {
    const res = await fetch('/admin/unblock-ip', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      body: JSON.stringify({ ip }),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert(`IP ${ip} unblocked`, 'success');
      refreshSecurityData();
    } else {
      showAlert('Failed to unblock IP', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

function showRevokeSessionModal() {
  const sessionId = prompt('Enter session ID to revoke:');
  if (sessionId) revokeSession(sessionId);
}

async function revokeSession(sessionId) {
  try {
    const res = await fetch('/admin/revoke-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      body: JSON.stringify({ sessionId }),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Session revoked', 'success');
      refreshSecurityData();
    } else {
      showAlert('Failed to revoke session', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

async function updateBotThreshold(threshold) {
  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
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
// Encryption Key Functions
// ============================================
async function fetchEncryptionKeys() {
  try {
    const res = await fetch('/admin/keys');
    if (res.ok) {
      const data = await res.json();
      encryptionKeys = data.keys || [];
      renderEncryptionKeys();
      
      const currentKeyEl = document.getElementById('currentKeyId');
      if (currentKeyEl && data.currentKey) {
        currentKeyEl.textContent = `${data.currentKey.id.substring(0, 8)}... (v${data.currentKey.version})`;
      }
    }
  } catch (err) {
    showAlert('Failed to load encryption keys', 'error');
  }
}

function renderEncryptionKeys() {
  const keysTable = document.getElementById('keysTableBody');
  if (!keysTable) return;
  
  if (encryptionKeys.length === 0) {
    keysTable.innerHTML = '<tr><td colspan="6">No encryption keys found</td></tr>';
    return;
  }
  
  keysTable.innerHTML = encryptionKeys.map(key => `
    <tr>
      <td><code>${key.id.substring(0, 8)}...</code></td>
      <td>${key.version}</td>
      <td>${new Date(key.createdAt).toLocaleString()}</td>
      <td>${new Date(key.expiresAt).toLocaleString()}</td>
      <td>
        ${key.isCurrent ? '<span class="badge badge-success">Current</span>' : ''}
      </td>
      <td>
        <button class="btn btn-sm btn-secondary view-key" data-key-id="${key.id}">
          <i class="fas fa-eye"></i>
        </button>
      </td>
    </tr>
  `).join('');
  
  document.querySelectorAll('.view-key').forEach(btn => {
    btn.addEventListener('click', () => showKeyDetails(btn.dataset.keyId));
  });
}

async function rotateEncryptionKeys() {
  if (!confirm('Are you sure you want to rotate encryption keys? This will generate a new key.')) {
    return;
  }
  
  try {
    const res = await fetch('/admin/keys/rotate', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      credentials: 'include'
    });
    
    if (res.ok) {
      const data = await res.json();
      showAlert(`New key generated: ${data.keyId.substring(0, 8)}...`, 'success');
      fetchEncryptionKeys();
    } else {
      showAlert('Failed to rotate keys', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

async function backupEncryptionKeys() {
  try {
    const res = await fetch('/admin/keys/backup', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      credentials: 'include'
    });
    
    if (res.ok) {
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `keys-backup-${new Date().toISOString()}.enc`;
      a.click();
      window.URL.revokeObjectURL(url);
      showAlert('Keys backup downloaded', 'success');
    } else {
      showAlert('Failed to backup keys', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

function showKeyDetails(keyId) {
  const key = encryptionKeys.find(k => k.id === keyId);
  if (!key) return;
  
  const modalContent = `
    <div style="margin-bottom: 1.5rem;">
      <p><strong>Key ID:</strong> <code>${key.id}</code></p>
      <p><strong>Version:</strong> ${key.version}</p>
      <p><strong>Created:</strong> ${new Date(key.createdAt).toLocaleString()}</p>
      <p><strong>Expires:</strong> ${new Date(key.expiresAt).toLocaleString()}</p>
      <p><strong>Status:</strong> ${key.isCurrent ? '<span class="badge badge-success">Current</span>' : '<span class="badge badge-info">Archived</span>'}</p>
      <p><strong>Age:</strong> ${formatDuration((Date.now() - new Date(key.createdAt)) / 1000)}</p>
    </div>
  `;
  
  document.getElementById('keyModalContent').innerHTML = modalContent;
  document.getElementById('keyModal').classList.add('active');
}

// ============================================
// Audit Log Functions
// ============================================
async function fetchAuditLogs() {
  try {
    const res = await fetch('/admin/audit/logs');
    if (res.ok) {
      const data = await res.json();
      auditLogs = data.logs || [];
      renderAuditLogs();
    }
  } catch (err) {
    showAlert('Failed to load audit logs', 'error');
  }
}

function renderAuditLogs() {
  const logsTable = document.getElementById('auditLogsBody');
  if (!logsTable) return;
  
  if (auditLogs.length === 0) {
    logsTable.innerHTML = '<tr><td colspan="5">No audit logs found</td></tr>';
    return;
  }
  
  logsTable.innerHTML = auditLogs.map(log => `
    <tr>
      <td>${new Date(log.timestamp).toLocaleString()}</td>
      <td><span class="badge badge-info">${log.action}</span></td>
      <td>${log.user || 'system'}</td>
      <td>${log.ip || 'N/A'}</td>
      <td>${JSON.stringify(log.details || {})}</td>
    </tr>
  `).join('');
}

function filterAuditLogs() {
  // Implement filtering logic
  console.log('Filtering audit logs...');
}

function exportAuditLogs() {
  const dataStr = JSON.stringify(auditLogs, null, 2);
  const blob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-logs-${new Date().toISOString()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showAlert('Audit logs exported', 'success');
}

function addAuditEntry(entry) {
  auditLogs.unshift(entry);
  if (auditLogs.length > 1000) {
    auditLogs.pop();
  }
  
  const activeTab = document.querySelector('.tab-content.active')?.id;
  if (activeTab === 'audit-log') {
    renderAuditLogs();
  }
}

// ============================================
// Backup Functions
// ============================================
async function fetchBackupStatus() {
  try {
    const res = await fetch('/admin/backup/status');
    if (res.ok) {
      backupStatus = await res.json();
      updateBackupStatus();
    }
  } catch (err) {
    showAlert('Failed to load backup status', 'error');
  }
}

function updateBackupStatus() {
  const lastBackupEl = document.getElementById('lastBackup');
  const backupCountEl = document.getElementById('backupCount');
  const backupSizeEl = document.getElementById('backupSize');
  
  if (lastBackupEl && backupStatus.lastBackup) {
    lastBackupEl.textContent = new Date(backupStatus.lastBackup).toLocaleString();
  }
  if (backupCountEl) {
    backupCountEl.textContent = backupStatus.count || 0;
  }
  if (backupSizeEl) {
    backupSizeEl.textContent = formatBytes(backupStatus.totalSize || 0);
  }
}

async function runBackup() {
  try {
    const res = await fetch('/admin/backup/run', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Backup started', 'success');
      fetchBackupStatus();
    } else {
      showAlert('Failed to start backup', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

function showRestoreModal() {
  const backupId = prompt('Enter backup ID to restore:');
  if (backupId) restoreBackup(backupId);
}

async function restoreBackup(backupId) {
  if (!confirm('Are you sure you want to restore this backup? This will overwrite current data.')) {
    return;
  }
  
  try {
    const res = await fetch('/admin/backup/restore', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      body: JSON.stringify({ backupId }),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Backup restored', 'success');
    } else {
      showAlert('Failed to restore backup', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

function showBackupConfig() {
  // Open backup configuration modal or page
  window.location.href = '/admin/backup/config';
}

// ============================================
// Settings Functions
// ============================================
async function saveLinkModeSettings() {
  const settingLinkLengthMode = document.getElementById('settingLinkLengthMode');
  const settingAllowLinkModeSwitch = document.getElementById('settingAllowLinkModeSwitch');
  const settingLongLinkSegments = document.getElementById('settingLongLinkSegments');
  const settingLongLinkParams = document.getElementById('settingLongLinkParams');
  const settingLinkEncodingLayers = document.getElementById('settingLinkEncodingLayers');
  const settingMaxEncodingIterations = document.getElementById('settingMaxEncodingIterations');
  const settingEnableCompression = document.getElementById('settingEnableCompression');
  const settingEnableEncryption = document.getElementById('settingEnableEncryption');
  const settingEncodingComplexityThreshold = document.getElementById('settingEncodingComplexityThreshold');
  
  const settings = {
    linkLengthMode: settingLinkLengthMode ? settingLinkLengthMode.value : 'short',
    allowLinkModeSwitch: settingAllowLinkModeSwitch ? settingAllowLinkModeSwitch.checked : true,
    longLinkSegments: parseInt(settingLongLinkSegments ? settingLongLinkSegments.value : 6),
    longLinkParams: parseInt(settingLongLinkParams ? settingLongLinkParams.value : 13),
    linkEncodingLayers: parseInt(settingLinkEncodingLayers ? settingLinkEncodingLayers.value : 4),
    maxEncodingIterations: parseInt(settingMaxEncodingIterations ? settingMaxEncodingIterations.value : 3),
    enableCompression: settingEnableCompression ? settingEnableCompression.checked : true,
    enableEncryption: settingEnableEncryption ? settingEnableEncryption.checked : false,
    encodingComplexityThreshold: parseInt(settingEncodingComplexityThreshold ? settingEncodingComplexityThreshold.value : 50)
  };
  
  try {
    const res = await fetch('/api/settings/link-mode', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
      },
      body: JSON.stringify(settings),
      credentials: 'include'
    });
    
    if (res.ok) {
      showAlert('Link mode settings saved', 'success');
      
      // Update local variables (these are globals)
      if (settings.linkLengthMode) window.LINK_LENGTH_MODE = settings.linkLengthMode;
      if (settings.longLinkSegments) window.LONG_LINK_SEGMENTS = settings.longLinkSegments;
      if (settings.longLinkParams) window.LONG_LINK_PARAMS = settings.longLinkParams;
      if (settings.linkEncodingLayers) window.LINK_ENCODING_LAYERS = settings.linkEncodingLayers;
      
      selectLinkMode(window.LINK_LENGTH_MODE);
    } else {
      const error = await res.json();
      showAlert(error.error || 'Failed to save settings', 'error');
    }
  } catch (err) {
    showAlert('Network error', 'error');
  }
}

async function saveSystemSettings() {
  const settingLinkTTL = document.getElementById('settingLinkTTL');
  const settingDesktopChallenge = document.getElementById('settingDesktopChallenge');
  const settingBotDetection = document.getElementById('settingBotDetection');
  const settingAnalytics = document.getElementById('settingAnalytics');
  const settingLogLevel = document.getElementById('settingLogLevel');
  const settingLogFormat = document.getElementById('settingLogFormat');
  const settingLogRetention = document.getElementById('settingLogRetention');
  
  const settings = {
    linkTTL: parseInt(settingLinkTTL ? settingLinkTTL.value : 1800),
    desktopChallenge: settingDesktopChallenge ? settingDesktopChallenge.checked : true,
    botDetection: settingBotDetection ? settingBotDetection.checked : true,
    analytics: settingAnalytics ? settingAnalytics.checked : true,
    logLevel: settingLogLevel ? settingLogLevel.value : 'info',
    logFormat: settingLogFormat ? settingLogFormat.value : 'json',
    logRetentionDays: parseInt(settingLogRetention ? settingLogRetention.value : 30)
  };
  
  // Save each setting individually
  for (const [key, value] of Object.entries(settings)) {
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
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

async function saveSecuritySettings() {
  const settingBCryptRounds = document.getElementById('settingBCryptRounds');
  const settingSessionTTL = document.getElementById('settingSessionTTL');
  const settingLoginAttempts = document.getElementById('settingLoginAttempts');
  const settingCSRFEnabled = document.getElementById('settingCSRFEnabled');
  const settingCSPEnabled = document.getElementById('settingCSPEnabled');
  const settingHSTSEnabled = document.getElementById('settingHSTSEnabled');
  
  const settings = {
    bcryptRounds: parseInt(settingBCryptRounds ? settingBCryptRounds.value : 12),
    sessionTTL: parseInt(settingSessionTTL ? settingSessionTTL.value : 86400),
    loginAttempts: parseInt(settingLoginAttempts ? settingLoginAttempts.value : 10),
    csrfEnabled: settingCSRFEnabled ? settingCSRFEnabled.checked : true,
    cspEnabled: settingCSPEnabled ? settingCSPEnabled.checked : true,
    hstsEnabled: settingHSTSEnabled ? settingHSTSEnabled.checked : true
  };
  
  for (const [key, value] of Object.entries(settings)) {
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
        },
        body: JSON.stringify({ key, value }),
        credentials: 'include'
      });
    } catch (err) {
      console.error('Failed to save setting:', key, err);
    }
  }
  
  showAlert('Security settings saved', 'success');
}

async function saveNotificationSettings() {
  const settingNotificationSound = document.getElementById('settingNotificationSound');
  const settingAlertEmail = document.getElementById('settingAlertEmail');
  const settingSlackWebhook = document.getElementById('settingSlackWebhook');
  
  const settings = {
    notificationSound: settingNotificationSound ? settingNotificationSound.checked : false,
    alertEmail: settingAlertEmail ? settingAlertEmail.value : '',
    slackWebhook: settingSlackWebhook ? settingSlackWebhook.value : ''
  };
  
  for (const [key, value] of Object.entries(settings)) {
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
        },
        body: JSON.stringify({ key, value }),
        credentials: 'include'
      });
    } catch (err) {
      console.error('Failed to save setting:', key, err);
    }
  }
  
  showAlert('Notification settings saved', 'success');
}

async function reloadConfig() {
  try {
    const res = await fetch('/admin/reload-config', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
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

function refreshLinks() {
  if (socket) {
    socket.emit('command', { action: 'getLinks' });
  }
}

function clearForm() {
  const targetUrl = document.getElementById('targetUrl');
  const linkPassword = document.getElementById('linkPassword');
  const maxClicks = document.getElementById('maxClicks');
  const linkNotes = document.getElementById('linkNotes');
  const expiresIn = document.getElementById('expiresIn');
  const generateQR = document.getElementById('generateQR');
  const qrSize = document.getElementById('qrSize');
  const result = document.getElementById('result');
  const qrResult = document.getElementById('qrResult');
  const encodingDetails = document.getElementById('encodingDetails');
  
  if (targetUrl) targetUrl.value = typeof TARGET_URL !== 'undefined' ? TARGET_URL : '';
  if (linkPassword) linkPassword.value = '';
  if (maxClicks) maxClicks.value = '';
  if (linkNotes) linkNotes.value = '';
  if (expiresIn) expiresIn.value = '30m';
  if (generateQR) generateQR.checked = false;
  if (qrSize) qrSize.disabled = true;
  if (result) result.style.display = 'none';
  if (qrResult) qrResult.innerHTML = '';
  if (encodingDetails) encodingDetails.style.display = 'none';
}

function copyToClipboard() {
  const url = document.getElementById('generatedUrl');
  if (!url) return;
  
  url.select();
  document.execCommand('copy');
  showAlert('Copied to clipboard!', 'success');
}

function showQRFromResult() {
  const url = document.getElementById('generatedUrl')?.value;
  const size = document.getElementById('qrSize')?.value || 300;
  if (url) showQRModal(url, size);
}

function downloadQR(url, size) {
  window.location.href = '/qr/download?url=' + encodeURIComponent(url) + '&size=' + size;
}

function clearLogs() {
  const logs = document.getElementById('logs');
  if (!logs) return;
  
  logs.innerHTML = '<div class="log-entry" style="color: #7aa2f7; text-align: center;"><i class="fas fa-check-circle"></i> Logs cleared</div>';
  logCount = 0;
  
  const logCounter = document.getElementById('logCounter');
  const logRateEl = document.getElementById('logRate');
  
  if (logCounter) logCounter.textContent = '0';
  if (logRateEl) logRateEl.textContent = '0 logs/sec';
  showAlert('Logs cleared', 'success');
}

function exportLogs() {
  const logs = document.getElementById('logs');
  if (!logs) return;
  
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
  } else if (type === 'device') {
    action = 'clearDeviceCache';
    message = 'device cache';
  }
  
  if (!confirm(`Are you sure you want to clear ${message}?`)) return;
  
  if (type === 'all') {
    try {
      const res = await fetch('/admin/clear-cache', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
        },
        body: JSON.stringify({ _csrf: typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : '' }),
        credentials: 'include'
      });
      
      if (res.ok) {
        showAlert('All caches cleared', 'success');
      }
    } catch (err) {
      showAlert('Failed to clear cache', 'error');
    }
  } else {
    if (socket) {
      socket.emit('command', { action });
    }
  }
}

// ============================================
// Modal functions
// ============================================
function closeModal() {
  document.getElementById('linkModal')?.classList.remove('active');
}

function closeTestModal() {
  document.getElementById('testModal')?.classList.remove('active');
}

function closeHealthModal() {
  document.getElementById('healthModal')?.classList.remove('active');
}

function closeQRModal() {
  document.getElementById('qrModal')?.classList.remove('active');
}

function closeKeyModal() {
  document.getElementById('keyModal')?.classList.remove('active');
}

function closeAuditModal() {
  document.getElementById('auditModal')?.classList.remove('active');
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
  const keyModal = document.getElementById('keyModal');
  if (event.target === keyModal) {
    closeKeyModal();
  }
  const auditModal = document.getElementById('auditModal');
  if (event.target === auditModal) {
    closeAuditModal();
  }
};

// Handle escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeModal();
    closeTestModal();
    closeHealthModal();
    closeQRModal();
    closeKeyModal();
    closeAuditModal();
  }
});

// Handle window resize
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) {
    document.getElementById('sidebar')?.classList.remove('open');
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
    const queuesNavItem = document.getElementById('queuesNavItem');
    const dbStatus = document.getElementById('dbStatus');
    const redisStatus = document.getElementById('redisStatus');
    const queueStatus = document.getElementById('queueStatus');
    
    if (queuesNavItem && data.queues?.redirect === 'ready') {
      queuesNavItem.style.display = 'flex';
    }
    if (dbStatus) {
      dbStatus.className = data.database ? 'status-dot connected' : 'status-dot disconnected';
    }
    if (redisStatus) {
      redisStatus.className = data.redis === 'connected' ? 'status-dot connected' : 'status-dot disconnected';
    }
    if (queueStatus) {
      queueStatus.className = data.queues?.redirect === 'ready' ? 'status-dot connected' : 'status-dot disconnected';
    }
  })
  .catch(err => console.error('Health check failed:', err));

// ============================================
// Initialize everything
// ============================================
function init() {
  console.log('🚀 Initializing admin dashboard v4.1.0...');
  console.log('Environment:', typeof NODE_ENV !== 'undefined' ? NODE_ENV : 'unknown');
  console.log('Link Mode:', typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short');
  console.log('MFA Enabled:', typeof MFA_ENABLED !== 'undefined' ? MFA_ENABLED : 'false');
  console.log('WebAuthn Enabled:', typeof WEBAUTHN_ENABLED !== 'undefined' ? WEBAUTHN_ENABLED : 'false');
  
  initSocket();
  setupEventListeners();
  
  // Initialize the first tab
  showTab('dashboard');
  
  // Load security data in background
  setTimeout(() => {
    refreshSecurityData();
    fetchEncryptionKeys();
    fetchBackupStatus();
  }, 1000);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  // DOM is already loaded
  init();
}
