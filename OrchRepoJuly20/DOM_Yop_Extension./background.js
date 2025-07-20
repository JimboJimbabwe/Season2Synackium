let requestLog = [];
let domStates = {};
let requestCounter = 0;
let isRecording = false;
let scopeConfig = null;

// Load scope from storage on startup
browser.storage.local.get('scopeConfig').then(result => {
  if (result.scopeConfig) {
    scopeConfig = result.scopeConfig;
    console.log('Loaded scope config from storage:', scopeConfig);
  }
});

// Function to check if URL is in scope
function isInScope(url) {
  if (!scopeConfig || !scopeConfig.target || !scopeConfig.target.scope) {
    // No scope defined, capture everything
    return true;
  }
  
  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol.slice(0, -1); // Remove trailing ':'
    const host = urlObj.hostname;
    const path = urlObj.pathname + urlObj.search;
    
    // Check excludes first
    const excludes = scopeConfig.target.scope.exclude || [];
    for (const rule of excludes) {
      if (!rule.enabled) continue;
      
      if (matchesRule(protocol, host, path, rule)) {
        console.log(`URL ${url} excluded by rule:`, rule);
        return false;
      }
    }
    
    // Check includes
    const includes = scopeConfig.target.scope.include || [];
    for (const rule of includes) {
      if (!rule.enabled) continue;
      
      if (matchesRule(protocol, host, path, rule)) {
        console.log(`URL ${url} included by rule:`, rule);
        return true;
      }
    }
    
    // Not explicitly included
    return false;
  } catch (e) {
    console.error('Error checking scope for URL:', url, e);
    return false;
  }
}

// Function to match a URL against a scope rule
function matchesRule(protocol, host, path, rule) {
  // Check protocol
  if (rule.protocol && rule.protocol !== 'any') {
    if (protocol !== rule.protocol) {
      return false;
    }
  }
  
  // Check host (handle regex)
  if (rule.host) {
    try {
      // Remove '^' and '$' if present for more flexible matching
      let hostPattern = rule.host;
      if (hostPattern.startsWith('^')) {
        hostPattern = hostPattern.substring(1);
      }
      if (hostPattern.endsWith('$')) {
        hostPattern = hostPattern.substring(0, hostPattern.length - 1);
      }
      
      const hostRegex = new RegExp(hostPattern);
      if (!hostRegex.test(host)) {
        return false;
      }
    } catch (e) {
      console.error('Invalid host regex:', rule.host, e);
      return false;
    }
  }
  
  // Check file/path (handle regex)
  if (rule.file) {
    try {
      const fileRegex = new RegExp(rule.file);
      if (!fileRegex.test(path)) {
        return false;
      }
    } catch (e) {
      console.error('Invalid file regex:', rule.file, e);
      return false;
    }
  }
  
  return true;
}

// Track all requests
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!isRecording) return;
    
    // Check if URL is in scope
    if (!isInScope(details.url)) {
      console.log('Skipping out-of-scope URL:', details.url);
      return;
    }
    
    const requestIndex = requestCounter++;
    const requestData = {
      index: requestIndex,
      timestamp: Date.now(),
      method: details.method,
      url: details.url,
      type: details.type,
      tabId: details.tabId,
      frameId: details.frameId,
      initiator: details.initiator,
      requestBody: details.requestBody
    };
    
    requestLog.push(requestData);
    
    // Store request index for this tab
    if (details.tabId > 0) {
      browser.tabs.sendMessage(details.tabId, {
        action: 'tagRequest',
        requestIndex: requestIndex,
        url: details.url
      }).catch(err => {
        // Tab might not be ready yet, ignore error
      });
    }
    
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Capture headers
browser.webRequest.onSendHeaders.addListener(
  (details) => {
    if (!isRecording) return;
    
    // Check if URL is in scope
    if (!isInScope(details.url)) {
      return;
    }
    
    // Find corresponding request
    const request = requestLog.find(r => 
      r.url === details.url && 
      r.method === details.method &&
      Math.abs(r.timestamp - Date.now()) < 1000
    );
    
    if (request) {
      request.requestHeaders = details.requestHeaders;
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Message handler
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'saveDOMState') {
    // Check if URL is in scope before saving DOM state
    if (!isInScope(request.url)) {
      console.log('Skipping DOM state for out-of-scope URL:', request.url);
      sendResponse({ success: false, reason: 'out-of-scope' });
      return;
    }
    
    const key = `${request.requestIndex}_${request.timestamp}`;
    domStates[key] = {
      requestIndex: request.requestIndex,
      url: request.url,
      timestamp: request.timestamp,
      dom: request.dom,
      cookies: request.cookies,
      localStorage: request.localStorage,
      sessionStorage: request.sessionStorage,
      windowLocation: request.windowLocation,
      documentReadyState: request.documentReadyState
    };
    sendResponse({ success: true });
  } else if (request.action === 'startRecording') {
    isRecording = true;
    requestLog = [];
    domStates = {};
    requestCounter = 0;
    sendResponse({ success: true });
  } else if (request.action === 'stopRecording') {
    isRecording = false;
    exportData();
    sendResponse({ success: true });
  } else if (request.action === 'getRecordingStatus') {
    sendResponse({ isRecording, hasScope: !!scopeConfig });
  } else if (request.action === 'loadScope') {
    scopeConfig = request.scopeConfig;
    // Save to storage
    browser.storage.local.set({ scopeConfig: scopeConfig }).then(() => {
      console.log('Scope config saved to storage');
    });
    sendResponse({ success: true });
  } else if (request.action === 'clearScope') {
    scopeConfig = null;
    browser.storage.local.remove('scopeConfig').then(() => {
      console.log('Scope config cleared from storage');
    });
    sendResponse({ success: true });
  } else if (request.action === 'getScope') {
    sendResponse({ scopeConfig });
  }
  
  return true; // Will respond asynchronously
});

// Export data function
function exportData() {
  const exportData = {
    requests: requestLog,
    domStates: domStates,
    exportTime: new Date().toISOString(),
    scopeConfig: scopeConfig
  };
  
  const blob = new Blob([JSON.stringify(exportData, null, 2)], 
    { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  browser.downloads.download({
    url: url,
    filename: `dom-capture-${Date.now()}.json`,
    saveAs: true
  });
}
