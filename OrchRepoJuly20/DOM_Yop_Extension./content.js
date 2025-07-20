let lastRequestIndex = null;

// Listen for request tags from background
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'tagRequest') {
    lastRequestIndex = request.requestIndex;
    
    // Capture DOM state after page renders
    setTimeout(() => captureCurrentState(request.requestIndex), 100);
  }
});

function captureCurrentState(requestIndex) {
  try {
    const domState = {
      requestIndex: requestIndex || lastRequestIndex,
      url: window.location.href,
      timestamp: Date.now(),
      dom: document.documentElement.outerHTML,
      cookies: document.cookie,
      localStorage: captureStorage(localStorage),
      sessionStorage: captureStorage(sessionStorage),
      windowLocation: {
        href: window.location.href,
        origin: window.location.origin,
        pathname: window.location.pathname,
        search: window.location.search,
        hash: window.location.hash
      },
      documentReadyState: document.readyState,
      // Additional useful state
      scrollPosition: {
        x: window.scrollX,
        y: window.scrollY
      },
      viewportSize: {
        width: window.innerWidth,
        height: window.innerHeight
      }
    };
    
    browser.runtime.sendMessage({
      action: 'saveDOMState',
      ...domState
    });
  } catch (error) {
    console.error('Error capturing DOM state:', error);
  }
}

function captureStorage(storage) {
  const items = {};
  try {
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      items[key] = storage.getItem(key);
    }
  } catch (e) {
    console.error('Error capturing storage:', e);
  }
  return items;
}

// Also capture on significant DOM changes
const observer = new MutationObserver((mutations) => {
  // Debounce to avoid too many captures
  clearTimeout(window.domCaptureTimeout);
  window.domCaptureTimeout = setTimeout(() => {
    if (mutations.length > 5) { // Significant change
      captureCurrentState();
    }
  }, 500);
});

// Start observing
observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true
});
