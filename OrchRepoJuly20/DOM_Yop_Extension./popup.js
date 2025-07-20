let isRecording = false;
let hasScope = false;

document.addEventListener('DOMContentLoaded', async () => {
    // Check current recording status
    const response = await browser.runtime.sendMessage({action: 'getRecordingStatus'});
    isRecording = response.isRecording;
    hasScope = response.hasScope;
    updateUI();
    
    // Load existing scope if any
    const scopeResponse = await browser.runtime.sendMessage({action: 'getScope'});
    if (scopeResponse.scopeConfig) {
        document.getElementById('scopeJson').value = JSON.stringify(scopeResponse.scopeConfig, null, 2);
        hasScope = true;
    }
    
    updateScopeStatus();
});

document.getElementById('toggleRecord').addEventListener('click', async () => {
    if (isRecording) {
        await browser.runtime.sendMessage({action: 'stopRecording'});
        isRecording = false;
    } else {
        await browser.runtime.sendMessage({action: 'startRecording'});
        isRecording = true;
    }
    updateUI();
});

document.getElementById('export').addEventListener('click', async () => {
    await browser.runtime.sendMessage({action: 'stopRecording'});
    isRecording = false;
    updateUI();
});

document.getElementById('loadScope').addEventListener('click', async () => {
    const scopeJsonText = document.getElementById('scopeJson').value.trim();
    
    if (!scopeJsonText) {
        alert('Please paste a scope JSON first');
        return;
    }
    
    try {
        const scopeConfig = JSON.parse(scopeJsonText);
        
        // Validate scope structure
        if (!scopeConfig.target || !scopeConfig.target.scope) {
            throw new Error('Invalid scope file structure. Expected format: { "target": { "scope": { "include": [...], "exclude": [...] } } }');
        }
        
        // Send to background script
        const response = await browser.runtime.sendMessage({
            action: 'loadScope',
            scopeConfig: scopeConfig
        });
        
        if (response.success) {
            hasScope = true;
            updateScopeStatus();
            document.getElementById('status').textContent = 'Scope loaded successfully';
            
            // Format the JSON nicely
            document.getElementById('scopeJson').value = JSON.stringify(scopeConfig, null, 2);
        }
    } catch (error) {
        alert('Error loading scope: ' + error.message);
    }
});

document.getElementById('clearScope').addEventListener('click', async () => {
    const response = await browser.runtime.sendMessage({action: 'clearScope'});
    if (response.success) {
        hasScope = false;
        updateScopeStatus();
        document.getElementById('status').textContent = 'Scope cleared';
        document.getElementById('scopeJson').value = '';
    }
});

function updateUI() {
    const button = document.getElementById('toggleRecord');
    const status = document.getElementById('status');
    
    if (isRecording) {
        button.textContent = 'Stop Recording';
        button.classList.add('recording');
        status.textContent = 'Recording in progress...';
    } else {
        button.textContent = 'Start Recording';
        button.classList.remove('recording');
        status.textContent = 'Ready';
    }
}

async function updateScopeStatus() {
    const scopeStatus = document.getElementById('scopeStatus');
    
    if (hasScope) {
        // Get scope details
        const response = await browser.runtime.sendMessage({action: 'getScope'});
        const scope = response.scopeConfig;
        
        if (scope && scope.target && scope.target.scope) {
            const includeCount = (scope.target.scope.include || []).filter(r => r.enabled).length;
            const excludeCount = (scope.target.scope.exclude || []).filter(r => r.enabled).length;
            
            scopeStatus.innerHTML = `
                <span class="scope-active">Scope Active</span><br>
                ${includeCount} include rules, ${excludeCount} exclude rules
            `;
            scopeStatus.className = 'scope-status scope-active';
        }
    } else {
        scopeStatus.textContent = 'No scope loaded - capturing all URLs';
        scopeStatus.className = 'scope-status scope-inactive';
    }
}
