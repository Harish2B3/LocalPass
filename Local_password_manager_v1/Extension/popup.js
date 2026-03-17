/**
 * Popup Script for Password Manager Extension
 * Handles:
 * - User authentication with Email & OTP
 * - Session management
 * - Password generator
 * - Quick actions for current site
 */

const API_URL = 'http://localhost:3001/api/users';
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
const MAIN_APP_URL = 'http://localhost:3000'; // Vite dev server

// ============================================
// DOM ELEMENTS
// ============================================

const elements = {
    // Views
    loadingView: document.getElementById('loading-view'),
    loginView: document.getElementById('login-view'),
    statusView: document.getElementById('status-view'),
    generatorView: document.getElementById('generator-view'),

    // Login Form
    loginForm: document.getElementById('login-form'),
    emailInput: document.getElementById('email'),
    otpInput: document.getElementById('otp'),
    otpGroup: document.getElementById('otp-group'),
    loginBtn: document.getElementById('login-btn'),
    loginBtnText: document.getElementById('login-btn-text'),
    errorMessage: document.getElementById('error-message'),
    discoverySection: document.getElementById('discovery-section'),
    deviceList: document.getElementById('device-list'),
    devicesContainer: document.getElementById('devices-container'),
    manualConnectTrigger: document.getElementById('manual-connect-trigger'),
    manualIpGroup: document.getElementById('manual-ip-group'),
    manualIpInput: document.getElementById('manual-ip'),
    backToDiscovery: document.getElementById('back-to-discovery'),

    // Status View
    userAvatar: document.getElementById('user-avatar'),
    userGreeting: document.getElementById('user-greeting'),
    sessionTimer: document.getElementById('session-timer'),
    currentSite: document.getElementById('current-site'),
    credentialCount: document.getElementById('credential-count'),

    // Action Buttons
    autofillBtn: document.getElementById('autofill-btn'),
    addSiteBtn: document.getElementById('add-site-btn'),
    openVaultBtn: document.getElementById('open-vault-btn'),
    generatePasswordBtn: document.getElementById('generate-password-btn'),
    logoutBtn: document.getElementById('logout-btn'),

    // Password Generator
    backBtn: document.getElementById('back-btn'),
    generatedPassword: document.getElementById('generated-password'),
    copyPassword: document.getElementById('copy-password'),
    passwordLength: document.getElementById('password-length'),
    lengthValue: document.getElementById('length-value'),
    includeUppercase: document.getElementById('include-uppercase'),
    includeLowercase: document.getElementById('include-lowercase'),
    includeNumbers: document.getElementById('include-numbers'),
    includeSymbols: document.getElementById('include-symbols'),
    strengthFill: document.getElementById('strength-fill'),
    strengthLabel: document.getElementById('strength-label'),
    regenerateBtn: document.getElementById('regenerate-btn')
};

// ============================================
// STATE
// ============================================

let currentUser = null;
let sessionTimerInterval = null;
let currentTabInfo = null;
let discoveredDevices = [];
let selectedDevice = null;
let authStep = 'find'; // 'find', 'select', 'otp'

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
    // Security enforcements
    setupSecurityMeasures();

    // Check authentication state
    await checkSession();

    // Setup event listeners
    setupEventListeners();

    // Get current tab info
    await getCurrentTabInfo();
});

// ============================================
// SECURITY MEASURES
// ============================================

function setupSecurityMeasures() {
    // Disable context menu
    document.addEventListener('contextmenu', e => e.preventDefault());

    // Block DevTools hotkeys
    document.addEventListener('keydown', (e) => {
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
            (e.ctrlKey && e.key === 'u')
        ) {
            e.preventDefault();
            triggerSecurityAlert();
        }
    });
}

function triggerSecurityAlert() {
    chrome.runtime.sendMessage({ type: 'SECURITY_ALERT' }, () => {
        showView('login');
        showError('Security Alert: Suspicious activity detected. Session terminated.');
    });
}

// ============================================
// VIEW MANAGEMENT
// ============================================

function showView(viewName) {
    elements.loadingView.classList.add('hidden');
    elements.loginView.classList.add('hidden');
    elements.statusView.classList.add('hidden');
    elements.generatorView.classList.add('hidden');

    switch (viewName) {
        case 'loading':
            elements.loadingView.classList.remove('hidden');
            break;
        case 'login':
            elements.loginView.classList.remove('hidden');
            elements.emailInput.focus();
            break;
        case 'status':
            elements.statusView.classList.remove('hidden');
            break;
        case 'generator':
            elements.generatorView.classList.remove('hidden');
            generatePassword();
            break;
    }
}

// ============================================
// SESSION MANAGEMENT
// ============================================

async function checkSession() {
    showView('loading');

    try {
        const response = await chrome.runtime.sendMessage({ type: 'CHECK_SESSION' });

        if (response && response.valid && response.user) {
            currentUser = response.user;
            showStatusView(currentUser);
        } else {
            showView('login');
        }
    } catch (error) {
        console.error('Session check failed:', error);
        showView('login');
    }
}

function showStatusView(user) {
    currentUser = user;

    // Update UI
    elements.userAvatar.textContent = (user.username || 'U')[0].toUpperCase();
    elements.userGreeting.textContent = `Hello, ${user.username}`;

    // Start session timer
    startSessionTimer();

    // Update credential count for current site
    updateCredentialCount();

    showView('status');
}

function startSessionTimer() {
    if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
    }

    const updateTimer = async () => {
        const { lastActivity } = await chrome.storage.local.get(['lastActivity']);
        if (lastActivity) {
            const elapsed = Date.now() - lastActivity;
            const remaining = Math.max(0, SESSION_TIMEOUT - elapsed);
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);

            if (remaining <= 0) {
                elements.sessionTimer.textContent = 'Session expired';
                clearInterval(sessionTimerInterval);
                setTimeout(() => showView('login'), 1500);
            } else if (remaining < 60000) {
                elements.sessionTimer.textContent = `Expires in ${seconds}s`;
                elements.sessionTimer.style.color = '#f59e0b';
            } else {
                elements.sessionTimer.textContent = `Active (${minutes}:${seconds.toString().padStart(2, '0')})`;
                elements.sessionTimer.style.color = '';
            }
        }
    };

    updateTimer();
    sessionTimerInterval = setInterval(updateTimer, 1000);
}

// ============================================
// TAB INFORMATION
// ============================================

async function getCurrentTabInfo() {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs[0]) {
            currentTabInfo = tabs[0];
            const url = new URL(tabs[0].url);
            elements.currentSite.textContent = url.hostname;
        }
    } catch (error) {
        console.error('Failed to get tab info:', error);
        elements.currentSite.textContent = 'Unknown';
    }
}

async function updateCredentialCount() {
    if (!currentTabInfo || !currentTabInfo.url) return;

    try {
        const response = await chrome.runtime.sendMessage({
            type: 'GET_CREDENTIALS',
            url: currentTabInfo.url
        });

        const count = response?.credentials?.length || 0;
        elements.credentialCount.textContent = count;
        elements.credentialCount.title = `${count} saved credential${count !== 1 ? 's' : ''} for this site`;
    } catch (error) {
        console.error('Failed to get credential count:', error);
        elements.credentialCount.textContent = '0';
    }
}

// ============================================
// EVENT LISTENERS
// ============================================

// ============================================
// EVENT LISTENERS
// ============================================

function setupEventListeners() {
    // Login Form Listener
    elements.loginForm.addEventListener('submit', handleAuthSubmit);

    // Status view actions
    elements.autofillBtn.addEventListener('click', handleAutofill);
    elements.addSiteBtn.addEventListener('click', handleAddSite);
    elements.openVaultBtn.addEventListener('click', handleOpenVault);
    elements.generatePasswordBtn.addEventListener('click', () => showView('generator'));
    elements.logoutBtn.addEventListener('click', handleLogout);

    // Password generator
    elements.backBtn.addEventListener('click', () => showView('status'));
    elements.copyPassword.addEventListener('click', handleCopyPassword);
    elements.passwordLength.addEventListener('input', handleLengthChange);
    elements.regenerateBtn.addEventListener('click', generatePassword);

    // Discovery UI actions
    elements.manualConnectTrigger.addEventListener('click', (e) => {
        e.preventDefault();
        showManualIpInput();
    });

    elements.backToDiscovery.addEventListener('click', (e) => {
        e.preventDefault();
        resetAuthUI();
    });

    // Generator option changes
    [elements.includeUppercase, elements.includeLowercase,
    elements.includeNumbers, elements.includeSymbols].forEach(checkbox => {
        checkbox.addEventListener('change', generatePassword);
    });

    // Listen for messages from background
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'SESSION_EXPIRED') {
            showView('login');
            showError('Session expired due to inactivity.');
        } else if (message.type === 'DEVICE_FOUND') {
            handleDeviceFound(message.device);
        } else if (message.type === 'DISCOVERY_FINISHED') {
            handleDiscoveryFinished();
        }
    });
}

// ============================================
// AUTHENTICATION LOGIC (Login with Discovery)
// ============================================

async function handleAuthSubmit(e) {
    e.preventDefault();
    hideError();

    if (authStep === 'find') {
        const email = elements.emailInput.value.trim();
        if (!email) {
            showError('Please enter your email address');
            return;
        }
        startDiscovery(email);
    } else if (authStep === 'manual') {
        const email = elements.emailInput.value.trim();
        let ip = elements.manualIpInput.value.trim();

        if (!ip) {
            showError('Please enter the server IP address');
            return;
        }

        // Sanitize IP: remove http/https, trailing slashes, and port if present
        ip = ip.replace(/^https?:\/\//i, '').replace(/\/+$/, '').split(':')[0];

        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip) && ip !== 'localhost') {
            showError('Please enter a valid IP address (e.g., 192.168.1.50)');
            return;
        }

        await connectToManualIp(ip, email);
    } else if (authStep === 'otp') {
        const otp = elements.otpInput.value.trim();
        if (!otp || !/^\d{6}$/.test(otp)) {
            showError('Please enter a valid 6-digit OTP');
            return;
        }
        await performLogin({ email: elements.emailInput.value.trim(), otp });
    }
}

function startDiscovery(email) {
    authStep = 'discovery';
    discoveredDevices = [];
    elements.devicesContainer.innerHTML = '';

    elements.discoverySection.classList.remove('hidden');
    elements.deviceList.classList.add('hidden');
    elements.otpGroup.classList.add('hidden');

    elements.loginBtn.disabled = true;
    elements.loginBtnText.textContent = 'Scanning...';

    chrome.runtime.sendMessage({ type: 'DISCOVER_DEVICES', data: { email } });
}

function handleDiscoveryFinished() {
    if (authStep === 'discovery') {
        if (discoveredDevices.length === 0) {
            showError('No devices found on your network. Check if the server is running and your machine is reachable.');
            resetAuthUI();
        } else if (discoveredDevices.length === 1) {
            selectDevice(discoveredDevices[0]);
        } else {
            authStep = 'select';
            elements.discoverySection.querySelector('.discovery-loader').classList.add('hidden');
            elements.deviceList.classList.remove('hidden');
            elements.loginBtnText.textContent = 'Select a device';
        }
    }
}

function handleDeviceFound(device) {
    // Check if already found
    if (discoveredDevices.find(d => d.ip === device.ip)) return;

    discoveredDevices.push(device);

    const deviceEl = document.createElement('div');
    deviceEl.className = 'device-item';
    deviceEl.innerHTML = `
        <div class="device-info">
            <span class="device-name">${device.hostname || 'Unknown Device'}</span>
            <span class="device-ip">${device.ip}</span>
        </div>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/>
        </svg>
    `;

    deviceEl.addEventListener('click', () => selectDevice(device));
    elements.devicesContainer.appendChild(deviceEl);
}

async function selectDevice(device) {
    selectedDevice = device;
    authStep = 'otp';

    elements.discoverySection.classList.add('hidden');
    elements.otpGroup.classList.remove('hidden');
    elements.otpInput.focus();

    elements.loginBtn.disabled = false;
    elements.loginBtnText.textContent = 'Verify & Access Vault';

    chrome.runtime.sendMessage({ type: 'SELECT_DEVICE', data: { url: device.url } });
}

function showManualIpInput() {
    authStep = 'manual';
    elements.discoverySection.classList.add('hidden');
    elements.manualIpGroup.classList.remove('hidden');
    elements.loginBtnText.textContent = 'Connect & Verify';
    elements.manualIpInput.focus();
}

async function connectToManualIp(ip, email) {
    hideError();
    elements.loginBtn.disabled = true;
    elements.loginBtnText.textContent = 'Connecting...';

    // Temporary listener for verification
    const verificationListener = (message) => {
        if (message.type === 'DEVICE_FOUND' && (message.device.ip === ip || message.device.url.includes(ip))) {
            chrome.runtime.onMessage.removeListener(verificationListener);
            clearTimeout(verifyTimeout);
            proceedAfterVerification(message.device);
        }
    };

    chrome.runtime.onMessage.addListener(verificationListener);

    // Timeout if server not found
    const verifyTimeout = setTimeout(() => {
        chrome.runtime.onMessage.removeListener(verificationListener);
        showError('No vault found at this IP address. Ensure your backend shows "Network: http://' + ip + ':3001"');
        elements.loginBtn.disabled = false;
        elements.loginBtnText.textContent = 'Connect & Verify';
    }, 6000);

    try {
        await chrome.runtime.sendMessage({
            type: 'DISCOVER_DEVICES',
            data: { email, singleIp: ip }
        });
    } catch (e) {
        chrome.runtime.onMessage.removeListener(verificationListener);
        clearTimeout(verifyTimeout);
        showError('Connection failed: ' + e.message);
        elements.loginBtn.disabled = false;
        elements.loginBtnText.textContent = 'Connect & Verify';
    }
}

async function proceedAfterVerification(device) {
    const result = await chrome.runtime.sendMessage({
        type: 'SELECT_DEVICE',
        data: { url: device.url }
    });

    if (result.success) {
        authStep = 'otp';
        elements.manualIpGroup.classList.add('hidden');
        elements.otpGroup.classList.remove('hidden');
        elements.otpInput.focus();
        elements.loginBtn.disabled = false;
        elements.loginBtnText.textContent = 'Verify & Access Vault';
    } else {
        showError('Failed to select device.');
        elements.loginBtn.disabled = false;
    }
}

function resetAuthUI() {
    authStep = 'find';
    elements.loginBtn.disabled = false;
    elements.loginBtnText.textContent = 'Find Device';
    elements.discoverySection.classList.add('hidden');
    elements.deviceList.classList.add('hidden');
    elements.manualIpGroup.classList.add('hidden');
    elements.otpGroup.classList.add('hidden');
    elements.emailInput.disabled = false;

    // Stop any ongoing discovery
    chrome.runtime.sendMessage({ type: 'STOP_DISCOVERY' });
}

async function performLogin(data) {
    setLoginLoading(true);
    try {
        // Delegate login to background script
        const response = await chrome.runtime.sendMessage({
            type: 'LOGIN',
            data: data
        });

        if (response.success) {
            elements.loginForm.reset();
            showStatusView(response.user);

            // Show successful login notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: 'PassManager Secure',
                message: 'Vault unlocked with OTP. Session active for 24h.',
                priority: 2
            });
        } else {
            showError(response.error || 'Invalid credentials');
        }
    } catch (error) {
        showError('Connection failed: ' + error.message);
    } finally {
        setLoginLoading(false);
    }
}

function setLoginLoading(loading) {
    elements.loginBtn.disabled = loading;
    const btnText = elements.loginBtn.querySelector('.btn-text');
    const btnLoader = elements.loginBtn.querySelector('.btn-loader');

    if (loading) {
        btnText.classList.add('hidden');
        btnLoader.classList.remove('hidden');
    } else {
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
    }
}

// ============================================
// ACTION HANDLERS
// ============================================

async function handleAutofill() {
    await refreshSession();

    if (currentTabInfo && currentTabInfo.id) {
        try {
            await chrome.tabs.sendMessage(currentTabInfo.id, { type: 'TRIGGER_AUTOFILL' });
            window.close();
        } catch (error) {
            showError('Cannot autofill on this page');
        }
    }
}

async function handleAddSite() {
    await refreshSession();

    if (currentTabInfo && currentTabInfo.id) {
        try {
            await chrome.tabs.sendMessage(currentTabInfo.id, { type: 'OPEN_SAVE_DIALOG' });
            window.close();
        } catch (error) {
            showError('Cannot save credentials on this page');
        }
    }
}

function handleOpenVault() {
    chrome.tabs.create({ url: MAIN_APP_URL });
    window.close();
}

async function handleLogout() {
    await chrome.storage.local.remove(['user', 'lastActivity']);

    if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
    }

    currentUser = null;
    showView('login');
}

async function refreshSession() {
    await chrome.storage.local.set({ lastActivity: Date.now() });
}

// ============================================
// PASSWORD GENERATOR
// ============================================

function generatePassword() {
    const length = parseInt(elements.passwordLength.value);
    const options = {
        uppercase: elements.includeUppercase.checked,
        lowercase: elements.includeLowercase.checked,
        numbers: elements.includeNumbers.checked,
        symbols: elements.includeSymbols.checked
    };

    if (!options.uppercase && !options.lowercase && !options.numbers && !options.symbols) {
        elements.includeLowercase.checked = true;
        options.lowercase = true;
    }

    let charset = '';
    if (options.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (options.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (options.numbers) charset += '0123456789';
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset[array[i] % charset.length];
    }

    elements.generatedPassword.value = password;
    updateStrengthMeter(password);
}

function handleLengthChange() {
    elements.lengthValue.textContent = elements.passwordLength.value;
    generatePassword();
}

function updateStrengthMeter(password) {
    let score = 0;

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    let strength, label;
    if (score <= 2) {
        strength = 'weak';
        label = 'Weak';
    } else if (score <= 4) {
        strength = 'fair';
        label = 'Fair';
    } else if (score <= 5) {
        strength = 'good';
        label = 'Good';
    } else {
        strength = 'strong';
        label = 'Very Strong';
    }

    elements.strengthFill.className = `strength-fill ${strength}`;
    elements.strengthLabel.textContent = label;
}

async function handleCopyPassword() {
    const password = elements.generatedPassword.value;
    if (!password) return;

    try {
        await navigator.clipboard.writeText(password);

        const originalHTML = elements.copyPassword.innerHTML;
        elements.copyPassword.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
            </svg>
        `;
        elements.copyPassword.style.background = 'linear-gradient(135deg, #22c55e, #16a34a)';

        setTimeout(() => {
            elements.copyPassword.innerHTML = originalHTML;
            elements.copyPassword.style.background = '';
        }, 1500);
    } catch (error) {
        console.error('Failed to copy:', error);
    }
}

// ============================================
// ERROR HANDLING
// ============================================

function showError(message) {
    elements.errorMessage.textContent = message;
    elements.errorMessage.classList.remove('hidden');
}

function hideError() {
    elements.errorMessage.textContent = '';
    elements.errorMessage.classList.add('hidden');
}
