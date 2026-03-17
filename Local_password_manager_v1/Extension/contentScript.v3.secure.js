/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║   SECURE CONTENT SCRIPT (ZERO-CRYPTO VERSION)                ║
 * ║   This script is a DUMB BRIDGE - no secrets, no crypto       ║
 * ╚═══════════════════════════════════════════════════════════════╝
 * 
 * SECURITY ARCHITECTURE:
 * ┌────────────────┐
 * │   Web Page     │  ← HOSTILE (never trust)
 * └───────┬────────┘
 *         │ (isolated world boundary)
 * ┌───────▼────────┐
 * │ This Script    │  ← BRIDGE (UI only, no secrets)
 * │  • Find forms  │
 * │  • Fill fields │
 * │  • Show UI     │
 * │  • NO CRYPTO   │
 * └───────┬────────┘
 *         │ (message passing)
 * ┌───────▼────────┐
 * │Service Worker  │  ← BRAIN (all crypto, all secrets)
 * └────────────────┘
 * 
 * WHAT THIS SCRIPT DOES:
 * ✅ Detects login forms
 * ✅ Requests credentials from service worker
 * ✅ Fills form fields with received credentials
 * ✅ Shows save dialogs
 * ✅ Injects autofill UI
 * 
 * WHAT THIS SCRIPT NEVER DOES:
 * ❌ Store credentials
 * ❌ Encrypt/decrypt anything
 * ❌ Access vault
 * ❌ Make crypto decisions
 */

// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
    DEBOUNCE_DELAY: 500,
    AUTOFILL_HIGHLIGHT_COLOR: '#e8f5e9',
    ICON_SIZE: 20,
    MAX_DROPDOWN_ITEMS: 5
};

const KEYWORDS = {
    username: ['user', 'username', 'login', 'email', 'uid', 'account'],
    password: ['pass', 'password', 'pwd', 'secret', 'current-password'],
    submit: ['login', 'signin', 'sign-in', 'submit', 'auth', 'enter']
};

const IGNORE_TYPES = ['hidden', 'file', 'image', 'button', 'reset', 'submit', 'checkbox', 'radio'];

// ============================================
// STATE
// ============================================

let cachedCredentials = [];
let currentDomain = '';
let autofillIconsInjected = new WeakSet();

// ============================================
// SECURITY: IFRAME PROTECTION
// ============================================

/**
 * CRITICAL: Never autofill in iframes (phishing protection)
 * Exception: Explicitly allow localhost for development
 */
if (window !== window.top) {
    const isLocalhost = window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1';

    if (!isLocalhost) {
        console.warn('🛑 PassManager: Autofill blocked in iframe for security');
        // Exit immediately - don't run any code in iframes
        throw new Error('Iframe protection');
    }
}

// ============================================
// FORM DETECTION
// ============================================

function getFieldScore(element, typeKeywords) {
    let score = 0;
    const id = (element.id || '').toLowerCase();
    const name = (element.name || '').toLowerCase();
    const autocomplete = (element.autocomplete || '').toLowerCase();
    const type = (element.type || '').toLowerCase();
    const placeholder = (element.placeholder || '').toLowerCase();

    // Priority 1: Autocomplete attribute
    if (typeKeywords === KEYWORDS.username) {
        if (autocomplete === 'username') score += 100;
        if (autocomplete === 'email') score += 90;
    }
    if (typeKeywords === KEYWORDS.password) {
        if (autocomplete === 'current-password') score += 100;
        if (type === 'password') score += 60;
    }

    // Priority 2: Input type
    if (typeKeywords === KEYWORDS.username && type === 'email') score += 60;

    // Priority 3: Keyword matching
    typeKeywords.forEach(kw => {
        if (id.includes(kw)) score += 30;
        if (name.includes(kw)) score += 25;
        if (placeholder.includes(kw)) score += 20;
    });

    return score;
}

function isElementVisible(element) {
    if (!element) return false;

    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();

    return (
        style.display !== 'none' &&
        style.visibility !== 'hidden' &&
        style.opacity !== '0' &&
        rect.width > 0 &&
        rect.height > 0 &&
        element.type !== 'hidden' &&
        !element.disabled
    );
}

function findCredentialFields(container) {
    const inputs = Array.from(container.querySelectorAll('input'));
    const visibleInputs = inputs.filter(input =>
        !IGNORE_TYPES.includes(input.type) && isElementVisible(input)
    );

    let bestUser = null;
    let bestPass = null;
    let maxUserScore = 0;
    let maxPassScore = 0;

    visibleInputs.forEach(input => {
        const userScore = getFieldScore(input, KEYWORDS.username);
        const passScore = getFieldScore(input, KEYWORDS.password);

        if (input.type === 'password' && passScore >= maxPassScore) {
            bestPass = input;
            maxPassScore = passScore;
        } else if (userScore > maxUserScore && input.type !== 'password') {
            bestUser = input;
            maxUserScore = userScore;
        }
    });

    // Fallback: Look for text input before password
    if (bestPass && !bestUser) {
        const passIndex = visibleInputs.indexOf(bestPass);
        for (let i = passIndex - 1; i >= 0; i--) {
            const input = visibleInputs[i];
            if ((input.type === 'text' || input.type === 'email') && !input.disabled) {
                bestUser = input;
                break;
            }
        }
    }

    return { username: bestUser, password: bestPass };
}

function isLoginForm(form) {
    const inputs = form.querySelectorAll('input[type="password"]');
    if (inputs.length > 1) return false; // Likely signup/change password

    const formText = form.innerText.toLowerCase();
    const signupKeywords = ['register', 'signup', 'sign up', 'create account'];
    return !signupKeywords.some(kw => formText.includes(kw));
}

function findLoginForms() {
    const forms = document.querySelectorAll('form');
    return Array.from(forms).filter(form => {
        const { password } = findCredentialFields(form);
        return password && isLoginForm(form);
    });
}

// ============================================
// DOMAIN UTILITIES
// ============================================

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace(/^www\./, '').toLowerCase();
    } catch {
        return '';
    }
}

function getRegistrableDomain(hostname) {
    const parts = hostname.split('.');
    // Return last 2 parts (example: google.com from accounts.google.com)
    return parts.slice(-2).join('.');
}

// ============================================
// AUTOFILL LOGIC
// ============================================

async function checkAndAutofill() {
    currentDomain = extractDomain(window.location.href);
    const loginForms = findLoginForms();

    if (loginForms.length === 0) return;

    // Request credentials from service worker
    if (cachedCredentials.length === 0) {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'GET_CREDENTIALS',
                url: window.location.href
            });

            if (response?.credentials && response.credentials.length > 0) {
                cachedCredentials = response.credentials;

                // Auto-fill if exactly one match
                if (cachedCredentials.length === 1) {
                    setTimeout(() => {
                        loginForms.forEach(form =>
                            fillCredentials(form, cachedCredentials[0])
                        );
                    }, 100);
                }
            }
        } catch (e) {
            console.error('PassManager: Failed to fetch credentials:', e);
        }
    }

    // Inject autofill icons
    loginForms.forEach(form => {
        const { password } = findCredentialFields(form);
        if (password && !autofillIconsInjected.has(password)) {
            injectAutofillIcon(password);
            autofillIconsInjected.add(password);
        }
    });
}

function fillInput(input, value) {
    if (!input || !value) return;

    input.focus();
    input.value = value;
    input.setAttribute('value', value);

    // Dispatch events for frameworks
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));

    input.blur();
    input.style.backgroundColor = CONFIG.AUTOFILL_HIGHLIGHT_COLOR;

    setTimeout(() => {
        input.style.backgroundColor = '';
    }, 2000);
}

function fillCredentials(form, credential) {
    const { username, password } = findCredentialFields(form);
    if (username && credential.username) fillInput(username, credential.username);
    if (password && credential.password) fillInput(password, credential.password);
}

// ============================================
// AUTOFILL UI
// ============================================

function injectAutofillIcon(passwordField) {
    const icon = document.createElement('div');
    icon.className = 'pm-autofill-icon';
    icon.innerHTML = `
        <svg width="${CONFIG.ICON_SIZE}" height="${CONFIG.ICON_SIZE}" viewBox="0 0 24 24" fill="none">
            <path d="M12 2C9.24 2 7 4.24 7 7V9H6C4.9 9 4 9.9 4 11V21C4 22.1 4.9 23 6 23H18C19.1 23 20 22.1 20 21V11C20 9.9 19.1 9 18 9H17V7C17 4.24 14.76 2 12 2ZM12 4C13.65 4 15 5.35 15 7V9H9V7C9 5.35 10.35 4 12 4ZM12 13C13.1 13 14 13.9 14 15C14 16.1 13.1 17 12 17C10.9 17 10 16.1 10 15C10 13.9 10.9 13 12 13Z" fill="#3498db"/>
        </svg>
    `;

    Object.assign(icon.style, {
        position: 'absolute',
        cursor: 'pointer',
        zIndex: '2147483646',
        padding: '4px',
        borderRadius: '4px',
        transition: 'transform 0.2s, opacity 0.2s',
        opacity: '0.7'
    });

    icon.addEventListener('mouseenter', () => {
        icon.style.opacity = '1';
        icon.style.transform = 'scale(1.1)';
    });

    icon.addEventListener('mouseleave', () => {
        icon.style.opacity = '0.7';
        icon.style.transform = 'scale(1)';
    });

    icon.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showCredentialDropdown(passwordField);
    });

    positionIcon(icon, passwordField);
    document.body.appendChild(icon);

    window.addEventListener('resize', () => positionIcon(icon, passwordField));
}

function positionIcon(icon, field) {
    const rect = field.getBoundingClientRect();
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;

    Object.assign(icon.style, {
        top: `${rect.top + scrollTop + (rect.height - CONFIG.ICON_SIZE) / 2}px`,
        left: `${rect.right + scrollLeft - CONFIG.ICON_SIZE - 30}px`
    });
}

function showCredentialDropdown(passwordField) {
    const existing = document.getElementById('pm-credential-dropdown');
    if (existing) existing.remove();

    if (cachedCredentials.length === 0) return;

    const dropdown = document.createElement('div');
    dropdown.id = 'pm-credential-dropdown';
    dropdown.attachShadow({ mode: 'open' });

    const shadow = dropdown.shadowRoot;

    const style = document.createElement('style');
    style.textContent = `
        .dropdown {
            position: fixed;
            background: #1e1e2e;
            border: 1px solid #313244;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            min-width: 280px;
            overflow: hidden;
        }
        
        .header {
            padding: 12px 16px;
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            font-size: 13px;
            font-weight: 600;
        }
        
        .item {
            display: flex;
            padding: 12px 16px;
            cursor: pointer;
            border-bottom: 1px solid #313244;
        }
        
        .item:hover {
            background: #313244;
        }
        
        .avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            margin-right: 12px;
        }
        
        .info {
            flex: 1;
        }
        
        .username {
            color: #cdd6f4;
            font-size: 14px;
        }
        
        .service {
            color: #6c7086;
            font-size: 12px;
        }
    `;

    const container = document.createElement('div');
    container.className = 'dropdown';

    container.innerHTML = `
        <div class="header">🔒 PassManager - Select Account</div>
        <div class="items">
            ${cachedCredentials.slice(0, CONFIG.MAX_DROPDOWN_ITEMS).map((cred, index) => `
                <div class="item" data-index="${index}">
                    <div class="avatar">${(cred.username || 'U')[0].toUpperCase()}</div>
                    <div class="info">
                        <div class="username">${escapeHtml(cred.username)}</div>
                        <div class="service">${escapeHtml(extractDomain(cred.service))}</div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(container);

    const rect = passwordField.getBoundingClientRect();
    container.style.top = `${rect.bottom + 5}px`;
    container.style.left = `${rect.left}px`;

    container.querySelectorAll('.item').forEach(item => {
        item.addEventListener('click', (e) => {
            const index = parseInt(e.currentTarget.dataset.index);
            const credential = cachedCredentials[index];
            const form = passwordField.closest('form') || document.body;
            fillCredentials(form, credential);
            dropdown.remove();
        });
    });

    document.body.appendChild(dropdown);

    setTimeout(() => {
        document.addEventListener('click', function handler(e) {
            if (!dropdown.contains(e.target)) {
                dropdown.remove();
                document.removeEventListener('click', handler);
            }
        });
    }, 100);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

// ============================================
// CREDENTIAL CAPTURE
// ============================================

document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    if (!isLoginForm(form)) return;

    const { username, password } = findCredentialFields(form);

    if (password && password.value.length > 0) {
        captureAndPrompt(
            username ? username.value : '',
            password.value
        );
    }
}, true);

async function captureAndPrompt(username, password) {
    if (!password) return;

    // Show save dialog
    createSaveDialog(username, password);
}

function createSaveDialog(username, password) {
    const existing = document.getElementById('pm-save-dialog');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.id = 'pm-save-dialog';
    container.attachShadow({ mode: 'open' });

    const shadow = container.shadowRoot;

    const style = document.createElement('style');
    style.textContent = `
        .card {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 320px;
            background: #1e1e2e;
            color: #cdd6f4;
            border: 1px solid #313244;
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        .title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
        }
        
        .info {
            background: #313244;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 8px;
            font-size: 13px;
        }
        
        .buttons {
            display: flex;
            gap: 10px;
            margin-top: 16px;
        }
        
        button {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
        }
        
        .save {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
        }
        
        .cancel {
            background: transparent;
            color: #a6adc8;
            border: 1px solid #313244;
        }
    `;

    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
        <div class="title">🔒 Save Password?</div>
        <div class="info">Username: ${escapeHtml(username) || '(empty)'}</div>
        <div class="info">Password: ••••••••</div>
        <div class="buttons">
            <button class="save" id="save-btn">Save</button>
            <button class="cancel" id="cancel-btn">Never</button>
        </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(card);
    document.body.appendChild(container);

    shadow.getElementById('save-btn').addEventListener('click', async () => {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'SAVE_CREDENTIAL',
                data: {
                    service: window.location.origin,
                    username,
                    password
                }
            });

            if (response?.success) {
                card.innerHTML = '<div class="title">✅ Saved!</div>';
                setTimeout(() => container.remove(), 1500);
            }
        } catch (error) {
            console.error('Save failed:', error);
        }
    });

    shadow.getElementById('cancel-btn').addEventListener('click', () => {
        container.remove();
    });

    setTimeout(() => container.remove(), 30000);
}

// ============================================
// INITIALIZATION
// ============================================

const observer = new MutationObserver((mutations) => {
    const hasFormChanges = mutations.some(m =>
        Array.from(m.addedNodes).some(node =>
            node.tagName === 'FORM' ||
            node.tagName === 'INPUT' ||
            (node.querySelectorAll && node.querySelectorAll('form, input[type="password"]').length > 0)
        )
    );

    if (hasFormChanges) {
        setTimeout(checkAndAutofill, CONFIG.DEBOUNCE_DELAY);
    }
});

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

function init() {
    observer.observe(document.body, { childList: true, subtree: true });
    checkAndAutofill();
}
