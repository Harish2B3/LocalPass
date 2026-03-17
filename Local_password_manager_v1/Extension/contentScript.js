/**
 * Enhanced Content Script for Password Manager Extension
 * Features:
 * - Advanced form detection with scoring algorithm
 * - Shadow DOM and iframe support
 * - Click-based credential capture
 * - Secure autofill with domain verification
 * - Inline credential selector
 * - Autofill icon injection
 */

// ============================================
// 1. SECURITY (Block DevTools)
// ============================================

document.addEventListener('keydown', (e) => {
    if (
        e.key === 'F12' ||
        (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
        (e.ctrlKey && e.key === 'u')
    ) {
        e.preventDefault();
        e.stopPropagation();
    }
});

// ============================================
// 2. CONFIGURATION & CONSTANTS
// ============================================

const CONFIG = {
    API_TIMEOUT: 10000,
    DEBOUNCE_DELAY: 500,
    AUTOFILL_HIGHLIGHT_COLOR: '#e8f5e9',
    MAX_DROPDOWN_ITEMS: 5
};

const KEYWORDS = {
    username: ['user', 'username', 'login', 'email', 'uid', 'user_id', 'account', 'member', 'identity', 'id', 'email_address', 'mail', 'phone', 'mobile', 'login_id', 'signin_id', 'name', 'identifier', 'handle'],
    password: ['pass', 'password', 'pwd', 'login_password', 'secret', 'current-password', 'passwd', 'password_field', 'pass_field'],
    submit: ['login', 'sign in', 'signin', 'sign-in', 'submit', 'auth', 'enter', 'continue', 'next', 'log in', 'access'],
    remember: ['remember', 'persistent', 'keep_signed_in', 'stay_logged'],
    signup: ['register', 'signup', 'sign-up', 'create', 'new_account', 'join', 'subscribe']
};

const IGNORE_TYPES = ['hidden', 'file', 'image', 'button', 'reset', 'submit', 'checkbox', 'radio'];

// ============================================
// 3. SECURE CHANNEL INITIALIZATION
// ============================================

let secureChannel = null;
let cachedCredentials = [];
let isFetching = false;
let currentDomain = '';

// Initialize secure channel when crypto module is available
function initializeSecureChannel() {
    if (typeof SecureMessaging !== 'undefined') {
        secureChannel = new SecureMessaging.SecureChannel();
    }
}

// ============================================
// 4. DOMAIN UTILITIES
// ============================================

/**
 * Extract primary domain from URL
 */
function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace(/^www\./, '').toLowerCase();
    } catch {
        return '';
    }
}

/**
 * Check if two URLs match on domain level
 */
function isDomainMatch(savedUrl, currentUrl) {
    const savedDomain = extractDomain(savedUrl);
    const currentDomain = extractDomain(currentUrl);

    if (!savedDomain || !currentDomain) return false;

    // Exact match
    if (savedDomain === currentDomain) return true;

    // Handle subdomain matching (e.g., login.example.com matches example.com)
    if (savedDomain.endsWith('.' + currentDomain) || currentDomain.endsWith('.' + savedDomain)) {
        return true;
    }

    return false;
}

/**
 * Check if current page appears to be a login page
 */
function isLoginPage() {
    const url = window.location.href.toLowerCase();
    const loginIndicators = ['login', 'signin', 'sign-in', 'auth', 'session', 'account'];
    return loginIndicators.some(indicator => url.includes(indicator));
}

/**
 * Check if current page appears to be a registration page
 */
function isRegistrationPage() {
    const url = window.location.href.toLowerCase();
    const registrationIndicators = ['register', 'signup', 'sign-up', 'create-account', 'join', 'signup'];
    const pageText = (document.title + (document.body ? document.body.innerText : '')).toLowerCase();

    const hasRegUrl = registrationIndicators.some(indicator => url.includes(indicator));
    const hasRegText = ['create account', 'sign up', 'register now', 'join us'].some(kw => pageText.includes(kw));

    return hasRegUrl || (hasRegText && document.querySelectorAll('input[type="password"]').length >= 1);
}

// ============================================
// 5. FORM DETECTION ENGINE
// ============================================

/**
 * Calculate a score for how likely an element is a specific field type
 */
function getFieldScore(element, typeKeywords) {
    let score = 0;
    const id = (element.id || '').toLowerCase();
    const name = (element.name || '').toLowerCase();
    const autocomplete = (element.autocomplete || '').toLowerCase();
    const type = (element.type || '').toLowerCase();
    const placeholder = (element.placeholder || '').toLowerCase();
    const ariaLabel = (element.getAttribute('aria-label') || '').toLowerCase();
    const className = (element.className || '').toLowerCase();

    // Priority 1: Autocomplete attribute (highest confidence)
    if (typeKeywords === KEYWORDS.username) {
        if (autocomplete === 'username') score += 100;
        if (autocomplete === 'email') score += 90;
    }
    if (typeKeywords === KEYWORDS.password) {
        if (autocomplete === 'current-password') score += 100;
        if (autocomplete === 'new-password') score += 80;
    }

    // Priority 2: Input type
    if (typeKeywords === KEYWORDS.username && type === 'email') score += 60;
    if (typeKeywords === KEYWORDS.password && type === 'password') score += 60;

    // Priority 3: Keyword matching in attributes
    typeKeywords.forEach(kw => {
        if (id === kw) score += 50; // Exact match bonus
        if (name === kw) score += 50; // Exact match bonus

        if (id.includes(kw)) score += 30;
        if (name.includes(kw)) score += 35; // Increased weight for 'name' attribute
        if (placeholder.includes(kw)) score += 20;
        if (ariaLabel.includes(kw)) score += 15;
        if (className.includes(kw)) score += 10;
    });

    return score;
}

/**
 * Check if an element is visible and interactable
 */
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

/**
 * Find all forms including those in Shadow DOM
 */
function findAllForms(root = document) {
    const forms = [...root.querySelectorAll('form')];

    // Search in Shadow DOM
    root.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) {
            forms.push(...findAllForms(el.shadowRoot));
        }
    });

    return forms;
}

/**
 * Find credential fields in a form or container
 */
function findCredentialFields(container) {
    const inputs = Array.from(container.querySelectorAll('input, select, textarea'));
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

        if ((input.type === 'password' || passScore > 10) && passScore >= maxPassScore) {
            bestPass = input;
            maxPassScore = passScore;
        } else if (userScore > maxUserScore && input.type !== 'password') {
            bestUser = input;
            maxUserScore = userScore;
        }
    });

    // Fallback: If we found password but no username, look for the nearest text/email input BEFORE the password field
    if (bestPass && !bestUser) {
        const passIndex = visibleInputs.indexOf(bestPass);
        for (let i = passIndex - 1; i >= 0; i--) {
            const input = visibleInputs[i];
            if ((input.type === 'text' || input.type === 'email' || input.type === 'tel') && !input.disabled) {
                // If it's a very small field or looks like a search box, skip
                if (input.offsetWidth < 50) continue;
                bestUser = input;
                break;
            }
        }
    }

    return { username: bestUser, password: bestPass };
}

/**
 * Detect if a form is a login form (not signup)
 */
function isLoginForm(form) {
    const inputs = form.querySelectorAll('input[type="password"]');
    const formText = (form.innerText + form.outerHTML).toLowerCase();

    // Multiple password fields (password + confirm) usually indicate signup/change password
    if (inputs.length > 1) return false;

    // Check for signup keywords in the submit button specifically
    const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), .btn, .button');
    const submitText = submitBtn ? (submitBtn.innerText || submitBtn.value || '').toLowerCase() : '';
    const signupKeywords = ['register', 'signup', 'sign up', 'create account', 'join'];

    if (signupKeywords.some(kw => submitText.includes(kw))) return false;

    // Exclude "change password" forms often found in settings
    const changePasswordKeywords = ['change password', 'update password', 'old password'];
    if (changePasswordKeywords.some(kw => formText.includes(kw))) return false;

    // Must have at least one password field
    return inputs.length === 1;
}

/**
 * Detect if a form is a registration form
 */
function isRegistrationForm(form) {
    const inputs = form.querySelectorAll('input[type="password"]');
    const formText = (form.innerText + form.outerHTML).toLowerCase();

    // Multiple password fields is a very strong indicator of signup/reset
    if (inputs.length >= 2) return true;

    // Check for signup keywords
    const signupKeywords = ['register', 'signup', 'sign up', 'create account', 'new password', 'confirm password', 'join'];
    if (signupKeywords.some(kw => formText.includes(kw))) {
        // If it also has login keywords, it might be a multi-intent page, but if it has "confirm" it's registration
        if (formText.includes('confirm') || formText.includes('new password')) return true;

        const loginKeywords = ['login', 'sign in', 'signin', 'log in'];
        return !loginKeywords.some(kw => formText.includes(kw));
    }

    return false;
}

/**
 * Find all login forms on the page
 */
function findLoginForms() {
    const allForms = findAllForms();
    return allForms.filter(form => {
        const { password } = findCredentialFields(form);
        return password && isLoginForm(form);
    });
}

/**
 * Find all registration forms on the page
 */
function findRegistrationForms() {
    const allForms = findAllForms();
    return allForms.filter(form => {
        const { password } = findCredentialFields(form);
        return password && isRegistrationForm(form);
    });
}

function formHasLoginKeywords(form) {
    const text = (form.innerText + form.outerHTML).toLowerCase();
    const keywords = ['login', 'sign in', 'signin', 'log in', 'enter password'];
    return keywords.some(k => text.includes(k));
}

// ============================================
// 6. AUTOFILL LOGIC
// ============================================

/**
 * Check and autofill credentials on the page
 */
async function checkAndAutofill() {
    currentDomain = extractDomain(window.location.href);
    const loginForms = findLoginForms();
    const registrationForms = findRegistrationForms();
    const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"])'));

    if (loginForms.length === 0 && registrationForms.length === 0) {
        // Still check for orphan password fields
        const orphanPasswords = Array.from(document.querySelectorAll('input[type="password"]'));
        if (orphanPasswords.length === 0) return;
    }

    // Fetch credentials if not cached
    if (cachedCredentials.length === 0 && !isFetching) {
        isFetching = true;
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'GET_CREDENTIALS',
                url: window.location.href
            });

            if (response && response.credentials && response.credentials.length > 0) {
                cachedCredentials = response.credentials.filter(cred =>
                    isDomainMatch(cred.service, window.location.href)
                );

                // Auto-fill if exactly one
                if (cachedCredentials.length === 1) {
                    setTimeout(() => {
                        const currentLoginForms = findLoginForms();
                        currentLoginForms.forEach(form => fillCredentials(form, cachedCredentials[0]));
                    }, 100);
                }
            }
        } catch (e) {
            console.error('Error fetching credentials:', e);
        }
        isFetching = false;
    }

    // Setup dropdowns for login forms
    loginForms.forEach(form => {
        const { username, password } = findCredentialFields(form);
        if (username) setupAutofillDropdown(username);
        if (password) setupAutofillDropdown(password);
    });

    // Setup dropdowns for registration forms
    registrationForms.forEach(form => {
        const { username, password } = findCredentialFields(form);
        if (username) setupRegistrationDropdown(username);
        if (password) setupRegistrationDropdown(password);
    });

    // Handle orphan fields
    allInputs.forEach(input => {
        const userScore = getFieldScore(input, KEYWORDS.username);
        const passScore = getFieldScore(input, KEYWORDS.password);

        if (input.type === 'password' || passScore > 40) {
            setupAutofillDropdown(input);
        } else if (userScore > 40) {
            setupAutofillDropdown(input);
        }
    });
}

/**
 * Fill an input field with a value
 */
function fillInput(input, value) {
    if (!input || !value) return;

    input.focus();
    input.value = value;
    input.setAttribute('value', value);

    // Dispatch events to trigger validation and frameworks
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));

    input.blur();
    input.style.backgroundColor = CONFIG.AUTOFILL_HIGHLIGHT_COLOR;

    // Reset color after 2 seconds
    setTimeout(() => {
        input.style.backgroundColor = '';
    }, 2000);
}

/**
 * Fill credentials for a specific entry
 */
function fillCredentials(form, credential) {
    const { username, password } = findCredentialFields(form);
    if (username) fillInput(username, credential.username);
    if (password) fillInput(password, credential.password);
}

// ============================================
// 7. AUTOFILL UI COMPONENTS
// ============================================

const fieldListenersAdded = new WeakMap();

/**
 * Setup dropdown for credential selection
 */
function setupAutofillDropdown(field) {
    if (fieldListenersAdded.has(field)) return;

    field.addEventListener('focus', () => {
        if (cachedCredentials.length > 0) {
            showCredentialDropdown(field);
        }
    });

    field.addEventListener('click', (e) => {
        if (cachedCredentials.length > 0) {
            showCredentialDropdown(field);
        }
    });

    fieldListenersAdded.set(field, true);
}

/**
 * Setup dropdown for registration (suggest password)
 */
function setupRegistrationDropdown(field) {
    if (fieldListenersAdded.has(field)) return;

    field.addEventListener('focus', () => {
        showPasswordGeneratorDropdown(field);
    });

    field.addEventListener('click', (e) => {
        showPasswordGeneratorDropdown(field);
    });

    fieldListenersAdded.set(field, true);
}

/**
 * Show dropdown with available credentials
 */
function showCredentialDropdown(triggerField) {
    removeDropdown();

    if (cachedCredentials.length === 0) return;

    const dropdownRoot = document.createElement('div');
    dropdownRoot.id = 'pm-credential-dropdown';
    dropdownRoot.attachShadow({ mode: 'open' });

    const shadow = dropdownRoot.shadowRoot;

    const style = document.createElement('style');
    style.textContent = `
        .dropdown {
            position: fixed;
            background: #1e1e2e;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-width: 260px;
            max-width: 320px;
            overflow: hidden;
            animation: pm-fadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            color: #cdd6f4;
        }

        @keyframes pm-fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .header {
            display: flex;
            align-items: center;
            padding: 12px 14px;
            background: rgba(255, 255, 255, 0.03);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 11px;
            font-weight: 600;
            color: #9399b2;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .header svg {
            margin-right: 8px;
            color: #89b4fa;
        }

        .items {
            max-height: 280px;
            overflow-y: auto;
        }

        .item {
            display: flex;
            align-items: center;
            padding: 10px 14px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .item:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .avatar {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: linear-gradient(135deg, #89b4fa, #b4befe);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #1e1e2e;
            font-weight: 700;
            font-size: 14px;
            margin-right: 12px;
            flex-shrink: 0;
        }

        .info {
            flex: 1;
            min-width: 0;
        }

        .username {
            font-size: 13.5px;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: #f5f5f7;
        }

        .service {
            font-size: 11px;
            color: #7f849c;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .divider {
            height: 1px;
            background: rgba(255, 255, 255, 0.05);
            margin: 4px 0;
        }

        .action-item {
            display: flex;
            align-items: center;
            padding: 10px 14px;
            cursor: pointer;
            transition: background 0.2s;
            color: #a6adc8;
            font-size: 13px;
        }

        .action-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: #f5c2e7;
        }

        .action-icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 12px;
            flex-shrink: 0;
        }
    `;

    const container = document.createElement('div');
    container.className = 'dropdown';

    const itemsHtml = cachedCredentials.slice(0, CONFIG.MAX_DROPDOWN_ITEMS).map((cred, index) => `
        <div class="item" data-index="${index}">
            <div class="avatar">${(cred.username || 'U')[0].toUpperCase()}</div>
            <div class="info">
                <div class="username">${escapeHtml(cred.username)}</div>
                <div class="service">${escapeHtml(extractDomain(cred.service))}</div>
            </div>
        </div>
    `).join('');

    container.innerHTML = `
        <div class="header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
            </svg>
            Select account to fill
        </div>
        <div class="items">
            ${itemsHtml}
            <div class="divider"></div>
            <div class="action-item" id="btn-generate-password">
                <div class="action-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 5v14M5 12h14"/>
                    </svg>
                </div>
                <span>Generate Strong Password</span>
            </div>
        </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(container);

    // Position calculation
    const rect = triggerField.getBoundingClientRect();
    const dropdownHeight = 200; // estimated
    const spaceBelow = window.innerHeight - rect.bottom;

    if (spaceBelow < dropdownHeight && rect.top > dropdownHeight) {
        container.style.bottom = `${window.innerHeight - rect.top + 5}px`;
    } else {
        container.style.top = `${rect.bottom + 5}px`;
    }
    container.style.left = `${rect.left}px`;

    // Handle clicks inside dropdown
    container.querySelectorAll('.item').forEach(item => {
        item.addEventListener('click', (e) => {
            const index = parseInt(item.dataset.index);
            const credential = cachedCredentials[index];
            const form = triggerField.closest('form') || triggerField.parentElement;
            fillCredentials(form, credential);
            removeDropdown();
        });
    });

    shadow.getElementById('btn-generate-password').addEventListener('click', () => {
        const password = SecureCrypto.generatePassword();
        const form = triggerField.closest('form') || triggerField.parentElement;
        const passwordFields = form.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
            passwordFields.forEach(field => fillInput(field, password));
        } else if (triggerField.type === 'password') {
            fillInput(triggerField, password);
        }
        removeDropdown();
    });

    document.body.appendChild(dropdownRoot);

    // Close on click outside
    setTimeout(() => {
        document.addEventListener('click', handleDropdownClose);
    }, 10);
}

/**
 * Show dedicated password generator dropdown for registration
 */
function showPasswordGeneratorDropdown(triggerField) {
    removeDropdown();

    const dropdownRoot = document.createElement('div');
    dropdownRoot.id = 'pm-credential-dropdown';
    dropdownRoot.attachShadow({ mode: 'open' });
    const shadow = dropdownRoot.shadowRoot;

    const style = document.createElement('style');
    style.textContent = `
        .dropdown {
            position: fixed;
            background: #1e1e2e;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 16px;
            min-width: 260px;
            animation: pm-fadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            color: #cdd6f4;
        }

        @keyframes pm-fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .header {
            color: #9399b2;
            font-size: 11px;
            font-weight: 600;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: flex;
            align-items: center;
        }

        .header svg {
            margin-right: 8px;
            color: #a6e3a1;
        }

        .suggestion-box {
            background: rgba(255, 255, 255, 0.03);
            border: 1px dashed rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #89b4fa;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 15px;
            letter-spacing: 0.1em;
            font-weight: 600;
        }

        .btn {
            background: #89b4fa;
            color: #11111b;
            border: none;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
            font-size: 13px;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn:hover {
            background: #b4befe;
            transform: translateY(-1px);
        }

        .footer {
            margin-top: 14px;
            text-align: center;
            font-size: 10px;
            color: #6c7086;
        }
    `;

    const suggestedPassword = SecureCrypto.generatePassword();

    const container = document.createElement('div');
    container.className = 'dropdown';
    container.innerHTML = `
        <div class="header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M12 2v20M5 12h14"/>
            </svg>
            Suggested Password
        </div>
        <div class="suggestion-box">${suggestedPassword}</div>
        <button class="btn" id="btn-use-suggested">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                <path d="M20 6L9 17l-5-5"></path>
            </svg>
            Use Suggested Password
        </button>
        <div class="footer">Securely generated by PassManager</div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(container);

    // Position calculation (to match credential dropdown)
    const rect = triggerField.getBoundingClientRect();
    const dropdownHeight = 160;
    const spaceBelow = window.innerHeight - rect.bottom;

    if (spaceBelow < dropdownHeight && rect.top > dropdownHeight) {
        container.style.bottom = `${window.innerHeight - rect.top + 5}px`;
    } else {
        container.style.top = `${rect.bottom + 5}px`;
    }
    container.style.left = `${rect.left}px`;

    shadow.getElementById('btn-use-suggested').addEventListener('click', () => {
        const form = triggerField.closest('form') || triggerField.parentElement;
        const passwordFields = form.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
            passwordFields.forEach(field => fillInput(field, suggestedPassword));
        } else {
            fillInput(triggerField, suggestedPassword);
        }
        removeDropdown();
    });

    document.body.appendChild(dropdownRoot);
    setTimeout(() => document.addEventListener('click', handleDropdownClose), 10);
}

/**
 * Remove the credential dropdown
 */
function removeDropdown() {
    const existing = document.getElementById('pm-credential-dropdown');
    if (existing) existing.remove();
    document.removeEventListener('click', handleDropdownClose);
}

function handleDropdownClose(e) {
    const dropdown = document.getElementById('pm-credential-dropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        removeDropdown();
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

// ============================================
// 8. CREDENTIAL CAPTURE
// ============================================

/**
 * Handle form submission to capture credentials
 */
document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form || form.tagName !== 'FORM') return;

    if (!isLoginForm(form)) return;

    const { username, password } = findCredentialFields(form);

    if (password && password.value.length > 0) {
        const usernameVal = username ? username.value : '';
        const passwordVal = password.value;
        captureAndPrompt(usernameVal, passwordVal);
    }
}, true);

/**
 * Handle click-based form submission (for SPAs and AJAX forms)
 */
document.addEventListener('click', (e) => {
    const button = e.target.closest('button, [role="button"], input[type="submit"], a[href*="login"]');
    if (!button) return;

    // Check if this looks like a login button
    const buttonText = (button.textContent || button.value || '').toLowerCase();
    const isLoginButton = KEYWORDS.submit.some(kw => buttonText.includes(kw));

    if (!isLoginButton) return;

    // Find associated form or look for nearby password field
    const form = button.closest('form');
    if (form) {
        // Form will be handled by submit event
        return;
    }

    // Look for password field in the same container
    const container = button.closest('[class*="form"], [class*="login"], [class*="auth"], section, article, main') || document.body;
    const passwordField = container.querySelector('input[type="password"]');

    if (passwordField && passwordField.value.length > 0) {
        const { username } = findCredentialFields(container);
        const usernameVal = username ? username.value : '';

        // Delay to allow login to process
        setTimeout(() => {
            captureAndPrompt(usernameVal, passwordField.value);
        }, 500);
    }
}, true);

/**
 * Capture credentials and show save dialog
 */
async function captureAndPrompt(username, password) {
    if (!password) return;

    try {
        // Check if credentials already exist
        const response = await chrome.runtime.sendMessage({
            type: 'CHECK_EXISTING',
            url: window.location.origin,
            username: username
        });

        if (response?.exists) {
            createSaveDialog(username, password, 'update', response.id);
        } else {
            createSaveDialog(username, password, 'new');
        }
    } catch (e) {
        // If check fails, default to new save
        createSaveDialog(username, password, 'new');
    }
}

// ============================================
// 9. SAVE DIALOG UI
// ============================================

function createSaveDialog(username, password, mode = 'new', existingId = null) {
    const existing = document.getElementById('pm-save-dialog-root');
    if (existing) existing.remove();

    const container = document.createElement('div');
    container.id = 'pm-save-dialog-root';
    const shadow = container.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = `
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap');
        
        .card {
            position: fixed;
            top: 24px;
            right: 24px;
            width: 360px;
            background: rgba(30, 30, 46, 0.85);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 24px;
            box-shadow: 
                0 20px 50px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(255, 255, 255, 0.05) inset;
            z-index: 2147483647;
            font-family: 'Outfit', -apple-system, sans-serif;
            animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3498db, #8b5cf6);
        }
        
        @keyframes slideIn {
            from { transform: translateX(40px) translateY(-10px); opacity: 0; }
            to { transform: translateX(0) translateY(0); opacity: 1; }
        }

        @keyframes fadeOut {
            to { opacity: 0; transform: scale(0.95); }
        }
        
        .header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .icon-container {
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 16px;
            box-shadow: 0 8px 16px rgba(59, 130, 246, 0.3);
            flex-shrink: 0;
        }
        
        .title-group {
            flex: 1;
            min-width: 0;
        }

        .title-group h3 {
            margin: 0;
            font-size: 17px;
            font-weight: 600;
            color: #ffffff;
            letter-spacing: -0.01em;
        }
        
        .title-group p {
            margin: 4px 0 0 0;
            font-size: 13px;
            color: #94a3b8;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .secure-badge {
            display: inline-flex;
            align-items: center;
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid rgba(34, 197, 94, 0.2);
            border-radius: 6px;
            padding: 6px 10px;
            margin-bottom: 20px;
            font-size: 11px;
            font-weight: 500;
            color: #4ade80;
            letter-spacing: 0.02em;
        }
        
        .secure-badge svg {
            margin-right: 6px;
            width: 12px;
            height: 12px;
        }
        
        .field-group {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            padding: 4px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .info-row {
            display: flex;
            align-items: center;
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .info-row:last-child {
            border-bottom: none;
        }
        
        .info-label {
            color: #94a3b8;
            font-size: 12px;
            font-weight: 500;
            width: 80px;
            flex-shrink: 0;
        }
        
        .info-value {
            color: #f1f5f9;
            font-size: 13px;
            font-weight: 500;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: monospace;
            letter-spacing: 0.02em;
        }
        
        .btn-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }
        
        button {
            padding: 12px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            font-family: 'Outfit', sans-serif;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        button::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0);
            transition: background 0.2s;
        }

        button:hover::after {
            background: rgba(255, 255, 255, 0.08);
        }
        
        .btn-save {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }
        
        .btn-save:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(59, 130, 246, 0.5);
        }
        
        .btn-update {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
        }
        
        .btn-update:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(245, 158, 11, 0.5);
        }
        
        .btn-cancel {
            background: rgba(255, 255, 255, 0.05);
            color: #94a3b8;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .btn-cancel:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }
        
        .success-state {
            text-align: center;
            padding: 30px 0;
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        
        .success-state svg {
            width: 56px;
            height: 56px;
            margin-bottom: 16px;
            filter: drop-shadow(0 4px 12px rgba(34, 197, 94, 0.4));
        }
        
        .success-state h3 {
            margin: 0;
            color: #f0fdf4;
            font-size: 20px;
            font-weight: 600;
        }
    `;

    const isUpdate = mode === 'update';
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
        <div class="header">
            <div class="icon-container">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="white">
                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                    <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zm0 8c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z" fill-opacity="0.3"/>
                </svg>
            </div>
            <div class="title-group">
                <h3>${isUpdate ? 'Update Password?' : 'Save Password?'}</h3>
                <p>for ${extractDomain(window.location.href)}</p>
            </div>
        </div>
        
        <div class="secure-badge">
            <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
            </svg>
            End-to-end encrypted
        </div>
        
        <div class="field-group">
            <div class="info-row">
                <span class="info-label">Username</span>
                <span class="info-value" title="${escapeHtml(username)}">${escapeHtml(username) || '(empty)'}</span>
            </div>
            
            <div class="info-row">
                <span class="info-label">Password</span>
                <span class="info-value">••••••••••••</span>
            </div>
        </div>
        
        <div class="btn-group">
            <button class="btn-cancel" id="cancel-btn">Never</button>
            <button class="${isUpdate ? 'btn-update' : 'btn-save'}" id="save-btn">
                ${isUpdate ? 'Update' : 'Save Password'}
            </button>
        </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(card);
    document.body.appendChild(container);

    shadow.getElementById('save-btn').addEventListener('click', async () => {
        const messageType = isUpdate ? 'UPDATE_CREDENTIALS' : 'SAVE_CREDENTIALS';
        const messageData = {
            url: window.location.origin,
            username: username,
            password: password
        };

        if (isUpdate && existingId) {
            messageData.id = existingId;
        }

        try {
            const response = await chrome.runtime.sendMessage({
                type: messageType,
                data: messageData
            });

            if (response?.success) {
                card.innerHTML = `
                    <div class="success-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="#22c55e">
                            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                        </svg>
                        <h3>${isUpdate ? 'Updated!' : 'Saved!'}</h3>
                    </div>
                `;

                // Refresh cached credentials
                cachedCredentials = [];

                setTimeout(() => container.remove(), 1500);
            } else {
                showError(card, response?.error || 'Failed to save');
            }
        } catch (error) {
            showError(card, error.message);
        }
    });

    shadow.getElementById('cancel-btn').addEventListener('click', () => {
        container.remove();
    });

    // Auto-close after 30 seconds
    setTimeout(() => {
        if (document.getElementById('pm-save-dialog-root')) {
            container.remove();
        }
    }, 30000);
}

function showError(card, message) {
    const errorDiv = card.querySelector('.error-message') || document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style.cssText = 'color: #ef4444; font-size: 12px; margin-top: 10px; text-align: center;';
    errorDiv.textContent = message;
    if (!card.querySelector('.error-message')) {
        card.appendChild(errorDiv);
    }
}

// ============================================
// 10. MUTATION OBSERVER (SPA Support)
// ============================================

let debounceTimer;
const observer = new MutationObserver((mutations) => {
    const hasRelevantChanges = mutations.some(m =>
        Array.from(m.addedNodes).some(node =>
            node.tagName === 'FORM' ||
            node.tagName === 'INPUT' ||
            (node.querySelectorAll &&
                (node.querySelectorAll('form').length > 0 ||
                    node.querySelectorAll('input[type="password"]').length > 0))
        )
    );

    if (hasRelevantChanges) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(checkAndAutofill, CONFIG.DEBOUNCE_DELAY);
    }
});

// ============================================
// 11. MESSAGE LISTENERS
// ============================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'OPEN_SAVE_DIALOG') {
        const passwordInput = document.querySelector('input[type="password"]');
        let bestUser = '', bestPass = '';

        if (passwordInput) {
            const form = passwordInput.closest('form');
            if (form) {
                const best = findCredentialFields(form);
                bestUser = best.username ? best.username.value : '';
                bestPass = best.password ? best.password.value : '';
            } else {
                bestPass = passwordInput.value;
            }
        }
        createSaveDialog(bestUser, bestPass);
        sendResponse({ success: true });
    }

    if (message.type === 'TRIGGER_AUTOFILL') {
        checkAndAutofill();
        sendResponse({ success: true });
    }

    if (message.type === 'CLEAR_CACHE') {
        cachedCredentials = [];
        sendResponse({ success: true });
    }

    return true;
});

// ============================================
// 12. INITIALIZATION
// ============================================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

function init() {
    initializeSecureChannel();
    observer.observe(document.body, { childList: true, subtree: true });
    checkAndAutofill();
}
