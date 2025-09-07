/**
 * Document Tracking System - Authentication JavaScript
 * Handles view management, form validation, and AJAX requests
 */

// Application state management
const AppState = {
    currentView: 'login',
    currentStep: 'login-step1',
    isEmailVerified: false,
    currentUser: null,
    otpSent: false
};

// DOM elements cache
const elements = {
    navButtons: document.querySelectorAll('.nav-btn'),
    loginView: document.getElementById('login-view'),
    signupView: document.getElementById('signup-view'),
    alertContainer: document.getElementById('alert-container'),
    loginSteps: document.querySelectorAll('.login-step'),
    
    // Login elements
    loginStep1: document.getElementById('login-step1'),
    loginStep2: document.getElementById('login-step2'),
    otpStep: document.getElementById('otp-step'),
    continueAuthBtn: document.getElementById('continue-auth'),
    sendOtpBtn: document.getElementById('send-otp'),
    verifyOtpBtn: document.getElementById('verify-otp'),
    
    // Signup elements
    signupForm: document.getElementById('signup-form'),
    sendVerificationBtn: document.getElementById('send-verification'),
    verificationCodeSection: document.getElementById('verification-code-section'),
    signupBtn: document.getElementById('signup-btn'),
    
    // Password toggle buttons
    toggleLoginPassword: document.getElementById('toggle-login-password'),
    toggleSignupPassword: document.getElementById('toggle-signup-password')
};

/**
 * Initialize the application
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializePasswordToggles();
    initializeFormHandlers();
    setActiveView('login');
});

/**
 * Set up navigation between login and signup views
 */
function initializeNavigation() {
    elements.navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const view = this.dataset.view;
            setActiveView(view);
            
            // Update button states
            elements.navButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

/**
 * Set up password visibility toggle functionality
 */
function initializePasswordToggles() {
    // Login password toggle
    elements.toggleLoginPassword.addEventListener('click', function() {
        togglePasswordVisibility('login-password', this);
    });
    
    // Signup password toggle
    elements.toggleSignupPassword.addEventListener('click', function() {
        togglePasswordVisibility('signup-password', this);
    });
}

/**
 * Toggle password visibility
 * @param {string} inputId - ID of the password input
 * @param {HTMLElement} toggleBtn - Toggle button element
 */
function togglePasswordVisibility(inputId, toggleBtn) {
    const passwordInput = document.getElementById(inputId);
    const icon = toggleBtn.querySelector('i');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('bi-eye');
        icon.classList.add('bi-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('bi-eye-slash');
        icon.classList.add('bi-eye');
    }
}

/**
 * Set up form event handlers
 */
function initializeFormHandlers() {
    // Login Step 1 form handler
    elements.loginStep1.addEventListener('submit', handleLoginStep1);
    
    // Continue authentication handler
    elements.continueAuthBtn.addEventListener('click', handleContinueAuth);
    
    // Send OTP handler
    elements.sendOtpBtn.addEventListener('click', handleSendOtp);
    
    // Verify OTP handler
    elements.verifyOtpBtn.addEventListener('click', handleVerifyOtp);
    
    // Send verification code handler (signup)
    elements.sendVerificationBtn.addEventListener('click', handleSendVerificationCode);
    
    // Signup form handler
    elements.signupForm.addEventListener('submit', handleSignup);
    
    // Email verification code input handler
    document.getElementById('verification-code').addEventListener('input', handleVerificationCodeInput);
}

/**
 * Switch between login and signup views
 * @param {string} view - View name ('login' or 'signup')
 */
function setActiveView(view) {
    AppState.currentView = view;
    
    // Hide all views
    elements.loginView.style.display = 'none';
    elements.signupView.style.display = 'none';
    
    // Show selected view
    if (view === 'login') {
        elements.loginView.style.display = 'block';
        resetLoginSteps();
    } else if (view === 'signup') {
        elements.signupView.style.display = 'block';
    }
    
    clearAlerts();
}

/**
 * Reset login steps to initial state
 */
function resetLoginSteps() {
    elements.loginSteps.forEach(step => step.style.display = 'none');
    elements.loginStep1.style.display = 'block';
    AppState.currentStep = 'login-step1';
}

/**
 * Handle login step 1 (username and password validation)
 * @param {Event} e - Form submit event
 */
async function handleLoginStep1(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    if (!username || !password) {
        showAlert('Please enter both username and password.', 'danger');
        return;
    }
    
    try {
        showAlert('Validating credentials...', 'info');
        
        // AJAX call to validate credentials
        const response = await fetch('auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `action=validate_credentials&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        });
        
        const result = await response.json();
        
        if (result.success) {
            AppState.currentUser = result.user;
            showAlert('Credentials validated! Proceeding to two-factor authentication.', 'success');
            
            // Move to step 2
            setTimeout(() => {
                elements.loginStep1.style.display = 'none';
                elements.loginStep2.style.display = 'block';
                AppState.currentStep = 'login-step2';
            }, 1500);
        } else {
            showAlert(result.message || 'Invalid username or password.', 'danger');
        }
    } catch (error) {
        showAlert('An error occurred. Please try again.', 'danger');
        console.error('Login error:', error);
    }
}

/**
 * Handle continue authentication (move to OTP step)
 */
function handleContinueAuth() {
    const selectedMethod = document.querySelector('input[name="auth-method"]:checked').value;
    
    if (selectedMethod === 'otp') {
        elements.loginStep2.style.display = 'none';
        elements.otpStep.style.display = 'block';
        AppState.currentStep = 'otp-step';
        showAlert('Please request an OTP to continue.', 'info');
    }
}

/**
 * Handle sending OTP via email
 */
async function handleSendOtp() {
    if (!AppState.currentUser) {
        showAlert('Session expired. Please login again.', 'danger');
        resetLoginSteps();
        return;
    }
    
    try {
        elements.sendOtpBtn.disabled = true;
        elements.sendOtpBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Sending...';
        
        // AJAX call to send OTP
        const response = await fetch('auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `action=send_otp&email=${encodeURIComponent(AppState.currentUser.email)}`
        });
        
        const result = await response.json();
        
        if (result.success) {
            AppState.otpSent = true;
            showAlert('OTP sent to your email! Please check and enter the code.', 'success');
        } else {
            showAlert(result.message || 'Failed to send OTP.', 'danger');
        }
    } catch (error) {
        showAlert('Failed to send OTP. Please try again.', 'danger');
        console.error('OTP send error:', error);
    } finally {
        elements.sendOtpBtn.disabled = false;
        elements.sendOtpBtn.innerHTML = 'Send OTP';
    }
}

/**
 * Handle OTP verification
 */
async function handleVerifyOtp() {
    const otpCode = document.getElementById('otp-code').value;
    
    if (!otpCode || otpCode.length !== 6) {
        showAlert('Please enter a valid 6-digit OTP code.', 'danger');
        return;
    }
    
    if (!AppState.otpSent) {
        showAlert('Please send OTP first.', 'danger');
        return;
    }
    
    try {
        elements.verifyOtpBtn.disabled = true;
        elements.verifyOtpBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';
        
        // AJAX call to verify OTP
        const response = await fetch('auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `action=verify_otp&email=${encodeURIComponent(AppState.currentUser.email)}&otp=${encodeURIComponent(otpCode)}`
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('Login successful! Welcome to the Document Tracking System.', 'success');
            // In a real application, you would redirect to dashboard
            setTimeout(() => {
                alert('Login successful! You would now be redirected to the dashboard.');
            }, 2000);
        } else {
            showAlert(result.message || 'Invalid OTP code.', 'danger');
        }
    } catch (error) {
        showAlert('Verification failed. Please try again.', 'danger');
        console.error('OTP verification error:', error);
    } finally {
        elements.verifyOtpBtn.disabled = false;
        elements.verifyOtpBtn.innerHTML = 'Verify & Login';
    }
}

/**
 * Handle sending verification code for signup
 */
async function handleSendVerificationCode() {
    const email = document.getElementById('email').value;
    
    if (!email || !isValidEmail(email)) {
        showAlert('Please enter a valid email address.', 'danger');
        return;
    }
    
    try {
        elements.sendVerificationBtn.disabled = true;
        elements.sendVerificationBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        
        // AJAX call to send verification code
        const response = await fetch('auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `action=send_verification&email=${encodeURIComponent(email)}`
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('Verification code sent to your email!', 'success');
            elements.verificationCodeSection.style.display = 'block';
        } else {
            showAlert(result.message || 'Failed to send verification code.', 'danger');
        }
    } catch (error) {
        showAlert('Failed to send verification code. Please try again.', 'danger');
        console.error('Verification send error:', error);
    } finally {
        elements.sendVerificationBtn.disabled = false;
        elements.sendVerificationBtn.innerHTML = 'Send Code';
    }
}

/**
 * Handle verification code input and validation
 */
async function handleVerificationCodeInput() {
    const code = document.getElementById('verification-code').value;
    const email = document.getElementById('email').value;
    
    if (code.length === 6) {
        try {
            // AJAX call to verify code
            const response = await fetch('auth.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=verify_code&email=${encodeURIComponent(email)}&code=${encodeURIComponent(code)}`
            });
            
            const result = await response.json();
            
            if (result.success) {
                AppState.isEmailVerified = true;
                elements.signupBtn.disabled = false;
                showAlert('Email verified! You can now complete your registration.', 'success');
            } else {
                AppState.isEmailVerified = false;
                elements.signupBtn.disabled = true;
                showAlert(result.message || 'Invalid verification code.', 'danger');
            }
        } catch (error) {
            AppState.isEmailVerified = false;
            elements.signupBtn.disabled = true;
            console.error('Code verification error:', error);
        }
    } else {
        AppState.isEmailVerified = false;
        elements.signupBtn.disabled = true;
    }
}

/**
 * Handle signup form submission
 * @param {Event} e - Form submit event
 */
async function handleSignup(e) {
    e.preventDefault();
    
    if (!AppState.isEmailVerified) {
        showAlert('Please verify your email first.', 'danger');
        return;
    }
    
    // Collect form data
    const formData = {
        firstName: document.getElementById('first-name').value,
        lastName: document.getElementById('last-name').value,
        address: document.getElementById('address').value,
        idNumber: document.getElementById('id-number').value,
        department: document.getElementById('department').value,
        year: document.getElementById('year').value,
        email: document.getElementById('email').value,
        username: document.getElementById('signup-username').value,
        password: document.getElementById('signup-password').value
    };
    
    // Validate required fields
    for (const [key, value] of Object.entries(formData)) {
        if (!value) {
            showAlert('Please fill in all required fields.', 'danger');
            return;
        }
    }
    
    // Validate password strength
    if (!isValidPassword(formData.password)) {
        showAlert('Password must be 8-12 characters with letters, numbers, and special characters.', 'danger');
        return;
    }
    
    try {
        elements.signupBtn.disabled = true;
        elements.signupBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating Account...';
        
        // AJAX call to create account
        const response = await fetch('auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: Object.keys(formData).map(key => 
                `${key}=${encodeURIComponent(formData[key])}`
            ).join('&') + '&action=signup'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('Account created successfully! You can now login.', 'success');
            
            // Reset form and switch to login
            setTimeout(() => {
                elements.signupForm.reset();
                elements.verificationCodeSection.style.display = 'none';
                AppState.isEmailVerified = false;
                setActiveView('login');
                elements.navButtons[0].click(); // Click login button
            }, 2000);
        } else {
            showAlert(result.message || 'Failed to create account.', 'danger');
        }
    } catch (error) {
        showAlert('Failed to create account. Please try again.', 'danger');
        console.error('Signup error:', error);
    } finally {
        elements.signupBtn.disabled = !AppState.isEmailVerified;
        elements.signupBtn.innerHTML = 'Sign Up';
    }
}

/**
 * Display alert messages to user
 * @param {string} message - Alert message
 * @param {string} type - Alert type ('success', 'danger', 'info')
 */
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    elements.alertContainer.innerHTML = '';
    elements.alertContainer.appendChild(alertDiv);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv && alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * Clear all alert messages
 */
function clearAlerts() {
    elements.alertContainer.innerHTML = '';
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} - True if valid
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {boolean} - True if valid
 */
function isValidPassword(password) {
    // 8-12 characters with letters, numbers, and special characters
    const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,12}$/;
    return passwordRegex.test(password);
}