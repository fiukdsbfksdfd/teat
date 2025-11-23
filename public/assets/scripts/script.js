import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm'

const supabaseUrl = 'https://grmihsppmbipapiwllau.supabase.co'
const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdybWloc3BwbWJpcGFwaXdsbGF1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY2NzY0MTUsImV4cCI6MjA3MjI1MjQxNX0.d_lqYj5CiCHb9pQLN8UypaQnkS07FoBmDVMvGKhTxkk"
const supabase = createClient(supabaseUrl, supabaseKey)

const SecureStorage = {
    setSession(key, value) {
        sessionStorage.setItem(key, value);
    },
    getSession(key) {
        return sessionStorage.getItem(key);
    },
    clearSession(key) {
        sessionStorage.removeItem(key);
    },
    clearAll() {
        sessionStorage.clear();
    }
};

class LoginAuth {
    constructor() {
        this.supabase = supabase;
        this.init();
    }

    async init() {
        await this.checkSession();
        const form = document.getElementById('login-form');
        if (form) {
            form.addEventListener('submit', (e) => this.handleLogin(e));
        }
    }

    async checkSession() {
        const { data: { user } } = await this.supabase.auth.getUser();
        if (user) {
            const params = new URLSearchParams(window.location.search);
            const redirect = params.get('redirect');
            
            if (redirect) {
                const { data: { session } } = await this.supabase.auth.getSession();
                if (session) {
                    const redirectUrl = new URL(redirect);
                    redirectUrl.searchParams.set('access_token', session.access_token);
                    redirectUrl.searchParams.set('refresh_token', session.refresh_token);
                    window.location.href = redirectUrl.toString();
                    return;
                }
            }
            
            window.location.href = 'dashboard';
        } else {
            const container = document.querySelector('.auth-container');
            if (container) {
                container.classList.add('visible');
            }
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const btn = document.getElementById('login-btn');
        const message = document.getElementById('login-message');

        if (!email || !password) {
            this.showMessage(message, 'Please fill in all fields', 'error');
            return;
        }

        this.setLoading(btn, true);
        this.hideMessage(message);

        try {
            const { data, error } = await this.supabase.auth.signInWithPassword({
                email: email,
                password: password
            });

            if (error) throw error;
            
            const params = new URLSearchParams(window.location.search);
            const redirect = params.get('redirect');
            
            if (redirect && data.session) {
                const redirectUrl = new URL(redirect);
                redirectUrl.searchParams.set('access_token', data.session.access_token);
                redirectUrl.searchParams.set('refresh_token', data.session.refresh_token);
                window.location.href = redirectUrl.toString();
                return;
            }
            
            window.location.href = 'dashboard';
        } catch (error) {
            this.setErrorState(btn);
            this.showMessage(message, error.message, 'error');
            this.shakeCard();
        }

        this.setLoading(btn, false);
    }

    setLoading(btn, loading) {
        if (!btn) return;
        if (loading) {
            btn.classList.add('loading');
            btn.disabled = true;
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    setSuccessState(btn) {
        if (!btn) return;
        btn.classList.remove('loading');
        btn.classList.add('success');
    }

    setErrorState(btn) {
        if (!btn) return;
        btn.classList.remove('loading', 'success');
    }

    showMessage(element, text, type) {
        if (!element) return;
        element.textContent = text;
        element.className = `message ${type}-message show`;
        element.classList.remove('hidden');
    }

    hideMessage(element) {
        if (!element) return;
        element.classList.remove('show');
        element.classList.add('hidden');
    }

    shakeCard() {
        const card = document.querySelector('.auth-card') || 
                     document.querySelector('.form-container') || 
                     document.querySelector('.split-container') ||
                     document.querySelector('.auth-container');
        
        if (card) {
            card.classList.add('shake');
            setTimeout(() => card.classList.remove('shake'), 500);
        } else {
            console.warn('No shakeable element found');
        }
    }
}

class SignupAuth {
    constructor() {
        this.supabase = supabase;
        this.init();
    }

    async init() {
        await this.checkSession();
        const form = document.getElementById('signup-form');
        if (form) {
            form.addEventListener('submit', (e) => this.handleSignup(e));
        }
        
        const passwordInput = document.getElementById('signup-password');
        const confirmInput = document.getElementById('signup-confirm');
        
        if (passwordInput) {
            passwordInput.addEventListener('input', () => this.checkPasswordStrength());
        }
        
        if (confirmInput) {
            confirmInput.addEventListener('input', () => this.checkPasswordMatch());
        }
    }

    async checkSession() {
        const container = document.querySelector('.auth-container');
        if (container) {
            container.classList.add('visible');
        }
    }

    checkPasswordStrength() {
        const password = document.getElementById('signup-password').value;
        const strengthBar = document.getElementById('password-strength-bar');
        const strengthText = document.getElementById('password-strength-text');
        
        if (!strengthBar || !strengthText) return;
        
        let strength = 0;
        
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;
        
        const strengthLevels = [
            { text: 'Very Weak', color: '#ef4444', width: '20%' },
            { text: 'Weak', color: '#f97316', width: '40%' },
            { text: 'Fair', color: '#eab308', width: '60%' },
            { text: 'Good', color: '#22c55e', width: '80%' },
            { text: 'Strong', color: '#10b981', width: '100%' }
        ];
        
        const level = strengthLevels[Math.min(strength, 4)];
        strengthBar.style.width = level.width;
        strengthBar.style.backgroundColor = level.color;
        strengthText.textContent = level.text;
        strengthText.style.color = level.color;
    }

    checkPasswordMatch() {
        const password = document.getElementById('signup-password').value;
        const confirm = document.getElementById('signup-confirm').value;
        const matchIndicator = document.getElementById('password-match-indicator');
        
        if (!matchIndicator || !confirm) return;
        
        if (confirm.length > 0) {
            if (password === confirm) {
                matchIndicator.innerHTML = '✓ Passwords match';
                matchIndicator.style.color = '#10b981';
                matchIndicator.style.display = 'block';
            } else {
                matchIndicator.innerHTML = '✗ Passwords do not match';
                matchIndicator.style.color = '#ef4444';
                matchIndicator.style.display = 'block';
            }
        } else {
            matchIndicator.style.display = 'none';
        }
    }

    async handleSignup(e) {
        e.preventDefault();
        
        const username = document.getElementById('signup-username').value.trim();
        const email = document.getElementById('signup-email').value.trim();
        const password = document.getElementById('signup-password').value;
        const confirm = document.getElementById('signup-confirm').value;
        const message = document.getElementById('signup-message');

        if (!username || !email || !password || !confirm) {
            this.showMessage(message, 'Please fill in all fields', 'error');
            return;
        }

        if (password !== confirm) {
            this.showMessage(message, 'Passwords do not match', 'error');
            this.shakeCard();
            return;
        }

        if (password.length < 6) {
            this.showMessage(message, 'Password must be at least 6 characters long', 'error');
            this.shakeCard();
            return;
        }

        this.showTOSModal(username, email, password);
    }

    showTOSModal(username, email, password) {
        const modal = document.getElementById('tos-modal');
        if (!modal) {
            // If no TOS modal, proceed directly
            this.createAccount(username, email, password);
            return;
        }

        modal.style.display = 'flex';
        this.pendingSignup = { username, email, password };

        const agreeBtn = document.getElementById('tos-agree');
        const declineBtn = document.getElementById('tos-decline');
        const closeBtn = document.getElementById('close-tos');

        if (agreeBtn) {
            agreeBtn.onclick = () => {
                this.closeTOSModal();
                this.createAccount(username, email, password);
            };
        }

        if (declineBtn) {
            declineBtn.onclick = () => {
                this.closeTOSModal();
                const message = document.getElementById('signup-message');
                this.showMessage(message, 'You must agree to the Terms of Service to create an account', 'error');
            };
        }

        if (closeBtn) {
            closeBtn.onclick = () => {
                this.closeTOSModal();
            };
        }

        modal.onclick = (e) => {
            if (e.target === modal) {
                this.closeTOSModal();
            }
        };
    }

    closeTOSModal() {
        const modal = document.getElementById('tos-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async createAccount(username, email, password) {
        const btn = document.getElementById('signup-btn');
        const message = document.getElementById('signup-message');

        this.setLoading(btn, true);
        this.hideMessage(message);

        try {
            // Create auth user with username in metadata
            const { data, error } = await this.supabase.auth.signUp({
                email: email,
                password: password,
                options: {
                    data: {
                        username: username
                    }
                }
            });

            if (error) throw error;

            if (!data.user) {
                throw new Error('No user data returned from signup');
            }

            this.showMessage(message, 'Wait A Moment...', 'success');
            this.setSuccessState(btn);        
            
            setTimeout(() => {
                window.location.href = 'login';
            }, 2000);

        } catch (error) {
            console.error('Account creation error:', error);
            this.setErrorState(btn);
            
            let errorMessage = 'Failed to create account. Please try again.';
            
            if (error.message.includes('already registered')) {
                errorMessage = 'This email is already registered. Please try logging in.';
            } else if (error.message.includes('email')) {
                errorMessage = 'Invalid email address. Please check and try again.';
            } else if (error.message) {
                errorMessage = error.message;
            }
            
            this.showMessage(message, errorMessage, 'error');
            this.shakeCard();
        } finally {
            this.setLoading(btn, false);
        }
    }

    setLoading(btn, loading) {
        if (!btn) return;
        if (loading) {
            btn.classList.add('loading');
            btn.disabled = true;
            btn.textContent = 'Creating Account...';
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
            btn.textContent = 'Sign Up';
        }
    }

    setSuccessState(btn) {
        if (!btn) return;
        btn.classList.remove('loading');
        btn.classList.add('success');
        btn.textContent = '✓ Success!';
    }

    setErrorState(btn) {
        if (!btn) return;
        btn.classList.remove('loading', 'success');
        btn.textContent = 'Sign Up';
    }

    showMessage(element, text, type) {
        if (!element) return;
        element.textContent = text;
        element.className = `message ${type}-message show`;
        element.classList.remove('hidden');
    }

    hideMessage(element) {
        if (!element) return;
        element.classList.remove('show');
        element.classList.add('hidden');
    }

    shakeCard() {
        const card = document.querySelector('.auth-card') || document.querySelector('.form-container');
        if (card) {
            card.classList.add('shake');
            setTimeout(() => card.classList.remove('shake'), 500);
        }
    }
}

function handleNavbarScroll() {
    const navbar = document.getElementById('navbar');
    if (navbar) {
        const scrolled = window.scrollY > 50;
        if (scrolled) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }
}

window.addEventListener('beforeunload', () => {
    SecureStorage.clearAll();
});

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    
    if (loginForm) {
        new LoginAuth();
    } else if (signupForm) {
        new SignupAuth();
    }
    
    window.addEventListener('scroll', handleNavbarScroll);
});
