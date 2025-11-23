// Canvas Animations - Subtle Apple-like
class CanvasAnimation {
    constructor(canvasId, type) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.type = type;
        this.particles = [];
        this.animationId = null;

        this.resizeCanvas();
        this.init();
        this.animate();

        window.addEventListener('resize', () => this.resizeCanvas());
    }

    resizeCanvas() {
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
    }

    init() {
        this.particles = [];
        const particleCount = 8;

        for (let i = 0; i < particleCount; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                size: Math.random() * 3 + 2,
                opacity: Math.random() * 0.3 + 0.1,
                hue: Math.random() * 60 + 200,
            });
        }
    }

    animate() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        switch (this.type) {
            case 'floating':
                this.drawFloating();
                break;
            case 'wave':
                this.drawWave();
                break;
            case 'pulse':
                this.drawPulse();
                break;
            case 'flow':
                this.drawFlow();
                break;
        }

        this.animationId = requestAnimationFrame(() => this.animate());
    }

    drawFloating() {
        const time = Date.now() * 0.001;

        this.particles.forEach(particle => {
            const gradient = this.ctx.createRadialGradient(particle.x, particle.y, 0, particle.x, particle.y, particle.size * 2);
            gradient.addColorStop(0, `hsla(${particle.hue}, 70%, 70%, ${particle.opacity})`);
            gradient.addColorStop(1, `hsla(${particle.hue}, 70%, 70%, 0)`);

            this.ctx.fillStyle = gradient;
            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            this.ctx.fill();

            particle.x += Math.sin(time + particle.x * 0.01) * 0.2;
            particle.y += Math.cos(time + particle.y * 0.01) * 0.2;

            if (particle.x < 0) particle.x = this.canvas.width;
            if (particle.x > this.canvas.width) particle.x = 0;
            if (particle.y < 0) particle.y = this.canvas.height;
            if (particle.y > this.canvas.height) particle.y = 0;
        });
    }

    drawWave() {
        const time = Date.now() * 0.001;
        const gradient = this.ctx.createLinearGradient(0, 0, this.canvas.width, this.canvas.height);
        gradient.addColorStop(0, 'rgba(30, 58, 138, 0.1)');
        gradient.addColorStop(1, 'rgba(0, 0, 0, 0.1)');

        this.ctx.strokeStyle = gradient;
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();

        for (let x = 0; x < this.canvas.width; x += 5) {
            const y = this.canvas.height / 2 + Math.sin(x * 0.01 + time) * 20;
            if (x === 0) {
                this.ctx.moveTo(x, y);
            } else {
                this.ctx.lineTo(x, y);
            }
        }
        this.ctx.stroke();
    }

    drawPulse() {
        const time = Date.now() * 0.001;
        const centerX = this.canvas.width / 2;
        const centerY = this.canvas.height / 2;

        for (let i = 0; i < 3; i++) {
            const radius = 20 + Math.sin(time + i * 0.5) * 15;
            const opacity = 0.1 - i * 0.03;

            const gradient = this.ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radius);
            gradient.addColorStop(0, `rgba(30, 58, 138, ${opacity})`);
            gradient.addColorStop(1, 'rgba(30, 58, 138, 0)');

            this.ctx.fillStyle = gradient;
            this.ctx.beginPath();
            this.ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
            this.ctx.fill();
        }
    }

    drawFlow() {
        const time = Date.now() * 0.001;

        this.ctx.strokeStyle = 'rgba(30, 58, 138, 0.1)';
        this.ctx.lineWidth = 1;

        for (let i = 0; i < 5; i++) {
            this.ctx.beginPath();
            const startX = ((time * 30 + i * 40) % (this.canvas.width + 40)) - 40;
            const startY = this.canvas.height / 2 + Math.sin(time + i) * 30;

            this.ctx.moveTo(startX, startY);
            this.ctx.quadraticCurveTo(startX + 20, startY - 10, startX + 40, startY);
            this.ctx.stroke();
        }
    }

    destroy() {
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
        }
    }
}

// Navbar scroll effect
function handleNavbarScroll() {
    const navbar = document.getElementById('navbar');
    const scrolled = window.scrollY > 50;

    if (scrolled) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
}

// FAQ Toggle
function initFAQ() {
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');

        question.addEventListener('click', () => {
            const isActive = item.classList.contains('active');

            // Close all other items
            faqItems.forEach(otherItem => {
                otherItem.classList.remove('active');
            });

            // Toggle current item
            if (!isActive) {
                item.classList.add('active');
            }
        });
    });
}

// Enhanced smooth scroll for anchor links
function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const target = document.getElementById(targetId);
            
            if (target) {
                // Calculate offset for fixed navbar
                const navbar = document.querySelector('.navbar');
                const offset = navbar ? navbar.offsetHeight + 40 : 40;
                
                const targetPosition = target.offsetTop - offset;
                
                // Use smooth scrolling with easing
                smoothScrollTo(targetPosition, 800);
            }
        });
    });
}

// Custom smooth scroll function with easing
function smoothScrollTo(targetPosition, duration) {
    const startPosition = window.pageYOffset;
    const distance = targetPosition - startPosition;
    let startTime = null;

    function animation(currentTime) {
        if (startTime === null) startTime = currentTime;
        const timeElapsed = currentTime - startTime;
        const run = easeInOutQuad(timeElapsed, startPosition, distance, duration);
        window.scrollTo(0, run);
        if (timeElapsed < duration) requestAnimationFrame(animation);
    }

    // Easing function for smooth animation
    function easeInOutQuad(t, b, c, d) {
        t /= d / 2;
        if (t < 1) return c / 2 * t * t + b;
        t--;
        return -c / 2 * (t * (t - 2) - 1) + b;
    }

    requestAnimationFrame(animation);
}

function initCyclingText() {
    const games = ['Valorant', 'Rivals', 'OW2'];
    const element = document.getElementById('cycling-game');
    let currentIndex = 0;

    function cycleText() {
        element.style.opacity = '0';
        element.style.transform = 'translateY(15px)';

        setTimeout(() => {
            currentIndex = (currentIndex + 1) % games.length;
            element.textContent = games[currentIndex];
            
            element.style.transition = 'none';
            element.style.transform = 'translateY(-15px)';
            element.style.opacity = '0';
            
            setTimeout(() => {
                element.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, 50);
        }, 500);
    }

    setInterval(cycleText, 5000);
}

document.addEventListener('DOMContentLoaded', function () {
    window.addEventListener('scroll', handleNavbarScroll);
    initFAQ();
    initCyclingText();
    initSmoothScrolling();

    new CanvasAnimation('canvas1', 'floating');
    new CanvasAnimation('canvas2', 'wave');
    new CanvasAnimation('canvas3', 'pulse');
    new CanvasAnimation('canvas4', 'flow');
    
    checkAuthAndUpdateNav();
    initScrollAnimations();
});

// Initialize scroll-triggered animations
function initScrollAnimations() {
    const animateObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                animateObserver.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    // Observe detection container
    const detectionContainer = document.querySelector('.detection-container');
    if (detectionContainer) {
        animateObserver.observe(detectionContainer);
    }
    
    // Observe all sections
    const sections = document.querySelectorAll('section');
    sections.forEach(section => {
        animateObserver.observe(section);
    });
    
    // Observe FAQ section
    const faq = document.querySelector('.faq');
    if (faq) {
        animateObserver.observe(faq);
    }
    
    // Observe footer
    const footer = document.querySelector('.footer');
    if (footer) {
        animateObserver.observe(footer);
    }
    
    // Observe product cards individually
    const productCards = document.querySelectorAll('.product-card');
    productCards.forEach(card => {
        animateObserver.observe(card);
    });
}

async function checkAuthAndUpdateNav() {
    try {
        const supabaseUrl = 'https://grmihsppmbipapiwllau.supabase.co';
        const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdybWloc3BwbWJpcGFwaXdsbGF1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY2NzY0MTUsImV4cCI6MjA3MjI1MjQxNX0.d_lqYj5CiCHb9pQLN8UypaQnkS07FoBmDVMvGKhTxkk';
        const { createClient } = supabase;
        const supabaseClient = createClient(supabaseUrl, supabaseKey);
        
        const { data: { user } } = await supabaseClient.auth.getUser();
        const authLink = document.getElementById('auth-link');
        
        if (user) {
            authLink.textContent = 'Dashboard';
            authLink.href = 'dashboard/dashboard.html';
        } else {
            authLink.textContent = 'Dashboard';
            authLink.href = 'dashboard/login.html';
        }
    } catch (error) {
        console.error('Auth check error:', error);
        const authLink = document.getElementById('auth-link');
        authLink.textContent = 'Dashboard';
        authLink.href = 'dashboard/login.html';
    }
}



// Demo UI State
let isRunning = false;

// Demo UI Elements
const delaySlider = document.getElementById('delaySlider');
const delayValue = document.getElementById('delayValue');
const toleranceSlider = document.getElementById('toleranceSlider');
const toleranceValue = document.getElementById('toleranceValue');
const burstSlider = document.getElementById('burstSlider');
const burstValue = document.getElementById('burstValue');
const fovXSlider = document.getElementById('fovXSlider');
const fovXValue = document.getElementById('fovXValue');
const fovYSlider = document.getElementById('fovYSlider');
const fovYValue = document.getElementById('fovYValue');
const fovBox = document.getElementById('fovBox');
const fovDisplay = document.getElementById('fovDisplay');
const bindButton = document.getElementById('bindButton');
const bindModal = document.getElementById('bindModal');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const statusIndicator = document.getElementById('statusIndicator');
const statusText = document.getElementById('statusText');
const statusSubtext = document.getElementById('statusSubtext');

// Slider Updates
if (delaySlider) {
    delaySlider.addEventListener('input', (e) => {
        delayValue.textContent = e.target.value;
    });
}

if (toleranceSlider) {
    toleranceSlider.addEventListener('input', (e) => {
        toleranceValue.textContent = e.target.value;
    });
}

if (burstSlider) {
    burstSlider.addEventListener('input', (e) => {
        burstValue.textContent = e.target.value;
    });
}


// Bind Button Modal
if (bindButton && bindModal) {
    bindButton.addEventListener('click', () => {
        bindModal.classList.add('show');
    });
}

function closeDemoModal() {
    if (bindModal) {
        bindModal.classList.remove('show');
    }
}

if (bindModal) {
    bindModal.addEventListener('click', (e) => {
        if (e.target === bindModal) {
            closeDemoModal();
        }
    });
}

// Draggable Window Functionality
const demoWindow = document.getElementById('demoWindow');
const windowTitlebar = document.getElementById('windowTitlebar');
let isDragging = false;
let currentX;
let currentY;
let initialX;
let initialY;

if (windowTitlebar) {
    windowTitlebar.addEventListener('mousedown', (e) => {
        if (e.target.classList.contains('window-close-btn')) return;
        isDragging = true;
        initialX = e.clientX - demoWindow.offsetLeft;
        initialY = e.clientY - demoWindow.offsetTop;
        windowTitlebar.style.cursor = 'grabbing';
    });
}

document.addEventListener('mousemove', (e) => {
    if (isDragging && demoWindow) {
        currentX = e.clientX - initialX;
        currentY = e.clientY - initialY;
        demoWindow.style.left = currentX + 'px';
        demoWindow.style.top = currentY + 'px';
    }
});

document.addEventListener('mouseup', () => {
    isDragging = false;
    if (windowTitlebar) {
        windowTitlebar.style.cursor = 'grab';
    }
});

// Close button functionality
const closeBtn = document.querySelector('.window-close-btn');
if (closeBtn) {
    closeBtn.addEventListener('click', () => {
        demoWindow.style.display = 'none';
    });
}


    // Opening animation functionality
    window.addEventListener('load', function() {
        const overlay = document.getElementById('openingOverlay');
        const isMobile = window.innerWidth <= 768;
        
        // Check if user has scrolled more than 5% of page height
        const scrollPercentage = (window.scrollY / document.documentElement.scrollHeight) * 100;
        
        if (scrollPercentage > 5) {
            // Skip animation if already scrolled down more than 5%
            overlay.remove();
            return;
        }
        
        // Mobile: 0.6s icon + 0.6s text + 1s wait + 0.5s fade elements + 0.5s fade overlay = 3.2s total
        // Desktop: keep original 2.75s timing
        const animationDuration = isMobile ? 2600 : 2750;
        
        setTimeout(function() {
            overlay.classList.add('fade-out');
            
            setTimeout(function() {
                overlay.remove();
            }, isMobile ? 500 : 800);
        }, animationDuration); 
    });

    document.addEventListener('DOMContentLoaded', function() {
        const notification = document.getElementById('notificationPopup');
        const closeBtn = document.getElementById('closeNotification');
        const isMobile = window.innerWidth <= 768;
        
        const modalAnimationDuration = isMobile ? 2600 : 2750; // Based on opening animation
        const notificationDelay = modalAnimationDuration + 1000; // Add a small buffer

        setTimeout(function() {
            notification.classList.add('show');
        }, notificationDelay);
        
        // Close notification on button click
        closeBtn.addEventListener('click', function() {
            notification.classList.remove('show');
            notification.classList.add('hide');
        });
        
        // Auto-hide after 10 seconds (optional)
        setTimeout(function() {
            if (notification.classList.contains('show')) {
                notification.classList.remove('show');
                notification.classList.add('hide');
            }
        }, notificationDelay + 8000);

        // Lazy load video - only play when visible
        const video = document.getElementById('demoVideo');
        if (video) {
            const videoObserver = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        video.play();
                    } else {
                        video.pause();
                    }
                });
            }, {
                threshold: 0.5 // Play when 50% of video is visible
            });
            
            videoObserver.observe(video);
        }
    });

    // Simple hover animation removed - using CSS only

// Function to generate a random string of specified length
function generateRandomString(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

// Function to check if element is in viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Function to animate SHA-256 hashing effect (showing only 6 characters)
function animateSHA256(element, callback) {
    const chars = '0123456789abcdef';
    let iterations = 0;
    const maxIterations = 8;
    const interval = 100;
    
    const originalText = element.textContent;
    const intervalId = setInterval(() => {
        let newHash = '';
        for (let i = 0; i < 6; i++) {  // Only generate 6 characters
            newHash += chars[Math.floor(Math.random() * chars.length)];
        }
        element.textContent = newHash;
        
        iterations++;
        if (iterations >= maxIterations) {
            clearInterval(intervalId);
            element.textContent = originalText;
            if (callback) callback();
        }
    }, interval);
}

// Function to animate file identifiers
function animateFileIdentifiers(element, callback) {
    const prefixes = ['PID_', 'FID_','UID_'];
    let iterations = 0;
    const maxIterations = 8;
    const interval = 100;
    
    const originalText = element.textContent;
    const intervalId = setInterval(() => {
        const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        let id = prefix;
        for (let i = 0; i < 4; i++) {
            id += Math.floor(Math.random() * 5);
        }
        element.textContent = id;
        
        iterations++;
        if (iterations >= maxIterations) {
            clearInterval(intervalId);
            element.textContent = originalText;
            if (callback) callback();
        }
    }, interval);
}

// Function to update shield appearance
function updateShieldColor(color, glowColor) {
    const shield = document.querySelector('.shield-icon');
    if (!shield) return;
    
    // Animate the color change
    shield.style.transition = 'all 0.5s ease';
    shield.style.background = color;
    shield.style.boxShadow = `0 0 0 1px ${color}, 0 0 15px ${glowColor || color}80`;
}

// Function to show shield with fade-in effect
function showShield() {
    const shield = document.querySelector('.shield-icon');
    if (!shield) return;
    
    // Make visible and fade in
    shield.style.visibility = 'visible';
    shield.style.opacity = '1';
}

// Function to check off an item in the checklist
function checkOffItem(index, callback) {
    const items = document.querySelectorAll('.checklist-item');
    if (index >= items.length) {
        if (callback) callback();
        return;
    }
    
    const item = items[index];
    const circle = item.querySelector('.check-circle');
    
    // Animate item appearance
    item.style.opacity = '1';
    item.style.transform = 'translateX(0)';
    
    // Animate circle fill
    setTimeout(() => {
        // Create fill circle
        const fill = document.createElement('div');
        fill.style.position = 'absolute';
        fill.style.top = '0';
        fill.style.left = '0';
        fill.style.width = '100%';
        fill.style.height = '100%';
        fill.style.background = '#10b981';
        fill.style.borderRadius = '50%';
        fill.style.opacity = '0';
        fill.style.transform = 'scale(0.5)';
        fill.style.transition = 'all 0.3s ease-out';
        
        // Add checkmark inside the fill
        fill.innerHTML = `
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -60%) rotate(-45deg);
                        width: 8px; height: 4px; border: 2px solid white; border-top: none; border-right: none;
                        opacity: 0; transition: opacity 0.2s ease-out 0.2s;"></div>
        `;
        
        circle.appendChild(fill);
        
        // Animate fill in
        requestAnimationFrame(() => {
            fill.style.opacity = '1';
            fill.style.transform = 'scale(1)';
            circle.style.borderColor = '#10b981';
            
            // Show checkmark after fill animation
            setTimeout(() => {
                const checkmark = fill.querySelector('div');
                checkmark.style.opacity = '1';
                
                // Handle specific item actions
                const textElement = item.querySelector('span');
                const next = () => checkOffItem(index + 1, callback);
                
                if (index === 0) { // First check - File Name
                    // Already handled in startAnimation
                    setTimeout(next, 300);
                } else if (index === 1) { // Second check - SHA-256
                    animateSHA256(textElement, () => {
                        // Show yellow shield after SHA-256 check
                        showShield();
                        next();
                    });
                } else if (index === 2) { // Third check - Others
                    animateFileIdentifiers(textElement, () => {
                        // Change shield from yellow to green after Others check
                        updateShieldColor('#10b981', '#10b981');
                        // Update the randomization status text
                        const statusText = document.querySelector('#randomizationChecklist h3');
                        if (statusText) {
                            statusText.textContent = 'Randomized';
                        }
                        if (callback) callback();
                    });
                } else {
                    setTimeout(next, 300);
                }
            }, 200);
        });
    }, 300);
}

// Function to add shield icon
function addShieldIcon() {
    const container = document.querySelector('.exe-icon-container');
    if (!container) return;
    
    const shield = document.createElement('div');
    shield.innerHTML = `
        <div style="position: absolute; top: -10px; right: -10px; background: #10b981; 
                    width: 28px; height: 28px; border-radius: 50%; display: flex; 
                    align-items: center; justify-content: center; z-index: 3;
                    animation: popIn 0.5s cubic-bezier(0.68, -0.55, 0.27, 1.55) forwards;">
            <i class="fas fa-shield-alt" style="color: white; font-size: 14px;"></i>
        </div>
    `;
    container.style.position = 'relative';
    container.appendChild(shield);
}

// Function to handle the animation
function startAnimation() {
    const element = document.getElementById('exeFileName');
    const checklist = document.getElementById('randomizationChecklist');
    
    if (!element || !checklist) {
        console.error('Required elements not found');
        return;
    }

    // Start with synthar.exe
    element.style.transition = 'all 0.3s ease';
    element.textContent = 'synthar.exe';
    
    // Show the checklist
    setTimeout(() => {
        checklist.style.opacity = '1';
        checklist.style.transform = 'translateX(0)';
        
        // Start the animation sequence after a short delay
        setTimeout(() => {
            // First, randomize the filename
            const randomString = generateRandomString(5) + '.exe';
            element.style.opacity = '0.5';
            
            setTimeout(() => {
                element.textContent = randomString;
                element.style.opacity = '1';
                
                // Start the checklist animation after filename changes
                setTimeout(() => {
                    checkOffItem(0, () => {
                        console.log('All checks completed');
                    });
                }, 300);
            }, 300);
        }, 500);
    }, 100);
}

// Run the animation when the page loads and element is in view
document.addEventListener('DOMContentLoaded', function() {
    const element = document.getElementById('exeFileName');
    if (!element) return;
    
    // Show shield immediately
    const shieldIcon = document.querySelector('.shield-icon');
    if (shieldIcon) {
        shieldIcon.style.opacity = '1';
        shieldIcon.style.visibility = 'visible';
    }
    
    // Start animation if element is already in view
    if (isInViewport(element)) {
        startAnimation();
    } else {
        // Or wait until it comes into view
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                startAnimation();
                observer.disconnect();
            }
        });
        observer.observe(element);
    }
});