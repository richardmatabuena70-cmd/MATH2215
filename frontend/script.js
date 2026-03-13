// Login and Register logic with Database API
// Purpose: Handle form switching and user authentication with validation

// Rate limiting for login attempts
let loginAttempts = 0;
const MAX_LOGIN_ATTEMPTS = 5;
let loginLockoutTime = 0;

// Sound Effects Manager using Web Audio API
const SoundManager = {
  audioContext: null,
  initialized: false,
  
  init() {
    if (!this.audioContext) {
      try {
        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      } catch (e) {
        console.warn('Web Audio API not supported');
        return false;
      }
    }
    // Resume if suspended (required by browsers for autoplay policy)
    if (this.audioContext.state === 'suspended') {
      this.audioContext.resume().catch(err => {
        console.warn('Failed to resume audio context:', err);
      });
    }
    this.initialized = true;
    return true;
  },
  
  playTone(frequency, duration, type = 'sine', volume = 0.3) {
    if (!this.init()) return;
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      oscillator.frequency.value = frequency;
      oscillator.type = type;
      gainNode.gain.value = volume;
      
      oscillator.start();
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + duration);
      oscillator.stop(this.audioContext.currentTime + duration);
    } catch (e) {
      console.warn('Error playing tone:', e);
    }
  },
  
  playUIClick() {
    if (!this.init()) return;
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      // Frequency sweep for a elegant "tap" effect
      oscillator.frequency.setValueAtTime(800, this.audioContext.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(600, this.audioContext.currentTime + 0.04);
      oscillator.type = 'sine';
      
      // Quick attack and decay
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.15, this.audioContext.currentTime + 0.005);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.04);
      
      oscillator.start();
      oscillator.stop(this.audioContext.currentTime + 0.04);
    } catch (e) {
      console.warn('Error playing UI click:', e);
    }
  },
  
  playSidebarClick() {
    if (!this.init()) return;
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      // Quick frequency bump for navigation feel
      oscillator.frequency.setValueAtTime(500, this.audioContext.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(400, this.audioContext.currentTime + 0.06);
      oscillator.type = 'sine';
      
      // Clean click envelope
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.2, this.audioContext.currentTime + 0.005);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.06);
      
      oscillator.start();
      oscillator.stop(this.audioContext.currentTime + 0.06);
    } catch (e) {
      console.warn('Error playing sidebar click:', e);
    }
  }
};

// Global UI Click Sound - plays on any click
document.addEventListener('click', function(e) {
  // Don't play on form submit buttons (they have their own actions)
  if (e.target.tagName === 'BUTTON' && e.target.type === 'submit') {
    return;
  }
  SoundManager.playUIClick();
}, true);

// Wait for DOM loaded
document.addEventListener("DOMContentLoaded", () => {
  // Check if user is already logged in - redirect to dashboard
  if (api.isAuthenticated()) {
    window.location.href = "dashboard.html";
    return;
  }

  // Get form elements
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const formTitle = document.getElementById("formTitle");
  const errorMessage = document.getElementById("errorMessage");

  // Get login inputs
  const loginEmail = document.getElementById("loginEmail");
  const loginPassword = document.getElementById("loginPassword");

  // Get register inputs
  const regName = document.getElementById("regName");
  const regEmail = document.getElementById("regEmail");
  const regPassword = document.getElementById("regPassword");
  const regConfirm = document.getElementById("regConfirm");

  // Show register form
  window.showRegister = function () {
    loginForm.classList.add("hidden");
    registerForm.classList.remove("hidden");
    formTitle.textContent = "Register";
    clearError();
  };

  // Show login form
  window.showLogin = function () {
    registerForm.classList.add("hidden");
    restoreForm.classList.add("hidden");
    loginForm.classList.remove("hidden");
    formTitle.textContent = "Login";
    clearError();
  };

  // Show restore form
  window.showRestore = function () {
    loginForm.classList.add("hidden");
    registerForm.classList.add("hidden");
    restoreForm.classList.remove("hidden");
    formTitle.textContent = "Restore Account";
    clearError();
  };

  // Helper function to show error
  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
  }

  // Helper function to clear error
  function clearError() {
    errorMessage.textContent = '';
    errorMessage.style.display = 'none';
  }

  // Helper function to validate email format
  function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Helper function to validate name format
  function isValidName(name) {
    const nameRegex = /^[a-zA-Z\s]{2,50}$/;
    return nameRegex.test(name);
  }

  // Helper function to validate password strength
  function isStrongPassword(password) {
    // At least 4 characters, one uppercase, one lowercase, one number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{4,50}$/;
    return passwordRegex.test(password);
  }

  // Register form submit
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    // Get values
    const name = regName.value.trim();
    const email = regEmail.value.trim().toLowerCase();
    const password = regPassword.value;
    const confirmPassword = regConfirm.value;

    // Frontend validation
    if (!name) {
      showError("Name is required");
      return;
    }

    if (!isValidName(name)) {
      showError("Name must be 2-50 letters only");
      return;
    }

    if (!email) {
      showError("Email is required");
      return;
    }

    if (!isValidEmail(email)) {
      showError("Please enter a valid email address");
      return;
    }

    if (!password) {
      showError("Password is required");
      return;
    }

    if (password.length < 4 || password.length > 50) {
      showError("Password must be 4-50 characters");
      return;
    }

    if (!isStrongPassword(password)) {
      showError("Password must contain uppercase, lowercase, and number");
      return;
    }

    if (password !== confirmPassword) {
      showError("Passwords do not match");
      return;
    }

    // Check if email contains spaces
    if (email.includes(' ')) {
      showError("Email cannot contain spaces");
      return;
    }

    try {
      // Disable form during submission
      const submitBtn = registerForm.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = "Creating Account...";

      const result = await api.register(name, email, password);
      
      if (result.success) {
        alert("Account created successfully! Please login.");
        showLogin();
        registerForm.reset();
      }
    } catch (error) {
      showError(error.message || "Registration failed. Email may already be registered.");
    } finally {
      const submitBtn = registerForm.querySelector('button[type="submit"]');
      submitBtn.disabled = false;
      submitBtn.textContent = "Create Account";
    }
  });

  // Login form submit
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    // Check if locked out
    const now = Date.now();
    if (loginLockoutTime > now) {
      const remainingTime = Math.ceil((loginLockoutTime - now) / 1000);
      showError(`Too many failed attempts. Try again in ${remainingTime} seconds.`);
      return;
    }

    // Get values
    const email = loginEmail.value.trim().toLowerCase();
    const password = loginPassword.value;

    // Frontend validation
    if (!email) {
      showError("Email is required");
      return;
    }

    if (!password) {
      showError("Password is required");
      return;
    }

    try {
      // Disable form during submission
      const submitBtn = loginForm.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = "Logging in...";

      const result = await api.login(email, password);
      
      if (result.success) {
        // Reset login attempts on successful login
        loginAttempts = 0;
        window.location.href = "dashboard.html";
      }
    } catch (error) {
      loginAttempts++;
      
      if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        loginLockoutTime = now + (60 * 1000); // Lockout for 1 minute
        showError(`Too many failed attempts. Account locked for 1 minute.`);
      } else {
        const remainingAttempts = MAX_LOGIN_ATTEMPTS - loginAttempts;
        showError(`Invalid credentials. ${remainingAttempts} attempts remaining.`);
      }
    } finally {
      const submitBtn = loginForm.querySelector('button[type="submit"]');
      submitBtn.disabled = false;
      submitBtn.textContent = "Login";
    }
  });

  // Restore form submit
  restoreForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    // Get values
    const email = restoreEmail.value.trim().toLowerCase();
    const password = restorePassword.value;

    // Frontend validation
    if (!email) {
      showError("Email is required");
      return;
    }

    if (!password) {
      showError("Password is required");
      return;
    }

    try {
      // Disable form during submission
      const submitBtn = restoreForm.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = "Restoring...";

      const result = await api.restoreAccount(email, password);
      
      if (result.success) {
        alert("Account restored successfully!");
        window.location.href = "dashboard.html";
      }
    } catch (error) {
      showError(error.message || "Failed to restore account. Please check your credentials.");
    } finally {
      const submitBtn = restoreForm.querySelector('button[type="submit"]');
      submitBtn.disabled = false;
      submitBtn.textContent = "♻️ Restore & Login";
    }
  });
});

// Generate floating math symbols background
function createFloatingMathSymbols() {
  const container = document.getElementById('mathSymbolsBg');
  if (!container) return;
  
  const symbols = [
    '∑', '∏', '∫', '√', '∞', 'π', '×', '÷', '±', '≠', 
    '≈', '≡', '⊂', '⊃', '∪', '∩', '∀', '∃', '∂', '∇',
    '∈', '∉', '∅', 'ℕ', 'ℤ', 'ℚ', 'ℝ', 'ℂ', '°', '‰',
    'ⁿ', '²', '³', '⁻¹', '⁺', '⁰', '¹', '⁴', '⁵', '⁶',
    'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ', 'λ', 'μ',
    'φ', 'ψ', 'ω', 'Γ', 'Δ', 'Θ', 'Λ', 'Π', 'Σ', 'Ω',
    'dx', 'dy', 'dz', 'dt', 'df', 'sin', 'cos', 'tan',
    'log', 'ln', 'exp', 'lim', 'max', 'min', 'sup', 'inf'
  ];
  
  const numSymbols = 40;
  
  for (let i = 0; i < numSymbols; i++) {
    const symbol = document.createElement('span');
    symbol.className = 'math-symbol';
    symbol.textContent = symbols[Math.floor(Math.random() * symbols.length)];
    symbol.style.left = Math.random() * 100 + '%';
    symbol.style.setProperty('--delay', (Math.random() * 25) + 's');
    symbol.style.fontSize = (Math.random() * 24 + 14) + 'px';
    symbol.style.animationDuration = (Math.random() * 20 + 20) + 's';
    symbol.style.opacity = Math.random() * 0.15 + 0.05;
    container.appendChild(symbol);
  }
}

// Generate particles
function createParticles() {
  const container = document.getElementById('particles');
  if (!container) return;
  
  const numParticles = 50;
  
  for (let i = 0; i < numParticles; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.setProperty('--delay', (Math.random() * 15) + 's');
    particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
    container.appendChild(particle);
  }
}

// Generate geometric shapes
function createGeometricShapes() {
  const container = document.getElementById('geometricShapes');
  if (!container) return;
  
  const shapes = ['circle', 'square', 'triangle'];
  const numShapes = 15;
  
  for (let i = 0; i < numShapes; i++) {
    const shape = document.createElement('div');
    shape.className = 'shape ' + shapes[Math.floor(Math.random() * shapes.length)];
    shape.style.left = Math.random() * 100 + '%';
    shape.style.setProperty('--delay', (Math.random() * 30) + 's');
    shape.style.animationDuration = (Math.random() * 20 + 25) + 's';
    container.appendChild(shape);
  }
}

// Mouse trail effect
function createMouseTrail() {
  const container = document.getElementById('mouseTrail');
  if (!container) return;
  
  document.addEventListener('mousemove', (e) => {
    const dot = document.createElement('div');
    dot.className = 'trail-dot';
    dot.style.left = e.clientX + 'px';
    dot.style.top = e.clientY + 'px';
    container.appendChild(dot);
    
    setTimeout(() => dot.remove(), 1000);
  });
}

// Initialize all background effects
function initBackgroundEffects() {
  createFloatingMathSymbols();
  createParticles();
  createGeometricShapes();
  createMouseTrail();
}

// Initialize on load
document.addEventListener('DOMContentLoaded', initBackgroundEffects);
