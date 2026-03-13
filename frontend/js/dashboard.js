// Global variables
let currentUser = null;
let currentQuizData = [];
let timerInterval = null;
let timeRemaining = 0;
let totalTimeRemaining = 0; // Track total remaining time
let lastGameTimeRemaining = 0; // Store last game's remaining time
let lastGameDifficulty = ''; // Store last game's difficulty
let currentScore = 0;
let currentAccuracy = 0;
let totalQuestions = 0;
let answeredQuestions = 0;
let questionsAnswered = [];
let userAnswers = [];
let currentDifficulty = 'easy';

// Stop the quiz and reset all quiz variables
function stopQuiz(clearAllData = false) {
  clearInterval(timerInterval);
  timerInterval = null;
  currentQuizData = [];
  timeRemaining = 0;
  totalTimeRemaining = 0;
  currentScore = 0;
  totalQuestions = 0;
  answeredQuestions = 0;
  questionsAnswered = [];
  userAnswers = [];
  currentDifficulty = 'easy';
  
  // Clear sessionStorage - only clear if starting new game
  if (clearAllData) {
    sessionStorage.removeItem('currentQuiz');
    sessionStorage.removeItem('userAnswers');
    sessionStorage.removeItem('totalTimeRemaining');
    sessionStorage.removeItem('difficulty');
    sessionStorage.removeItem('currentQuestionIndex');
    sessionStorage.removeItem('timeRemaining');
    sessionStorage.removeItem('quizData');
    sessionStorage.removeItem('totalTimeLeft');
  }
}

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
  
  playCorrect() {
    // High pitched pleasant "ding"
    this.playTone(880, 0.15, 'sine', 0.3);
    setTimeout(() => this.playTone(1100, 0.2, 'sine', 0.3), 100);
  },
  
  playWrong() {
    // Low pitched buzz
    this.playTone(150, 0.3, 'sawtooth', 0.3);
  },
  
  playClick() {
    // Soft click sound
    this.playTone(400, 0.05, 'sine', 0.2);
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
  },
  
  playTick() {
    // Soft tick for timer
    this.playTone(600, 0.03, 'sine', 0.1);
  },
  
  playGameOver() {
    // Descending tones for game over
    this.playTone(400, 0.2, 'square', 0.2);
    setTimeout(() => this.playTone(350, 0.2, 'square', 0.2), 200);
    setTimeout(() => this.playTone(300, 0.2, 'square', 0.2), 400);
    setTimeout(() => this.playTone(250, 0.4, 'square', 0.2), 600);
  },
  
  playVictory() {
    // Ascending victory tones
    this.playTone(523, 0.15, 'sine', 0.3);
    setTimeout(() => this.playTone(659, 0.15, 'sine', 0.3), 150);
    setTimeout(() => this.playTone(784, 0.15, 'sine', 0.3), 300);
    setTimeout(() => this.playTone(1047, 0.3, 'sine', 0.3), 450);
  }
};

// Global UI Click Sound - plays on any click
document.addEventListener('click', function(e) {
  // Don't play on game answer buttons (they have their own sounds)
  if (e.target.tagName === 'BUTTON' && 
      (e.target.classList.contains('answer-btn') || 
       e.target.id === 'submitAnswer' ||
       e.target.type === 'submit')) {
    return;
  }
  
  // Play appropriate sound based on button type
  if (e.target.classList.contains('level-btn') || 
      e.target.classList.contains('action-btn') ||
      e.target.id === 'startQuiz' || 
      e.target.id === 'restartQuiz' ||
      e.target.textContent.match(/^(Easy|Medium|Hard)$/)) {
    SoundManager.playSidebarClick();
  } else {
    SoundManager.playUIClick();
  }
}, true);

// Sidebar buttons sound effect - ensures all sidebar buttons play sidebar click sound
document.addEventListener('DOMContentLoaded', function() {
  const sidebar = document.getElementById('sidebar');
  if (sidebar) {
    sidebar.addEventListener('click', function(e) {
      if (e.target.tagName === 'BUTTON') {
        SoundManager.playSidebarClick();
      }
    }, true);
  }
});

// Theme Toggle
function toggleTheme() {
  const body = document.body;
  const themeToggle = document.getElementById('themeToggle');
  const themeLabel = document.getElementById('themeLabel');
  
  if (themeToggle.checked) {
    body.classList.add('light-theme');
    body.classList.remove('dark-theme');
    themeLabel.textContent = 'Light Mode';
  } else {
    body.classList.remove('light-theme');
    body.classList.add('dark-theme');
    themeLabel.textContent = 'Dark Mode';
  }
  
  localStorage.setItem('theme', themeToggle.checked ? 'light' : 'dark');
}

// Load theme preference
function loadTheme() {
  const themeToggle = document.getElementById('themeToggle');
  const themeLabel = document.getElementById('themeLabel');
  const savedTheme = localStorage.getItem('theme');
  
  if (savedTheme === 'light') {
    themeToggle.checked = true;
    document.body.classList.add('light-theme');
    themeLabel.textContent = 'Light Mode';
  } else {
    themeToggle.checked = false;
    document.body.classList.add('dark-theme');
    themeLabel.textContent = 'Dark Mode';
  }
}

// Toggle Sidebar
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
}

// Check login status
async function checkLoginStatus() {
  const token = localStorage.getItem('token');
  const userId = localStorage.getItem('userId');
  
  if (!token || !userId) {
    window.location.href = 'index.html';
    return;
  }
  
  try {
    const response = await fetch(`/api/users/${userId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('User not found');
    }
    
    const user = await response.json();
    currentUser = user;
    loadTheme();
  } catch (error) {
    console.error('Login check failed:', error);
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    sessionStorage.clear();
    window.location.href = 'index.html';
  }
}

// Logout
function logout() {
  // Clear all quiz data from sessionStorage
  sessionStorage.clear();
  
  localStorage.removeItem('token');
  localStorage.removeItem('userId');
  window.location.href = 'index.html';
}

// Show Achievements
async function showAchievements() {
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  main.innerHTML = '<h1>🏅 Your Achievements</h1><div class="loading">Loading achievements...</div>';
  
  try {
    const response = await fetch('/api/achievements', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) throw new Error('Failed to load achievements');
    
    const achievements = await response.json();
    const earnedCount = achievements.filter(a => a.earned).length;
    
    main.innerHTML = `
      <h1>🏅 Your Achievements</h1>
      <div class="achievement-stats">
        <div class="stat-box">
          <span class="stat-number">${earnedCount}</span>
          <span class="stat-label">Earned</span>
        </div>
        <div class="stat-box">
          <span class="stat-number">${achievements.length}</span>
          <span class="stat-label">Total</span>
        </div>
      </div>
      <div class="achievements-grid">
        ${achievements.map(a => `
          <div class="achievement-card ${a.earned ? 'earned' : 'locked'}">
            <div class="achievement-icon">${a.earned ? a.icon : '🔒'}</div>
            <div class="achievement-info">
              <h3>${a.name}</h3>
              <p>${a.description}</p>
              <span class="achievement-points">+${a.points} pts</span>
            </div>
            ${a.earned ? `<div class="achievement-badge">✓</div>` : ''}
          </div>
        `).join('')}
      </div>
      <style>
        .achievement-stats {
          display: flex;
          justify-content: center;
          gap: 40px;
          margin: 20px 0 30px;
        }
        .stat-box {
          background: rgba(255,255,255,0.1);
          padding: 20px 40px;
          border-radius: 15px;
          text-align: center;
        }
        .stat-number {
          display: block;
          font-size: 2.5rem;
          font-weight: bold;
          color: #00d9ff;
        }
        .stat-label {
          color: #aaa;
        }
        .achievements-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
          gap: 20px;
        }
        .achievement-card {
          background: rgba(255,255,255,0.05);
          border-radius: 15px;
          padding: 20px;
          display: flex;
          align-items: center;
          gap: 15px;
          position: relative;
          border: 2px solid transparent;
          transition: all 0.3s;
        }
        .achievement-card.earned {
          border-color: #10b981;
          background: rgba(16, 185, 129, 0.1);
        }
        .achievement-card.locked {
          opacity: 0.5;
        }
        .achievement-icon {
          font-size: 2.5rem;
          width: 60px;
          height: 60px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(255,255,255,0.1);
          border-radius: 50%;
        }
        .achievement-info h3 {
          margin: 0 0 5px;
          color: #fff;
        }
        .achievement-info p {
          margin: 0 0 8px;
          color: #aaa;
          font-size: 0.9rem;
        }
        .achievement-points {
          background: linear-gradient(135deg, #f59e0b, #ef4444);
          padding: 3px 10px;
          border-radius: 20px;
          font-size: 0.8rem;
          font-weight: bold;
        }
        .achievement-badge {
          position: absolute;
          top: 10px;
          right: 10px;
          background: #10b981;
          color: white;
          width: 24px;
          height: 24px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 0.8rem;
        }
      </style>
    `;
  } catch (error) {
    main.innerHTML = `<h1>🏅 Achievements</h1><p class="error">Failed to load achievements</p>`;
  }
}

// Show Statistics
async function showStats() {
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  main.innerHTML = '<h1>📊 My Statistics</h1><div class="loading">Loading statistics...</div>';
  
  try {
    const response = await fetch('/api/stats', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) throw new Error('Failed to load stats');
    
    const stats = await response.json();
    const accuracy = stats.total_questions > 0 
      ? Math.round((stats.total_correct / stats.total_questions) * 100) 
      : 0;
    
    main.innerHTML = `
      <h1>📊 My Statistics</h1>
      
      <div class="stats-container">
        <!-- Overview Section -->
        <div class="stats-section">
          <div class="stats-section-header">
            <span class="section-icon">📋</span>
            <span class="section-title">Overview</span>
          </div>
          <div class="stats-grid">
            <div class="stat-card primary">
              <div class="stat-icon">🎮</div>
              <div class="stat-info">
                <span class="stat-value">${stats.total_games || 0}</span>
                <span class="stat-name">Games Played</span>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-icon">📝</div>
              <div class="stat-info">
                <span class="stat-value">${stats.total_questions || 0}</span>
                <span class="stat-name">Total Questions</span>
              </div>
            </div>
            <div class="stat-card gold">
              <div class="stat-icon">🏆</div>
              <div class="stat-info">
                <span class="stat-value">${stats.highest_score || 0}</span>
                <span class="stat-name">High Score</span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Performance Section -->
        <div class="stats-section">
          <div class="stats-section-header">
            <span class="section-icon">🎯</span>
            <span class="section-title">Performance</span>
          </div>
          <div class="stats-grid">
            <div class="stat-card cyan">
              <div class="stat-icon">📊</div>
              <div class="stat-info">
                <span class="stat-value">${accuracy}%</span>
                <span class="stat-name">Accuracy</span>
              </div>
            </div>
            <div class="stat-card green">
              <div class="stat-icon">✓</div>
              <div class="stat-info">
                <span class="stat-value">${stats.total_correct || 0}</span>
                <span class="stat-name">Correct</span>
              </div>
            </div>
            <div class="stat-card red">
              <div class="stat-icon">✗</div>
              <div class="stat-info">
                <span class="stat-value">${(stats.total_questions || 0) - (stats.total_correct || 0)}</span>
                <span class="stat-name">Wrong</span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Streaks Section -->
        <div class="stats-section">
          <div class="stats-section-header">
            <span class="section-icon">🔥</span>
            <span class="section-title">Streaks</span>
          </div>
          <div class="stats-grid half">
            <div class="stat-card fire">
              <div class="stat-icon">🔥</div>
              <div class="stat-info">
                <span class="stat-value">${stats.current_streak || 0}</span>
                <span class="stat-name">Current</span>
              </div>
            </div>
            <div class="stat-card purple">
              <div class="stat-icon">⭐</div>
              <div class="stat-info">
                <span class="stat-value">${stats.longest_streak || 0}</span>
                <span class="stat-name">Best</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <style>
        .stats-container { display: flex; flex-direction: column; gap: 25px; margin-top: 30px; }
        .stats-section { background: rgba(255,255,255,0.02); border-radius: 20px; padding: 25px; border: 1px solid rgba(255,255,255,0.05); }
        .stats-section-header { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .section-icon { font-size: 1.5rem; }
        .section-title { font-size: 1.1rem; font-weight: 600; color: #fff; text-transform: uppercase; letter-spacing: 1px; }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .stats-grid.half { grid-template-columns: repeat(2, 1fr); max-width: 500px; }
        .stat-card { background: rgba(255,255,255,0.05); border-radius: 16px; padding: 25px; display: flex; align-items: center; gap: 15px; border: 1px solid rgba(255,255,255,0.1); transition: transform 0.3s, box-shadow 0.3s; }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .stat-card.primary { background: linear-gradient(135deg, rgba(99, 102, 241, 0.3), rgba(139, 92, 246, 0.3)); border-color: #6366f1; }
        .stat-card.gold { background: linear-gradient(135deg, rgba(234, 179, 8, 0.3), rgba(234, 179, 8, 0.2)); border-color: #eab308; }
        .stat-card.fire { background: linear-gradient(135deg, rgba(245, 158, 11, 0.3), rgba(239, 68, 68, 0.3)); border-color: #f59e0b; }
        .stat-card.cyan { background: linear-gradient(135deg, rgba(6, 182, 212, 0.3), rgba(6, 182, 212, 0.2)); border-color: #06b6d4; }
        .stat-card.green { background: linear-gradient(135deg, rgba(16, 185, 129, 0.3), rgba(16, 185, 129, 0.2)); border-color: #10b981; }
        .stat-card.red { background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(239, 68, 68, 0.2)); border-color: #ef4444; }
        .stat-card.purple { background: linear-gradient(135deg, rgba(168, 85, 247, 0.3), rgba(168, 85, 247, 0.2)); border-color: #a855f7; }
        .stat-icon { font-size: 2.2rem; }
        .stat-info { display: flex; flex-direction: column; }
        .stat-value { font-size: 1.8rem; font-weight: bold; color: #00d9ff; }
        .stat-name { color: #aaa; font-size: 0.85rem; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: 1fr; } .stats-grid.half { grid-template-columns: 1fr; max-width: 100%; } }
      </style>
    `;
  } catch (error) {
    console.error('Stats error:', error);
    main.innerHTML = `<h1>📊 Statistics</h1><p class="error">Failed to load statistics</p>`;
  }
}

// Achievement Notification System
function showAchievementNotification(achievement) {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = 'achievement-notification';
  notification.innerHTML = `
    <div class="an-icon">${achievement.icon}</div>
    <div class="an-content">
      <span class="an-title">🏆 Achievement Unlocked!</span>
      <span class="an-name">${achievement.name}</span>
      <span class="an-desc">${achievement.description}</span>
    </div>
    <button class="an-close" onclick="this.parentElement.remove()">×</button>
  `;
  
  // Add styles
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 2px solid #10b981;
    border-radius: 16px;
    padding: 20px;
    display: flex;
    align-items: center;
    gap: 15px;
    z-index: 10000;
    animation: slideIn 0.5s ease, glow 2s ease infinite;
    box-shadow: 0 0 30px rgba(16, 185, 129, 0.4);
    max-width: 400px;
  `;
  
  document.body.appendChild(notification);
  
  // Play achievement sound
  if (typeof SoundManager !== 'undefined') {
    SoundManager.playVictory();
  }
  
  // Auto remove after 5 seconds
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.5s ease forwards';
    setTimeout(() => notification.remove(), 500);
  }, 5000);
}

// Add animation keyframes
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(100%);
      opacity: 0;
    }
  }
  @keyframes glow {
    0%, 100% {
      box-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
    }
    50% {
      box-shadow: 0 0 40px rgba(16, 185, 129, 0.6);
    }
  }
  .achievement-notification .an-icon {
    font-size: 3rem;
  }
  .achievement-notification .an-content {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .achievement-notification .an-title {
    color: #10b981;
    font-weight: bold;
    font-size: 0.85rem;
  }
  .achievement-notification .an-name {
    color: #fff;
    font-weight: 600;
    font-size: 1.1rem;
  }
  .achievement-notification .an-desc {
    color: #aaa;
    font-size: 0.85rem;
  }
  .achievement-notification .an-close {
    position: absolute;
    top: 5px;
    right: 10px;
    background: none;
    border: none;
    color: #aaa;
    font-size: 1.5rem;
    cursor: pointer;
  }
`;
document.head.appendChild(style);

// Choose Level
function chooseLevel() {
  const main = document.getElementById('content');
  main.innerHTML = `
    <h1>🧮 Choose Your Challenge</h1>
    
    <div class="mode-toggle">
      <button class="mode-btn active" onclick="setGameMode('timed')" id="modeTimed">
        ⏱ Timed Mode
      </button>
    </div>
    
    <p class="mode-desc" id="modeDesc">Answer as fast as you can!</p>
    
    <div class="setup-container">
      <!-- Category Selection -->
      <div class="setup-section">
        <h2>📚 Select Category</h2>
        <div class="category-buttons">
          <button onclick="selectCategory('addition')" class="category-btn" data-category="addition">
            <span class="cat-icon">➕</span>
            <span class="cat-name">Addition</span>
            <span class="cat-desc">Sum of numbers</span>
          </button>
          <button onclick="selectCategory('subtraction')" class="category-btn" data-category="subtraction">
            <span class="cat-icon">➖</span>
            <span class="cat-name">Subtraction</span>
            <span class="cat-desc">Difference of numbers</span>
          </button>
          <button onclick="selectCategory('multiplication')" class="category-btn" data-category="multiplication">
            <span class="cat-icon">✖️</span>
            <span class="cat-name">Multiplication</span>
            <span class="cat-desc">Product of numbers</span>
          </button>
          <button onclick="selectCategory('division')" class="category-btn" data-category="division">
            <span class="cat-icon">➗</span>
            <span class="cat-name">Division</span>
            <span class="cat-desc">Quotient of numbers</span>
          </button>
        </div>
        <div class="mixed-category-container">
          <button onclick="selectCategory('mixed')" class="category-btn selected" data-category="mixed">
            <span class="cat-icon">🎲</span>
            <span class="cat-name">Mixed</span>
            <span class="cat-desc">All operations</span>
          </button>
        </div>
      </div>
      
      <!-- Difficulty Selection -->
      <div class="setup-section" id="difficulty-section">
        <h2>⚡ Select Difficulty</h2>
        <div class="difficulty-buttons">
          <button onclick="selectDifficulty('easy')" class="diff-btn easy">
            <span class="diff-icon">🌟</span>
            <span class="diff-name">Easy</span>
            <span class="diff-time">5s/question</span>
          </button>
          <button onclick="selectDifficulty('medium')" class="diff-btn medium">
            <span class="diff-icon">🔥</span>
            <span class="diff-name">Medium</span>
            <span class="diff-time">7s/question</span>
          </button>
          <button onclick="selectDifficulty('hard')" class="diff-btn hard">
            <span class="diff-icon">💀</span>
            <span class="diff-name">Hard</span>
            <span class="diff-time">10s/question</span>
          </button>
        </div>
      </div>
      
      <!-- Confirmation Section (Hidden by default) -->
      <div class="setup-section" id="confirm-section" style="display: none;">
        <h2>✅ Ready to Start?</h2>
        <p id="selected-summary" style="text-align: center; font-size: 1.1rem; margin: 20px 0;"></p>
        <div style="display: flex; justify-content: center; gap: 15px;">
          <button onclick="confirmStartGame()" style="padding: 15px 40px; font-size: 1.1rem; background: #28a745; color: white; border: none; border-radius: 25px; cursor: pointer; font-weight: bold;">✓ Start Quiz</button>
          <button onclick="cancelStartGame()" style="padding: 15px 30px; font-size: 1rem; background: #6c757d; color: white; border: none; border-radius: 25px; cursor: pointer;">Cancel</button>
        </div>
      </div>
    </div>
    
    <style>
      .mode-toggle {
        display: flex;
        justify-content: center;
        gap: 10px;
        margin-bottom: 15px;
      }
      .mode-btn {
        padding: 12px 25px;
        border: 2px solid rgba(255,255,255,0.2);
        border-radius: 25px;
        background: rgba(255,255,255,0.05);
        color: white;
        cursor: pointer;
        font-size: 1rem;
        transition: all 0.3s;
      }
      .mode-btn.active {
        background: var(--math-gradient);
        border-color: #6366f1;
      }
      .mode-desc {
        text-align: center;
        color: #aaa;
        margin-bottom: 25px;
        font-size: 0.95rem;
      }
      .setup-container {
        max-width: 800px;
        margin: 0 auto;
      }
      .setup-section {
        margin-bottom: 30px;
      }
      .setup-section h2 {
        color: #00d9ff;
        margin-bottom: 15px;
        text-align: center;
      }
      .category-buttons, .difficulty-buttons {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 15px;
        justify-items: center;
      }
      .mixed-category-container {
        display: flex;
        justify-content: center;
        margin-top: 15px;
      }
      .category-btn, .diff-btn {
        padding: 20px;
        min-width: 140px;
        border: 2px solid rgba(255,255,255,0.1);
        border-radius: 16px;
        background: rgba(255,255,255,0.05);
        color: white;
        cursor: pointer;
        transition: all 0.3s ease;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 5px;
      }
      .category-btn:hover, .diff-btn:hover {
        transform: translateY(-3px);
        background: rgba(255,255,255,0.1);
      }
      .category-btn.selected {
        border-color: #00d9ff;
        background: rgba(0, 217, 255, 0.2);
        box-shadow: 0 0 20px rgba(0, 217, 255, 0.3);
      }
      .cat-icon, .diff-icon {
        font-size: 2rem;
      }
      .cat-name, .diff-name {
        font-weight: 600;
        font-size: 1.1rem;
      }
      .cat-desc, .diff-time {
        font-size: 0.8rem;
        opacity: 0.7;
      }
      .diff-btn.easy { border-color: #10b981; }
      .diff-btn.easy:hover { background: rgba(16, 185, 129, 0.2); }
      .diff-btn.medium { border-color: #f59e0b; }
      .diff-btn.medium:hover { background: rgba(245, 158, 11, 0.2); }
      .diff-btn.hard { border-color: #ef4444; }
      .diff-btn.hard:hover { background: rgba(239, 68, 68, 0.2); }
    </style>
  `;
  
  // Set default category and mode
  window.selectedCategory = 'mixed';
  window.gameMode = 'timed';
}

// Set game mode (timed mode only)
function setGameMode(mode) {
  window.gameMode = 'timed';
  
  // Always active for timed mode
  document.getElementById('modeTimed').classList.add('active');
  
  // Update description
  const desc = document.getElementById('modeDesc');
  desc.textContent = '⏱ Answer as fast as you can!';
  
  SoundManager.playUIClick();
}

// Category Selection
function selectCategory(category) {
  // Remove selected class from all buttons
  document.querySelectorAll('.category-btn').forEach(btn => btn.classList.remove('selected'));
  // Add selected class to clicked button
  event.target.closest('.category-btn').classList.add('selected');
  window.selectedCategory = category;
  currentCategory = category;
  SoundManager.playUIClick();
}

// Store selected difficulty for confirmation
let pendingDifficulty = null;

// Select difficulty - show confirmation
function selectDifficulty(difficulty) {
  pendingDifficulty = difficulty;
  
  const category = window.selectedCategory || 'mixed';
  const categoryNames = {
    'addition': 'Addition',
    'subtraction': 'Subtraction', 
    'multiplication': 'Multiplication',
    'division': 'Division',
    'mixed': 'Mixed'
  };
  const difficultyNames = {
    'easy': 'Easy',
    'medium': 'Medium',
    'hard': 'Hard'
  };
  
  document.getElementById('difficulty-section').style.display = 'none';
  document.getElementById('confirm-section').style.display = 'block';
  document.getElementById('selected-summary').innerHTML = 
    `Category: <b>${categoryNames[category]}</b> &nbsp;|&nbsp; Difficulty: <b>${difficultyNames[difficulty]}</b>`;
}

// Confirm and start the game
function confirmStartGame() {
  if (pendingDifficulty) {
    startGame(pendingDifficulty);
    pendingDifficulty = null;
  }
}

// Cancel and go back to difficulty selection
function cancelStartGame() {
  pendingDifficulty = null;
  document.getElementById('difficulty-section').style.display = 'block';
  document.getElementById('confirm-section').style.display = 'none';
}

// Start Game
async function startGame(difficulty) {
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  // Get selected category or default to mixed
  const category = window.selectedCategory || 'mixed';
  currentCategory = category;
  currentDifficulty = difficulty;
  
  // Stop any running quiz and clear ALL data when starting new game
  stopQuiz(true);
  
  // Reset game variables
  lastGameTimeRemaining = 0;
  lastGameDifficulty = '';
  currentScore = 0;
  
  try {
    const response = await fetch('/api/quiz/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ difficulty, category, count: 10 })
    });
    
    if (!response.ok) {
      throw new Error('Failed to generate quiz');
    }
    
    const quizData = await response.json();
    currentQuizData = quizData.questions;
    totalQuestions = currentQuizData.length;
    answeredQuestions = 0;
    questionsAnswered = [];
    userAnswers = [];
    currentDifficulty = difficulty;
    
    // Calculate total time based on difficulty
    const timePerQuestion = difficulty === 'hard' ? 10 : (difficulty === 'medium' ? 7 : 5);
    totalTimeRemaining = timePerQuestion * totalQuestions;
    
    // Set timer for first question
    timeRemaining = timePerQuestion;
    
    sessionStorage.setItem('currentQuiz', JSON.stringify(currentQuizData));
    sessionStorage.setItem('difficulty', difficulty);
    
    main.innerHTML = `
      <div class="game-container">
        <div class="game-header">
          <h2>${difficulty.toUpperCase()} MODE</h2>
          <div class="timer-display">Time: <span id="timer">${timeRemaining}</span>s</div>
        </div>
        <div class="total-time-display">Total Remaining: <span id="totalTime">${totalTimeRemaining}</span>s</div>
        <div class="score-display">Score: <span id="score">0</span></div>
        <div class="question-display" id="question-container"></div>
        <div class="answers-display" id="answers-container"></div>
      </div>
    `;
    
    loadQuestion(0);
    startTimer();
    
  } catch (error) {
    console.error('Failed to start game:', error);
    main.innerHTML = `<p style="color: var(--math-red);">Failed to start game: ${error.message}</p>`;
  }
}

// Load Question
function loadQuestion(index) {
  if (index >= currentQuizData.length) {
    endGame();
    return;
  }
  
  const question = currentQuizData[index];
  
  const questionContainer = document.getElementById('question-container');
  const answersContainer = document.getElementById('answers-container');
  
  questionContainer.innerHTML = `
    <div class="question-box">
      <h3>Question ${index + 1} of ${totalQuestions}</h3>
      <p class="question-text">${question.num1} ${question.operator} ${question.num2} = ?</p>
    </div>
  `;
  
  const answers = generateAnswers(question);
  
  answersContainer.innerHTML = `
    <div class="answers-grid">
      ${answers.map((answer, i) => `
        <button class="answer-btn" onclick="submitAnswer(${answer}, ${question.correctAnswer}, ${index})">
          ${answer}
        </button>
      `).join('')}
    </div>
  `;
}

// Generate Answers
function generateAnswers(question) {
  const answers = new Set([question.correctAnswer]);
  
  while (answers.size < 4) {
    const offset = Math.floor(Math.random() * 20) - 10;
    const answer = question.correctAnswer + offset;
    if (answer >= 0 && !answers.has(answer)) {
      answers.add(answer);
    }
  }
  
  return Array.from(answers).sort(() => Math.random() - 0.5);
}

// Submit Answer
function submitAnswer(answer, correctAnswer, questionIndex) {
  // Initialize audio context on user interaction
  SoundManager.init();
  
  const isCorrect = answer === correctAnswer;
  const timePerQuestion = currentDifficulty === 'hard' ? 10 : (currentDifficulty === 'medium' ? 7 : 5);
  
  // Play sound based on answer
  if (isCorrect) {
    SoundManager.playCorrect();
  } else {
    SoundManager.playWrong();
  }
  
  if (isCorrect) {
    currentScore += 1;
    document.getElementById('score').textContent = currentScore;
  }
  
  answeredQuestions++;
  questionsAnswered.push(questionIndex);
  userAnswers.push({
    questionIndex,
    userAnswer: answer,
    correctAnswer,
    isCorrect
  });
  
  // Save to sessionStorage for Response Review and Question Progress
  sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
  
  // Reset timer for next question
  timeRemaining = timePerQuestion;
  
  updateTimerDisplay();
  
  loadQuestion(questionIndex + 1);
}

// Update timer display
function updateTimerDisplay() {
  const timerEl = document.getElementById('timer');
  if (timerEl) {
    timerEl.textContent = timeRemaining;
  }
}

// Update total time display
function updateTotalTimeDisplay() {
  const totalTimeEl = document.getElementById('totalTime');
  if (totalTimeEl) {
    totalTimeEl.textContent = totalTimeRemaining;
  }
}

// Start Timer
function startTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
  }
  
  const timePerQuestion = currentDifficulty === 'hard' ? 10 : (currentDifficulty === 'medium' ? 7 : 5);
  
  timerInterval = setInterval(() => {
    timeRemaining--;
    totalTimeRemaining--;
    
    // Save time to sessionStorage for Question Progress
    sessionStorage.setItem('totalTimeRemaining', totalTimeRemaining.toString());
    
    // Update displays
    const timerEl = document.getElementById('timer');
    if (timerEl) {
      timerEl.textContent = timeRemaining;
    }
    updateTotalTimeDisplay();
    
    // Play tick sound for last 3 seconds
    if (timeRemaining <= 3) {
      SoundManager.playTick();
    }
    
    if (timeRemaining <= 0) {
      // Timer done - check if it's the last question
      const currentIndex = questionsAnswered.length;
      
      if (currentIndex < totalQuestions - 1) {
        // Not the last question - move to next
        const question = currentQuizData[currentIndex];
        userAnswers.push({
          questionIndex: currentIndex,
          userAnswer: null,
          correctAnswer: question.correctAnswer,
          isCorrect: false,
          timeout: true
        });
        
        // Save to sessionStorage
        sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
        
        answeredQuestions++;
        questionsAnswered.push(currentIndex);
        
        // Reset timer for next question
        timeRemaining = timePerQuestion;
        
        updateTimerDisplay();
        loadQuestion(currentIndex + 1);
      } else {
        // Last question - record timeout and end game
        const question = currentQuizData[currentIndex];
        userAnswers.push({
          questionIndex: currentIndex,
          userAnswer: null,
          correctAnswer: question.correctAnswer,
          isCorrect: false,
          timeout: true
        });
        
        // Save to sessionStorage
        sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
        
        endGame();
      }
    }
  }, 1000);
}

// End Game
async function endGame() {
  clearInterval(timerInterval);
  timerInterval = null;
  
  // Store last game's remaining time and difficulty
  lastGameTimeRemaining = totalTimeRemaining;
  lastGameDifficulty = currentDifficulty;
  
  // Save final state to sessionStorage for Response Review and Question Progress
  sessionStorage.setItem('currentQuiz', JSON.stringify(currentQuizData));
  sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
  sessionStorage.setItem('totalTimeRemaining', totalTimeRemaining.toString());
  sessionStorage.setItem('difficulty', currentDifficulty);
  
  const token = localStorage.getItem('token');
  const userId = localStorage.getItem('userId');
  const difficulty = sessionStorage.getItem('difficulty');
  
  const correctAnswers = userAnswers.filter(a => a.isCorrect).length;
  currentAccuracy = totalQuestions > 0 ? (correctAnswers / totalQuestions) * 100 : 0;
  
  // Initialize audio context
  SoundManager.init();
  
  // Play victory or game over sound based on score
  if (correctAnswers >= 7) {
    SoundManager.playVictory();
  } else {
    SoundManager.playGameOver();
  }
  
  // Prepare questions data for saving
  const questionsData = currentQuizData.map((q, i) => {
    const userAnswer = userAnswers.find(a => a.questionIndex === i);
    return {
      questionNumber: i + 1,
      question: q.question,
      correctAnswer: q.correctAnswer,
      userAnswer: userAnswer ? userAnswer.userAnswer : null,
      isCorrect: userAnswer ? userAnswer.isCorrect : false
    };
  });
  
  // Save quiz session with questions
  try {
    console.log('Saving quiz data:', {
      score: currentScore,
      correctAnswers,
      totalQuestions,
      difficulty,
      timeLeft: totalTimeRemaining
    });
    
    await fetch('/api/scores', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        score: currentScore,
        correctAnswers,
        totalQuestions,
        difficulty,
        timeLeft: totalTimeRemaining,
        category: currentQuizData[0]?.category || 'mixed',
        questions: questionsData
      })
    });
    
    // Update user stats and check achievements
    await fetch('/api/stats/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        score: currentScore,
        correctAnswers,
        totalQuestions,
        difficulty,
        category: currentQuizData[0]?.category || 'mixed'
      })
    });
  } catch (error) {
    console.error('Failed to save score:', error);
  }
  
  // Format remaining time nicely
  const minutes = Math.floor(lastGameTimeRemaining / 60);
  const seconds = lastGameTimeRemaining % 60;
  const timeDisplay = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
  
  const main = document.getElementById('content');
  main.innerHTML = `
    <div class="game-over">
      <h2>GAME OVER!</h2>
      <div class="final-stats">
        <p>Final Score: <span>${currentScore}</span></p>
        <p>Accuracy: <span>${currentAccuracy.toFixed(1)}%</span></p>
        <p>Correct Answers: <span>${correctAnswers}/${totalQuestions}</span></p>
        <p class="time-bonus">Time Remaining: <span>${timeDisplay}</span></p>
      </div>
      <button onclick="showAnswers()" class="review-btn">📝 Review Responses</button>
      <button onclick="chooseLevel()" class="restart-btn">🔄 Play Again</button>
    </div>
  `;
}

// Show Scores
async function showScores() {
  // Stop quiz if running
  stopQuiz();
  
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  try {
    const response = await fetch('/api/scores', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch scores');
    }
    
    const scores = await response.json();
    
    main.innerHTML = `
      <h1>Score History</h1>
      <div class="scores-list">
        ${scores.length === 0 ? '<p>No games played yet.</p>' : ''}
        ${scores.map((score, i) => `
          <div class="score-item">
            <span>Game ${scores.length - i}</span>
            <span>${score.difficulty.toUpperCase()}</span>
            <span>Score: ${score.score}</span>
            <span>${new Date(score.created_at).toLocaleDateString()}</span>
          </div>
        `).join('')}
      </div>
    `;
  } catch (error) {
    main.innerHTML = `<p style="color: var(--math-red);">Failed to load scores: ${error.message}</p>`;
  }
}

// Show Time
function showTime() {
  // Stop quiz if running
  stopQuiz();
  
  const main = document.getElementById('content');
  
  // Format last game's remaining time
  const minutes = Math.floor(lastGameTimeRemaining / 60);
  const seconds = lastGameTimeRemaining % 60;
  const timeDisplay = lastGameTimeRemaining > 0 
    ? (minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`)
    : 'No games played yet';
  
  // Format difficulty display
  const difficultyDisplay = lastGameDifficulty ? lastGameDifficulty.toUpperCase() : '';
  
  main.innerHTML = `
    <h1>Time Remaining</h1>
    <div class="stats-container">
      <div class="stat-card">
        <h3>Last Game (${difficultyDisplay})</h3>
        <p class="stat-value">${timeDisplay}</p>
        <p class="stat-label">${lastGameTimeRemaining > 0 ? `(${lastGameTimeRemaining} seconds remaining)` : 'Play a game to see your time'}</p>
      </div>
      <div class="stat-card">
        <h3>Easy</h3>
        <p class="stat-value">50s</p>
        <p class="stat-label">Total (10 questions × 5s)</p>
      </div>
      <div class="stat-card">
        <h3>Medium</h3>
        <p class="stat-value">70s</p>
        <p class="stat-label">Total (10 questions × 7s)</p>
      </div>
      <div class="stat-card">
        <h3>Hard</h3>
        <p class="stat-value">100s</p>
        <p class="stat-label">Total (10 questions × 10s)</p>
      </div>
    </div>
    <p style="margin-top: 20px;">Timer resets for each question. If you don't answer in time, you move to the next question automatically.</p>
  `;
}

// Show Accuracy
function showAccuracy() {
  // Stop quiz if running
  stopQuiz();
  
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  fetch('/api/scores', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(response => response.json())
  .then(scores => {
    // Handle case where scores is undefined or null
    const scoresArray = Array.isArray(scores) ? scores : [];
    
    // Calculate totals using score (which equals number of correct answers)
    const correctCount = scoresArray.reduce((acc, score) => acc + (score.score || 0), 0);
    const totalCount = scoresArray.reduce((acc, score) => acc + (score.total_questions || 0), 0);
    const overallAccuracy = totalCount > 0 ? ((correctCount / totalCount) * 100).toFixed(1) : 0;
    
    // Calculate per-difficulty stats
    const easyScores = scoresArray.filter(s => s.difficulty === 'easy');
    const mediumScores = scoresArray.filter(s => s.difficulty === 'medium');
    const hardScores = scoresArray.filter(s => s.difficulty === 'hard');
    
    const getStats = (scoreList) => {
      const correct = scoreList.reduce((acc, s) => acc + (s.score || 0), 0);
      const total = scoreList.reduce((acc, s) => acc + (s.total_questions || 0), 0);
      const accuracy = total > 0 ? ((correct / total) * 100).toFixed(1) : 0;
      return { correct, total, accuracy };
    };
    
    const easyStats = getStats(easyScores);
    const mediumStats = getStats(mediumScores);
    const hardStats = getStats(hardScores);
    
    // If no scores, show message
    if (scoresArray.length === 0) {
      main.innerHTML = `
        <h1>Accuracy Statistics</h1>
        <div class="stats-container">
          <div class="stat-card">
            <h3>Overall Accuracy</h3>
            <p class="stat-value">0%</p>
          </div>
          <div class="stat-card">
            <h3>Total Correct</h3>
            <p class="stat-value">0</p>
          </div>
          <div class="stat-card">
            <h3>Total Questions</h3>
            <p class="stat-value">0</p>
          </div>
        </div>
        <p style="margin-top: 20px; text-align: center;">No games played yet. Play a game to see your accuracy!</p>
      `;
      return;
    }
    
    main.innerHTML = `
      <h1>Accuracy Statistics</h1>
      <div class="stats-container">
        <div class="stat-card">
          <h3>Overall Accuracy</h3>
          <p class="stat-value">${overallAccuracy}%</p>
        </div>
        <div class="stat-card">
          <h3>Total Correct</h3>
          <p class="stat-value">${correctCount}</p>
        </div>
        <div class="stat-card">
          <h3>Total Questions</h3>
          <p class="stat-value">${totalCount}</p>
        </div>
      </div>
      <h2 style="margin-top: 30px; margin-bottom: 20px; color: var(--text-color);">By Difficulty</h2>
      <div class="stats-container">
        <div class="stat-card easy">
          <h3>Easy Mode</h3>
          <p class="stat-value">${easyStats.accuracy}%</p>
          <p class="stat-detail">${easyStats.correct}/${easyStats.total} correct</p>
        </div>
        <div class="stat-card medium">
          <h3>Medium Mode</h3>
          <p class="stat-value">${mediumStats.accuracy}%</p>
          <p class="stat-detail">${mediumStats.correct}/${mediumStats.total} correct</p>
        </div>
        <div class="stat-card hard">
          <h3>Hard Mode</h3>
          <p class="stat-value">${hardStats.accuracy}%</p>
          <p class="stat-detail">${hardStats.correct}/${hardStats.total} correct</p>
        </div>
      </div>
    `;
  })
  .catch(error => {
    main.innerHTML = `<p style="color: var(--math-red);">Failed to load accuracy: ${error.message}</p>`;
  });
}

// Show Answers - displays quiz history with timestamps
function showAnswers() {
  const main = document.getElementById('content');
  
  main.innerHTML = `<h1>Response Review</h1><div class="loading">Loading quiz history...</div>`;
  
  // Fetch quiz history from the API
  api.getHistory()
    .then(sessions => {
      console.log('Quiz history loaded:', sessions);
      if (!sessions || sessions.length === 0) {
        main.innerHTML = `
          <h1>Response Review</h1>
          <p>No quiz history available. Play a game first!</p>
          <button onclick="chooseLevel()" class="start-btn">🎮 Play Now</button>
        `;
        return;
      }
      
      // Format date helper
      const formatDate = (dateStr) => {
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      };
      
      // Render quiz history list
      let historyHTML = `
        <div class="quiz-history-header">
          <h2>Your Quiz History</h2>
          <button onclick="showAllUsersQuizzes()" class="view-all-btn">👥 View All Users' Quizzes</button>
        </div>
        <div class="quiz-history-list">
      `;
      
      sessions.forEach((session) => {
        const dateStr = formatDate(session.created_at);
        const percentage = session.total_questions > 0 ? Math.round((session.correct_answers / session.total_questions) * 100) : 0;
        
        historyHTML += `
          <div class="quiz-history-item" onclick="showSessionDetails('${session.id}')">
            <div class="quiz-history-info">
              <div class="quiz-history-date">📅 ${dateStr}</div>
              <div class="quiz-history-details">
                <span class="difficulty-badge">${session.difficulty}</span>
                <span class="category-badge">${session.category || 'mixed'}</span>
              </div>
            </div>
            <div class="quiz-history-stats">
              <div class="score">Score: <strong>${session.score}</strong></div>
              <div class="accuracy">${session.correct_answers}/${session.total_questions} (${percentage}%)</div>
              <div class="time-left">⏱ ${session.time_left}s left</div>
            </div>
          </div>
        `;
      });
      
      historyHTML += `</div>`;
      main.innerHTML = historyHTML;
    })
    .catch(error => {
      console.error('Error fetching history:', error);
      main.innerHTML = `
        <h1>Response Review</h1>
        <p>Error loading quiz history: ${error.message}</p>
        <button onclick="chooseLevel()" class="start-btn">🎮 Play Now</button>
      `;
    });
}

// Show session details (questions and answers)
function showSessionDetails(sessionId) {
  const main = document.getElementById('content');
  main.innerHTML = `<h1>Quiz Details</h1><div class="loading">Loading quiz details...</div>`;
  
  api.getSessionQuestions(sessionId)
    .then(data => {
      const session = data.session;
      const questions = data.questions || [];
      
      const formatDate = (dateStr) => {
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      };
      
      const percentage = session.total_questions > 0 ? Math.round((session.correct_answers / session.total_questions) * 100) : 0;
      
      let detailsHTML = `
        <div class="session-details">
          <button onclick="showAnswers()" class="back-btn">← Back to History</button>
          <div class="session-header">
            <h2>📝 Your Quiz</h2>
            <p><strong>Date:</strong> ${formatDate(session.created_at)}</p>
            <p><strong>Difficulty:</strong> ${session.difficulty} | <strong>Category:</strong> ${session.category || 'mixed'}</p>
            <p><strong>Score:</strong> ${session.score} | <strong>Accuracy:</strong> ${session.correct_answers}/${session.total_questions} (${percentage}%)</p>
            <p><strong>Time Remaining:</strong> ${session.time_left}s</p>
          </div>
          <h3>Questions & Answers</h3>
          <div class="answers-container">
            <div class="answers-grid">
      `;
      
      questions.forEach((q, i) => {
        const bgClass = q.is_correct == 1 ? '#10b981' : '#ef4444';
        const statusText = q.is_correct == 1 ? '✓ Correct' : '✗ Wrong';
        const userAnswer = q.user_answer !== null ? q.user_answer : 'No Answer';
        
        detailsHTML += `
          <div class="answer-item" style="background: ${bgClass};">
            <div class="question-text">
              <strong>Question ${i + 1}:</strong> ${q.question}
            </div>
            <div class="answer-details">
              <span>Your Answer: <strong>${userAnswer}</strong></span>
              <span>Correct Answer: <strong>${q.correct_answer}</strong></span>
            </div>
            <div class="status-text">${statusText}</div>
          </div>
        `;
      });
      
      if (questions.length === 0) {
        detailsHTML += `<p style="grid-column: 1/-1; text-align: center;">No question data available.</p>`;
      }
      
      detailsHTML += `
            </div>
          </div>
        </div>
      `;
      
      main.innerHTML = detailsHTML;
    })
    .catch(error => {
      console.error('Error loading session:', error);
      main.innerHTML = `
        <h1>Quiz Details</h1>
        <p>Error loading quiz details.</p>
        <button onclick="showAnswers()" class="back-btn">← Back</button>
      `;
    });
}

// Show all users' quizzes
function showAllUsersQuizzes() {
  const main = document.getElementById('content');
  main.innerHTML = `<h1>All Users' Quizzes</h1><div class="loading">Loading all quizzes...</div>`;
  
  api.getAllSessions()
    .then(sessions => {
      if (!sessions || sessions.length === 0) {
        main.innerHTML = `
          <h1>All Users' Quizzes</h1>
          <p>No quizzes available yet.</p>
          <button onclick="showAnswers()" class="back-btn">← Back</button>
        `;
        return;
      }
      
      const currentUserId = api.getUserId();
      const formatDate = (dateStr) => {
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      };
      
      let allQuizzesHTML = `
        <div class="all-quizzes-header">
          <h2>All Users' Quiz History</h2>
          <button onclick="showAnswers()" class="back-btn">← Back to My History</button>
        </div>
        <div class="all-quizzes-list">
      `;
      
      sessions.forEach((session) => {
        const dateStr = formatDate(session.created_at);
        const percentage = session.total_questions > 0 ? Math.round((session.correct_answers / session.total_questions) * 100) : 0;
        const isCurrentUser = session.user_id == currentUserId;
        const userLabel = isCurrentUser ? ' (You)' : '';
        const userName = session.user_name || 'Unknown User';
        
        allQuizzesHTML += `
          <div class="quiz-history-item ${isCurrentUser ? 'current-user' : ''}" onclick="showOtherUserSessionDetails('${session.id}')">
            <div class="quiz-history-info">
              <div class="quiz-history-user">👤 ${userName}${userLabel}</div>
              <div class="quiz-history-date">📅 ${dateStr}</div>
              <div class="quiz-history-details">
                <span class="difficulty-badge">${session.difficulty}</span>
                <span class="category-badge">${session.category || 'mixed'}</span>
              </div>
            </div>
            <div class="quiz-history-stats">
              <div class="score">Score: <strong>${session.score}</strong></div>
              <div class="accuracy">${session.correct_answers}/${session.total_questions} (${percentage}%)</div>
              <div class="time-left">⏱ ${session.time_left}s left</div>
            </div>
          </div>
        `;
      });
      
      allQuizzesHTML += `</div>`;
      main.innerHTML = allQuizzesHTML;
    })
    .catch(error => {
      console.error('Error fetching all sessions:', error);
      main.innerHTML = `
        <h1>All Users' Quizzes</h1>
        <p>Error loading quizzes: ${error.message}</p>
        <button onclick="showAnswers()" class="back-btn">← Back</button>
      `;
    });
}

// Show other user's session details
function showOtherUserSessionDetails(sessionId) {
  const main = document.getElementById('content');
  main.innerHTML = `<h1>Quiz Details</h1><div class="loading">Loading quiz details...</div>`;
  
  api.getSessionQuestions(sessionId)
    .then(data => {
      const session = data.session;
      const questions = data.questions || [];
      const currentUserId = api.getUserId();
      const isCurrentUser = session.user_id == currentUserId;
      
      const formatDate = (dateStr) => {
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      };
      
      const percentage = session.total_questions > 0 ? Math.round((session.correct_answers / session.total_questions) * 100) : 0;
      const userName = session.user_name || 'Unknown User';
      
      let detailsHTML = `
        <div class="session-details">
          <button onclick="showAllUsersQuizzes()" class="back-btn">← Back to All Quizzes</button>
          <div class="session-header">
            <h2>👤 Quiz by ${userName}${isCurrentUser ? ' (You)' : ''}</h2>
            <p><strong>Date:</strong> ${formatDate(session.created_at)}</p>
            <p><strong>Difficulty:</strong> ${session.difficulty} | <strong>Category:</strong> ${session.category || 'mixed'}</p>
            <p><strong>Score:</strong> ${session.score} | <strong>Accuracy:</strong> ${session.correct_answers}/${session.total_questions} (${percentage}%)</p>
            <p><strong>Time Remaining:</strong> ${session.time_left}s</p>
          </div>
          <h3>Questions & Answers</h3>
          <div class="answers-container">
            <div class="answers-grid">
      `;
      
      questions.forEach((q, i) => {
        const bgClass = q.is_correct == 1 ? '#10b981' : '#ef4444';
        const statusText = q.is_correct == 1 ? '✓ Correct' : '✗ Wrong';
        const userAnswer = q.user_answer !== null ? q.user_answer : 'No Answer';
        
        detailsHTML += `
          <div class="answer-item" style="background: ${bgClass};">
            <div class="question-text">
              <strong>Question ${i + 1}:</strong> ${q.question}
            </div>
            <div class="answer-details">
              <span>Answer: <strong>${userAnswer}</strong></span>
              <span>Correct Answer: <strong>${q.correct_answer}</strong></span>
            </div>
            <div class="status-text">${statusText}</div>
          </div>
        `;
      });
      
      if (questions.length === 0) {
        detailsHTML += `<p style="grid-column: 1/-1; text-align: center;">No question data available.</p>`;
      }
      
      detailsHTML += `
            </div>
          </div>
        </div>
      `;
      
      main.innerHTML = detailsHTML;
    })
    .catch(error => {
      console.error('Error loading session:', error);
      main.innerHTML = `
        <h1>Quiz Details</h1>
        <p>Error loading quiz details.</p>
        <button onclick="showAllUsersQuizzes()" class="back-btn">← Back</button>
      `;
    });
}

// Show Live Progress
function showLiveProgress() {
  // Get quiz data from sessionStorage directly (don't call stopQuiz first)
  const main = document.getElementById('content');
  
  // Try to restore from sessionStorage - check all possible formats
  const sessionCurrentQuiz = sessionStorage.getItem('currentQuiz');
  const sessionQuiz = sessionStorage.getItem('quizData');
  const quizData = sessionCurrentQuiz ? JSON.parse(sessionCurrentQuiz) : (sessionQuiz ? JSON.parse(sessionQuiz) : null);
  
  // Get userAnswers from sessionStorage
  const sessionAnswers = sessionStorage.getItem('userAnswers');
  let userAnswerData = sessionAnswers ? JSON.parse(sessionAnswers) : [];
  
  // Get total time from sessionStorage
  const sessionCurrentTime = sessionStorage.getItem('totalTimeRemaining');
  const sessionQuizTime = sessionStorage.getItem('totalTimeLeft');
  const totalTime = sessionCurrentTime ? parseInt(sessionCurrentTime) : (sessionQuizTime ? parseInt(sessionQuizTime) : 0);
  
  // Also check memory variables (dashboard.js quiz)
  if (currentQuizData.length > 0 && userAnswers.length > 0) {
    // Use memory data from dashboard.js quiz
    userAnswerData = userAnswers;
  }
  
  // Get total questions from various sources
  const totalQ = currentQuizData.length > 0 ? currentQuizData.length : (quizData ? quizData.length : 0);
  const answered = userAnswerData ? userAnswerData.length : 0;
  
  main.innerHTML = `
    <h1>Question Progress</h1>
    <p>Track your progress through the current game.</p>
    ${totalQ > 0 ? `
      <div class="progress-bar-container">
        <div class="progress-bar" style="width: ${(answered / totalQ) * 100}%"></div>
      </div>
      <p>Questions Answered: ${answered} / ${totalQ}</p>
      <p>Total Time Remaining: ${totalTime} seconds</p>
      ${userAnswerData && userAnswerData.length > 0 ? `
        <div class="progress-details" style="margin-top:20px;">
          ${userAnswerData.map((a, i) => {
            const status = a.isCorrect ? '✓' : (a.timeout ? '⏱' : '✗');
            const color = a.isCorrect ? '#10b981' : (a.timeout ? '#f59e0b' : '#ef4444');
            return `<span style="display:inline-block;margin:5px;padding:8px 12px;background:${color};border-radius:5px;">Q${i+1}: ${status}</span>`;
          }).join('')}
        </div>
      ` : ''}
    ` : '<p>No active game. Start playing to see your progress!</p>'}
  `;
}

// Show Ranking
async function showRanking() {
  // Stop quiz if running
  stopQuiz();
  
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  const userId = parseInt(localStorage.getItem('userId'));
  
  try {
    const response = await fetch('/api/scores/ranking', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch rankings');
    }
    
    const rankings = await response.json();
    
    main.innerHTML = `
      <h1>Leaderboard</h1>
      <div class="rankings-list">
        ${rankings.length === 0 ? '<p>No rankings available yet.</p>' : ''}
        ${rankings.map((rank, i) => `
          <div class="rank-item ${rank.user_id === userId ? 'highlight' : ''}">
            <span class="rank">#${i + 1}</span>
            <span class="username">${rank.username}</span>
            <span class="total-score">Total Score: ${rank.totalScore}</span>
          </div>
        `).join('')}
      </div>
    `;
  } catch (error) {
    main.innerHTML = `<p style="color: var(--math-red);">Failed to load rankings: ${error.message}</p>`;
  }
}

// Show Users
async function showUsers() {
  // Stop quiz if running
  stopQuiz();
  
  const main = document.getElementById('content');
  const token = localStorage.getItem('token');
  
  // Check current user status
  const isDeleted = currentUser.is_deleted || false;
  
  main.innerHTML = `
    <h1>User Account</h1>
    <div class="user-info">
      <p><strong>Username:</strong> ${currentUser.name}</p>
      <p><strong>Email:</strong> ${currentUser.email}</p>
      <p><strong>Account Status:</strong> ${isDeleted ? '<span style="color: var(--math-red);">Deleted (can be restored)</span>' : '<span style="color: var(--math-green);">Active</span>'}</p>
    </div>
    <div class="user-actions">
      ${!isDeleted ? `
        <button onclick="deleteRecord()" class="action-btn">🗑 Delete Last Record</button>
        <button onclick="deleteAllRecords()" class="action-btn">🗑 Delete All Records</button>
        <button onclick="softDeleteAccount()" class="action-btn danger">🗑️ Delete Account</button>
      ` : `
        <button onclick="restoreAccount()" class="action-btn">♻️ Restore Account</button>
      `}
      <button onclick="permanentDeleteAccount()" class="action-btn danger">❌ Permanent Delete</button>
    </div>
    <h2 style="margin-top: 30px;">All Registered Users</h2>
    <div id="allUsersList" class="users-list">Loading...</div>
  `;
  
  // Fetch all users
  try {
    const response = await fetch('/api/users', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }
    
    const users = await response.json();
    
    const usersList = document.getElementById('allUsersList');
    
    if (users.length === 0) {
      usersList.innerHTML = '<p>No users registered yet.</p>';
      return;
    }
    
    usersList.innerHTML = `
      <table class="users-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(user => `
            <tr class="${user.id === currentUser.id ? 'current-user' : ''}">
              <td>${user.id}</td>
              <td>${user.name}</td>
              <td>${user.email}</td>
              <td>${user.is_deleted ? '<span style="color: var(--math-red);">Deleted</span>' : '<span style="color: var(--math-green);">Active</span>'}</td>
              <td>${new Date(user.created_at).toLocaleDateString()}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (error) {
    document.getElementById('allUsersList').innerHTML = '<p style="color: var(--math-red);">Failed to load users.</p>';
  }
}

// Soft Delete Account (mark as deleted but can be restored)
async function softDeleteAccount() {
  if (!confirm('Are you sure you want to delete your account?\n\nYou can restore it later using the "Restore Account" button.\n\nClick OK to delete or Cancel to keep your account.')) return;
  
  const token = localStorage.getItem('token');
  
  try {
    const response = await fetch('/api/users', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete account');
    }
    
    alert('Account deleted successfully!\n\nYou can restore it later by clicking "Restore Account".');
    logout();
  } catch (error) {
    alert('Failed to delete account: ' + error.message);
  }
}

// Permanent Delete Account
async function permanentDeleteAccount() {
  if (!confirm('⚠️ PERMANENT DELETE WARNING\n\nThis will PERMANENTLY delete your account and ALL data.\nThis CANNOT be undone!\n\nAre you absolutely sure?')) return;
  
  const token = localStorage.getItem('token');
  const password = prompt('Please enter your password to confirm permanent deletion:');
  
  if (!password) {
    alert('Password is required for permanent deletion.');
    return;
  }
  
  try {
    const response = await fetch('/api/users/permanent', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to permanently delete account');
    }
    
    alert('Account permanently deleted.\n\nAll data has been removed.');
    logout();
  } catch (error) {
    alert('Failed to permanently delete account: ' + error.message);
  }
}

// Delete Record
async function deleteRecord() {
  if (!confirm('Delete your last game record?')) return;
  
  const token = localStorage.getItem('token');
  
  try {
    const response = await fetch('/api/scores/latest', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete record');
    }
    
    const result = await response.json();
    
    // Check if this was the last quiz session
    const remainingSessions = result.remainingSessions || 0;
    
    if (remainingSessions === 0) {
      // Clear ALL quiz-related sessionStorage data (Question Progress, Response View)
      sessionStorage.removeItem('currentQuiz');
      sessionStorage.removeItem('quizData');
      sessionStorage.removeItem('userAnswers');
      sessionStorage.removeItem('totalTimeRemaining');
      sessionStorage.removeItem('totalTimeLeft');
      sessionStorage.removeItem('timeRemaining');
      sessionStorage.removeItem('difficulty');
      sessionStorage.removeItem('currentDifficulty');
      sessionStorage.removeItem('quizStarted');
      sessionStorage.removeItem('lastAnswerTime');
      sessionStorage.removeItem('currentQuestionIndex');
      sessionStorage.removeItem('questionStartTime');
      
      // Reset time remaining variables
      lastGameTimeRemaining = 0;
      lastGameDifficulty = '';
    } else {
      // Fetch the new last game's time remaining (for non-last quiz deletion)
      const scoresRes = await fetch('/api/scores', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (scoresRes.ok) {
        const scores = await scoresRes.json();
        if (scores.length > 0) {
          // Get the most recent game's time
          const lastScore = scores[0];
          lastGameTimeRemaining = lastScore.time_remaining || 0;
          lastGameDifficulty = lastScore.difficulty || '';
        }
      }
    }
    
    alert('Record deleted successfully!');
    showUsers();
  } catch (error) {
    alert('Failed to delete record: ' + error.message);
  }
}

// Delete All Records
async function deleteAllRecords() {
  if (!confirm('Delete ALL your game records? This will also delete your achievements and statistics. This cannot be undone!')) return;
  
  const token = localStorage.getItem('token');
  
  try {
    const response = await fetch('/api/scores', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete records');
    }
    
    // Clear ALL sidebar session data (Response Review, Question Progress, etc.)
    sessionStorage.removeItem('currentQuiz');
    sessionStorage.removeItem('quizData');
    sessionStorage.removeItem('userAnswers');
    sessionStorage.removeItem('totalTimeRemaining');
    sessionStorage.removeItem('totalTimeLeft');
    sessionStorage.removeItem('timeRemaining');
    sessionStorage.removeItem('difficulty');
    sessionStorage.removeItem('quizStarted');
    sessionStorage.removeItem('lastAnswerTime');
    sessionStorage.removeItem('currentQuestionIndex');
    sessionStorage.removeItem('questionStartTime');
    
    // Reset time remaining variables
    lastGameTimeRemaining = 0;
    lastGameDifficulty = '';
    
    alert('All records, achievements and statistics have been deleted!');
    
    // Refresh the display to show empty state
    if (typeof showUsers === 'function') {
      showUsers();
    }
  } catch (error) {
    alert('Failed to delete records: ' + error.message);
  }
}

// Restore Account
async function restoreAccount() {
  const token = localStorage.getItem('token');
  
  try {
    const response = await fetch('/api/users/restore', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to restore account');
    }
    
    alert('Account restored successfully!');
    checkLoginStatus();
    showUsers();
  } catch (error) {
    alert('Failed to restore account: ' + error.message);
  }
}

// Remove Account
async function removeAccount() {
  if (!confirm('Are you sure you want to permanently delete your account? This cannot be undone!')) return;
  
  const token = localStorage.getItem('token');
  const password = prompt('Please enter your password to confirm:');
  
  if (!password) {
    alert('Password is required to delete account.');
    return;
  }
  
  try {
    const response = await fetch('/api/users', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to remove account');
    }
    
    alert('Account removed successfully!');
    logout();
  } catch (error) {
    alert('Failed to remove account: ' + error.message);
  }
}

// ============================================
// Background Effects - Math Symbols, Particles, Shapes
// ============================================

// Math symbols for floating background
const mathSymbols = ['∑', '∏', '√', 'π', '∞', '±', '×', '÷', '∂', '∇', '∫', '∬', '∭', '∴', '∵', '≅', '≈', '≠', '≤', '≥', '⊂', '⊃', '⊆', '⊇', '∈', '∉', '∪', '∩', '∅', 'ℵ', 'Ω', 'Δ', 'Γ', 'Λ', 'Ξ', 'Π', 'Σ', 'Φ', 'Ψ', 'Ω', 'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ', 'λ', 'μ', 'σ', 'φ', 'χ', 'ψ', 'ω', '²', '³', '√', '∛', '∑', '∏', '∫', '∂', '∇', 'ℯ', 'ⁱ', '⁰', 'ⁿ'];

// Generate floating math symbols
function generateMathSymbols() {
  const container = document.getElementById('mathSymbolsBg');
  if (!container) return;
  
  container.innerHTML = '';
  
  for (let i = 0; i < 40; i++) {
    const symbol = document.createElement('div');
    symbol.className = 'math-symbol';
    symbol.textContent = mathSymbols[Math.floor(Math.random() * mathSymbols.length)];
    symbol.style.left = Math.random() * 100 + 'vw';
    symbol.style.animationDelay = (Math.random() * 25) + 's';
    symbol.style.fontSize = (Math.random() * 20 + 16) + 'px';
    symbol.style.setProperty('--delay', (Math.random() * 25) + 's');
    container.appendChild(symbol);
  }
}

// Generate particles
function generateParticles() {
  const container = document.getElementById('particles');
  if (!container) return;
  
  container.innerHTML = '';
  
  const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#06b6d4', '#10b981', '#f59e0b'];
  
  for (let i = 0; i < 50; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + 'vw';
    particle.style.animationDelay = (Math.random() * 15) + 's';
    particle.style.setProperty('--delay', (Math.random() * 15) + 's');
    particle.style.background = colors[Math.floor(Math.random() * colors.length)];
    container.appendChild(particle);
  }
}

// Generate geometric shapes
function generateGeometricShapes() {
  const container = document.getElementById('geometricShapes');
  if (!container) return;
  
  container.innerHTML = '';
  
  const shapes = ['circle', 'square', 'triangle'];
  const colors = ['#6366f1', '#8b5cf6', '#f59e0b', '#10b981', '#06b6d4'];
  
  for (let i = 0; i < 20; i++) {
    const shape = document.createElement('div');
    shape.className = 'shape ' + shapes[Math.floor(Math.random() * shapes.length)];
    shape.style.left = Math.random() * 100 + 'vw';
    shape.style.animationDelay = (Math.random() * 30) + 's';
    shape.style.setProperty('--delay', (Math.random() * 30) + 's');
    shape.style.borderColor = colors[Math.floor(Math.random() * colors.length)];
    container.appendChild(shape);
  }
}

// Mouse trail effect
document.addEventListener('mousemove', (e) => {
  const container = document.getElementById('mouseTrail');
  if (!container) return;
  
  const trail = document.createElement('div');
  trail.className = 'trail-dot';
  trail.style.left = e.clientX + 'px';
  trail.style.top = e.clientY + 'px';
  trail.style.background = 'linear-gradient(135deg, #6366f1, #8b5cf6, #ec4899)';
  container.appendChild(trail);
  
  // Remove trail dot after animation
  setTimeout(() => trail.remove(), 1000);
});

// Initialize all background effects
function initBackgroundEffects() {
  generateMathSymbols();
  generateParticles();
  generateGeometricShapes();
}

// Run on page load
window.addEventListener('load', initBackgroundEffects);

// Initialize
document.addEventListener('DOMContentLoaded', checkLoginStatus);

