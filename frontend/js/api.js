// API Helper for Math Quiz Game
const API_URL = '/api';

const api = {
  // Token management (matching dashboard.js)
  getToken() {
    return localStorage.getItem('token');
  },

  setToken(token) {
    localStorage.setItem('token', token);
  },

  removeToken() {
    localStorage.removeItem('token');
  },

  // Helper to get current user ID from localStorage
  getUserId() {
    return localStorage.getItem('userId');
  },

  setUserId(userId) {
    localStorage.setItem('userId', userId);
  },

  // Helper for authenticated requests
  async request(endpoint, options = {}) {
    const token = this.getToken();
    console.log('API Request:', endpoint, 'Token:', token ? 'present' : 'missing');
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers
    };

    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers
    });

    console.log('API Response status:', response.status);
    const data = await response.json();
    console.log('API Response data:', data);

    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }

    return data;
  },

  // Authentication
  async register(name, email, password) {
    const data = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password })
    });
    
    if (data.token) {
      this.setToken(data.token);
      this.setUserId(data.user.id);
    }
    
    return data;
  },

  async login(email, password) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    
    if (data.token) {
      this.setToken(data.token);
      this.setUserId(data.user.id);
    }
    
    return data;
  },

  logout() {
    this.removeToken();
    localStorage.removeItem('userId');
    window.location.href = 'index.html';
  },

  async getCurrentUser() {
    return await this.request('/auth/me');
  },

  async updateTheme(theme) {
    return await this.request('/auth/theme', {
      method: 'PUT',
      body: JSON.stringify({ theme })
    });
  },

  // User management
  async getUsers() {
    return await this.request('/users');
  },

  // Quiz operations
  async startQuiz(difficulty, timeLeft = 600) {
    return await this.request('/quiz/start', {
      method: 'POST',
      body: JSON.stringify({ difficulty, timeLeft })
    });
  },

  async addQuestion(sessionId, questionNumber, question, correctAnswer) {
    return await this.request('/quiz/question', {
      method: 'POST',
      body: JSON.stringify({ sessionId, questionNumber, question, correctAnswer })
    });
  },

  async submitAnswer(sessionId, questionNumber, userAnswer) {
    return await this.request('/quiz/answer', {
      method: 'PUT',
      body: JSON.stringify({ sessionId, questionNumber, userAnswer })
    });
  },

  async finishQuiz(sessionId, score, timeLeft) {
    return await this.request('/quiz/finish', {
      method: 'POST',
      body: JSON.stringify({ sessionId, score, timeLeft })
    });
  },

  async getHistory() {
    return await this.request('/scores');
  },

  async getAllSessions() {
    return await this.request('/scores/all');
  },

  async getSessionQuestions(sessionId) {
    return await this.request(`/quiz/session/${sessionId}/questions`);
  },

  async deleteSession(sessionId) {
    return await this.request(`/quiz/session/${sessionId}`, {
      method: 'DELETE'
    });
  },

  // Statistics
  async getStats() {
    return await this.request('/stats/user');
  },

  async getLeaderboard() {
    return await this.request('/stats/leaderboard');
  },

  // Check if user is authenticated
  isAuthenticated() {
    return !!this.getToken();
  },

  // Restore deleted account and login
  async restoreAccount(email, password) {
    const response = await fetch(`${API_URL}/auth/restore`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Restore failed');
    }

    if (data.token) {
      this.setToken(data.token);
      this.setUserId(data.user.id);
    }

    return data;
  }
};

// Make api available globally
window.api = api;
