const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'math-quiz-game-secret-key-2024';

// Rate limiting
const rateLimit = require('express-rate-limit');

// PostgreSQL Connection Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // 25 requests per window
  message: { error: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per window
  message: { error: 'Too many login attempts, please try again in 15 minutes.' }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// JWT Token verification middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Database initialization - tables created via Supabase SQL Editor
// This function verifies connection and logs status
async function initDatabase() {
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('Database connected successfully at:', result.rows[0].now);
    
    // Check if tables exist
    const tableCheck = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    const tables = tableCheck.rows.map(r => r.table_name);
    console.log('Existing tables:', tables);
    
  } catch (error) {
    console.error('Database connection error:', error.message);
  }
}

// Initialize database connection
initDatabase();

// Input validation helpers
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validateName(name) {
  return name && name.trim().length >= 2 && name.trim().length <= 50 && /^[a-zA-Z\s]+$/.test(name.trim());
}

function validatePassword(password) {
  return password && password.length >= 4 && password.length <= 50;
}

function validateDifficulty(difficulty) {
  return ['easy', 'medium', 'hard'].includes(difficulty);
}

// ============ AUTH ROUTES ============

// Register with rate limiting
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Server-side validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!validateName(name)) {
      return res.status(400).json({ error: 'Name must be 2-50 characters and contain only letters' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be 4-50 characters' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user exists
    const existingUsers = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_deleted = 0',
      [normalizedEmail]
    );
    if (existingUsers.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if deleted user with same email exists
    const deletedUsers = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_deleted = 1',
      [normalizedEmail]
    );

    if (deletedUsers.rows.length > 0) {
      // Restore deleted user
      const hashedPassword = bcrypt.hashSync(password, 10);
      await pool.query(
        'UPDATE users SET password = $1, name = $2, is_deleted = 0, deleted_at = NULL WHERE id = $3',
        [hashedPassword, name.trim(), deletedUsers.rows[0].id]
      );

      const token = jwt.sign({ id: deletedUsers.rows[0].id, email: normalizedEmail }, JWT_SECRET, { expiresIn: '24h' });
      return res.json({
        success: true,
        token,
        user: { id: deletedUsers.rows[0].id, name: name.trim(), email: normalizedEmail, theme: 'dark' }
      });
    }

    // Create new user
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, theme',
      [name.trim(), normalizedEmail, hashedPassword]
    );

    const newUser = result.rows[0];
    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: { id: newUser.id, name: newUser.name, email: newUser.email, theme: newUser.theme }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login with rate limiting
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_deleted = 0',
      [normalizedEmail]
    );
    const user = result.rows[0];

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, theme: user.theme }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Restore deleted user and login (no rate limiting for restore)
app.post('/api/auth/restore', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user exists and is deleted
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_deleted = 1',
      [normalizedEmail]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'No deleted account found with this email' });
    }

    // Verify password
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Restore the account
    await pool.query('UPDATE users SET is_deleted = 0, deleted_at = NULL WHERE id = $1', [user.id]);

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, theme: user.theme, is_deleted: 0 }
    });
  } catch (error) {
    console.error('Restore error:', error);
    res.status(500).json({ error: 'Failed to restore account' });
  }
});

// Get all users (for admin display)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, theme, is_deleted, deleted_at, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Get user by ID (must be after /api/users to avoid conflict)
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId) || userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await pool.query(
      'SELECT id, name, email, theme, is_deleted, deleted_at, created_at FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Restore deleted user
app.post('/api/users/restore', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_deleted = 0, deleted_at = NULL WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: 'Account restored' });
  } catch (error) {
    console.error('Restore user error:', error);
    res.status(500).json({ error: 'Failed to restore account' });
  }
});

// Soft delete user (set is_deleted = 1)
app.delete('/api/users', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_deleted = 1, deleted_at = NOW() WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: 'Account deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Permanent delete user
app.delete('/api/users/permanent', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    // Verify password before deletion
    const result = await pool.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Permanently delete user (cascade will delete quiz sessions and questions)
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: 'Account permanently deleted' });
  } catch (error) {
    console.error('Permanent delete user error:', error);
    res.status(500).json({ error: 'Failed to permanently delete account' });
  }
});

// Update theme
app.put('/api/auth/theme', authenticateToken, async (req, res) => {
  try {
    const { theme } = req.body;

    if (!['dark', 'light'].includes(theme)) {
      return res.status(400).json({ error: 'Invalid theme' });
    }

    await pool.query('UPDATE users SET theme = $1 WHERE id = $2', [theme, req.user.id]);
    res.json({ success: true, theme });
  } catch (error) {
    console.error('Update theme error:', error);
    res.status(500).json({ error: 'Failed to update theme' });
  }
});

// ============ QUIZ ROUTES ============

// Get user stats
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    let result = await pool.query('SELECT * FROM user_stats WHERE user_id = $1', [req.user.id]);

    if (result.rows.length === 0) {
      // Create stats if not exists
      await pool.query('INSERT INTO user_stats (user_id) VALUES ($1)', [req.user.id]);
      result = await pool.query('SELECT * FROM user_stats WHERE user_id = $1', [req.user.id]);
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Get achievements
app.get('/api/achievements', authenticateToken, async (req, res) => {
  try {
    // Get all achievements
    const allAchievements = await pool.query('SELECT * FROM achievements ORDER BY points');

    // Get user's earned achievements
    const userAchievements = await pool.query(
      'SELECT achievement_id, earned_at FROM user_achievements WHERE user_id = $1',
      [req.user.id]
    );

    const earnedIds = new Set(userAchievements.rows.map(a => a.achievement_id));

    const achievements = allAchievements.rows.map(achievement => ({
      ...achievement,
      earned: earnedIds.has(achievement.id),
      earned_at: userAchievements.rows.find(u => u.achievement_id === achievement.id)?.earned_at
    }));

    res.json(achievements);
  } catch (error) {
    console.error('Get achievements error:', error);
    res.status(500).json({ error: 'Failed to get achievements' });
  }
});

// Save quiz session
app.post('/api/quiz/save', authenticateToken, async (req, res) => {
  try {
    const { difficulty, category, score, timeLeft, questions, correctAnswers } = req.body;

    if (!difficulty || score === undefined || timeLeft === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!validateDifficulty(difficulty)) {
      return res.status(400).json({ error: 'Invalid difficulty' });
    }

    // Create quiz session
    const sessionResult = await pool.query(
      `INSERT INTO quiz_sessions (user_id, difficulty, category, score, time_left, total_questions, correct_answers)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [req.user.id, difficulty, category || 'mixed', score, timeLeft, questions?.length || 10, correctAnswers || 0]
    );

    const sessionId = sessionResult.rows[0].id;

    // Save questions
    if (questions && questions.length > 0) {
      for (let i = 0; i < questions.length; i++) {
        await pool.query(
          `INSERT INTO quiz_questions (session_id, question_number, question, correct_answer, user_answer, is_correct)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            sessionId,
            i + 1,
            JSON.stringify(questions[i]),
            questions[i].correctAnswer,
            questions[i].userAnswer,
            questions[i].isCorrect ? 1 : 0
          ]
        );
      }
    }

    // Update user stats
    const statsResult = await pool.query('SELECT * FROM user_stats WHERE user_id = $1', [req.user.id]);

    if (statsResult.rows.length === 0) {
      await pool.query(
        'INSERT INTO user_stats (user_id, total_games, total_correct, total_questions, highest_score, last_played_date) VALUES ($1, 1, $2, $3, $4, CURRENT_DATE)',
        [req.user.id, correctAnswers || 0, questions?.length || 10, score]
      );
    } else {
      const stats = statsResult.rows[0];
      const newHighestScore = Math.max(stats.highest_score, score);
      const today = new Date().toISOString().split('T')[0];
      const lastPlayed = stats.last_played_date ? stats.last_played_date.toISOString().split('T')[0] : null;

      let newStreak = stats.current_streak;
      if (lastPlayed !== today) {
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        const yesterdayStr = yesterday.toISOString().split('T')[0];

        if (lastPlayed === yesterdayStr) {
          newStreak = stats.current_streak + 1;
        } else if (lastPlayed !== today) {
          newStreak = 1;
        }
      }

      const newLongestStreak = Math.max(stats.longest_streak, newStreak);

      await pool.query(
        `UPDATE user_stats SET
          total_games = total_games + 1,
          total_correct = total_correct + $1,
          total_questions = total_questions + $2,
          highest_score = $3,
          current_streak = $4,
          longest_streak = $5,
          last_played_date = CURRENT_DATE
        WHERE user_id = $6`,
        [correctAnswers || 0, questions?.length || 10, newHighestScore, newStreak, newLongestStreak, req.user.id]
      );
    }

    // Check and award achievements
    await checkAndAwardAchievements(req.user.id, score, correctAnswers || 0);

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Save quiz error:', error);
    res.status(500).json({ error: 'Failed to save quiz' });
  }
});

// Get quiz history
app.get('/api/quiz/history', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT qs.*, 
        (SELECT COUNT(*) FROM quiz_questions WHERE session_id = qs.id AND is_correct = 1) as correct
       FROM quiz_sessions qs
       WHERE qs.user_id = $1
       ORDER BY qs.created_at DESC
       LIMIT 20`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// Helper function to check and award achievements
async function checkAndAwardAchievements(userId, score, correctAnswers) {
  try {
    // Get current stats
    const statsResult = await pool.query('SELECT * FROM user_stats WHERE user_id = $1', [userId]);
    if (statsResult.rows.length === 0) return;

    const stats = statsResult.rows[0];

    // Get all achievements
    const achievementsResult = await pool.query('SELECT * FROM achievements');
    const achievements = achievementsResult.rows;

    // Get user's already earned achievements
    const earnedResult = await pool.query(
      'SELECT achievement_id FROM user_achievements WHERE user_id = $1',
      [userId]
    );
    const earnedIds = new Set(earnedResult.rows.map(e => e.achievement_id));

    for (const achievement of achievements) {
      if (earnedIds.has(achievement.id)) continue;

      let earned = false;

      switch (achievement.requirement_type) {
        case 'games':
          earned = stats.total_games >= achievement.requirement_value;
          break;
        case 'correct':
          earned = stats.total_correct >= achievement.requirement_value;
          break;
        case 'score':
          earned = score && score >= achievement.requirement_value;
          break;
        case 'streak':
          earned = stats.current_streak >= achievement.requirement_value;
          break;
        case 'perfect':
          earned = score && score >= 100;
          break;
        case 'addition':
        case 'subtraction':
        case 'multiplication':
        case 'division':
          // For operation-specific achievements, we'd need more detailed tracking
          break;
      }

      if (earned) {
        await pool.query(
          'INSERT INTO user_achievements (user_id, achievement_id) VALUES ($1, $2)',
          [userId, achievement.id]
        );
        console.log(`Achievement earned: ${achievement.name}`);
      }
    }
  } catch (error) {
    console.error('Check achievements error:', error);
  }
}

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
