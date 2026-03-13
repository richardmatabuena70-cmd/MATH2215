-- Math Quiz Game Database Setup
-- Run this script in MySQL Workbench or command line
--
-- Command line usage:
-- mysql -u root -p < database.sql

-- Create database
CREATE DATABASE IF NOT EXISTS math_quiz_game;
USE math_quiz_game;

-- Drop existing tables if needed (for fresh setup)
-- DROP TABLE IF EXISTS quiz_questions;
-- DROP TABLE IF EXISTS quiz_sessions;
-- DROP TABLE IF EXISTS user_achievements;
-- DROP TABLE IF EXISTS user_stats;
-- DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  theme VARCHAR(50) DEFAULT 'dark',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create user_stats table for tracking daily streaks and statistics
CREATE TABLE IF NOT EXISTS user_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  total_games INT DEFAULT 0,
  total_correct INT DEFAULT 0,
  total_questions INT DEFAULT 0,
  highest_score INT DEFAULT 0,
  current_streak INT DEFAULT 0,
  longest_streak INT DEFAULT 0,
  last_played_date DATE DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create achievements table
CREATE TABLE IF NOT EXISTS achievements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL,
  icon VARCHAR(50) NOT NULL,
  requirement_type VARCHAR(50) NOT NULL,
  requirement_value INT NOT NULL,
  points INT DEFAULT 10
);

-- Insert default achievements
INSERT INTO achievements (name, description, icon, requirement_type, requirement_value, points) VALUES
('First Steps', 'Complete your first quiz', '🎯', 'games', 1, 10),
('Getting Started', 'Complete 10 quizzes', '🌟', 'games', 10, 25),
('Quiz Master', 'Complete 50 quizzes', '🏆', 'games', 50, 50),
('Math Wizard', 'Complete 100 quizzes', '🧙', 'games', 100, 100),
('Perfect Score', 'Get 100% on a quiz', '💯', 'perfect', 1, 30),
('Streak Starter', 'Achieve a 3-day streak', '🔥', 'streak', 3, 20),
('On Fire', 'Achieve a 7-day streak', '💥', 'streak', 7, 40),
('Unstoppable', 'Achieve a 30-day streak', '🚀', 'streak', 30, 100),
('Speed Demon', 'Answer 50 questions correctly', '⚡', 'correct', 50, 25),
('Math Genius', 'Answer 200 questions correctly', '🧠', 'correct', 200, 75),
('High Scorer', 'Score over 80 points in one game', '🎖️', 'score', 80, 20),
('Addition Expert', 'Answer 50 addition questions correctly', '➕', 'addition', 50, 30),
('Subtraction Expert', 'Answer 50 subtraction questions correctly', '➖', 'subtraction', 50, 30),
('Multiplication Expert', 'Answer 50 multiplication questions correctly', '✖️', 'multiplication', 50, 30),
('Division Expert', 'Answer 50 division questions correctly', '➗', 'division', 50, 30);

-- Create user_achievements table
CREATE TABLE IF NOT EXISTS user_achievements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  achievement_id INT NOT NULL,
  earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (achievement_id) REFERENCES achievements(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_achievement (user_id, achievement_id)
);

-- Create quiz_sessions table (updated with category)
CREATE TABLE IF NOT EXISTS quiz_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  difficulty VARCHAR(50) NOT NULL,
  category VARCHAR(50) DEFAULT 'mixed',
  score INT NOT NULL,
  time_left INT NOT NULL,
  total_questions INT DEFAULT 10,
  correct_answers INT DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create quiz_questions table
CREATE TABLE IF NOT EXISTS quiz_questions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_id INT NOT NULL,
  question_number INT NOT NULL,
  question TEXT NOT NULL,
  correct_answer INT NOT NULL,
  user_answer INT,
  is_correct INT,
  FOREIGN KEY (session_id) REFERENCES quiz_sessions(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_quiz_sessions_user ON quiz_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_session ON quiz_questions(session_id);
CREATE INDEX IF NOT EXISTS idx_user_stats_user ON user_stats(user_id);
CREATE INDEX IF NOT EXISTS idx_user_achievements_user ON user_achievements(user_id);

-- Verify tables created
SELECT 'Users table:' AS '';
DESCRIBE users;

SELECT 'User Stats table:' AS '';
DESCRIBE user_stats;

SELECT 'Achievements table:' AS '';
DESCRIBE achievements;

SELECT 'User Achievements table:' AS '';
DESCRIBE user_achievements;

SELECT 'Quiz Sessions table:' AS '';
DESCRIBE quiz_sessions;

SELECT 'Quiz Questions table:' AS '';
DESCRIBE quiz_questions;

SELECT 'Database math_quiz_game is ready!' AS 'Status';
