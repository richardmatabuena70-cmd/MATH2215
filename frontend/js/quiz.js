let quizData = [];
let currentIndex = 0;
let userAnswers = [];
let questionTimer = 0;
let timerInterval = null;
let cameFromProgress = false;
let currentSessionId = null;
let currentUser = null;
let currentDifficulty = 'easy';
let currentCategory = 'mixed'; // NEW: Addition, Subtraction, Multiplication, Division, Mixed
let totalTimeLeft = 0; // Track total remaining time across all questions
let gameMode = 'timed'; // 'timed' mode only

// Math Category Configuration
const MATH_CATEGORIES = {
  addition: { name: '➕ Addition', symbol: '➕', desc: 'Sum of numbers', color: '#10b981' },
  subtraction: { name: '➖ Subtraction', symbol: '➖', desc: 'Difference of numbers', color: '#3b82f6' },
  multiplication: { name: '✖️ Multiplication', symbol: '✖️', desc: 'Product of numbers', color: '#f59e0b' },
  division: { name: '➗ Division', symbol: '➗', desc: 'Quotient of numbers', color: '#ec4899' },
  mixed: { name: '🎲 Mixed', symbol: '🎲', desc: 'All operations', color: '#8b5cf6' }
};

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
  if (e.target.id === 'startQuiz' || 
      e.target.id === 'restartQuiz' ||
      e.target.textContent.match(/^(Easy|Medium|Hard)$/)) {
    SoundManager.playSidebarClick();
  } else {
    SoundManager.playUIClick();
  }
}, true);

function generateQuestions() {
  quizData = [];

  let max;
  if (currentDifficulty === "easy") max = 10;
  else if (currentDifficulty === "medium") max = 30;
  else max = 100; // hard

  const operations = currentCategory === 'mixed' 
    ? ['addition', 'subtraction', 'multiplication', 'division']
    : [currentCategory];

  for (let i = 0; i < 10; i++) {
    let a = Math.floor(Math.random() * max) + 1;
    let b = Math.floor(Math.random() * max) + 1;

    let question, correct, operation;
    
    // Select operation based on category
    if (currentCategory === 'mixed') {
      operation = operations[Math.floor(Math.random() * operations.length)];
    } else {
      operation = currentCategory;
    }

    // Generate question based on operation
    switch(operation) {
      case 'addition':
        correct = a + b;
        question = `${a} + ${b} = ?`;
        break;
      case 'subtraction':
        // Ensure no negative for easy/medium
        if (currentDifficulty !== 'hard' && b > a) [a, b] = [b, a];
        correct = a - b;
        question = `${a} − ${b} = ?`;
        break;
      case 'multiplication':
        // Limit numbers for easy mode
        if (currentDifficulty === 'easy') {
          a = Math.floor(Math.random() * 10) + 1;
          b = Math.floor(Math.random() * 10) + 1;
        }
        correct = a * b;
        question = `${a} × ${b} = ?`;
        break;
      case 'division':
        // Make sure division is exact
        b = Math.floor(Math.random() * 10) + 1; // Divisor 1-10
        if (currentDifficulty === 'easy') {
          a = b * (Math.floor(Math.random() * 10) + 1); // Result 1-10
        } else {
          a = b * (Math.floor(Math.random() * max / 10) + 1);
        }
        correct = a / b;
        question = `${a} ÷ ${b} = ?`;
        break;
      default:
        correct = a + b;
        question = `${a} + ${b} = ?`;
    }

    // Generate choices
    let choices = new Set([correct]);
    while (choices.size < 3) {
      let offset = Math.floor(Math.random() * 10) - 5;
      if (offset === 0) offset = 1;
      choices.add(correct + offset);
    }

    quizData.push({
      question,
      choices: [...choices].sort(() => Math.random() - 0.5),
      answer: correct,
      operation: operation
    });
  }
}

function getQuestionTimeLimit() {
  // Easy: 5 seconds per question
  // Medium: 7 seconds per question
  // Hard: 10 seconds per question
  if (currentDifficulty === "medium") {
    return 7;
  } else if (currentDifficulty === "hard") {
    return 10;
  }
  return 5; // easy
}

async function loadGame() {
  generateQuestions();
  userAnswers = Array(10).fill(null);
  currentIndex = 0;
  
  // Get game mode from window variable (set by dashboard.js)
  gameMode = window.gameMode || 'timed';
  
  // Use actual timer for all games
  questionTimer = getQuestionTimeLimit();
  totalTimeLeft = getQuestionTimeLimit() * 10; // 10 questions
  
  currentUser = api.getUserFromStorage();
  
  // Start quiz session in database
  try {
    const result = await api.startQuiz(currentDifficulty, totalTimeLeft);
    currentSessionId = result.sessionId;
    
    // Save questions to database
    for (let i = 0; i < quizData.length; i++) {
      await api.addQuestion(currentSessionId, i + 1, quizData[i].question, quizData[i].answer);
    }
    
    // Save initial data to sessionStorage for later retrieval
    sessionStorage.setItem('quizData', JSON.stringify(quizData));
    sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
    sessionStorage.setItem('totalTimeLeft', totalTimeLeft.toString());
    sessionStorage.setItem('currentDifficulty', currentDifficulty);
  } catch (error) {
    console.error('Failed to start quiz session:', error);
  }
  
  // Start quiz timer
  startQuestionTimer();
  renderQuestion();
}

function renderQuestion() {
  // para sa Game Over Screen
  if (currentIndex >= quizData.length) {
    showGameOverScreen();
    return; 
  }

  // para lang sa button highlight sa question view
  let q = quizData[currentIndex];

  let backButton = cameFromProgress
    ? `<button onclick="backToProgress()">⬅ Back to Question Progress</button>`
    : "";

  content.classList.add('quiz-mode');
  
  // Always show timer in timed mode
  const timerDisplay = `<div class="timer-display" style="font-size: 28px; font-weight: bold; margin-bottom: 15px; color: ${questionTimer <= 3 ? '#ff4444' : 'inherit'};">
      ⏱ ${questionTimer}s
    </div>`;
  
  const difficultyLabel = currentDifficulty.toUpperCase();
  const categoryLabel = currentCategory.charAt(0).toUpperCase() + currentCategory.slice(1);
  const modeLabel = '⏱';
  
  content.innerHTML = `
    <div class="quiz-container" style="text-align: center;">
      ${backButton}
      ${timerDisplay}
      <h2>Question ${currentIndex + 1}/10 (${difficultyLabel} • ${categoryLabel}) ${modeLabel}</h2>
      <h3>${q.question}</h3>

      <div class="choices-container" style="display: flex; flex-direction: row; justify-content: center; gap: 15px; flex-wrap: wrap;">
        ${q.choices
          .map(
            (c) => `
          <button class="${userAnswers[currentIndex] === c ? "selected" : ""}"
            onclick="selectAnswer(${c})" style="min-width: 120px; padding: 12px 24px; border-radius: 25px; text-align: center;">${c}</button>
        `,
          )
          .join("")}
      </div>

      <div style="margin-top: 20px; text-align: center;">
        <button onclick="prevQuestion()" style="border-radius: 20px; padding: 10px 30px;">Previous</button>
        <button onclick="nextQuestion()" style="border-radius: 20px; padding: 10px 30px;">Next</button>
      </div>
    </div>
  `;

  updateTextColors();

  function backToProgress() {
    cameFromProgress = false;
    showQuizProgress();
  }

  const isLight = document.body.classList.contains("light-theme");
  const selectedBg = isLight ? "#0021b4" : "#000ed3";
  const selectedText = isLight ? "#000000" : "#ffffff";

  document.querySelectorAll("button.selected").forEach((b) => {
    b.style.backgroundColor = selectedBg;
    b.style.color = selectedText;
  });
}

function startQuestionTimer() {
  clearInterval(timerInterval);
  
  timerInterval = setInterval(() => {
    questionTimer--;
    totalTimeLeft--; // Track total remaining time
    updateTimerDisplay();
    
    // Play tick sound for last 3 seconds
    if (questionTimer <= 3) {
      SoundManager.playTick();
    }
    
    if (questionTimer <= 0) {
      clearInterval(timerInterval);
      // Time's up - move to next question (no answer)
      nextQuestion();
    }
  }, 1000);
}

function updateTimerDisplay() {
  const timerEl = document.querySelector('.timer-display');
  if (timerEl) {
    const timeDisplay = `${questionTimer}s`;
    timerEl.textContent = `⏱ ${timeDisplay}`;
    // Turn red when less than 3 seconds
    timerEl.style.color = questionTimer <= 3 ? '#ff4444' : 'inherit';
  }
}

async function selectAnswer(ans) {
  // Initialize audio context on user interaction
  SoundManager.init();
  
  const isCorrect = ans === quizData[currentIndex].answer;
  
  // Play sound based on answer
  if (isCorrect) {
    SoundManager.playCorrect();
  } else {
    SoundManager.playWrong();
  }
  
  userAnswers[currentIndex] = ans;
  
  // Save to sessionStorage for later retrieval
  sessionStorage.setItem('quizData', JSON.stringify(quizData));
  sessionStorage.setItem('userAnswers', JSON.stringify(userAnswers));
  sessionStorage.setItem('totalTimeLeft', totalTimeLeft.toString());
  sessionStorage.setItem('currentDifficulty', currentDifficulty);
  
  // Submit answer to database
  if (currentSessionId) {
    try {
      await api.submitAnswer(currentSessionId, currentIndex + 1, ans);
    } catch (error) {
      console.error('Failed to submit answer:', error);
    }
  }
  
  // Re-render to show selected answer (stay on current question)
  renderQuestion();
}

async function goToQuestion(index) {
  cameFromProgress = true;
  currentIndex = index;

  // Load last quiz from database
  try {
    const history = await api.getHistory();
    if (history && history.length > 0) {
      const lastGame = history[0];
      currentSessionId = lastGame.id;
      quizData = lastGame.questions.map(q => ({
        question: q.question,
        answer: q.correct_answer,
        choices: []
      }));
      userAnswers = lastGame.questions.map(q => q.user_answer);
    }
  } catch (error) {
    console.error('Failed to load quiz:', error);
  }

  renderQuestion();
}

function backToProgress() {
  cameFromProgress = false;
  showLiveProgress();
}

function nextQuestion() {
  if (currentIndex >= quizData.length - 1) {
    finishQuiz(); 
    return;
  }
  currentIndex++;
  // Reset timer for new question only in timed mode
  if (gameMode === 'timed') {
    questionTimer = getQuestionTimeLimit();
    startQuestionTimer();
  }
  renderQuestion();
}

function prevQuestion() {
  if (currentIndex > 0) {
    currentIndex--;
    // Reset timer for current question only in timed mode
    if (gameMode === 'timed') {
      questionTimer = getQuestionTimeLimit();
      startQuestionTimer();
    }
  }
  renderQuestion();
}

async function finishQuiz() {
  clearInterval(timerInterval);

  // Calculate score from current quiz data
  let correct = 0;
  quizData.forEach((q, i) => {
    if (userAnswers[i] === q.answer) correct++;
  });

  const score = correct * 10;
  
  // Initialize audio context
  SoundManager.init();
  
  // Play game over or victory sound based on score
  if (correct >= 7) {
    SoundManager.playVictory();
  } else {
    SoundManager.playGameOver();
  }

  // Finish quiz in database
  if (currentSessionId) {
    try {
      await api.finishQuiz(currentSessionId, score, totalTimeLeft);
    } catch (error) {
      console.error('Failed to finish quiz:', error);
    }
  }

  //  show game over screen pagtapos ng quiz
  showGameOverScreen();
}

function showGameOverScreen() {
  content.classList.remove('quiz-mode');
  
  // Calculate stats from current quiz
  let correct = 0;
  let wrong = 0;
  let unanswered = 0;

  quizData.forEach((q, i) => {
    if (userAnswers[i] === null || userAnswers[i] === undefined) {
      unanswered++;
    } else if (userAnswers[i] === q.answer) {
      correct++;
    } else {
      wrong++;
    }
  });

  const score = correct * 10;
  const user = currentUser || api.getUserFromStorage();

  content.innerHTML = `
    <div style="
      max-width:800px;
      margin:40px auto;
      padding:25px;
      border-radius:12px;
      text-align:center;
      background:#1e1e1e;
      color:white;
    ">
      <h1>🎮 Game Over</h1>
      <h2>${user ? user.name : 'Player'}</h2>
      <p><b>Difficulty:</b> ${currentDifficulty.toUpperCase()}</p>

      <p><b>Score:</b> ${score} / ${quizData.length * 10}</p>
      <p>✅ Correct: ${correct}</p>
      <p>❌ Wrong: ${wrong}</p>
      <p>⚪ Unanswered: ${unanswered}</p>

      <div style="margin-top:20px">
        <button onclick="showQuizAnswers()">📋 Review Answers</button>
        <button onclick="showQuizProgress()">📊 Question Progress</button>
        <button onclick="playAgain()">🔁 Play Again</button>
      </div>
    </div>
  `;
}

function chooseLevel() {
  content.classList.add('quiz-mode');
  content.innerHTML = `
    <div style="text-align: center;">
      <h2>Select Quiz Level</h2>
      <p><b>Easy:</b> 5 seconds per question</p>
      <p><b>Medium:</b> 7 seconds per question</p>
      <p><b>Hard:</b> 10 seconds per question</p>
      <div id="level-buttons" style="display: flex; flex-direction: row; justify-content: center; gap: 15px; margin-top: 20px;">
        <button onclick="selectLevel('easy')" style="min-width: 120px; padding: 12px 24px; border-radius: 25px;">Easy</button>
        <button onclick="selectLevel('medium')" style="min-width: 120px; padding: 12px 24px; border-radius: 25px;">Medium</button>
        <button onclick="selectLevel('hard')" style="min-width: 120px; padding: 12px 24px; border-radius: 25px;">Hard</button>
      </div>
      <div id="confirm-start" style="display: none; margin-top: 30px;">
        <p id="selected-level-text" style="font-size: 18px; margin-bottom: 15px;"></p>
        <button onclick="confirmStartQuiz()" style="min-width: 200px; padding: 15px 30px; border-radius: 25px; background: #28a745; color: white; font-size: 16px; font-weight: bold;">✓ Start Quiz</button>
        <button onclick="resetLevelSelection()" style="min-width: 120px; padding: 12px 24px; border-radius: 25px; margin-left: 10px;">Cancel</button>
      </div>
    </div>
  `;
}

// Store selected level temporarily
let selectedLevel = null;

function selectLevel(level) {
  selectedLevel = level;
  
  // Hide level buttons, show confirmation
  document.getElementById('level-buttons').style.display = 'none';
  document.getElementById('confirm-start').style.display = 'block';
  
  // Update the text
  const levelNames = { 'easy': 'Easy', 'medium': 'Medium', 'hard': 'Hard' };
  document.getElementById('selected-level-text').innerHTML = `You selected: <b>${levelNames[level]}</b> mode`;
}

function resetLevelSelection() {
  selectedLevel = null;
  document.getElementById('level-buttons').style.display = 'flex';
  document.getElementById('confirm-start').style.display = 'none';
}

function confirmStartQuiz() {
  if (selectedLevel) {
    startQuiz(selectedLevel);
  }
}

// Theme toggle function - syncs with dashboard toggle
function toggleTheme() {
  const checkbox = document.getElementById('themeToggle');
  const label = document.getElementById('themeLabel');
  
  if (checkbox && label) {
    if (checkbox.checked) {
      document.body.classList.add('light-theme');
      label.textContent = 'Light Mode';
      api.updateTheme('light').catch(console.error);
    } else {
      document.body.classList.remove('light-theme');
      label.textContent = 'Dark Mode';
      api.updateTheme('dark').catch(console.error);
    }
  } else {
    document.body.classList.toggle("light-theme");
  }
  updateTextColors();
}

function updateTextColors() {
  const isLight = document.body.classList.contains("light-theme");
  const textColor = isLight ? "#000000" : "#ffffff";
  const panelColor = isLight ? "#ffffff" : "#1e1e1e";
  const buttonBg = isLight ? "#f0f0f0" : "#2a2a2a";
  const buttonText = isLight ? "#000000" : "#ffffff";

  document.body.style.color = textColor;
  document.body.style.backgroundColor = isLight ? "#f5f5f5" : "#111111";

  const panels = document.querySelectorAll(".panel");
  panels.forEach((p) => {
    p.style.backgroundColor = panelColor;
    p.style.color = textColor;
  });

  const inputs = document.querySelectorAll("input");
  inputs.forEach((i) => {
    i.style.backgroundColor = isLight ? "#ffffff" : "#333333";
    i.style.color = textColor;
    i.style.borderColor = isLight ? "#ccc" : "#555";
  });

  const buttons = document.querySelectorAll("button");
  buttons.forEach((b) => {
    b.style.backgroundColor = buttonBg;
    b.style.color = buttonText;
  });

  const contentArea = document.getElementById("content");
  if (contentArea) {
    contentArea.style.color = textColor;
  }
}

window.onload = function () {
  const checkbox = document.getElementById('themeToggle');
  const label = document.getElementById('themeLabel');
  
  if (checkbox && label) {
    const isLight = document.body.classList.contains('light-theme');
    checkbox.checked = isLight;
    label.textContent = isLight ? 'Light Mode' : 'Dark Mode';
  }
  
  updateTextColors();
};

// Show Answers / Review Responses (for quiz game over screen)
function showQuizAnswers() {
  content.classList.remove('quiz-mode');
  
  let html = '<div style="max-width:800px;margin:40px auto;padding:25px;border-radius:12px;background:#1e1e1e;color:white;">';
  html += '<h2>📋 Review Answers</h2>';
  
  quizData.forEach((q, i) => {
    const userAns = userAnswers[i];
    const isCorrect = userAns === q.answer;
    const status = userAns === null ? '⚪ Unanswered' : (isCorrect ? '✅ Correct' : '❌ Wrong');
    const userAnswerText = userAns === null ? 'No Answer' : userAns;
    
    html += `<div style="margin:15px 0;padding:15px;border-radius:8px;background:${isCorrect ? '#1b5e20' : '#b71c1c'}">`;
    html += `<p><strong>Q${i+1}:</strong> ${q.question}</p>`;
    html += `<p><strong>Your Answer:</strong> ${userAnswerText}</p>`;
    html += `<p><strong>Correct Answer:</strong> ${q.answer}</p>`;
    html += `<p><strong>Status:</strong> ${status}</p>`;
    html += '</div>';
  });
  
  html += '<button onclick="showGameOverScreen()" style="margin-top:20px;padding:10px 30px;border-radius:20px;">Back to Game Over</button>';
  html += '</div>';
  
  content.innerHTML = html;
}

// Show Question Progress (for quiz game over screen)
function showQuizProgress() {
  content.classList.remove('quiz-mode');
  
  let html = '<div style="max-width:800px;margin:40px auto;padding:25px;border-radius:12px;background:#1e1e1e;color:white;">';
  html += '<h2>📊 Question Progress</h2>';
  
  let answered = 0;
  let correct = 0;
  let wrong = 0;
  let unanswered = 0;
  
  quizData.forEach((q, i) => {
    const userAns = userAnswers[i];
    const isCorrect = userAns === q.answer;
    
    if (userAns === null) {
      unanswered++;
    } else if (isCorrect) {
      correct++;
      answered++;
    } else {
      wrong++;
      answered++;
    }
    
    const status = userAns === null ? '⚪' : (isCorrect ? '✅' : '❌');
    html += `<div style="margin:10px 0;padding:10px;border-radius:5px;background:#333;">`;
    html += `<span style="font-size:24px;margin-right:10px;">${status}</span>`;
    html += `<span>Q${i+1}:</span> <span style="opacity:0.8">${q.question}</span>`;
    html += '</div>';
  });
  
  html += '<div style="margin-top:20px;padding:15px;background:#333;border-radius:8px;">';
  html += `<p>Answered: ${answered}/${quizData.length}</p>`;
  html += `<p>✅ Correct: ${correct}</p>`;
  html += `<p>❌ Wrong: ${wrong}</p>`;
  html += `<p>⚪ Unanswered: ${unanswered}</p>`;
  html += '</div>';
  
  html += '<div style="margin-top:20px;">';
  html += '<button onclick="showGameOverScreen()" style="margin-right:10px;padding:10px 30px;border-radius:20px;">Back</button>';
  
  // Add buttons to go to each question
  html += '<div style="margin-top:15px;">';
  quizData.forEach((q, i) => {
    html += `<button onclick="goToQuestionFromProgress(${i})" style="margin:5px;padding:8px 15px;border-radius:5px;">Q${i+1}</button>`;
  });
  html += '</div>';
  
  html += '</div>';
  html += '</div>';
  
  content.innerHTML = html;
}

// Go to question from progress screen
function goToQuestionFromProgress(index) {
  currentIndex = index;
  cameFromProgress = true;
  renderQuestion();
}

function playAgain() {
  userAnswers = [];
  quizData = [];
  currentIndex = 0;
  questionTimer = 0;
  cameFromProgress = false;
  currentSessionId = null;
  clearInterval(timerInterval);

  chooseLevel();
}
