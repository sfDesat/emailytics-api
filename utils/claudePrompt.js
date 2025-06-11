module.exports = function buildClaudePrompt({ sender, subject, emailContent, plan = 'free' }) {
  const CATEGORY_PROMPTS = {
    priority: '1. "priority": What is the urgency? ("High", "Medium", "Low")',
    intent: '2. "intent": What is the sender’s intention?',
    tasks: '3. "tasks": Up to 2 requested action items. Each ≤ 100 characters.',
    sentiment: '4. "sentiment": Is the sentiment positive, neutral, or negative?',
    tone: '5. "tone": Describe the tone. Choose: "Professional", "Polite", "Casual", "Frustrated", "Excited", "Demanding", or "Neutral".',
    deadline: '6. "deadline": Deadline in ISO format (e.g., "2025-06-09"), or "null".',
    confidence: '7. "confidence": From 0 to 100, how confident are you in your ability to extract this information?'
  };

  const PLAN_FEATURES = {
    free: ['priority', 'intent'],
    standard: ['priority', 'intent', 'tasks', 'sentiment'],
    pro: ['priority', 'intent', 'tasks', 'sentiment', 'tone', 'deadline', 'confidence']
  };

  const features = PLAN_FEATURES[plan] || PLAN_FEATURES.free;
  const body = features.map(f => CATEGORY_PROMPTS[f]).join('\n');

  return `You are an expert email assistant. Analyze the email message below and return a structured JSON response with only the following fields:

${body}

Only return a JSON object. Do not explain your reasoning.

Email Details:
Sender: ${sender || 'Unknown'}
Subject: ${subject || 'No subject'}
Content: ${emailContent}`;
};
