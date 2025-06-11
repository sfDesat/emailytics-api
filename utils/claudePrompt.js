module.exports = function buildClaudePrompt({ sender, subject, emailContent }) {
  return `You are an expert email assistant. Analyze the email message below and return a structured JSON response with the following fields:

1. "priority": What is the urgency of the email? Choose: "High", "Medium", or "Low".
2. "intent": What is the sender’s main intention? (e.g., scheduling, requesting info, following up, etc.)
3. "tone": Describe the tone. Choose from: "Professional", "Polite", "Casual", "Frustrated", "Excited", "Demanding", or "Neutral".
4. "sentiment": Is the sentiment positive, neutral, or negative?
5. "tasks": A list of up to 2 action items the sender is requesting. Each task should be ≤ 100 characters and phrased as a clear instruction.
6. "deadline": If a deadline is mentioned, extract it in ISO 8601 format (e.g., "2025-06-09"). If no deadline is present, write "null".
7. "ai_confidence": From 0 to 100, how confident are you in your ability to correctly extract the information from this email? Consider clarity, length, grammar, and structure.

Only return a JSON object. Do not explain your reasoning.

Email Details:
Sender: ${sender || 'Unknown'}
Subject: ${subject || 'No subject'}
Content: ${emailContent}`;
};
