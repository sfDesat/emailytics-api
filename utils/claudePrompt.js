module.exports = function buildClaudePrompt({ sender, subject, emailContent }) {
  return `Analyze this email and return ONLY a valid JSON object with these exact fields:
- urgency: number from 1-10 (10 = extremely urgent)
- response_pressure: "none", "low", "medium", "high"  
- action_type: "information", "question", "request", "task", "feedback", or "meeting"
- has_money_request: true or false
- money_details: object with amount, due_date, type (null if no money involved)
- ai_confidence: number from 1-10
- sentiment: "positive", "neutral", "negative", or "mixed"

Email Details:
Sender: ${sender || 'Unknown'}
Subject: ${subject || 'No subject'}
Content: ${emailContent}

Return only the JSON, no other text.`;
};
