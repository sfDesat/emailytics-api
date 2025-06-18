module.exports = function buildClaudePrompt({
  sender,
  subject,
  emailContent,
  fields = []    // passed in from server.js = PLAN_FEATURES[plan]
}) {
  // Build a minimal JSON schema description
  const schemaLines = [
    '{',
    ...fields.map((f, i) => {
      // quote keys, comma‐separate
      const comma = i < fields.length - 1 ? ',' : '';
      switch (f) {
        case 'priority':
          return `  "priority": "High|Medium|Low"${comma}`;
        case 'intent':
          return `  "intent": "string"${comma}`;
        case 'tasks':
          return `  "tasks": ["string", ...] (max 2 items)${comma}`;
        case 'sentiment':
          return `  "sentiment": "positive|neutral|negative"${comma}`;
        case 'tone':
          return `  "tone": "Professional|Polite|Casual|Frustrated|Excited|Demanding|Neutral"${comma}`;
        case 'deadline':
          return `  "deadline": "YYYY-MM-DD" or null${comma}`;
        case 'confidence':
          return `  "ai_confidence": integer (between 0 and 100, no decimals, no quotes)${comma}`;
        default:
          return `  "${f}": "string"${comma}`;
      }
    }),
    '}'
  ].join('\n');

  return `You are an expert email assistant that analyzes emails and extract key information in JSON only.
  
Return exactly a JSON object matching this schema:
${schemaLines}

Do not include explanations. Only output the raw JSON. Confidence must be a number, no decimals.

Email:
Sender: ${sender || 'Unknown'}
Subject: ${subject || 'No subject'}
Content: ${emailContent}`;
};
