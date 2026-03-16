export const getRuleBasedResponse = (message) => {
  const lowerMessage = message.toLowerCase();

  const rules = [
    {
      keywords: ["phishing", "email scam", "suspicious email"],
      response:
        "Phishing is a cyber attack where attackers impersonate trusted entities to steal sensitive data like passwords or credit card numbers. Always verify sender emails and avoid clicking suspicious links.",
    },
    {
      keywords: ["malware", "virus", "trojan", "spyware"],
      response:
        "Malware refers to malicious software designed to harm or exploit systems. Examples include viruses, trojans, and spyware.",
    },
    {
      keywords: ["ransomware"],
      response:
        "Ransomware is a type of malware that permanently blocks access to your personal data or systems by encrypting them, and then demands a ransom for the decryption key.",
    },
    {
      keywords: ["password security", "password", "passwords"],
      response:
        "Use strong passwords with a mix of uppercase, lowercase, numbers, and special characters. Avoid reusing passwords across sites and consider using a reputable password manager.",
    },
    {
      keywords: ["suspicious link", "safe browsing", "dangerous website"],
      response:
        "Safe browsing involves verifying URLs before clicking, looking for HTTPS, avoiding downloads from untrusted sources, and keeping your browser and its security extensions updated.",
    },
  ];

  for (const rule of rules) {
    if (rule.keywords.some((keyword) => lowerMessage.includes(keyword))) {
      return rule.response;
    }
  }

  // Return null if no rule matches, triggering the Groq API fallback
  return null;
};
