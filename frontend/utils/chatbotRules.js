export const getRuleBasedResponse = (message, language = "en") => {
  const lowerMessage = message.toLowerCase();

  const rulesMap = {
    en: [
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
    ],
    hi: [
      {
        keywords: ["फ़िशिंग", "phishing", "ईमेल घोटाला", "संदिग्ध ईमेल"],
        response:
          "फ़िशिंग एक साइबर हमला है जहाँ हमलावर पासवर्ड या क्रेडिट कार्ड नंबर जैसे संवेदनशील डेटा चुराने के लिए विश्वसनीय संस्थाओं का रूप धारण करते हैं। हमेशा प्रेषक के ईमेल को सत्यापित करें और संदिग्ध लिंक पर क्लिक करने से बचें।",
      },
      {
        keywords: ["मैलवेयर", "malware", "वायरस", "trojan", "स्पाईवेयर"],
        response:
          "मैलवेयर एक दुर्भावनापूर्ण सॉफ़्टवेयर है जिसे सिस्टम को नुकसान पहुँचाने या उसका शोषण करने के लिए डिज़ाइन किया गया है। उदाहरणों में वायरस, ट्रोजन और स्पाईवेयर शामिल हैं।",
      },
      {
        keywords: ["रैंसमवेयर", "ransomware"],
        response:
          "रैंसमवेयर एक प्रकार का मैलवेयर है जो आपके व्यक्तिगत डेटा या सिस्टम को एन्क्रिप्ट करके स्थायी रूप से उस तक पहुंच को अवरुद्ध करता है, और फिर डिक्रिप्शन कुंजी के लिए फिरौती की मांग करता है।",
      },
      {
        keywords: ["पासवर्ड", "password", "पासवर्ड सुरक्षा"],
        response:
          "अपरकेस, लोअरकेस, नंबर और विशेष वर्णों के मिश्रण वाले मजबूत पासवर्ड का उपयोग करें। सभी साइटों पर एक ही पासवर्ड का पुनः उपयोग करने से बचें।",
      },
      {
        keywords: ["संदिग्ध लिंक", "सुरक्षित ब्राउज़िंग", "खतरनाक वेबसाइट"],
        response:
          "सुरक्षित ब्राउज़िंग में क्लिक करने से पहले यूआरएल सत्यापित करना, HTTPS देखना, अविश्वसनीय स्रोतों से डाउनलोड करने से बचना और ब्राउज़र को अपडेट रखना शामिल है।",
      },
    ],
    mr: [
      {
        keywords: ["फिशिंग", "phishing", "ईमेल घोटाळा", "संशयास्पद ईमेल"],
        response:
          "फिशिंग हा एक सायबर हल्ला आहे जिथे हल्लेखोर पासवर्ड किंवा क्रेडिट कार्ड नंबरसारखा संवेदनशील डेटा चोरण्यासाठी विश्वसनीय संस्थांचे रूप घेतात. नेहमी प्रेषकाच्या ईमेलची पडताळणी करा आणि संशयास्पद लिंकवर क्लिक करणे टाळा.",
      },
      {
        keywords: ["मालवेअर", "malware", "व्हायरस", "trojan", "स्पायवेअर"],
        response:
          "मालवेअर म्हणजे सिस्टमचे नुकसान करण्यासाठी किंवा त्याचा गैरफायदा घेण्यासाठी डिझाइन केलेले सॉफ्टवेअर. उदाहरणांमध्ये व्हायरस, ट्रोजन आणि स्पायवेअर समाविष्ट आहेत.",
      },
      {
        keywords: ["रॅन्समवेअर", "ransomware"],
        response:
          "रॅन्समवेअर हा एक प्रकारचा मालवेअर आहे जो आपला वैयक्तिक डेटा किंवा सिस्टिम एन्क्रिप्ट करून कायमस्वरूपी ब्लॉक करतो आणि डिक्रिप्शन कीसाठी खंडणी मागतो.",
      },
      {
        keywords: ["पासवर्ड", "password", "पासवर्ड सुरक्षा"],
        response:
          "अपरकेस, लोअरकेस, नंबर आणि विशेष वर्णांचे मिश्रण असलेले मजबूत पासवर्ड वापरा. अनेक साइट्सवर समान पासवर्ड वापरणे टाळा.",
      },
      {
        keywords: ["संशयास्पद लिंक", "सुरक्षित ब्राउझिंग", "धोकादायक वेबसाइट"],
        response:
          "सुरक्षित ब्राउझिंगमध्ये क्लिक करण्यापूर्वी URL शहानिशा करणे, HTTPS शोधणे, अविश्वासू स्त्रोतांकडून डाउनलोड करणे टाळणे आणि ब्राउझर अद्ययावत ठेवणे समाविष्ट आहे.",
      },
    ],
  };

  const rules = rulesMap[language] || rulesMap["en"];

  for (const rule of rules) {
    if (rule.keywords.some((keyword) => lowerMessage.includes(keyword))) {
      return rule.response;
    }
  }

  // Return null if no rule matches, triggering the Groq API fallback
  return null;
};
