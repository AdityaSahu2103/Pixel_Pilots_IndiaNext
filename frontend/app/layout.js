import Chatbot from "../components/Chatbot";
import { LanguageProvider } from "../context/LanguageContext";
import "./globals.css";

export const metadata = {
  title: "ThreatFuse AI — Cybersecurity Command Center",
  description:
    "AI-powered cybersecurity platform for detecting phishing emails, malicious URLs, and emerging cyber threats. Built for Security Operations Centers.",
  keywords:
    "cybersecurity, phishing detection, threat intelligence, AI security, SOC dashboard",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@400;500;600;700;800;900&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased">
        <LanguageProvider>
          {children}
          <Chatbot />
        </LanguageProvider>
      </body>
    </html>
  );
}
