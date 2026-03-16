"use client";

import React, { useState, useRef, useEffect } from "react";
import { getRuleBasedResponse } from "../utils/chatbotRules";
import { useTranslate } from "../hooks/useTranslate";

const Chatbot = () => {
  const { t, language } = useTranslate();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);

  // Set initial greeting based on language
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([
        {
          role: "bot",
          content: t("chatbot.defaultGreeting"),
        },
      ]);
    }
  }, [t, messages.length]);

  // Auto-scroll to bottom of chat
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = input.trim();
    // Add user message to state
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setInput("");
    setIsLoading(true);

    // 1. Check Rule-Based Responses
    const ruleResponse = getRuleBasedResponse(userMessage, language);

    if (ruleResponse) {
      setTimeout(() => {
        setMessages((prev) => [
          ...prev,
          { role: "bot", content: ruleResponse },
        ]);
        setIsLoading(false);
      }, 500); // Simulate brief network delay
      return;
    }

    // 2. Fallback to Groq API
    try {
      // NOTE: In production, API calls should go through a secure backend route.
      const apiKey = process.env.NEXT_PUBLIC_GROQ_API_KEY;

      const languageMapping = {
        en: "English",
        hi: "Hindi",
        mr: "Marathi",
      };

      const aiLanguage = languageMapping[language] || "English";

      const response = await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "llama-3.3-70b-versatile",
            messages: [
              {
                role: "system",
                content: `You are a cybersecurity assistant helping users understand online threats. Always respond in ${aiLanguage}.`,
              },
              { role: "user", content: userMessage },
            ],
          }),
        },
      );

      if (!response.ok) {
        throw new Error("Failed to communicate with Groq AI");
      }

      const data = await response.json();

      if (data.choices && data.choices.length > 0) {
        setMessages((prev) => [
          ...prev,
          { role: "bot", content: data.choices[0].message.content },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            role: "bot",
            content: t("chatbot.formatError"),
          },
        ]);
      }
    } catch (error) {
      console.error("Groq API Error:", error);
      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          content: t("chatbot.networkError"),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleSend();
    }
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 font-sans">
      {/* Chat Window */}
      <div
        className={`mb-4 w-[360px] sm:w-[400px] h-[600px] max-h-[80vh] flex flex-col overflow-hidden transition-all duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] rounded-2xl border border-white/10 bg-[#0a0f18]/80 backdrop-blur-2xl shadow-[0_8px_40px_-12px_rgba(6,182,212,0.4)] absolute bottom-16 right-0 transform origin-bottom-right ${
          isOpen
            ? "scale-100 opacity-100 translate-y-0"
            : "scale-95 opacity-0 translate-y-5 pointer-events-none"
        }`}
      >
        {/* Header */}
        <div className="relative p-5 bg-gradient-to-b from-cyan-900/40 to-transparent border-b border-white/5 flex justify-between items-center z-10 overflow-hidden">
          {/* Subtle animated background grid/glow in header */}
          <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-30 mix-blend-overlay"></div>
          <div className="absolute -top-10 -left-10 w-32 h-32 bg-cyan-500/20 rounded-full blur-3xl"></div>

          <div className="relative flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-400/30 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <div className="absolute inset-0 rounded-full animate-ping opacity-20 bg-cyan-400"></div>
              <svg
                className="w-5 h-5 text-cyan-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div>
              <h3 className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 to-blue-500 font-extrabold tracking-wide text-lg">
                {t("chatbot.botName")}
              </h3>
              <p className="text-xs text-cyan-400/70 flex items-center gap-1.5 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_5px_#34d399]"></span>
                {t("chatbot.botActive")}
              </p>
            </div>
          </div>

          <button
            onClick={() => setIsOpen(false)}
            className="relative w-8 h-8 flex items-center justify-center rounded-full bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white border border-transparent hover:border-white/10 transition-all focus:outline-none backdrop-blur-md"
            aria-label={t("chatbot.close")}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        {/* Messages Area */}
        <div className="flex-1 p-5 overflow-y-auto custom-scrollbar flex flex-col gap-4">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`flex w-full ${msg.role === "user" ? "justify-end" : "justify-start"} animate-in fade-in slide-in-from-bottom-2 duration-300`}
            >
              {msg.role === "bot" && (
                <div className="w-8 h-8 rounded-full bg-cyan-900/50 border border-cyan-500/30 flex-shrink-0 flex items-center justify-center mr-3 mt-1 shadow-[0_0_10px_rgba(6,182,212,0.15)]">
                  <svg
                    className="w-4 h-4 text-cyan-400"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path d="M13 2H7a2 2 0 00-2 2v2H4a2 2 0 00-2 2v7a2 2 0 002 2h12a2 2 0 002-2V8a2 2 0 00-2-2h-1V4a2 2 0 00-2-2zM7 4h6v2H7V4zm9 11H4V8h12v7z" />
                    <circle cx="7" cy="11" r="1.5" />
                    <circle cx="13" cy="11" r="1.5" />
                  </svg>
                </div>
              )}

              <div
                className={`max-w-[75%] p-3.5 text-sm leading-relaxed whitespace-pre-wrap shadow-lg ${
                  msg.role === "user"
                    ? "bg-gradient-to-br from-cyan-600 to-blue-700 text-white rounded-2xl rounded-tr-sm border border-cyan-400/20"
                    : "bg-[#111827]/80 text-gray-200 rounded-2xl rounded-tl-sm border border-white/5 backdrop-blur-md"
                }`}
              >
                {msg.content}
              </div>
            </div>
          ))}

          {/* Typing Indicator */}
          {isLoading && (
            <div className="flex w-full justify-start animate-in fade-in duration-300">
              <div className="w-8 h-8 rounded-full bg-cyan-900/50 border border-cyan-500/30 flex-shrink-0 flex items-center justify-center mr-3 mt-1 shadow-[0_0_10px_rgba(6,182,212,0.15)]">
                <svg
                  className="w-4 h-4 text-cyan-400"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path d="M13 2H7a2 2 0 00-2 2v2H4a2 2 0 00-2 2v7a2 2 0 002 2h12a2 2 0 002-2V8a2 2 0 00-2-2h-1V4a2 2 0 00-2-2zM7 4h6v2H7V4zm9 11H4V8h12v7z" />
                  <circle cx="7" cy="11" r="1.5" />
                  <circle cx="13" cy="11" r="1.5" />
                </svg>
              </div>
              <div className="bg-[#111827]/80 border border-white/5 rounded-2xl rounded-tl-sm p-4 flex items-center gap-1.5 backdrop-blur-md shadow-lg">
                <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"></div>
                <div
                  className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"
                  style={{ animationDelay: "0.15s" }}
                ></div>
                <div
                  className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"
                  style={{ animationDelay: "0.3s" }}
                ></div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} className="h-2" />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-[#05080f]/90 border-t border-white/5 backdrop-blur-xl">
          <div className="relative flex items-center bg-[#0f172a] border border-white/10 rounded-full focus-within:border-cyan-500/50 focus-within:ring-2 focus-within:ring-cyan-500/20 transition-all duration-300 overflow-hidden shadow-inner">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyPress}
              placeholder={t("chatbot.placeholder")}
              className="flex-1 bg-transparent text-gray-100 px-5 py-3.5 text-sm outline-none placeholder-gray-500/80 font-medium w-full"
            />
            <button
              onClick={handleSend}
              disabled={isLoading || !input.trim()}
              className="absolute right-2 p-2 rounded-full bg-gradient-to-r from-cyan-600 to-blue-600 text-white hover:from-cyan-500 hover:to-blue-500 transition-all disabled:opacity-0 disabled:scale-75 disabled:pointer-events-none transform scale-100 flex items-center justify-center shadow-[0_0_10px_rgba(6,182,212,0.4)]"
              aria-label={t("chatbot.send")}
            >
              <svg
                className="w-4 h-4 ml-0.5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2.5"
                  d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                />
              </svg>
            </button>
          </div>
          <div className="text-center mt-2">
            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold font-mono">
              {t("chatbot.protectedBy")}
            </span>
          </div>
        </div>
      </div>

      {/* Floating Widget Button */}
      <div
        className={`relative transition-all duration-500 transform ${isOpen ? "scale-0 opacity-0 pointer-events-none" : "scale-100 opacity-100 hover:-translate-y-1 hover:scale-105"}`}
      >
        <div className="absolute inset-0 bg-gradient-to-tr from-cyan-400 to-blue-600 rounded-full blur opacity-40 animate-pulse"></div>
        <button
          onClick={() => setIsOpen(true)}
          className="relative flex items-center justify-center w-16 h-16 bg-gradient-to-tr from-[#0f172a] to-[#1e293b] border-2 border-cyan-500/50 text-cyan-400 rounded-full shadow-[0_0_25px_rgba(6,182,212,0.3)] group focus:outline-none transition-all duration-300"
          aria-label={t("chatbot.open")}
        >
          <div className="absolute inset-0 rounded-full group-hover:bg-cyan-500/10 transition-colors"></div>
          <svg
            className="w-7 h-7 relative z-10"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
            ></path>
          </svg>
        </button>
        <div className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 border-2 border-gray-900 rounded-full"></div>
      </div>
    </div>
  );
};

export default Chatbot;
