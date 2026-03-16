"use client";

import React, { useState } from "react";
import { useTranslate } from "../hooks/useTranslate";

export default function LanguageToggle() {
  const { t, language, changeLanguage } = useTranslate();
  const [isOpen, setIsOpen] = useState(false);

  const languages = [
    { code: "en", label: "EN" },
    { code: "hi", label: "हिन्दी" },
    { code: "mr", label: "मराठी" },
  ];

  return (
    <div className="relative inline-block text-left z-50">
      <div>
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex justify-center flex-row items-center gap-1.5 w-full rounded-md border border-cyan-500/30 shadow-sm px-3 py-1.5 bg-[#0a0f18] text-sm font-medium text-cyan-400 hover:bg-[#111827] focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors backdrop-blur-md"
          id="options-menu"
          aria-haspopup="true"
          aria-expanded="true"
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
              d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"
            ></path>
          </svg>
          {languages.find((l) => l.code === language)?.label || "EN"}
          <svg
            className="-mr-1 ml-1 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            aria-hidden="true"
          >
            <path
              fillRule="evenodd"
              d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      </div>

      {isOpen && (
        <div
          className="origin-top-right absolute right-0 mt-2 w-32 rounded-md shadow-lg bg-[#0a0f18] border border-cyan-500/30 overflow-hidden"
          role="menu"
          aria-orientation="vertical"
          aria-labelledby="options-menu"
        >
          <div className="py-1" role="none">
            {languages.map((lang) => (
              <button
                key={lang.code}
                onClick={() => {
                  changeLanguage(lang.code);
                  setIsOpen(false);
                }}
                className={`block w-full text-left px-4 py-2 text-sm transition-colors ${
                  language === lang.code
                    ? "bg-cyan-900/50 text-cyan-300 font-bold"
                    : "text-gray-300 hover:bg-cyan-900/30 hover:text-cyan-400"
                }`}
                role="menuitem"
              >
                {lang.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
