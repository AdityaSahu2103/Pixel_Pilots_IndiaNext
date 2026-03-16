import { useContext } from "react";
import { LanguageContext } from "../context/LanguageContext";
import en from "../i18n/en";
import hi from "../i18n/hi";
import mr from "../i18n/mr";

const translations = { en, hi, mr };

export const useTranslate = () => {
  const { language, changeLanguage } = useContext(LanguageContext);

  const t = (key) => {
    const keys = key.split(".");
    let value = translations[language];

    for (const k of keys) {
      if (value && value[k]) {
        value = value[k];
      } else {
        // Fallback to English if key is missing in chosen language
        let fallback = translations["en"];
        for (const fk of keys) {
          if (fallback) fallback = fallback[fk];
        }
        return fallback || key; // Return English key or the literal key string if missing entirely
      }
    }
    return value;
  };

  return { t, language, changeLanguage };
};
