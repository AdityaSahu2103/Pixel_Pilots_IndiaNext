"use client";

import { useTranslate } from "../hooks/useTranslate";
import dynamic from "next/dynamic";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  Zap,
  Mail,
  Link2,
  Brain,
  BarChart3,
  ArrowRight,
  ChevronRight,
  Lock,
  Eye,
  AlertTriangle,
} from "lucide-react";
import LanguageToggle from "@/components/LanguageToggle";

const ParticleField = dynamic(
  () => import("@/components/three/ParticleField"),
  { ssr: false },
);
const CyberGlobe = dynamic(() => import("@/components/three/CyberGlobe"), {
  ssr: false,
});

const featuresList = [
  {
    icon: Shield,
    key: "phishing",
    color: "#00F5FF",
  },
  {
    icon: Link2,
    key: "url",
    color: "#8B5CF6",
  },
  {
    icon: Eye,
    key: "deepfake",
    color: "#F59E0B",
  },
  {
    icon: AlertTriangle,
    key: "prompt",
    color: "#FF3B3B",
  },
  {
    icon: Brain,
    key: "explainable",
    color: "#22C55E",
  },
  {
    icon: BarChart3,
    key: "adversarial",
    color: "#F97316",
  },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
};

export default function Landing() {
  const { t } = useTranslate();

  return (
    <div
      className="min-h-screen relative overflow-x-hidden"
      style={{ background: "#0A0F1C" }}
    >
      <ParticleField />

      {/* Navigation */}
      <motion.nav
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 w-full"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}
      >
        <div className="max-w-7xl mx-auto flex items-center justify-between px-6 md:px-12 py-5">
          <Link href="/" className="flex items-center gap-3 cursor-pointer">
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center animate-glow-pulse"
              style={{
                background: "linear-gradient(135deg, #00F5FF, #8B5CF6)",
              }}
            >
              <Zap className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1
                className="text-lg font-bold tracking-wider"
                style={{ fontFamily: "Orbitron", color: "#00F5FF" }}
              >
                ThreatFuse
              </h1>
            </div>
          </Link>
          <div className="flex items-center gap-4">
            <LanguageToggle />
            <Link href="/dashboard">
              <motion.button
                whileHover={{
                  scale: 1.03,
                  boxShadow: "0 0 25px rgba(0, 245, 255, 0.3)",
                }}
                whileTap={{ scale: 0.98 }}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold cursor-pointer"
                style={{
                  background:
                    "linear-gradient(135deg, rgba(0, 245, 255, 0.15), rgba(139, 92, 246, 0.15))",
                  border: "1px solid rgba(0, 245, 255, 0.3)",
                  color: "#00F5FF",
                }}
              >
                {t("landing.openDashboard")}
                <ArrowRight className="w-4 h-4" />
              </motion.button>
            </Link>
          </div>
        </div>
      </motion.nav>

      {/* Hero Section */}
      <section className="relative z-10 w-full">
        <div className="max-w-7xl mx-auto flex flex-col lg:flex-row items-center gap-12 px-6 md:px-12 py-16 lg:py-24">
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="flex-1 w-full max-w-xl lg:max-w-none"
          >
            <div
              className="flex items-center gap-2 mb-6 px-4 py-2 rounded-full w-fit"
              style={{
                background: "rgba(0, 245, 255, 0.06)",
                border: "1px solid rgba(0, 245, 255, 0.15)",
              }}
            >
              <Lock className="w-3.5 h-3.5" style={{ color: "#00F5FF" }} />
              <span
                className="text-xs font-medium tracking-wider"
                style={{ color: "#00F5FF" }}
              >
                {t("landing.badge")}
              </span>
            </div>

            <h1
              className="text-4xl lg:text-5xl xl:text-6xl font-bold leading-tight mb-6"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("landing.titlePrefix")}{" "}
              <span className="text-glow-cyan" style={{ color: "#00F5FF" }}>
                {t("landing.titleThreat")}
              </span>{" "}
              {t("landing.titleMiddle")}{" "}
              <span className="text-glow-purple" style={{ color: "#8B5CF6" }}>
                {t("landing.titleDefense")}
              </span>
            </h1>

            <p
              className="text-base lg:text-lg mb-8 leading-relaxed max-w-lg"
              style={{ color: "#9CA3AF" }}
            >
              {t("landing.subtitle")}
            </p>

            <div className="flex flex-wrap items-center gap-4">
              <Link href="/dashboard">
                <motion.button
                  whileHover={{
                    scale: 1.03,
                    boxShadow: "0 0 35px rgba(0, 245, 255, 0.4)",
                  }}
                  whileTap={{ scale: 0.97 }}
                  className="flex items-center gap-2 px-7 py-3.5 rounded-xl text-sm font-bold tracking-wide cursor-pointer"
                  style={{
                    background: "linear-gradient(135deg, #00F5FF, #8B5CF6)",
                    color: "#0A0F1C",
                  }}
                >
                  Launch Command Center
                  <ChevronRight className="w-4 h-4" />
                </motion.button>
              </Link>
              <Link href="/url-scanner">
                <motion.button
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.97 }}
                  className="flex items-center gap-2 px-7 py-3.5 rounded-xl text-sm font-semibold cursor-pointer"
                  style={{
                    background: "transparent",
                    border: "1px solid rgba(255,255,255,0.15)",
                    color: "#E5E7EB",
                  }}
                >
                  Scan a URL
                </motion.button>
              </Link>
            </div>

            {/* Stats */}
            <div
              className="flex items-center gap-10 mt-12 pt-8"
              style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
            >
              {[
                { value: "6+", label: "Detection Agents" },
                { value: "< 5s", label: "Avg Scan Time" },
                { value: "99%", label: "Accuracy" },
              ].map((stat) => (
                <div key={stat.label}>
                  <div
                    className="text-2xl font-bold font-mono"
                    style={{ color: "#00F5FF" }}
                  >
                    {stat.value}
                  </div>
                  <div className="text-xs mt-1" style={{ color: "#6B7280" }}>
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* 3D Globe */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1, delay: 0.4 }}
            className="flex-1 w-full max-w-md lg:max-w-lg flex items-center justify-center"
          >
            <CyberGlobe height="420px" />
          </motion.div>
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 w-full">
        <div className="max-w-7xl mx-auto px-6 md:px-12 py-20">
          <div className="text-center mb-16">
            <h2
              className="text-3xl font-bold mb-4"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("landing.featuresTitle")}
            </h2>
          </div>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-14"
          >
            <h2
              className="text-3xl font-bold mb-4"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("landing.detection")}{" "}
              <span style={{ color: "#00F5FF" }}>
                {t("landing.capabilities")}
              </span>
            </h2>
            <p
              className="text-sm max-w-xl mx-auto"
              style={{ color: "#9CA3AF" }}
            >
              {t("landing.featuresSubtitle")}
            </p>
          </motion.div>

          <motion.div
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {featuresList.map((feature) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={feature.key}
                  variants={itemVariants}
                  whileHover={{ y: -4, borderColor: `${feature.color}33` }}
                  className="glass-card p-6 rounded-2xl cursor-default"
                >
                  <div
                    className="w-11 h-11 rounded-lg flex items-center justify-center mb-4"
                    style={{
                      background: `${feature.color}15`,
                      border: `1px solid ${feature.color}30`,
                    }}
                  >
                    <Icon
                      className="w-5 h-5"
                      style={{ color: feature.color }}
                    />
                  </div>
                  <h3
                    className="text-sm font-semibold mb-2"
                    style={{ color: "#E5E7EB", fontFamily: "Orbitron" }}
                  >
                    {t(`landing.features.${feature.key}.title`)}
                  </h3>
                  <p
                    className="text-sm leading-relaxed"
                    style={{ color: "#9CA3AF" }}
                  >
                    {t(`landing.features.${feature.key}.desc`)}
                  </p>
                </motion.div>
              );
            })}
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative z-10 w-full">
        <div className="max-w-7xl mx-auto px-6 md:px-12 py-20">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-2xl mx-auto text-center glass-card p-12 rounded-3xl"
            style={{ border: "1px solid rgba(0, 245, 255, 0.15)" }}
          >
            <h2
              className="text-2xl font-bold mb-4"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("landing.ctaTitle")}
            </h2>
            <p className="text-sm mb-8" style={{ color: "#9CA3AF" }}>
              {t("landing.ctaSubtitle")}
            </p>
            <Link href="/dashboard">
              <motion.button
                whileHover={{
                  scale: 1.03,
                  boxShadow: "0 0 40px rgba(0, 245, 255, 0.4)",
                }}
                whileTap={{ scale: 0.97 }}
                className="px-8 py-3.5 rounded-xl text-sm font-bold tracking-wide cursor-pointer"
                style={{
                  background: "linear-gradient(135deg, #00F5FF, #8B5CF6)",
                  color: "#0A0F1C",
                }}
              >
                {t("landing.getStarted")}
              </motion.button>
            </Link>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer
        className="relative z-10 w-full"
        style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}
      >
        <div className="max-w-7xl mx-auto px-6 md:px-12 py-8 text-center">
          <p className="text-xs" style={{ color: "#6B7280" }}>
            {t("landing.footer")}
          </p>
        </div>
      </footer>
    </div>
  );
}
