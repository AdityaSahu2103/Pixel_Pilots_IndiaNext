"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Shield,
  Mail,
  Link2,
  Brain,
  FileBarChart,
  Settings,
  ChevronLeft,
  ChevronRight,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { useTranslate } from "@/hooks/useTranslate";

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const { t } = useTranslate();

  const navItems = [
    {
      href: "/dashboard",
      label: t("sidebar.dashboard"),
      icon: LayoutDashboard,
    },
    {
      href: "/threat-scanner",
      label: t("sidebar.threatScanner"),
      icon: Shield,
    },
    { href: "/email-analyzer", label: t("sidebar.emailAnalyzer"), icon: Mail },
    { href: "/url-scanner", label: t("sidebar.urlScanner"), icon: Link2 },
    { href: "/ai-intel", label: t("sidebar.aiIntel"), icon: Brain },
    { href: "/reports", label: t("sidebar.reports"), icon: FileBarChart },
    { href: "/settings", label: t("sidebar.settings"), icon: Settings },
  ];

  return (
    <motion.aside
      initial={{ width: 260 }}
      animate={{ width: collapsed ? 72 : 260 }}
      transition={{ duration: 0.3, ease: "easeInOut" }}
      className="fixed left-0 top-0 h-screen z-50 flex flex-col"
      style={{
        background: "linear-gradient(180deg, #0d1322 0%, #0A0F1C 100%)",
        borderRight: "1px solid rgba(255,255,255,0.06)",
      }}
    >
      {/* Logo */}
      <Link
        href="/"
        className="flex items-center gap-3 px-5 py-6 border-b cursor-pointer hover:bg-white/5 transition-colors"
        style={{ borderColor: "rgba(255,255,255,0.06)" }}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 animate-glow-pulse"
          style={{ background: "linear-gradient(135deg, #00F5FF, #8B5CF6)" }}
        >
          <Zap className="w-5 h-5 text-white" />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: "auto" }}
              exit={{ opacity: 0, width: 0 }}
              className="overflow-hidden whitespace-nowrap"
            >
              <h1
                className="text-base font-bold tracking-wider"
                style={{ fontFamily: "Orbitron, sans-serif", color: "#00F5FF" }}
              >
                {t("sidebar.title") || "ThreatFuse"}
              </h1>
              <p
                className="text-[10px] tracking-widest"
                style={{ color: "#8B5CF6" }}
              >
                AI SECURITY
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </Link>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link key={item.href} href={item.href}>
              <motion.div
                whileHover={{
                  x: 4,
                  backgroundColor: "rgba(0, 245, 255, 0.05)",
                }}
                whileTap={{ scale: 0.98 }}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer transition-all duration-200 relative ${
                  isActive ? "nav-active" : ""
                }`}
                style={{
                  background: isActive
                    ? "rgba(0, 245, 255, 0.08)"
                    : "transparent",
                }}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeIndicator"
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-r-full"
                    style={{
                      background: "#00F5FF",
                      boxShadow: "0 0 10px #00F5FF",
                    }}
                  />
                )}
                <Icon
                  className="w-5 h-5 flex-shrink-0"
                  style={{ color: isActive ? "#00F5FF" : "#9CA3AF" }}
                />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: "auto" }}
                      exit={{ opacity: 0, width: 0 }}
                      className="text-sm font-medium overflow-hidden whitespace-nowrap"
                      style={{ color: isActive ? "#E5E7EB" : "#9CA3AF" }}
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </motion.div>
            </Link>
          );
        })}
      </nav>

      {/* Collapse Toggle */}
      <div
        className="p-3 border-t"
        style={{ borderColor: "rgba(255,255,255,0.06)" }}
      >
        <motion.button
          whileHover={{ backgroundColor: "rgba(0, 245, 255, 0.08)" }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl transition-colors cursor-pointer"
          style={{ color: "#9CA3AF" }}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <ChevronLeft className="w-4 h-4" />
          )}
          <AnimatePresence>
            {!collapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-xs"
              >
                Collapse
              </motion.span>
            )}
          </AnimatePresence>
        </motion.button>
      </div>
    </motion.aside>
  );
}
