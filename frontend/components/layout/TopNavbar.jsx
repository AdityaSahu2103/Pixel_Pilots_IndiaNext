"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Bell, Search, Activity, Shield, Wifi } from "lucide-react";
import { checkHealth } from "@/lib/api";
import LanguageToggle from "../LanguageToggle";

export default function TopNavbar() {
  const [health, setHealth] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    checkHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const agentCount = health ? Object.keys(health.agents).length : 0;
  const activeAgents = health
    ? Object.values(health.agents).filter((s) => s === "active").length
    : 0;

  return (
    <motion.header
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="sticky top-0 z-40 flex items-center justify-between px-6 py-3"
      style={{
        background: "rgba(10, 15, 28, 0.8)",
        backdropFilter: "blur(20px)",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}
    >
      {/* Search */}
      <div className="relative w-80">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
          style={{ color: "#6B7280" }}
        />
        <input
          type="text"
          placeholder="Search threats, scans, reports..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 pr-4 py-2 text-sm rounded-xl w-full"
          style={{
            background: "rgba(17, 24, 39, 0.6)",
            border: "1px solid rgba(255,255,255,0.06)",
          }}
        />
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-5">
        {/* System Status */}
        <div className="flex items-center gap-4">
          <motion.div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
            style={{
              background: "rgba(34, 197, 94, 0.1)",
              border: "1px solid rgba(34, 197, 94, 0.2)",
            }}
            animate={{
              boxShadow: [
                "0 0 5px rgba(34, 197, 94, 0.1)",
                "0 0 15px rgba(34, 197, 94, 0.2)",
                "0 0 5px rgba(34, 197, 94, 0.1)",
              ],
            }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <Wifi className="w-3.5 h-3.5" style={{ color: "#22C55E" }} />
            <span className="text-xs font-medium" style={{ color: "#22C55E" }}>
              {health ? "ONLINE" : "OFFLINE"}
            </span>
          </motion.div>

          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
            style={{
              background: "rgba(0, 245, 255, 0.05)",
              border: "1px solid rgba(0, 245, 255, 0.1)",
            }}
          >
            <Activity className="w-3.5 h-3.5" style={{ color: "#00F5FF" }} />
            <span className="text-xs font-medium" style={{ color: "#9CA3AF" }}>
              {activeAgents}/{agentCount} Agents
            </span>
          </div>

          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
            style={{
              background: "rgba(139, 92, 246, 0.05)",
              border: "1px solid rgba(139, 92, 246, 0.1)",
            }}
          >
            <Shield className="w-3.5 h-3.5" style={{ color: "#8B5CF6" }} />
            <span className="text-xs font-medium" style={{ color: "#9CA3AF" }}>
              v{health?.version || "1.0.0"}
            </span>
          </div>
        </div>

        {/* Notifications */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="relative p-2 rounded-xl transition-colors cursor-pointer"
          style={{
            background: "rgba(17, 24, 39, 0.6)",
            border: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          <Bell className="w-4 h-4" style={{ color: "#9CA3AF" }} />
          <span
            className="absolute top-1 right-1 w-2 h-2 rounded-full"
            style={{ background: "#00F5FF", boxShadow: "0 0 6px #00F5FF" }}
          />
        </motion.button>

        {/* Language Toggle */}
        <LanguageToggle />
      </div>
    </motion.header>
  );
}
