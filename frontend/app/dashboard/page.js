"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { useTranslate } from "@/hooks/useTranslate";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Activity,
  Users,
  ArrowUpRight,
  ArrowDownRight,
  Clock,
  ExternalLink,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import DashboardLayout from "@/components/layout/DashboardLayout";
import GlassCard from "@/components/ui/GlassCard";
import ThreatBadge from "@/components/ui/ThreatBadge";
import SecurityScore from "@/components/ui/SecurityScore";
import { checkHealth, getReports } from "@/lib/api";

const CyberGlobe = dynamic(() => import("@/components/three/CyberGlobe"), {
  ssr: false,
});

// Mock data for charts
const threatTrend = [
  { time: "00:00", threats: 4, scans: 12 },
  { time: "04:00", threats: 7, scans: 18 },
  { time: "08:00", threats: 12, scans: 35 },
  { time: "12:00", threats: 8, scans: 42 },
  { time: "16:00", threats: 15, scans: 38 },
  { time: "20:00", threats: 6, scans: 25 },
  { time: "23:59", threats: 3, scans: 15 },
];

const threatTypes = [
  { name: "Phishing", value: 35, color: "#FF3B3B" },
  { name: "Malicious URL", value: 28, color: "#F97316" },
  { name: "Deepfake", value: 12, color: "#F59E0B" },
  { name: "Prompt Injection", value: 15, color: "#8B5CF6" },
  { name: "Anomaly", value: 10, color: "#00F5FF" },
];

const agentPerformance = [
  { name: "Phishing", accuracy: 94, scans: 120 },
  { name: "URL", accuracy: 97, scans: 85 },
  { name: "Deepfake", accuracy: 89, scans: 42 },
  { name: "Injection", accuracy: 92, scans: 65 },
  { name: "Anomaly", accuracy: 88, scans: 55 },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload) return null;
  return (
    <div
      className="glass-card p-3 rounded-xl"
      style={{ border: "1px solid rgba(0,245,255,0.2)" }}
    >
      <p className="text-xs font-mono mb-1" style={{ color: "#9CA3AF" }}>
        {label}
      </p>
      {payload.map((item, i) => (
        <p
          key={i}
          className="text-xs font-semibold"
          style={{ color: item.color }}
        >
          {item.name}: {item.value}
        </p>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const { t } = useTranslate();
  const [health, setHealth] = useState(null);
  const [reports, setReports] = useState([]);

  useEffect(() => {
    checkHealth()
      .then(setHealth)
      .catch(() => {});
    getReports()
      .then(setReports)
      .catch(() => {});
  }, []);

  const activeAgents = health
    ? Object.values(health.agents).filter((s) => s === "active").length
    : 0;
  const totalAgents = health ? Object.keys(health.agents).length : 0;
  const threatsDetected = reports.filter((r) => r.threats_detected > 0).length;

  const statCards = [
    {
      title: t("dashboard.totalScans"),
      value: reports.length || 0,
      icon: Activity,
      color: "#00F5FF",
      change: "+12%",
      up: true,
    },
    {
      title: t("dashboard.threatsDetected"),
      value: threatsDetected,
      icon: AlertTriangle,
      color: "#FF3B3B",
      change: threatsDetected > 0 ? "Active" : "None",
      up: false,
    },
    {
      title: t("dashboard.activeAgents"),
      value: `${activeAgents}/${totalAgents}`,
      icon: Users,
      color: "#22C55E",
      change: t("dashboard.operational"),
      up: true,
    },
    {
      title: t("dashboard.avgRiskScore"),
      value: reports.length
        ? Math.round(
            reports.reduce((a, r) => a + r.risk_score, 0) / reports.length,
          )
        : 0,
      icon: Shield,
      color: "#8B5CF6",
      change: "Stable",
      up: true,
    },
  ];

  return (
    <DashboardLayout>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {/* Page Title */}
        <motion.div variants={itemVariants} className="mb-6">
          <h1 className="text-2xl font-bold tracking-tight text-white">
            {t("dashboard.title")}
          </h1>
          <p className="text-sm mt-1" style={{ color: "#6B7280" }}>
            {t("dashboard.subtitle")}
          </p>
        </motion.div>

        {/* Stat Cards */}
        <motion.div
          variants={itemVariants}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6"
        >
          {statCards.map((card) => {
            const Icon = card.icon;
            return (
              <GlassCard key={card.title} className="relative overflow-hidden">
                <div className="flex items-start justify-between">
                  <div>
                    <p
                      className="text-xs font-medium uppercase tracking-wider mb-2"
                      style={{ color: "#6B7280" }}
                    >
                      {card.title}
                    </p>
                    <p
                      className="text-3xl font-bold font-mono"
                      style={{ color: card.color }}
                    >
                      {card.value}
                    </p>
                    <div className="flex items-center gap-1 mt-2">
                      {card.up ? (
                        <ArrowUpRight
                          className="w-3 h-3"
                          style={{ color: "#22C55E" }}
                        />
                      ) : (
                        <ArrowDownRight
                          className="w-3 h-3"
                          style={{ color: "#FF3B3B" }}
                        />
                      )}
                      <span className="text-xs" style={{ color: "#9CA3AF" }}>
                        {card.change}
                      </span>
                    </div>
                  </div>
                  <div
                    className="p-2.5 rounded-xl"
                    style={{
                      background: `${card.color}10`,
                      border: `1px solid ${card.color}25`,
                    }}
                  >
                    <Icon className="w-5 h-5" style={{ color: card.color }} />
                  </div>
                </div>
                {/* Decorative gradient line */}
                <div
                  className="absolute bottom-0 left-0 right-0 h-0.5"
                  style={{
                    background: `linear-gradient(90deg, ${card.color}, transparent)`,
                  }}
                />
              </GlassCard>
            );
          })}
        </motion.div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
          {/* Threat Activity Chart */}
          <motion.div variants={itemVariants} className="lg:col-span-2">
            <GlassCard>
              <div className="flex items-center justify-between mb-4">
                <h3
                  className="text-sm font-semibold"
                  style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                >
                  {t("dashboard.threatActivity")}
                </h3>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-1.5">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ background: "#FF3B3B" }}
                    />
                    <span className="text-[10px]" style={{ color: "#9CA3AF" }}>
                      {t("dashboard.threats")}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ background: "#00F5FF" }}
                    />
                    <span className="text-[10px]" style={{ color: "#9CA3AF" }}>
                      {t("dashboard.scans")}
                    </span>
                  </div>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={threatTrend}>
                  <defs>
                    <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#FF3B3B" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#FF3B3B" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00F5FF" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#00F5FF" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.04)"
                  />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#6B7280", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: "#6B7280", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    stroke="#00F5FF"
                    fill="url(#scanGrad)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#FF3B3B"
                    fill="url(#threatGrad)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </GlassCard>
          </motion.div>

          {/* Security Score + Globe */}
          <motion.div variants={itemVariants}>
            <GlassCard className="flex flex-col items-center justify-center h-full">
              <SecurityScore
                score={
                  reports.length
                    ? Math.round(
                        reports.reduce((a, r) => a + r.risk_score, 0) /
                          reports.length,
                      )
                    : 15
                }
                size={140}
              />
              <div className="mt-4 w-full">
                <div
                  className="flex justify-between text-xs py-2"
                  style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
                >
                  <span style={{ color: "#6B7280" }}>
                    {t("dashboard.systemStatus")}
                  </span>
                  <span style={{ color: "#22C55E" }}>
                    {t("dashboard.operational")}
                  </span>
                </div>
                <div
                  className="flex justify-between text-xs py-2"
                  style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
                >
                  <span style={{ color: "#6B7280" }}>
                    {t("dashboard.lastScan")}
                  </span>
                  <span style={{ color: "#9CA3AF" }}>
                    {t("dashboard.justNow")}
                  </span>
                </div>
              </div>
            </GlassCard>
          </motion.div>
        </div>

        {/* Bottom Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Threat Distribution */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <h3
                className="text-sm font-semibold mb-4"
                style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
              >
                {t("dashboard.threatDistribution")}
              </h3>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={threatTypes}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {threatTypes.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {threatTypes.map((t) => (
                  <div key={t.name} className="flex items-center gap-1.5">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ background: t.color }}
                    />
                    <span className="text-[10px]" style={{ color: "#9CA3AF" }}>
                      {t.name}
                    </span>
                  </div>
                ))}
              </div>
            </GlassCard>
          </motion.div>

          {/* Agent Performance */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <h3
                className="text-sm font-semibold mb-4"
                style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
              >
                {t("dashboard.agentPerformance")}
              </h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={agentPerformance} layout="vertical">
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.04)"
                  />
                  <XAxis
                    type="number"
                    tick={{ fill: "#6B7280", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    domain={[0, 100]}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fill: "#9CA3AF", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    width={60}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar
                    dataKey="accuracy"
                    fill="#00F5FF"
                    radius={[0, 4, 4, 0]}
                    barSize={12}
                  />
                </BarChart>
              </ResponsiveContainer>
            </GlassCard>
          </motion.div>

          {/* Recent Activity Feed */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <div className="flex items-center justify-between mb-4">
                <h3
                  className="text-sm font-semibold"
                  style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                >
                  {t("dashboard.recentActivity")}
                </h3>
                <a
                  href="/reports"
                  className="text-[10px] flex items-center gap-1"
                  style={{ color: "#00F5FF" }}
                >
                  {t("dashboard.viewAll")} <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <div className="space-y-3">
                {reports.length > 0 ? (
                  reports.slice(0, 5).map((r) => (
                    <div
                      key={r.scan_id}
                      className="flex items-center justify-between py-2"
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.04)",
                      }}
                    >
                      <div className="flex items-center gap-2">
                        <Clock
                          className="w-3.5 h-3.5"
                          style={{ color: "#6B7280" }}
                        />
                        <div>
                          <p
                            className="text-xs font-medium"
                            style={{ color: "#E5E7EB" }}
                          >
                            {r.source_type.toUpperCase()} Scan
                          </p>
                          <p
                            className="text-[10px]"
                            style={{ color: "#6B7280" }}
                          >
                            {new Date(r.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                      <ThreatBadge severity={r.severity} />
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8">
                    <Shield
                      className="w-8 h-8 mx-auto mb-2"
                      style={{ color: "#1f2937" }}
                    />
                    <p className="text-xs" style={{ color: "#6B7280" }}>
                      No scans yet
                    </p>
                    <p className="text-[10px]" style={{ color: "#4B5563" }}>
                      Run your first scan to see activity
                    </p>
                  </div>
                )}
              </div>
            </GlassCard>
          </motion.div>
        </div>

        {/* Globe Section */}
        <motion.div variants={itemVariants} className="mt-6">
          <GlassCard>
            <h3
              className="text-sm font-semibold mb-2"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              Global Threat Map
            </h3>
            <p className="text-xs mb-4" style={{ color: "#6B7280" }}>
              Real-time visualization of detected cyber threats worldwide
            </p>
            <CyberGlobe height="300px" />
          </GlassCard>
        </motion.div>
      </motion.div>
    </DashboardLayout>
  );
}
