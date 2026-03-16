import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Activity,
  Eye,
  Cpu,
  ArrowRight,
} from "lucide-react";
import DashboardLayout from "./layouts/DashboardLayout";

/* ── Stat Card ──────────────────────────────────────────────────── */
interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  change?: string;
  changeType?: "up" | "down" | "neutral";
  color: string;
  delay: number;
}

function StatCard({
  icon,
  label,
  value,
  change,
  changeType = "neutral",
  color,
  delay,
}: StatCardProps) {
  const changeColor =
    changeType === "up"
      ? "text-danger"
      : changeType === "down"
      ? "text-success"
      : "text-text-muted";

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="glass-card p-5"
    >
      <div className="flex items-start justify-between">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${color}15` }}
        >
          <span style={{ color }}>{icon}</span>
        </div>
        {change && (
          <span className={`text-xs font-semibold ${changeColor}`}>
            {change}
          </span>
        )}
      </div>
      <p className="mt-4 text-2xl font-bold text-text-primary">{value}</p>
      <p className="mt-1 text-sm text-text-muted">{label}</p>
    </motion.div>
  );
}

/* ── Agent Pipeline Preview ─────────────────────────────────────── */
const agents = [
  { name: "Orchestrator", icon: Cpu, status: "ready" },
  { name: "Net Scraper", icon: Activity, status: "ready" },
  { name: "Semantic AI", icon: Eye, status: "ready" },
  { name: "Explainer", icon: AlertTriangle, status: "ready" },
  { name: "Mitigator", icon: Shield, status: "ready" },
];

function AgentPipeline() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.6, duration: 0.5 }}
      className="glass-card p-6"
    >
      <h2 className="mb-6 text-sm font-semibold uppercase tracking-wider text-text-muted">
        Agent Pipeline
      </h2>
      <div className="flex items-center justify-between gap-2 overflow-x-auto">
        {agents.map((agent, i) => (
          <div key={agent.name} className="flex items-center gap-2">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{
                delay: 0.8 + i * 0.15,
                type: "spring",
                stiffness: 200,
              }}
              className="flex flex-col items-center gap-2"
            >
              <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-primary/20 bg-primary/5 transition-all hover:neon-glow hover:border-primary/40">
                <agent.icon className="h-5 w-5 text-primary" />
              </div>
              <span className="text-[11px] font-medium text-text-secondary whitespace-nowrap">
                {agent.name}
              </span>
              <span className="flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-success" />
                <span className="text-[10px] text-text-muted uppercase">
                  {agent.status}
                </span>
              </span>
            </motion.div>
            {i < agents.length - 1 && (
              <ArrowRight className="h-4 w-4 text-text-muted/50 mx-1 flex-shrink-0" />
            )}
          </div>
        ))}
      </div>
    </motion.div>
  );
}

/* ── Welcome Banner ─────────────────────────────────────────────── */
function WelcomeBanner() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="glass-card relative overflow-hidden p-6"
    >
      {/* Gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-neon-purple/5" />
      <div className="relative">
        <h1 className="text-2xl font-bold">
          Welcome to{" "}
          <span className="text-primary neon-text">ThreatFuse AI</span>
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-text-secondary">
          Agentic cybersecurity platform powered by a 5-agent pipeline. Detect,
          analyze, explain, and mitigate cyber threats in real time.
        </p>
        <div className="mt-4 flex gap-3">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-bg-deep transition-all hover:shadow-lg hover:shadow-primary/20"
          >
            <Shield className="h-4 w-4" />
            Analyze Threat
          </motion.button>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="flex items-center gap-2 rounded-xl border border-border bg-bg-surface/50 px-4 py-2.5 text-sm font-medium text-text-secondary transition-all hover:border-primary/30 hover:text-text-primary"
          >
            View Documentation
          </motion.button>
        </div>
      </div>
    </motion.div>
  );
}

/* ── App ────────────────────────────────────────────────────────── */
function App() {
  return (
    <DashboardLayout>
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Welcome */}
        <WelcomeBanner />

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            icon={<Shield className="h-5 w-5" />}
            label="Threats Detected"
            value="1,247"
            change="+12%"
            changeType="up"
            color="#EF4444"
            delay={0.2}
          />
          <StatCard
            icon={<Eye className="h-5 w-5" />}
            label="Scans Today"
            value="3,891"
            change="+8%"
            changeType="up"
            color="#38BDF8"
            delay={0.3}
          />
          <StatCard
            icon={<AlertTriangle className="h-5 w-5" />}
            label="False Positive Rate"
            value="2.1%"
            change="-0.3%"
            changeType="down"
            color="#F59E0B"
            delay={0.4}
          />
          <StatCard
            icon={<Activity className="h-5 w-5" />}
            label="Avg Response Time"
            value="1.2s"
            change="stable"
            changeType="neutral"
            color="#10B981"
            delay={0.5}
          />
        </div>

        {/* Agent Pipeline */}
        <AgentPipeline />
      </div>
    </DashboardLayout>
  );
}

export default App;
