import { motion } from "framer-motion";
import {
  Shield,
  Activity,
  Search,
  AlertTriangle,
  BarChart3,
  Settings,
  Terminal,
  type LucideIcon,
} from "lucide-react";

interface NavItem {
  icon: LucideIcon;
  label: string;
  active?: boolean;
}

const navItems: NavItem[] = [
  { icon: Shield, label: "Dashboard", active: true },
  { icon: Search, label: "Analyze" },
  { icon: Activity, label: "Pipeline" },
  { icon: AlertTriangle, label: "Threats" },
  { icon: BarChart3, label: "Reports" },
  { icon: Terminal, label: "Console" },
  { icon: Settings, label: "Settings" },
];

export default function Sidebar() {
  return (
    <motion.aside
      initial={{ x: -80, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="fixed inset-y-0 left-0 z-50 flex w-[72px] flex-col items-center border-r border-border bg-bg-base/80 py-6 backdrop-blur-xl"
    >
      {/* Logo */}
      <motion.div
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
        className="mb-8 flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 neon-border"
      >
        <Shield className="h-5 w-5 text-primary" />
      </motion.div>

      {/* Navigation */}
      <nav className="flex flex-1 flex-col items-center gap-2">
        {navItems.map((item, index) => (
          <motion.button
            key={item.label}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 * index, duration: 0.3 }}
            title={item.label}
            className={`group relative flex h-10 w-10 items-center justify-center rounded-xl transition-all duration-300 ${
              item.active
                ? "bg-primary/15 text-primary neon-glow"
                : "text-text-muted hover:bg-bg-surface hover:text-text-primary"
            }`}
          >
            <item.icon className="h-[18px] w-[18px]" />
            {/* Tooltip */}
            <span className="pointer-events-none absolute left-14 z-50 whitespace-nowrap rounded-lg bg-bg-elevated px-3 py-1.5 text-xs font-medium text-text-primary opacity-0 shadow-lg transition-opacity duration-200 group-hover:opacity-100">
              {item.label}
            </span>
            {/* Active indicator */}
            {item.active && (
              <motion.div
                layoutId="sidebar-active"
                className="absolute -left-[1px] h-6 w-[3px] rounded-r-full bg-primary"
              />
            )}
          </motion.button>
        ))}
      </nav>

      {/* Status indicator */}
      <div className="flex flex-col items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-success animate-pulse-neon" />
        </div>
        <span className="text-[10px] font-medium text-text-muted">LIVE</span>
      </div>
    </motion.aside>
  );
}
