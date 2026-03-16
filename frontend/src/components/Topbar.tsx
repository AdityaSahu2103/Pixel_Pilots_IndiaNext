import { motion } from "framer-motion";
import { Bell, Search, Zap } from "lucide-react";

export default function Topbar() {
  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="glass sticky top-0 z-40 flex h-16 items-center justify-between border-b border-border px-6"
    >
      {/* Left — Branding */}
      <div className="flex items-center gap-3">
        <Zap className="h-5 w-5 text-primary" />
        <h1 className="text-lg font-bold tracking-tight">
          <span className="text-primary neon-text">Threat</span>
          <span className="text-text-primary">Fuse</span>
          <span className="ml-1 text-xs font-medium text-text-muted">AI</span>
        </h1>
        <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-primary">
          Beta
        </span>
      </div>

      {/* Center — Search */}
      <div className="hidden md:flex max-w-md flex-1 mx-8">
        <div className="relative w-full">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Search threats, IPs, domains..."
            className="w-full rounded-xl border border-border bg-bg-base/50 py-2 pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:border-primary/40 focus:outline-none focus:ring-1 focus:ring-primary/20 transition-all"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 rounded border border-border bg-bg-surface px-1.5 py-0.5 text-[10px] font-mono text-text-muted">
            ⌘K
          </kbd>
        </div>
      </div>

      {/* Right — Actions */}
      <div className="flex items-center gap-4">
        <button className="relative rounded-lg p-2 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-danger animate-pulse" />
        </button>

        {/* Agent status */}
        <div className="flex items-center gap-2 rounded-lg border border-border bg-bg-surface/50 px-3 py-1.5">
          <span className="h-2 w-2 rounded-full bg-success" />
          <span className="text-xs font-medium text-text-secondary">
            5 Agents Online
          </span>
        </div>
      </div>
    </motion.header>
  );
}
