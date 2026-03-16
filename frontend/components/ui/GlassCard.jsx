'use client';

import { motion } from 'framer-motion';

export default function GlassCard({ children, className = '', glow = 'cyan', hover = true, ...props }) {
  const glowColors = {
    cyan: { border: 'rgba(0, 245, 255, 0.2)', shadow: '0 0 20px rgba(0, 245, 255, 0.15)' },
    purple: { border: 'rgba(139, 92, 246, 0.2)', shadow: '0 0 20px rgba(139, 92, 246, 0.15)' },
    danger: { border: 'rgba(255, 59, 59, 0.2)', shadow: '0 0 20px rgba(255, 59, 59, 0.15)' },
    success: { border: 'rgba(34, 197, 94, 0.2)', shadow: '0 0 20px rgba(34, 197, 94, 0.15)' },
    none: { border: 'rgba(255,255,255,0.08)', shadow: 'none' },
  };

  const g = glowColors[glow] || glowColors.cyan;

  return (
    <motion.div
      whileHover={hover ? {
        borderColor: g.border,
        boxShadow: g.shadow,
        y: -2,
      } : undefined}
      transition={{ duration: 0.25 }}
      className={`glass-card p-5 ${className}`}
      {...props}
    >
      {children}
    </motion.div>
  );
}
