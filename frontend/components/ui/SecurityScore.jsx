'use client';

import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

export default function SecurityScore({ score = 0, size = 160, label = 'Security Score' }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const safeScore = 100 - score; // higher = safer

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(safeScore), 200);
    return () => clearTimeout(timer);
  }, [safeScore]);

  const getColor = (val) => {
    if (val >= 80) return '#22C55E';
    if (val >= 60) return '#F59E0B';
    if (val >= 40) return '#F97316';
    return '#FF3B3B';
  };

  const color = getColor(animatedScore);
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        {/* Background circle */}
        <svg width={size} height={size} className="transform -rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="8"
          />
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.5, ease: 'easeOut', delay: 0.3 }}
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            className="text-3xl font-bold font-mono"
            style={{ color }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {animatedScore}
          </motion.span>
          <span className="text-[10px] tracking-wider uppercase" style={{ color: '#6B7280' }}>
            / 100
          </span>
        </div>
      </div>
      <span className="text-xs font-medium tracking-wider uppercase" style={{ color: '#9CA3AF', fontFamily: 'Orbitron, sans-serif' }}>
        {label}
      </span>
    </div>
  );
}
