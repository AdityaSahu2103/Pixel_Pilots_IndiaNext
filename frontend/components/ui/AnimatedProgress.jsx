'use client';

import { motion } from 'framer-motion';

export default function AnimatedProgress({ progress = 0, label = '', color = '#00F5FF' }) {
  return (
    <div className="w-full">
      {label && (
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs font-medium" style={{ color: '#9CA3AF' }}>{label}</span>
          <span className="text-xs font-mono font-bold" style={{ color }}>{Math.round(progress)}%</span>
        </div>
      )}
      <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: 'rgba(17, 24, 39, 0.8)' }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className="h-full rounded-full relative"
          style={{
            background: `linear-gradient(90deg, ${color}, ${color}dd)`,
            boxShadow: `0 0 10px ${color}66`,
          }}
        >
          <div className="absolute inset-0 scan-progress-bar opacity-40 rounded-full" />
        </motion.div>
      </div>
    </div>
  );
}
