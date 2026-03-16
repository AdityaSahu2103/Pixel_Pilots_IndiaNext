'use client';

import { motion } from 'framer-motion';
import { Scan } from 'lucide-react';

export default function ScanButton({ onClick, loading = false, label = 'Start Scan', className = '' }) {
  return (
    <motion.button
      whileHover={{ scale: 1.02, boxShadow: '0 0 30px rgba(0, 245, 255, 0.3)' }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      disabled={loading}
      className={`relative flex items-center justify-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm tracking-wide transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      style={{
        background: 'linear-gradient(135deg, rgba(0, 245, 255, 0.2), rgba(139, 92, 246, 0.2))',
        border: '1px solid rgba(0, 245, 255, 0.3)',
        color: '#00F5FF',
      }}
    >
      {loading ? (
        <>
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          >
            <Scan className="w-4 h-4" />
          </motion.div>
          <span>Scanning...</span>
        </>
      ) : (
        <>
          <Scan className="w-4 h-4" />
          <span>{label}</span>
        </>
      )}

      {loading && (
        <motion.div
          className="absolute inset-0 rounded-xl overflow-hidden"
          style={{ border: '1px solid transparent' }}
        >
          <motion.div
            className="absolute inset-0 opacity-20"
            style={{
              background: 'linear-gradient(90deg, transparent, #00F5FF, transparent)',
            }}
            animate={{ x: ['-100%', '100%'] }}
            transition={{ duration: 1.5, repeat: Infinity }}
          />
        </motion.div>
      )}
    </motion.button>
  );
}
