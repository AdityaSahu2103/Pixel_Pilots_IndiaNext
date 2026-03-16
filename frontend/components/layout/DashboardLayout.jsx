'use client';

import Sidebar from './Sidebar';
import TopNavbar from './TopNavbar';
import { motion } from 'framer-motion';

export default function DashboardLayout({ children }) {
  return (
    <div className="flex min-h-screen w-full" style={{ background: '#0A0F1C' }}>
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0" style={{ marginLeft: '260px' }}>
        <TopNavbar />
        <motion.main
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
          className="flex-1 p-6 dot-grid overflow-x-hidden"
        >
          <div className="max-w-[1400px] mx-auto w-full">
            {children}
          </div>
        </motion.main>
      </div>
    </div>
  );
}
