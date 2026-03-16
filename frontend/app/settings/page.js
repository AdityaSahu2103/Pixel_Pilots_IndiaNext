'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Settings as SettingsIcon, Server, Palette, Bell, Shield, Save, Check } from 'lucide-react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import GlassCard from '@/components/ui/GlassCard';
import { checkHealth } from '@/lib/api';

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [saved, setSaved] = useState(false);
  const [settings, setSettings] = useState({
    apiUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
    notifications: true,
    autoScan: false,
    darkMode: true,
  });

  useEffect(() => {
    checkHealth().then(setHealth).catch(() => {});
  }, []);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 },
  };

  return (
    <DashboardLayout>
      <motion.div variants={containerVariants} initial="hidden" animate="visible">
        <motion.div variants={itemVariants} className="mb-6">
          <h1 className="text-2xl font-bold tracking-wide" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
            Settings
          </h1>
          <p className="text-sm mt-1" style={{ color: '#6B7280' }}>
            Configure your ThreatFuse AI platform
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* API Configuration */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <Server className="w-5 h-5" style={{ color: '#00F5FF' }} />
                <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  API Configuration
                </h2>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="text-[10px] uppercase tracking-wider mb-1 block" style={{ color: '#6B7280' }}>
                    Backend API URL
                  </label>
                  <input
                    type="url"
                    value={settings.apiUrl}
                    onChange={(e) => setSettings({ ...settings, apiUrl: e.target.value })}
                    placeholder="http://localhost:8000"
                  />
                </div>

                <div className="p-3 rounded-xl" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium" style={{ color: '#9CA3AF' }}>Connection Status</span>
                    <span className="text-xs font-semibold" style={{ color: health ? '#22C55E' : '#FF3B3B' }}>
                      {health ? '● Connected' : '● Disconnected'}
                    </span>
                  </div>
                  {health && (
                    <div className="text-[10px] space-y-1" style={{ color: '#6B7280' }}>
                      <div className="flex justify-between">
                        <span>Version</span>
                        <span className="font-mono">{health.version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Status</span>
                        <span className="font-mono">{health.status}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </GlassCard>
          </motion.div>

          {/* Agent Status */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5" style={{ color: '#8B5CF6' }} />
                <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  Agent Status
                </h2>
              </div>

              {health?.agents ? (
                <div className="space-y-2">
                  {Object.entries(health.agents).map(([name, status]) => (
                    <div key={name} className="flex items-center justify-between p-2 rounded-lg"
                      style={{ background: 'rgba(0,0,0,0.2)' }}>
                      <span className="text-xs capitalize" style={{ color: '#E5E7EB' }}>
                        {name.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded"
                        style={{
                          color: status === 'active' ? '#22C55E' : '#F59E0B',
                          background: status === 'active' ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)',
                        }}>
                        {status}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-center py-4" style={{ color: '#6B7280' }}>
                  Connect to backend to view agent status
                </p>
              )}
            </GlassCard>
          </motion.div>

          {/* Preferences */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <Palette className="w-5 h-5" style={{ color: '#F59E0B' }} />
                <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  Preferences
                </h2>
              </div>

              <div className="space-y-4">
                {[
                  { label: 'Dark Mode', key: 'darkMode', desc: 'Use dark theme (recommended for SOC environments)' },
                  { label: 'Notifications', key: 'notifications', desc: 'Receive alerts for high-severity threats' },
                  { label: 'Auto-Scan', key: 'autoScan', desc: 'Automatically scan pasted content' },
                ].map((pref) => (
                  <div key={pref.key} className="flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium" style={{ color: '#E5E7EB' }}>{pref.label}</p>
                      <p className="text-[10px]" style={{ color: '#6B7280' }}>{pref.desc}</p>
                    </div>
                    <button
                      onClick={() => setSettings({ ...settings, [pref.key]: !settings[pref.key] })}
                      className="w-10 h-5 rounded-full relative cursor-pointer transition-colors"
                      style={{
                        background: settings[pref.key] ? 'rgba(0, 245, 255, 0.3)' : 'rgba(255,255,255,0.1)',
                        border: `1px solid ${settings[pref.key] ? 'rgba(0,245,255,0.5)' : 'rgba(255,255,255,0.1)'}`,
                      }}
                    >
                      <motion.div
                        className="w-3.5 h-3.5 rounded-full absolute top-0.5"
                        style={{ background: settings[pref.key] ? '#00F5FF' : '#6B7280' }}
                        animate={{ left: settings[pref.key] ? '20px' : '2px' }}
                        transition={{ duration: 0.2 }}
                      />
                    </button>
                  </div>
                ))}
              </div>
            </GlassCard>
          </motion.div>

          {/* About */}
          <motion.div variants={itemVariants}>
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <SettingsIcon className="w-5 h-5" style={{ color: '#22C55E' }} />
                <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  About
                </h2>
              </div>

              <div className="space-y-3 text-xs" style={{ color: '#9CA3AF' }}>
                <div className="flex justify-between">
                  <span>Platform</span>
                  <span className="font-mono" style={{ color: '#00F5FF' }}>ThreatFuse AI</span>
                </div>
                <div className="flex justify-between">
                  <span>Frontend</span>
                  <span className="font-mono">Next.js 15</span>
                </div>
                <div className="flex justify-between">
                  <span>Backend</span>
                  <span className="font-mono">FastAPI + Python</span>
                </div>
                <div className="flex justify-between">
                  <span>AI Model</span>
                  <span className="font-mono">LLaMA 3.3 70B (Groq)</span>
                </div>
                <div className="flex justify-between">
                  <span>Team</span>
                  <span className="font-mono">Pixel Pilots</span>
                </div>
                <div className="flex justify-between">
                  <span>Built For</span>
                  <span className="font-mono">IndiaNext Hackathon 2026</span>
                </div>
              </div>
            </GlassCard>
          </motion.div>
        </div>

        {/* Save Button */}
        <motion.div variants={itemVariants} className="mt-6 flex justify-end">
          <motion.button
            whileHover={{ scale: 1.03, boxShadow: '0 0 25px rgba(0, 245, 255, 0.3)' }}
            whileTap={{ scale: 0.97 }}
            onClick={handleSave}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-semibold cursor-pointer"
            style={{
              background: saved ? 'rgba(34, 197, 94, 0.2)' : 'linear-gradient(135deg, rgba(0, 245, 255, 0.15), rgba(139, 92, 246, 0.15))',
              border: `1px solid ${saved ? 'rgba(34, 197, 94, 0.3)' : 'rgba(0, 245, 255, 0.3)'}`,
              color: saved ? '#22C55E' : '#00F5FF',
            }}
          >
            {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
            {saved ? 'Saved!' : 'Save Settings'}
          </motion.button>
        </motion.div>
      </motion.div>
    </DashboardLayout>
  );
}
