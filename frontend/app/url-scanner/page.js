'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link2, AlertTriangle, CheckCircle, ExternalLink, Shield, Copy } from 'lucide-react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import GlassCard from '@/components/ui/GlassCard';
import ScanButton from '@/components/ui/ScanButton';
import ThreatBadge from '@/components/ui/ThreatBadge';
import AnimatedProgress from '@/components/ui/AnimatedProgress';
import { analyzeURL } from '@/lib/api';

export default function URLScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setScanProgress(0);

    // Simulate progress
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 90) { clearInterval(progressInterval); return 90; }
        return prev + Math.random() * 15;
      });
    }, 300);

    try {
      const data = await analyzeURL(url);
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => setResult(data), 400);
    } catch (err) {
      clearInterval(progressInterval);
      setScanProgress(0);
      setError(err.response?.data?.detail || 'Scan failed. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }}>
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold tracking-wide" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
            URL Scanner
          </h1>
          <p className="text-sm mt-1" style={{ color: '#6B7280' }}>
            Analyze URLs for phishing, malware, and other threats using VirusTotal & AI
          </p>
        </div>

        {/* Scan Input */}
        <GlassCard className="mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Link2 className="w-5 h-5" style={{ color: '#00F5FF' }} />
            <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
              Enter URL to Scan
            </h2>
          </div>

          <div className="flex gap-3">
            <div className="flex-1 relative">
              <input
                type="url"
                placeholder="https://example.com/suspicious-page"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                className="pr-10"
              />
              <ExternalLink className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: '#6B7280' }} />
            </div>
            <ScanButton onClick={handleScan} loading={loading} label="Scan URL" />
          </div>

          {/* Progress */}
          {loading && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mt-4">
              <AnimatedProgress progress={scanProgress} label="Scanning URL" />
              <div className="mt-3 flex items-center gap-2">
                <motion.div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#00F5FF' }}
                  animate={{ opacity: [0.3, 1, 0.3] }}
                  transition={{ duration: 1, repeat: Infinity }}
                />
                <span className="text-xs font-mono" style={{ color: '#6B7280' }}>
                  Running multi-agent analysis pipeline...
                </span>
              </div>
            </motion.div>
          )}
        </GlassCard>

        {/* Error */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mb-6"
            >
              <GlassCard glow="danger" className="flex items-center gap-3" style={{ borderColor: 'rgba(255,59,59,0.3)' }}>
                <AlertTriangle className="w-5 h-5" style={{ color: '#FF3B3B' }} />
                <p className="text-sm" style={{ color: '#FF3B3B' }}>{error}</p>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="space-y-4"
            >
              {/* Risk Overview */}
              <GlassCard>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                    Scan Results
                  </h3>
                  <ThreatBadge severity={result.risk_score?.severity || 'safe'} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#6B7280' }}>Risk Score</p>
                    <p className="text-3xl font-bold font-mono" style={{
                      color: result.risk_score?.overall_score > 60 ? '#FF3B3B' : result.risk_score?.overall_score > 30 ? '#F59E0B' : '#22C55E'
                    }}>
                      {Math.round(result.risk_score?.overall_score || 0)}
                      <span className="text-sm" style={{ color: '#6B7280' }}>/100</span>
                    </p>
                  </div>
                  <div className="p-4 rounded-xl" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#6B7280' }}>Confidence</p>
                    <p className="text-3xl font-bold font-mono" style={{ color: '#00F5FF' }}>
                      {Math.round((result.risk_score?.confidence || 0) * 100)}%
                    </p>
                  </div>
                  <div className="p-4 rounded-xl" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#6B7280' }}>Processing</p>
                    <p className="text-3xl font-bold font-mono" style={{ color: '#8B5CF6' }}>
                      {Math.round(result.processing_time_ms || 0)}
                      <span className="text-sm" style={{ color: '#6B7280' }}>ms</span>
                    </p>
                  </div>
                </div>
              </GlassCard>

              {/* Detections */}
              {result.detections?.length > 0 && (
                <GlassCard>
                  <h3 className="text-sm font-semibold mb-4" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                    <Shield className="w-4 h-4 inline mr-2" style={{ color: '#00F5FF' }} />
                    Detections
                  </h3>
                  <div className="space-y-3">
                    {result.detections.map((det, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.1 }}
                        className="p-3 rounded-xl flex items-center justify-between"
                        style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)' }}
                      >
                        <div className="flex items-center gap-3">
                          {det.detected ? (
                            <AlertTriangle className="w-4 h-4" style={{ color: '#FF3B3B' }} />
                          ) : (
                            <CheckCircle className="w-4 h-4" style={{ color: '#22C55E' }} />
                          )}
                          <div>
                            <p className="text-xs font-semibold capitalize" style={{ color: '#E5E7EB' }}>
                              {det.threat_type.replace('_', ' ')}
                            </p>
                            <p className="text-[10px]" style={{ color: '#6B7280' }}>
                              {det.agent_name} | {Math.round(det.confidence * 100)}% confidence
                            </p>
                          </div>
                        </div>
                        <ThreatBadge severity={det.severity} />
                      </motion.div>
                    ))}
                  </div>
                </GlassCard>
              )}

              {/* AI Explanation */}
              {result.explanation && (
                <GlassCard glow="purple">
                  <h3 className="text-sm font-semibold mb-3" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                    🤖 AI Explanation
                  </h3>
                  <p className="text-sm leading-relaxed mb-4" style={{ color: '#9CA3AF' }}>
                    {result.explanation.summary}
                  </p>
                  {result.explanation.recommended_actions?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold mb-2" style={{ color: '#8B5CF6' }}>Recommended Actions:</p>
                      <ul className="space-y-1.5">
                        {result.explanation.recommended_actions.map((action, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs" style={{ color: '#9CA3AF' }}>
                            <span style={{ color: '#8B5CF6' }}>→</span> {action}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </GlassCard>
              )}

              {/* Scan ID */}
              <div className="flex items-center justify-end gap-2">
                <span className="text-[10px] font-mono" style={{ color: '#4B5563' }}>
                  Scan ID: {result.scan_id}
                </span>
                <button onClick={() => navigator.clipboard.writeText(result.scan_id)} className="cursor-pointer">
                  <Copy className="w-3 h-3" style={{ color: '#4B5563' }} />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </DashboardLayout>
  );
}
