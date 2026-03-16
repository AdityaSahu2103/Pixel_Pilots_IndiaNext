'use client';

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileBarChart, Clock, Shield, ArrowRight, AlertTriangle,
  ChevronDown, ChevronUp, Zap, RefreshCw
} from 'lucide-react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import GlassCard from '@/components/ui/GlassCard';
import ThreatBadge from '@/components/ui/ThreatBadge';
import { getReports, getReport, runAdversarial } from '@/lib/api';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [adversarialLoading, setAdversarialLoading] = useState(false);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const data = await getReports();
      setReports(data);
    } catch {
      setReports([]);
    } finally {
      setLoading(false);
    }
  };

  const viewDetail = async (scanId) => {
    if (selectedReport?.scan_id === scanId) {
      setSelectedReport(null);
      return;
    }
    setDetailLoading(true);
    try {
      const data = await getReport(scanId);
      setSelectedReport(data);
    } catch {
      setSelectedReport(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleAdversarial = async (scanId) => {
    setAdversarialLoading(true);
    try {
      const result = await runAdversarial(scanId);
      // Refetch the detail to get updated adversarial data
      const updated = await getReport(scanId);
      setSelectedReport(updated);
    } catch {
      // silently fail
    } finally {
      setAdversarialLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-wide" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
              Intelligence Reports
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6B7280' }}>
              Deep dive into historical scan logs, AI reasoning, and adversarial resilience.
            </p>
          </div>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={fetchReports}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium cursor-pointer"
            style={{ background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.2)', color: '#00F5FF' }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Sync Latest Reports
          </motion.button>
        </div>

        {loading ? (
          <GlassCard className="text-center py-12">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              className="inline-block mb-3"
            >
              <RefreshCw className="w-6 h-6" style={{ color: '#00F5FF' }} />
            </motion.div>
            <p className="text-sm" style={{ color: '#6B7280' }}>Fetching intelligence reports...</p>
          </GlassCard>
        ) : reports.length === 0 ? (
          <GlassCard className="text-center py-16">
            <FileBarChart className="w-12 h-12 mx-auto mb-4" style={{ color: '#1f2937' }} />
            <h3 className="text-base font-semibold mb-2" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
              No Intelligence Available
            </h3>
            <p className="text-sm mb-4" style={{ color: '#6B7280' }}>
              Your database is clean. Start scanning endpoints or emails to generate AI reports.
            </p>
            <a href="/email-analyzer">
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                className="px-5 py-2.5 rounded-xl text-sm font-semibold cursor-pointer"
                style={{ background: 'rgba(0,245,255,0.1)', border: '1px solid rgba(0,245,255,0.3)', color: '#00F5FF' }}
              >
                Scan an Inbox
              </motion.button>
            </a>
          </GlassCard>
        ) : (
          <div className="space-y-4">
            {reports.map((report, i) => (
              <motion.div
                key={report.scan_id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <GlassCard className={`cursor-pointer transition-all duration-300 ${selectedReport?.scan_id === report.scan_id ? 'ring-1 ring-cyan-500/50' : 'hover:bg-[rgba(255,255,255,0.02)]'}`} onClick={() => viewDetail(report.scan_id)}>
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-start gap-4 flex-1">
                      <div className="p-3 rounded-xl flex-shrink-0"
                        style={{ background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.15)' }}>
                        <Shield className="w-5 h-5" style={{ color: '#00F5FF' }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-bold tracking-wider uppercase px-2 py-0.5 rounded" style={{ background: '#1f2937', color: '#9CA3AF' }}>
                            {report.source_type} SCAN
                          </span>
                          <span className="text-[10px] flex items-center gap-1" style={{ color: '#6B7280' }}>
                            <Clock className="w-3 h-3" />
                            {new Date(report.timestamp).toLocaleString()}
                          </span>
                        </div>

                        {/* Intelligent Context Display */}
                        {report.source_type === 'email' && report.subject ? (
                          <>
                            <p className="text-sm font-semibold truncate text-white">{report.subject}</p>
                            <p className="text-xs text-gray-400 truncate mt-0.5">From: {report.sender || 'Unknown'}</p>
                          </>
                        ) : report.source_type === 'url' && report.url ? (
                          <p className="text-sm font-mono truncate text-cyan-400">{report.url}</p>
                        ) : (
                          <p className="text-sm text-gray-300 italic truncate">Direct text injection scan</p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between md:justify-end gap-6 border-t md:border-t-0 border-gray-800 pt-3 md:pt-0">
                      <div className="text-center">
                        <p className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">Threats</p>
                        <p className="text-lg font-bold font-mono text-red-400">{report.threats_detected}</p>
                      </div>
                      <div className="text-center w-16">
                        <p className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">Score</p>
                        <p className="text-2xl font-bold font-mono leading-none" style={{
                          color: report.risk_score > 60 ? '#FF3B3B' : report.risk_score > 30 ? '#F59E0B' : '#22C55E'
                        }}>
                          {Math.round(report.risk_score)}
                        </p>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <ThreatBadge severity={report.severity} />
                        {selectedReport?.scan_id === report.scan_id ? (
                          <span className="text-[10px] text-cyan-500 flex items-center gap-1">Close <ChevronUp className="w-3 h-3" /></span>
                        ) : (
                          <span className="text-[10px] text-gray-500 flex items-center gap-1">Analyze <ChevronDown className="w-3 h-3" /></span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded Detail View */}
                  <AnimatePresence>
                    {selectedReport?.scan_id === report.scan_id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="overflow-hidden"
                      >
                        <div className="mt-6 pt-6 grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>

                          {/* Left Column: AI Reasoning */}
                          <div className="space-y-4">
                            {selectedReport.explanation && (
                              <div className="p-4 rounded-xl" style={{ background: 'rgba(139,92,246,0.05)', border: '1px solid rgba(139,92,246,0.2)' }}>
                                <div className="flex items-center gap-2 mb-2">
                                  <div className="w-2 h-2 rounded-full bg-purple-500 animate-pulse" />
                                  <h3 className="text-xs font-bold uppercase tracking-widest text-purple-400">LLM Deep Reasoning</h3>
                                </div>
                                <p className="text-sm leading-relaxed text-gray-300 mb-4">
                                  {selectedReport.explanation.summary}
                                </p>

                                {selectedReport.explanation.recommended_actions?.length > 0 && (
                                  <div>
                                    <p className="text-xs font-semibold text-purple-300 mb-2">Action Plan:</p>
                                    <ul className="space-y-1">
                                      {selectedReport.explanation.recommended_actions.map((act, idx) => (
                                        <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                                          <ArrowRight className="w-3 h-3 text-purple-500 mt-0.5 flex-shrink-0" />
                                          {act}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            )}

                            {selectedReport.detections?.length > 0 && (
                              <div>
                                <h3 className="text-xs font-bold uppercase tracking-widest text-gray-500 mb-3">Triggered Scanners</h3>
                                <div className="space-y-2">
                                  {selectedReport.detections.map((det, j) => (
                                    <div key={j} className="p-3 rounded-lg flex flex-col gap-2" style={{ background: 'rgba(0,0,0,0.3)' }}>
                                      <div className="flex items-center justify-between">
                                        <span className="text-sm font-semibold capitalize text-gray-200">
                                          {det.threat_type.replace('_', ' ')} Agent
                                        </span>
                                        <ThreatBadge severity={det.severity} />
                                      </div>
                                      <div className="w-full bg-gray-800 rounded-full h-1.5 mt-1">
                                        <div className="bg-cyan-500 h-1.5 rounded-full" style={{ width: `${det.confidence * 100}%` }}></div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Right Column: Adversarial Testing */}
                          <div className="p-5 rounded-xl flex flex-col" style={{ background: 'linear-gradient(145deg, rgba(249,115,22,0.05) 0%, rgba(0,0,0,0.4) 100%)', border: '1px solid rgba(249,115,22,0.15)' }}>
                            <div className="flex items-center gap-2 mb-1">
                              <Zap className="w-4 h-4 text-orange-500" />
                              <h3 className="text-sm font-bold uppercase tracking-widest text-orange-500">Adversarial Stress Test</h3>
                            </div>
                            <p className="text-xs text-gray-400 mb-6">
                              Hackers use "mutations" (like invisible zeroes, typos, or encoded characters) to bypass AI firewalls. We can automatically mutate this threat in massive quantities to see if your AI wall holds up.
                            </p>

                            {!selectedReport.adversarial ? (
                              <div className="flex-1 flex flex-col items-center justify-center py-6 text-center">
                                <motion.button
                                  whileHover={{ scale: 1.02 }}
                                  whileTap={{ scale: 0.98 }}
                                  onClick={(e) => { e.stopPropagation(); handleAdversarial(report.scan_id); }}
                                  disabled={adversarialLoading || !selectedReport.detections?.some(d => d.detected)}
                                  className="w-full max-w-[200px] flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-bold uppercase tracking-wider disabled:opacity-30 disabled:cursor-not-allowed"
                                  style={{ background: adversarialLoading ? '#4B5563' : '#F97316', color: '#fff' }}
                                >
                                  {adversarialLoading ? (
                                    <RefreshCw className="w-4 h-4 animate-spin" />
                                  ) : (
                                    <Shield className="w-4 h-4" />
                                  )}
                                  {adversarialLoading ? 'Simulating Attacks...' : 'Launch Attack Test'}
                                </motion.button>
                                {!selectedReport.detections?.some(d => d.detected) && (
                                  <p className="text-[10px] text-gray-500 mt-3">Cannot stress-test benign completely safe content.</p>
                                )}
                              </div>
                            ) : (
                              <div className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                  <div className="p-4 rounded-lg bg-black/40 border border-gray-800 text-center">
                                    <p className="text-[10px] uppercase text-gray-500 mb-1">System Robustness</p>
                                    <p className="text-3xl font-bold font-mono" style={{ color: selectedReport.adversarial.robustness_score > 70 ? '#22C55E' : '#F59E0B' }}>
                                      {Math.round(selectedReport.adversarial.robustness_score)}%
                                    </p>
                                  </div>
                                  <div className="p-4 rounded-lg bg-black/40 border border-gray-800 text-center">
                                    <p className="text-[10px] uppercase text-gray-500 mb-1">Hackers Evaded AI</p>
                                    <p className="text-3xl font-bold font-mono" style={{ color: selectedReport.adversarial.evasions_missed > 0 ? '#ef4444' : '#22C55E' }}>
                                      {selectedReport.adversarial.evasions_missed} <span className="text-sm text-gray-600">/ {selectedReport.adversarial.total_mutations}</span>
                                    </p>
                                  </div>
                                </div>

                                {selectedReport.adversarial.evasions_missed > 0 ? (
                                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                                    <p className="text-xs text-red-400 font-semibold mb-2">⚠️ Evasions Detected!</p>
                                    <p className="text-xs text-gray-400">
                                      The AI successfully blocked the original threat, but when hackers applied <strong>{selectedReport.adversarial.mutations?.filter(m => m.evasion_successful).map(m => m.mutation_type.replace(/_/g, ' ')).join(', ') || 'advanced mutation techniques'}</strong>, the AI failed to recognize it and let it through. You must harden the prompt injection models against this specific bypass technique.
                                    </p>
                                  </div>
                                ) : (
                                  <div className="p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                                    <p className="text-xs text-green-400 font-semibold">🛡️ Vault Solid</p>
                                    <p className="text-[10px] text-gray-400 mt-1">We threw {selectedReport.adversarial.total_mutations} heavily mutated bypassing attacks at the AI layer, and it caught 100% of them. Your current model thresholds are highly robust against adversarial attacks.</p>
                                  </div>
                                )}
                              </div>
                            )}

                          </div>
                        </div>

                        <div className="mt-4 pt-3 flex justify-between items-center" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                          <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest">
                            Scan ID: {report.scan_id}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </GlassCard>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>
    </DashboardLayout>
  );
}
