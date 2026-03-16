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
              Reports
            </h1>
            <p className="text-sm mt-1" style={{ color: '#6B7280' }}>
              View all scan history and threat analysis reports
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
            Refresh
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
            <p className="text-sm" style={{ color: '#6B7280' }}>Loading reports...</p>
          </GlassCard>
        ) : reports.length === 0 ? (
          <GlassCard className="text-center py-16">
            <FileBarChart className="w-12 h-12 mx-auto mb-4" style={{ color: '#1f2937' }} />
            <h3 className="text-base font-semibold mb-2" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
              No Reports Yet
            </h3>
            <p className="text-sm mb-4" style={{ color: '#6B7280' }}>
              Start scanning URLs, emails, or text to generate reports
            </p>
            <a href="/url-scanner">
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                className="px-5 py-2.5 rounded-xl text-sm font-semibold cursor-pointer"
                style={{ background: 'rgba(0,245,255,0.1)', border: '1px solid rgba(0,245,255,0.3)', color: '#00F5FF' }}
              >
                Run First Scan
              </motion.button>
            </a>
          </GlassCard>
        ) : (
          <div className="space-y-3">
            {reports.map((report, i) => (
              <motion.div
                key={report.scan_id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <GlassCard className="cursor-pointer" onClick={() => viewDetail(report.scan_id)}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="p-2 rounded-lg"
                        style={{ background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.15)' }}>
                        <Shield className="w-4 h-4" style={{ color: '#00F5FF' }} />
                      </div>
                      <div>
                        <p className="text-sm font-semibold" style={{ color: '#E5E7EB' }}>
                          {report.source_type.toUpperCase()} Scan
                        </p>
                        <div className="flex items-center gap-3 mt-1">
                          <div className="flex items-center gap-1 text-[10px]" style={{ color: '#6B7280' }}>
                            <Clock className="w-3 h-3" />
                            {new Date(report.timestamp).toLocaleString()}
                          </div>
                          <div className="flex items-center gap-1 text-[10px]" style={{ color: '#6B7280' }}>
                            <AlertTriangle className="w-3 h-3" />
                            {report.threats_detected} threat{report.threats_detected !== 1 ? 's' : ''}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right mr-3">
                        <p className="text-xs" style={{ color: '#6B7280' }}>Risk Score</p>
                        <p className="text-lg font-bold font-mono" style={{
                          color: report.risk_score > 60 ? '#FF3B3B' : report.risk_score > 30 ? '#F59E0B' : '#22C55E'
                        }}>
                          {Math.round(report.risk_score)}
                        </p>
                      </div>
                      <ThreatBadge severity={report.severity} />
                      {selectedReport?.scan_id === report.scan_id ? (
                        <ChevronUp className="w-4 h-4" style={{ color: '#6B7280' }} />
                      ) : (
                        <ChevronDown className="w-4 h-4" style={{ color: '#6B7280' }} />
                      )}
                    </div>
                  </div>

                  {/* Detail View */}
                  <AnimatePresence>
                    {selectedReport?.scan_id === report.scan_id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="overflow-hidden"
                      >
                        <div className="mt-4 pt-4" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                          {/* Detections */}
                          {selectedReport.detections?.length > 0 && (
                            <div className="mb-4">
                              <p className="text-xs font-semibold mb-2" style={{ color: '#9CA3AF' }}>Detections</p>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {selectedReport.detections.map((det, j) => (
                                  <div key={j} className="p-2 rounded-lg flex items-center justify-between"
                                    style={{ background: 'rgba(0,0,0,0.2)' }}>
                                    <span className="text-xs capitalize" style={{ color: '#E5E7EB' }}>
                                      {det.threat_type.replace('_', ' ')}
                                    </span>
                                    <ThreatBadge severity={det.severity} />
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Explanation */}
                          {selectedReport.explanation && (
                            <div className="mb-4 p-3 rounded-xl" style={{ background: 'rgba(139,92,246,0.05)', border: '1px solid rgba(139,92,246,0.15)' }}>
                              <p className="text-xs font-semibold mb-1" style={{ color: '#8B5CF6' }}>AI Summary</p>
                              <p className="text-xs leading-relaxed" style={{ color: '#9CA3AF' }}>
                                {selectedReport.explanation.summary}
                              </p>
                            </div>
                          )}

                          {/* Adversarial Test */}
                          <div className="flex items-center gap-3">
                            <motion.button
                              whileHover={{ scale: 1.03 }}
                              whileTap={{ scale: 0.97 }}
                              onClick={(e) => { e.stopPropagation(); handleAdversarial(report.scan_id); }}
                              disabled={adversarialLoading}
                              className="flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-semibold cursor-pointer disabled:opacity-50"
                              style={{ background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.3)', color: '#F97316' }}
                            >
                              <Zap className="w-3 h-3" />
                              {adversarialLoading ? 'Testing...' : 'Run Adversarial Test'}
                            </motion.button>

                            {selectedReport.adversarial && (
                              <div className="text-xs" style={{ color: '#9CA3AF' }}>
                                Robustness: <span className="font-bold font-mono" style={{ color: '#22C55E' }}>
                                  {Math.round(selectedReport.adversarial.robustness_score)}%
                                </span>
                                {' '}| Evasions: {selectedReport.adversarial.evasions_missed}/{selectedReport.adversarial.total_mutations}
                              </div>
                            )}
                          </div>

                          <p className="text-[10px] font-mono mt-3" style={{ color: '#4B5563' }}>
                            ID: {report.scan_id}
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
