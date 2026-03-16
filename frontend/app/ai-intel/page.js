'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Brain, Search, Shield, Zap, Database, Network, Eye } from 'lucide-react';
import DashboardLayout from '@/components/layout/DashboardLayout';
import GlassCard from '@/components/ui/GlassCard';
import ScanButton from '@/components/ui/ScanButton';
import ThreatBadge from '@/components/ui/ThreatBadge';
import { analyzeGeneral } from '@/lib/api';

const threatIntelCards = [
  {
    title: 'Phishing Campaigns',
    desc: 'Monitor active phishing campaigns targeting your organization.',
    icon: Shield,
    color: '#FF3B3B',
    stat: '24 Active',
  },
  {
    title: 'Malware Signatures',
    desc: 'Track known malware signatures and zero-day exploits.',
    icon: Database,
    color: '#F97316',
    stat: '1,284 Known',
  },
  {
    title: 'Threat Actors',
    desc: 'Profile threat actors and their tactics, techniques, and procedures.',
    icon: Eye,
    color: '#8B5CF6',
    stat: '156 Tracked',
  },
  {
    title: 'Attack Vectors',
    desc: 'Analyze common attack patterns and entry points.',
    icon: Network,
    color: '#00F5FF',
    stat: '12 Vectors',
  },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 },
};

export default function AIThreatIntel() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const data = await analyzeGeneral('text', query);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <motion.div variants={containerVariants} initial="hidden" animate="visible">
        <motion.div variants={itemVariants} className="mb-6">
          <h1 className="text-2xl font-bold tracking-wide" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
            AI Threat Intelligence
          </h1>
          <p className="text-sm mt-1" style={{ color: '#6B7280' }}>
            Leverage AI-powered threat intelligence to investigate and understand cyber threats
          </p>
        </motion.div>

        {/* Threat Intel Cards */}
        <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {threatIntelCards.map((card) => {
            const Icon = card.icon;
            return (
              <GlassCard key={card.title}>
                <div className="flex items-start justify-between mb-3">
                  <div className="p-2 rounded-lg" style={{ background: `${card.color}10`, border: `1px solid ${card.color}25` }}>
                    <Icon className="w-4 h-4" style={{ color: card.color }} />
                  </div>
                  <span className="text-xs font-mono font-bold" style={{ color: card.color }}>
                    {card.stat}
                  </span>
                </div>
                <h3 className="text-sm font-semibold mb-1" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  {card.title}
                </h3>
                <p className="text-xs" style={{ color: '#6B7280' }}>{card.desc}</p>
              </GlassCard>
            );
          })}
        </motion.div>

        {/* AI Query */}
        <motion.div variants={itemVariants}>
          <GlassCard className="mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Brain className="w-5 h-5" style={{ color: '#8B5CF6' }} />
              <h2 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                AI Threat Analysis
              </h2>
            </div>
            <p className="text-xs mb-4" style={{ color: '#6B7280' }}>
              Enter any suspicious content — URLs, email text, messages — and let our multi-agent AI pipeline analyze it.
            </p>
            <div className="flex gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: '#6B7280' }} />
                <input
                  type="text"
                  placeholder="Paste suspicious content for AI analysis..."
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
                  className="pl-10"
                />
              </div>
              <ScanButton onClick={handleAnalyze} loading={loading} label="Analyze" />
            </div>
          </GlassCard>
        </motion.div>

        {/* Results */}
        {error && (
          <GlassCard glow="danger" className="mb-4">
            <p className="text-sm" style={{ color: '#FF3B3B' }}>{error}</p>
          </GlassCard>
        )}

        {result && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            <GlassCard>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold" style={{ fontFamily: 'Orbitron', color: '#E5E7EB' }}>
                  Intelligence Report
                </h3>
                <ThreatBadge severity={result.risk_score?.severity || 'safe'} />
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <div className="p-3 rounded-xl text-center" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <p className="text-2xl font-bold font-mono" style={{
                    color: result.risk_score?.overall_score > 60 ? '#FF3B3B' : '#22C55E'
                  }}>
                    {Math.round(result.risk_score?.overall_score || 0)}
                  </p>
                  <p className="text-[10px]" style={{ color: '#6B7280' }}>Risk Score</p>
                </div>
                <div className="p-3 rounded-xl text-center" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <p className="text-2xl font-bold font-mono" style={{ color: '#00F5FF' }}>
                    {result.detections?.filter(d => d.detected).length || 0}
                  </p>
                  <p className="text-[10px]" style={{ color: '#6B7280' }}>Threats</p>
                </div>
                <div className="p-3 rounded-xl text-center" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <p className="text-2xl font-bold font-mono" style={{ color: '#8B5CF6' }}>
                    {result.detections?.length || 0}
                  </p>
                  <p className="text-[10px]" style={{ color: '#6B7280' }}>Agents Used</p>
                </div>
                <div className="p-3 rounded-xl text-center" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <p className="text-2xl font-bold font-mono" style={{ color: '#F59E0B' }}>
                    {Math.round(result.processing_time_ms || 0)}ms
                  </p>
                  <p className="text-[10px]" style={{ color: '#6B7280' }}>Processing</p>
                </div>
              </div>

              {result.explanation && (
                <div className="p-4 rounded-xl" style={{ background: 'rgba(139,92,246,0.05)', border: '1px solid rgba(139,92,246,0.15)' }}>
                  <p className="text-xs font-semibold mb-2" style={{ color: '#8B5CF6' }}>
                    <Zap className="w-3 h-3 inline mr-1" />AI Summary
                  </p>
                  <p className="text-sm leading-relaxed" style={{ color: '#9CA3AF' }}>
                    {result.explanation.summary}
                  </p>

                  {result.explanation.reasoning_chain?.length > 0 && (
                    <div className="mt-3 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                      <p className="text-xs font-semibold mb-2" style={{ color: '#00F5FF' }}>Reasoning Chain</p>
                      {result.explanation.reasoning_chain.map((step, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs mb-1" style={{ color: '#9CA3AF' }}>
                          <span className="font-mono font-bold flex-shrink-0" style={{ color: '#00F5FF' }}>{i + 1}.</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {result.explanation.threat_context && (
                    <div className="mt-3 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                      <p className="text-xs font-semibold mb-1" style={{ color: '#F59E0B' }}>Threat Context</p>
                      <p className="text-xs" style={{ color: '#9CA3AF' }}>{result.explanation.threat_context}</p>
                    </div>
                  )}
                </div>
              )}
            </GlassCard>
          </motion.div>
        )}
      </motion.div>
    </DashboardLayout>
  );
}
