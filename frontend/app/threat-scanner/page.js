"use client";

import { useState } from "react";
import { useTranslate } from "@/hooks/useTranslate";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Copy,
  MessageSquare,
} from "lucide-react";
import DashboardLayout from "@/components/layout/DashboardLayout";
import GlassCard from "@/components/ui/GlassCard";
import ScanButton from "@/components/ui/ScanButton";
import ThreatBadge from "@/components/ui/ThreatBadge";
import AnimatedProgress from "@/components/ui/AnimatedProgress";
import { analyzeText } from "@/lib/api";

export default function ThreatScanner() {
  const { t } = useTranslate();
  const [text, setText] = useState("");
  const [context, setContext] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);

  const handleScan = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setScanProgress(0);

    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + Math.random() * 15;
      });
    }, 350);

    try {
      const data = await analyzeText(text, context || null);
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => setResult(data), 400);
    } catch (err) {
      clearInterval(progressInterval);
      setScanProgress(0);
      setError(t("threatScanner.scanFailed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <div className="mb-6">
          <h1
            className="text-2xl font-bold tracking-wide"
            style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
          >
            {t("threatScanner.title")}
          </h1>
          <p className="text-sm mt-1" style={{ color: "#6B7280" }}>
            {t("threatScanner.subtitle")}
          </p>
        </div>

        <GlassCard className="mb-6">
          <div className="flex items-center gap-2 mb-4">
            <MessageSquare className="w-5 h-5" style={{ color: "#22C55E" }} />
            <h2
              className="text-sm font-semibold"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("threatScanner.textAnalysis")}
            </h2>
          </div>

          <div className="mb-3">
            <label
              className="text-[10px] uppercase tracking-wider mb-1 block"
              style={{ color: "#6B7280" }}
            >
              {t("threatScanner.contextLabel")}
            </label>
            <input
              type="text"
              placeholder={t("threatScanner.contextPlaceholder")}
              value={context}
              onChange={(e) => setContext(e.target.value)}
            />
          </div>

          <div className="mb-4">
            <label
              className="text-[10px] uppercase tracking-wider mb-1 block"
              style={{ color: "#6B7280" }}
            >
              {t("threatScanner.textContentLabel")}
            </label>
            <textarea
              placeholder={t("threatScanner.textContentPlaceholder")}
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={8}
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[10px]" style={{ color: "#4B5563" }}>
              {text.length} {t("threatScanner.characters")}
            </span>
            <ScanButton
              onClick={handleScan}
              loading={loading}
              label={t("threatScanner.scanButton")}
            />
          </div>

          {loading && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="mt-4"
            >
              <AnimatedProgress
                progress={scanProgress}
                label={t("threatScanner.scanningText")}
                color="#22C55E"
              />
            </motion.div>
          )}
        </GlassCard>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mb-6"
            >
              <GlassCard glow="danger">
                <div className="flex items-center gap-3">
                  <AlertTriangle
                    className="w-5 h-5"
                    style={{ color: "#FF3B3B" }}
                  />
                  <p className="text-sm" style={{ color: "#FF3B3B" }}>
                    {error}
                  </p>
                </div>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <GlassCard>
                <div className="flex items-center justify-between mb-4">
                  <h3
                    className="text-sm font-semibold"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    {t("threatScanner.scanResults")}
                  </h3>
                  <ThreatBadge
                    severity={result.risk_score?.severity || "safe"}
                  />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div
                    className="p-4 rounded-xl"
                    style={{ background: "rgba(0,0,0,0.2)" }}
                  >
                    <p
                      className="text-[10px] uppercase tracking-wider mb-1"
                      style={{ color: "#6B7280" }}
                    >
                      {t("threatScanner.riskScore")}
                    </p>
                    <p
                      className="text-3xl font-bold font-mono"
                      style={{
                        color:
                          result.risk_score?.overall_score > 60
                            ? "#FF3B3B"
                            : result.risk_score?.overall_score > 30
                              ? "#F59E0B"
                              : "#22C55E",
                      }}
                    >
                      {Math.round(result.risk_score?.overall_score || 0)}
                      <span className="text-sm" style={{ color: "#6B7280" }}>
                        /100
                      </span>
                    </p>
                  </div>
                  <div
                    className="p-4 rounded-xl"
                    style={{ background: "rgba(0,0,0,0.2)" }}
                  >
                    <p
                      className="text-[10px] uppercase tracking-wider mb-1"
                      style={{ color: "#6B7280" }}
                    >
                      {t("threatScanner.confidence")}
                    </p>
                    <p
                      className="text-3xl font-bold font-mono"
                      style={{ color: "#00F5FF" }}
                    >
                      {Math.round((result.risk_score?.confidence || 0) * 100)}%
                    </p>
                  </div>
                  <div
                    className="p-4 rounded-xl"
                    style={{ background: "rgba(0,0,0,0.2)" }}
                  >
                    <p
                      className="text-[10px] uppercase tracking-wider mb-1"
                      style={{ color: "#6B7280" }}
                    >
                      {t("threatScanner.processing")}
                    </p>
                    <p
                      className="text-3xl font-bold font-mono"
                      style={{ color: "#8B5CF6" }}
                    >
                      {Math.round(result.processing_time_ms || 0)}
                      <span className="text-sm" style={{ color: "#6B7280" }}>
                        ms
                      </span>
                    </p>
                  </div>
                </div>
              </GlassCard>

              {result.detections?.length > 0 && (
                <GlassCard>
                  <h3
                    className="text-sm font-semibold mb-4"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    {t("threatScanner.detections")}
                  </h3>
                  <div className="space-y-3">
                    {result.detections.map((det, i) => (
                      <div
                        key={i}
                        className="p-3 rounded-xl flex items-center justify-between"
                        style={{
                          background: "rgba(0,0,0,0.2)",
                          border: "1px solid rgba(255,255,255,0.04)",
                        }}
                      >
                        <div className="flex items-center gap-3">
                          {det.detected ? (
                            <AlertTriangle
                              className="w-4 h-4"
                              style={{ color: "#FF3B3B" }}
                            />
                          ) : (
                            <CheckCircle
                              className="w-4 h-4"
                              style={{ color: "#22C55E" }}
                            />
                          )}
                          <div>
                            <p
                              className="text-xs font-semibold capitalize"
                              style={{ color: "#E5E7EB" }}
                            >
                              {det.threat_type.replace("_", " ")}
                            </p>
                            <p
                              className="text-[10px]"
                              style={{ color: "#6B7280" }}
                            >
                              {Math.round(det.confidence * 100)}% confidence
                            </p>
                          </div>
                        </div>
                        <ThreatBadge severity={det.severity} />
                      </div>
                    ))}
                  </div>
                </GlassCard>
              )}

              {result.explanation && (
                <GlassCard glow="purple">
                  <h3
                    className="text-sm font-semibold mb-3"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    🤖 {t("threatScanner.aiAnalysis")}
                  </h3>
                  <p
                    className="text-sm leading-relaxed"
                    style={{ color: "#9CA3AF" }}
                  >
                    {result.explanation.summary}
                  </p>
                  {result.explanation.recommended_actions?.length > 0 && (
                    <div className="mt-4">
                      <p
                        className="text-xs font-semibold mb-2"
                        style={{ color: "#8B5CF6" }}
                      >
                        {t("threatScanner.recommendedActions")}
                      </p>
                      <ul className="space-y-1.5">
                        {result.explanation.recommended_actions.map((a, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 text-xs"
                            style={{ color: "#9CA3AF" }}
                          >
                            <span style={{ color: "#8B5CF6" }}>→</span> {a}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </GlassCard>
              )}

              <div className="flex items-center justify-end gap-2">
                <span
                  className="text-[10px] font-mono"
                  style={{ color: "#4B5563" }}
                >
                  {t("threatScanner.scanId")} {result.scan_id}
                </span>
                <button
                  onClick={() => navigator.clipboard.writeText(result.scan_id)}
                  className="cursor-pointer"
                >
                  <Copy className="w-3 h-3" style={{ color: "#4B5563" }} />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </DashboardLayout>
  );
}
