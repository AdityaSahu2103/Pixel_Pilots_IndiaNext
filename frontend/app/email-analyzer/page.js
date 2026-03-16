"use client";

import { useState } from "react";
import { useTranslate } from "@/hooks/useTranslate";
import { motion, AnimatePresence } from "framer-motion";
import {
  Mail,
  AlertTriangle,
  CheckCircle,
  Shield,
  Copy,
  User,
  FileText,
  RefreshCw,
  Key,
  Image as ImageIcon,
  UploadCloud,
} from "lucide-react";
import DashboardLayout from "@/components/layout/DashboardLayout";
import GlassCard from "@/components/ui/GlassCard";
import ScanButton from "@/components/ui/ScanButton";
import ThreatBadge from "@/components/ui/ThreatBadge";
import AnimatedProgress from "@/components/ui/AnimatedProgress";
import { analyzeEmail, syncLiveEmail, analyzeFile } from "@/lib/api";

export default function EmailAnalyzer() {
  const { t } = useTranslate();
  const [rawEmail, setRawEmail] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);

  // IMAP Live Sync State
  const [imapEmail, setImapEmail] = useState("");
  const [imapPassword, setImapPassword] = useState("");
  const [imapLoading, setImapLoading] = useState(false);
  const [imapResults, setImapResults] = useState([]);
  const [imapError, setImapError] = useState(null);

  // File Upload State
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadLoading, setUploadLoading] = useState(false);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploadFile(file);
    setUploadLoading(true);
    setResult(null);
    setError(null);
    setScanProgress(0);

    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + Math.random() * 12;
      });
    }, 400);

    try {
      const data = await analyzeFile(file);
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => setResult(data), 400);
    } catch (err) {
      clearInterval(progressInterval);
      setScanProgress(0);
      t("emailAnalyzer.fileScanFailed");
    } finally {
      setUploadLoading(false);
    }
  };

  const handleLiveSync = async () => {
    if (!imapEmail || !imapPassword) {
      setImapError(t("emailAnalyzer.missingCreds"));
      return;
    }
    setImapLoading(true);
    setImapError(null);
    setImapResults([]);
    try {
      const data = await syncLiveEmail(
        imapEmail,
        imapPassword,
        "imap.gmail.com",
        2,
      );
      setImapResults(data);
      if (data.length === 0) setImapError(t("emailAnalyzer.noEmails"));
    } catch (err) {
      if (err.message === "Network Error" || err.code === "ECONNABORTED") {
        setImapError(t("emailAnalyzer.timeout"));
      } else {
        setImapError(
          err.response?.data?.detail || t("emailAnalyzer.syncFailed"),
        );
      }
    } finally {
      setImapLoading(false);
    }
  };

  const handleScan = async () => {
    if (!rawEmail.trim()) return;
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
        return prev + Math.random() * 12;
      });
    }, 400);

    try {
      const data = await analyzeEmail(
        rawEmail,
        sender || null,
        subject || null,
      );
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => setResult(data), 400);
    } catch (err) {
      clearInterval(progressInterval);
      setScanProgress(0);
      setError(err.response?.data?.detail || t("emailAnalyzer.scanFailed"));
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
          <div className="flex items-center justify-between">
            <div>
              <h1
                className="text-2xl font-bold tracking-wide"
                style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
              >
                {t("emailAnalyzer.title")}
              </h1>
              <p className="text-sm mt-1" style={{ color: "#6B7280" }}>
                {t("emailAnalyzer.subtitle")}
              </p>
            </div>
          </div>
        </div>

        {/* Live Email Sync Section */}
        <GlassCard className="mb-6" glow="cyan">
          <div className="flex items-center gap-2 mb-4">
            <RefreshCw className="w-5 h-5" style={{ color: "#00F5FF" }} />
            <h2
              className="text-sm font-semibold"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("emailAnalyzer.liveSyncTitle")}
            </h2>
          </div>
          <p className="text-xs mb-4" style={{ color: "#9CA3AF" }}>
            {t("emailAnalyzer.liveSyncDesc")}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
            <div>
              <label
                className="text-[10px] uppercase tracking-wider mb-1 block"
                style={{ color: "#6B7280" }}
              >
                {t("emailAnalyzer.gmailAddress")}
              </label>
              <div className="relative">
                <Mail
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                  style={{ color: "#6B7280" }}
                />
                <input
                  type="email"
                  placeholder="you@gmail.com"
                  value={imapEmail}
                  onChange={(e) => setImapEmail(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div>
              <label
                className="text-[10px] uppercase tracking-wider mb-1 block"
                style={{ color: "#6B7280" }}
              >
                {t("emailAnalyzer.appPassword")}
              </label>
              <div className="relative">
                <Key
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                  style={{ color: "#6B7280" }}
                />
                <input
                  type="password"
                  placeholder={t("emailAnalyzer.appPasswordPlaceholder")}
                  value={imapPassword}
                  onChange={(e) => setImapPassword(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
          </div>

          <div className="flex justify-end mt-4">
            <button
              onClick={handleLiveSync}
              disabled={imapLoading}
              className="flex items-center gap-2 px-6 py-2 rounded-lg text-xs font-semibold"
              style={{
                background: imapLoading ? "#475569" : "#00F5FF",
                color: "#0f172a",
              }}
            >
              {imapLoading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              {imapLoading
                ? t("emailAnalyzer.syncingButton")
                : t("emailAnalyzer.syncButton")}
            </button>
          </div>

          {imapError && (
            <div
              className="mt-4 p-3 rounded-lg flex items-start gap-2 text-xs"
              style={{
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
              }}
            >
              <AlertTriangle className="w-4 h-4" style={{ color: "#ef4444" }} />
              <span className="text-red-400">{imapError}</span>
            </div>
          )}

          {imapResults.length > 0 && (
            <div className="mt-4 space-y-2">
              <h3
                className="text-xs font-semibold"
                style={{ color: "#E5E7EB" }}
              >
                {t("emailAnalyzer.recentScans")}
              </h3>
              {imapResults.map((res, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg flex items-center justify-between"
                  style={{
                    background: "rgba(0,0,0,0.2)",
                    border: "1px solid rgba(255,255,255,0.05)",
                  }}
                >
                  <div>
                    <p className="text-xs font-semibold text-white">
                      {res.subject}
                    </p>
                    <p className="text-[10px] text-gray-400">
                      From: {res.sender}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span
                      className="text-xs font-mono"
                      style={{
                        color:
                          res.severity === "Critical" || res.severity === "High"
                            ? "#ef4444"
                            : "#22c55e",
                      }}
                    >
                      Score: {res.risk_score}
                    </span>
                    <a
                      href={`/reports`}
                      className="text-[10px] px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 text-cyan-400"
                    >
                      {t("emailAnalyzer.viewInReports")}
                    </a>
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>

        <div className="flex items-center justify-center my-6">
          <div className="h-px bg-gray-800 w-full"></div>
          <span className="px-4 text-xs font-semibold text-gray-500 uppercase tracking-widest">
            {t("emailAnalyzer.or")}
          </span>
          <div className="h-px bg-gray-800 w-full"></div>
        </div>

        {/* Direct Media Upload Section */}
        <GlassCard className="mb-6" glow="purple">
          <div className="flex items-center gap-2 mb-4">
            <ImageIcon className="w-5 h-5" style={{ color: "#D946EF" }} />
            <h2
              className="text-sm font-semibold"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("emailAnalyzer.mediaScanTitle")}
            </h2>
          </div>
          <p className="text-xs mb-4" style={{ color: "#9CA3AF" }}>
            {t("emailAnalyzer.mediaScanDesc")}
          </p>

          <div className="flex items-center justify-between">
            <div className="flex-1 mr-4">
              <label
                className="text-[10px] uppercase tracking-wider mb-2 block"
                style={{ color: "#6B7280" }}
              >
                {t("emailAnalyzer.selectMedia")}
              </label>
              <div className="relative">
                <input
                  type="file"
                  accept="image/*,video/mp4"
                  onChange={handleFileUpload}
                  disabled={uploadLoading}
                  className="block w-full text-xs text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-gray-800 file:text-fuchsia-400 hover:file:bg-gray-700 cursor-pointer"
                />
              </div>
              {uploadFile && (
                <p className="text-[10px] mt-2" style={{ color: "#A78BFA" }}>
                  Selected: {uploadFile.name} (
                  {(uploadFile.size / 1024 / 1024).toFixed(2)} MB)
                </p>
              )}
            </div>

            {uploadLoading && (
              <div className="w-1/2">
                <AnimatedProgress
                  progress={scanProgress}
                  label={t("emailAnalyzer.analyzingMedia")}
                  color="#D946EF"
                />
                <div className="mt-2 flex items-center gap-2">
                  <motion.div
                    className="w-2 h-2 rounded-full"
                    style={{ background: "#D946EF" }}
                    animate={{ opacity: [0.3, 1, 0.3] }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                  <span
                    className="text-[10px] font-mono"
                    style={{ color: "#6B7280" }}
                  >
                    {t("emailAnalyzer.scanningPixels")}
                  </span>
                </div>
              </div>
            )}
          </div>
        </GlassCard>

        <div className="flex items-center justify-center my-6">
          <div className="h-px bg-gray-800 w-full"></div>
          <span className="px-4 text-xs font-semibold text-gray-500 uppercase tracking-widest">
            {t("emailAnalyzer.or")}
          </span>
          <div className="h-px bg-gray-800 w-full"></div>
        </div>

        {/* Manual Input Section */}

        <GlassCard className="mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Mail className="w-5 h-5" style={{ color: "#8B5CF6" }} />
            <h2
              className="text-sm font-semibold"
              style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
            >
              {t("emailAnalyzer.emailDetailsTitle")}
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
            <div>
              <label
                className="text-[10px] uppercase tracking-wider mb-1 block"
                style={{ color: "#6B7280" }}
              >
                {t("emailAnalyzer.senderLabel")}
              </label>
              <div className="relative">
                <User
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                  style={{ color: "#6B7280" }}
                />
                <input
                  type="text"
                  placeholder="sender@example.com"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div>
              <label
                className="text-[10px] uppercase tracking-wider mb-1 block"
                style={{ color: "#6B7280" }}
              >
                Subject (optional)
              </label>
              <div className="relative">
                <FileText
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                  style={{ color: "#6B7280" }}
                />
                <input
                  type="text"
                  placeholder="Re: Urgent action required"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
          </div>

          <div className="mb-4">
            <label
              className="text-[10px] uppercase tracking-wider mb-1 block"
              style={{ color: "#6B7280" }}
            >
              Raw Email Content
            </label>
            <textarea
              placeholder="Paste the full email content here (headers + body, or just the body)..."
              value={rawEmail}
              onChange={(e) => setRawEmail(e.target.value)}
              rows={10}
              className="font-mono text-xs"
              style={{ fontFamily: "JetBrains Mono, monospace" }}
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[10px]" style={{ color: "#4B5563" }}>
              {rawEmail.length} characters
            </span>
            <ScanButton
              onClick={handleScan}
              loading={loading}
              label="Analyze Email"
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
                label="Analyzing Email"
                color="#8B5CF6"
              />
              <div className="mt-3 flex items-center gap-2">
                <motion.div
                  className="w-2 h-2 rounded-full"
                  style={{ background: "#8B5CF6" }}
                  animate={{ opacity: [0.3, 1, 0.3] }}
                  transition={{ duration: 1, repeat: Infinity }}
                />
                <span
                  className="text-xs font-mono"
                  style={{ color: "#6B7280" }}
                >
                  Analyzing headers, content, and embedded URLs...
                </span>
              </div>
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
              <GlassCard
                glow="danger"
                style={{ borderColor: "rgba(255,59,59,0.3)" }}
              >
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
              {/* Risk Overview */}
              <GlassCard>
                <div className="flex items-center justify-between mb-4">
                  <h3
                    className="text-sm font-semibold"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    Analysis Results
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
                      Risk Score
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
                      Threats Found
                    </p>
                    <p
                      className="text-3xl font-bold font-mono"
                      style={{ color: "#FF3B3B" }}
                    >
                      {result.detections?.filter((d) => d.detected).length || 0}
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
                      Processing
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

              {/* Detections */}
              {result.detections?.length > 0 && (
                <GlassCard>
                  <h3
                    className="text-sm font-semibold mb-4"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    Phishing Indicators
                  </h3>
                  <div className="space-y-3">
                    {result.detections.map((det, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.1 }}
                        className="p-3 rounded-xl"
                        style={{
                          background: "rgba(0,0,0,0.2)",
                          border: "1px solid rgba(255,255,255,0.04)",
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
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
                            <span
                              className="text-xs font-semibold capitalize"
                              style={{ color: "#E5E7EB" }}
                            >
                              {det.threat_type.replace("_", " ")}
                            </span>
                          </div>
                          <ThreatBadge severity={det.severity} />
                        </div>
                        {det.evidence?.length > 0 && (
                          <div className="ml-6 space-y-1">
                            {det.evidence.map((ev, j) => (
                              <div
                                key={j}
                                className="flex items-start gap-2 text-xs"
                                style={{ color: "#9CA3AF" }}
                              >
                                <span style={{ color: "#F59E0B" }}>•</span>
                                <span>
                                  <strong style={{ color: "#E5E7EB" }}>
                                    {ev.indicator}:
                                  </strong>{" "}
                                  {ev.description}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </GlassCard>
              )}

              {/* AI Explanation */}
              {result.explanation && (
                <GlassCard glow="purple">
                  <h3
                    className="text-sm font-semibold mb-3"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    🤖 AI Analysis
                  </h3>
                  <p
                    className="text-sm leading-relaxed mb-4"
                    style={{ color: "#9CA3AF" }}
                  >
                    {result.explanation.summary}
                  </p>
                  {result.explanation.reasoning_chain?.length > 0 && (
                    <div className="mb-4">
                      <p
                        className="text-xs font-semibold mb-2"
                        style={{ color: "#00F5FF" }}
                      >
                        Reasoning Chain:
                      </p>
                      <div className="space-y-2">
                        {result.explanation.reasoning_chain.map((step, i) => (
                          <div
                            key={i}
                            className="flex items-start gap-2 text-xs"
                            style={{ color: "#9CA3AF" }}
                          >
                            <span
                              className="font-mono font-bold flex-shrink-0"
                              style={{ color: "#00F5FF" }}
                            >
                              {i + 1}.
                            </span>
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.explanation.recommended_actions?.length > 0 && (
                    <div>
                      <p
                        className="text-xs font-semibold mb-2"
                        style={{ color: "#8B5CF6" }}
                      >
                        Recommended Actions:
                      </p>
                      <ul className="space-y-1.5">
                        {result.explanation.recommended_actions.map(
                          (action, i) => (
                            <li
                              key={i}
                              className="flex items-start gap-2 text-xs"
                              style={{ color: "#9CA3AF" }}
                            >
                              <span style={{ color: "#8B5CF6" }}>→</span>{" "}
                              {action}
                            </li>
                          ),
                        )}
                      </ul>
                    </div>
                  )}
                </GlassCard>
              )}

              {/* Breadcrumbs */}
              {result.breadcrumbs?.length > 0 && (
                <GlassCard>
                  <h3
                    className="text-sm font-semibold mb-3"
                    style={{ fontFamily: "Orbitron", color: "#E5E7EB" }}
                  >
                    Evidence Breadcrumbs
                  </h3>
                  <div className="space-y-2">
                    {result.breadcrumbs.map((bc) => (
                      <div
                        key={bc.id}
                        className="p-3 rounded-xl text-xs"
                        style={{
                          background: `${bc.highlight_color}10`,
                          border: `1px solid ${bc.highlight_color}30`,
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="w-2 h-2 rounded-full"
                            style={{ background: bc.highlight_color }}
                          />
                          <span
                            className="font-semibold capitalize"
                            style={{ color: "#E5E7EB" }}
                          >
                            {bc.threat_type.replace("_", " ")}
                          </span>
                        </div>
                        <p className="font-mono" style={{ color: "#9CA3AF" }}>
                          &quot;{bc.content_snippet}&quot;
                        </p>
                        {bc.description && (
                          <p className="mt-1" style={{ color: "#6B7280" }}>
                            {bc.description}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </GlassCard>
              )}

              <div className="flex items-center justify-end gap-2">
                <span
                  className="text-[10px] font-mono"
                  style={{ color: "#4B5563" }}
                >
                  Scan ID: {result.scan_id}
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
