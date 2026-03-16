'use client';

const severityConfig = {
  critical: { bg: 'rgba(255, 59, 59, 0.15)', color: '#FF3B3B', border: 'rgba(255, 59, 59, 0.3)' },
  high: { bg: 'rgba(249, 115, 22, 0.15)', color: '#F97316', border: 'rgba(249, 115, 22, 0.3)' },
  medium: { bg: 'rgba(245, 158, 11, 0.15)', color: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)' },
  low: { bg: 'rgba(34, 197, 94, 0.15)', color: '#22C55E', border: 'rgba(34, 197, 94, 0.3)' },
  safe: { bg: 'rgba(59, 130, 246, 0.15)', color: '#3B82F6', border: 'rgba(59, 130, 246, 0.3)' },
};

export default function ThreatBadge({ severity = 'safe', label, className = '' }) {
  const config = severityConfig[severity] || severityConfig.safe;
  const displayLabel = label || severity.toUpperCase();

  return (
    <span
      className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-semibold tracking-wider uppercase ${className}`}
      style={{
        background: config.bg,
        color: config.color,
        border: `1px solid ${config.border}`,
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 flex-shrink-0"
        style={{ background: config.color, boxShadow: `0 0 6px ${config.color}` }} />
      {displayLabel}
    </span>
  );
}
