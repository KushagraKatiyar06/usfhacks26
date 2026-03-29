'use client';

import { useEffect, useRef } from 'react';
import Panel from './Panel';

// ── Stage type definitions (exported for use across the app) ──────────────────

export interface Stage1Data {
  malware_family: string;
  verdict: string;
  risk_score: number;
  severity: string;
  confidence: number;
  one_line_summary: string;
}

export interface Stage2Data {
  executive_summary: string;
  affected_systems: string[];
  business_impact: string;
  confidence: number;
}

export interface Stage3Data {
  mitre_techniques: Array<{ id: string; name: string; tactic: string; description: string }>;
  iocs: { domains: string[]; ips: string[]; files: string[]; registry_keys: string[] };
  attack_chain: string;
  confidence: number;
}

export interface Stage4Data {
  action_plan: Array<{ priority: number; action: string; urgency: string }>;
  yara_rule: string;
  iocs_to_block: string[];
  long_term_recommendations: string[];
  confidence: number;
}

export interface ReportStages {
  stage1?: Stage1Data;
  stage2?: Stage2Data;
  stage3?: Stage3Data;
  stage4?: Stage4Data;
}

// ── Panel: shows Stage 1 identity only (stages 2-4 live in the REPORTS tab) ──

interface Props {
  stage1?: Stage1Data;
}

export default function ThreatReportPanel({ stage1 }: Props) {
  const riskRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const score = stage1?.risk_score ?? 0;
    const t = setTimeout(() => {
      if (riskRef.current) riskRef.current.style.width = `${score}%`;
    }, 80);
    return () => clearTimeout(t);
  }, [stage1?.risk_score]);

  // Reset gauge when stage1 is cleared
  useEffect(() => {
    if (!stage1 && riskRef.current) riskRef.current.style.width = '0%';
  }, [stage1]);

  const severityColor =
    stage1?.severity === 'CRITICAL' ? 'var(--magenta)' :
    stage1?.severity === 'HIGH'     ? '#ffcc00'         : '#00f5ff';

  const pct = Math.round((stage1?.confidence ?? 0) <= 1
    ? (stage1?.confidence ?? 0) * 100
    : (stage1?.confidence ?? 0));

  return (
    <Panel title="// AI THREAT REPORT" className="ai-panel" style={{ gridRow: 1 }}>
      {!stage1 ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Awaiting analysis...<br /><span className="blink">_</span>
        </div>
      ) : (
        <>
          {/* Threat identity banner */}
          <div style={{
            padding: '10px 12px', marginBottom: 12,
            background: 'rgba(255,45,158,0.08)',
            border: '1px solid rgba(255,45,158,0.3)',
            borderRadius: 3,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 8, color: 'var(--text-dim)', letterSpacing: 2 }}>MALWARE FAMILY</div>
                <div style={{
                  fontSize: 14, fontFamily: "'Orbitron', monospace",
                  color: 'var(--magenta)', marginTop: 2, lineHeight: 1.2,
                }}>
                  {stage1.malware_family}
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 8, color: 'var(--text-dim)', letterSpacing: 2 }}>VERDICT</div>
                <div style={{ fontSize: 10, color: severityColor, fontFamily: "'Orbitron', monospace" }}>
                  {stage1.verdict}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 8, fontSize: 9, color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.5 }}>
              {stage1.one_line_summary}
            </div>
          </div>

          {/* Risk gauge */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <div className="f9 text-dim">RISK SCORE</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{
                fontSize: 18, fontFamily: "'Orbitron', monospace",
                color: stage1.risk_score >= 80 ? 'var(--magenta)' : '#ffcc00',
              }}>
                {stage1.risk_score}
              </span>
              <span style={{ fontSize: 9, color: 'var(--text-dim)' }}>/100</span>
              <span style={{
                fontSize: 7, padding: '1px 6px',
                border: `1px solid #00ff88`, borderRadius: 3,
                color: '#00ff88', fontFamily: "'Orbitron', monospace",
              }}>{pct}% CONF</span>
            </div>
          </div>
          <div className="risk-gauge">
            <div className="risk-fill" ref={riskRef} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: 'var(--text-dim)', marginTop: 2 }}>
            <span>LOW</span>
            <span style={{ color: severityColor, fontFamily: "'Orbitron', monospace", fontSize: 9 }}>
              {stage1.severity}
            </span>
            <span>CRITICAL</span>
          </div>

          <div className="section-divider" style={{ marginTop: 14 }} />
          <div className="f9 text-dim" style={{ marginBottom: 4 }}>FULL REPORT</div>
          <div style={{ fontSize: 9, color: 'var(--text-dim)', lineHeight: 1.6 }}>
            Stages 2–4 are available in the{' '}
            <span style={{ color: 'var(--text-cyan)' }}>REPORTS</span>{' '}
            tab of the analysis panel.
          </div>
        </>
      )}
    </Panel>
  );
}
