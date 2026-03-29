'use client';

import { useEffect, useRef } from 'react';
import Panel from './Panel';
import { DEMO_FINDINGS, DEMO_MITIGATIONS, DEMO_REASONING, type Finding } from '@/lib/data';

export interface ReportData {
  malware_type: string;
  risk_score: number;
  classification_confidence: number;
  behavior_confidence: number;
  findings: Finding[];
  mitigations: string[];
  reasoning: string;
  // Extended fields from AI pipeline
  mitre_techniques?: Array<{ id: string; name: string; tactic: string }>;
  iocs?: string[];
  yara_rule?: string;
}

interface Props {
  visible: boolean;
  data?: ReportData | null;
  pending?: boolean;
}

export default function ThreatReportPanel({ visible, data, pending }: Props) {
  const riskFillRef = useRef<HTMLDivElement>(null);

  const riskScore = data?.risk_score ?? 94;
  const malwareType = data?.malware_type ?? 'RANSOMWARE';
  const classConf = data?.classification_confidence ?? 97;
  const behConf = data?.behavior_confidence ?? 91;
  const findings = data?.findings ?? DEMO_FINDINGS;
  const mitigations = data?.mitigations ?? DEMO_MITIGATIONS;
  const reasoning = data?.reasoning ?? DEMO_REASONING;
  const mitreTechniques = data?.mitre_techniques ?? [];
  const iocs = data?.iocs ?? [];
  const yaraRule = data?.yara_rule ?? '';

  useEffect(() => {
    if (visible) {
      setTimeout(() => {
        if (riskFillRef.current) riskFillRef.current.style.width = `${riskScore}%`;
      }, 100);
    } else {
      if (riskFillRef.current) riskFillRef.current.style.width = '0%';
    }
  }, [visible, riskScore]);

  return (
    <Panel title="// AI THREAT REPORT" className="ai-panel" style={{ gridRow: 1 }}>
      {!visible ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Awaiting analysis...<br /><span className="blink">_</span>
        </div>
      ) : pending ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Finalizing AI report...<br /><span className="blink">_</span>
        </div>
      ) : (
        <>
          <div className="f9 text-dim">CLASSIFICATION</div>
          <div className="malware-type-badge">{malwareType}</div>

          <div className="f9 text-dim mt4">RISK SCORE</div>
          <div className="risk-gauge">
            <div className="risk-fill" ref={riskFillRef} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-dim)' }}>
            <span>LOW</span>
            <span className="text-cyan" style={{ fontFamily: "'Orbitron', monospace" }}>{riskScore}%</span>
            <span>CRITICAL</span>
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">CONFIDENCE</div>
          <div className="confidence-row mt4">
            <span>Classification accuracy</span>
            <span className="confidence-val">{classConf}%</span>
          </div>
          <div className="confidence-row">
            <span>Behavior signature match</span>
            <span className="confidence-val">{behConf}%</span>
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">KEY FINDINGS</div>
          <div style={{ marginTop: 6 }}>
            {findings.map((f, i) => (
              <div key={i} className={`ai-finding ${f.type}`}>
                <div className={`finding-label ${f.type}`}>{f.label}</div>
                {f.text}
              </div>
            ))}
          </div>

          <div className="section-divider" />

          <div className="f9 text-dim">MITIGATIONS</div>
          <div style={{ fontSize: 10, lineHeight: 1.8, marginTop: 6, color: 'var(--text-cyan)' }}>
            {mitigations.map((m, i) => (
              <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid rgba(0,245,255,0.06)' }}>{m}</div>
            ))}
          </div>

          {mitreTechniques.length > 0 && (
            <>
              <div className="section-divider" />
              <div className="f9 text-dim">MITRE ATT&amp;CK TECHNIQUES</div>
              <div style={{ marginTop: 6, overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 9 }}>
                  <thead>
                    <tr style={{ color: 'var(--text-dim)', borderBottom: '1px solid rgba(0,245,255,0.15)' }}>
                      <th style={{ textAlign: 'left', padding: '3px 4px', fontWeight: 400 }}>ID</th>
                      <th style={{ textAlign: 'left', padding: '3px 4px', fontWeight: 400 }}>TECHNIQUE</th>
                      <th style={{ textAlign: 'left', padding: '3px 4px', fontWeight: 400 }}>TACTIC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mitreTechniques.map((t, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid rgba(0,245,255,0.05)', color: i % 2 === 0 ? 'var(--text-cyan)' : '#7ab8cc' }}>
                        <td style={{ padding: '3px 4px', fontFamily: "'Orbitron', monospace", color: 'var(--magenta)', whiteSpace: 'nowrap' }}>{t.id}</td>
                        <td style={{ padding: '3px 4px' }}>{t.name}</td>
                        <td style={{ padding: '3px 4px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{t.tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {iocs.length > 0 && (
            <>
              <div className="section-divider" />
              <div className="f9 text-dim">INDICATORS OF COMPROMISE</div>
              <div style={{ marginTop: 6, fontSize: 9, lineHeight: 1.9 }}>
                {iocs.map((ioc, i) => (
                  <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid rgba(255,45,158,0.08)', color: 'var(--magenta)', wordBreak: 'break-all' }}>
                    <span style={{ color: 'var(--text-dim)', marginRight: 6 }}>▸</span>{ioc}
                  </div>
                ))}
              </div>
            </>
          )}

          {yaraRule && (
            <>
              <div className="section-divider" />
              <div className="f9 text-dim">YARA DETECTION RULE</div>
              <pre style={{
                marginTop: 6,
                padding: 10,
                background: '#010814',
                border: '1px solid rgba(0,245,255,0.12)',
                fontSize: 9,
                color: '#00ff88',
                overflowX: 'auto',
                lineHeight: 1.6,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}>
                {yaraRule}
              </pre>
            </>
          )}

          <div className="section-divider" />
          <div className="f9 text-dim">EXECUTIVE SUMMARY</div>
          <div style={{ fontSize: 10, lineHeight: 1.65, marginTop: 6, color: '#7ab8cc', fontStyle: 'italic' }}>
            {reasoning}
          </div>
        </>
      )}
    </Panel>
  );
}
