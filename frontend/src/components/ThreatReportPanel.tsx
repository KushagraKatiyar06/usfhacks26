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
    <Panel title="// AI THREAT REPORT" className="ai-panel" style={{ gridRow: 1, maxHeight: '82vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {!visible ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Awaiting analysis...<br /><span className="blink">_</span>
        </div>
      ) : pending ? (
        <div className="f9 text-dim" style={{ textAlign: 'center', padding: '30px 0' }}>
          Finalizing AI report...<br /><span className="blink">_</span>
        </div>
      ) : (
        <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4 }}>
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

          <div className="section-divider" />
          <div className="f9 text-dim">AI REASONING</div>
          <div style={{ fontSize: 10, lineHeight: 1.65, marginTop: 6, color: '#7ab8cc', fontStyle: 'italic' }}>
            {reasoning}
          </div>
        </div>
      )}
    </Panel>
  );
}
