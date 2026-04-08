'use client';

import { useEffect, useRef, useState } from 'react';
import Panel from './Panel';
import { type ReportStages, type Stage1Data, type Stage2Data, type Stage3Data, type Stage4Data } from './ThreatReportPanel';

// ── Agent status types (exported for dashboard/page.tsx) ──────────────────────

export type AgentStatus = 'idle' | 'running' | 'complete';

export interface AgentState {
  status: AgentStatus;
  detail: string;
}

export type AgentStatuses = Record<
  'ingestion' | 'static_analysis' | 'mitre_mapping' | 'remediation' | 'report' | 'virustotal',
  AgentState
>;

// Keep StaticResult exported so dashboard/page.tsx can use it
export interface StaticResult {
  file_type: string;
  file_name?: string;
  sha256?: string;
  entropy?: number;
  is_obfuscated?: boolean;
  threat_level?: string;
  behaviors?: string[];
  mitre_techniques?: string[];
  dangerous_functions?: string[];
  suspicious_imports?: string[];
  urls_found?: string[];
  ips_found?: string[];
  domains_found?: string[];
  registry_keys?: string[];
  dropped_files?: string[];
  yara_matches?: string[];
  strings_sample?: string[];
  pe_info?: {
    architecture?: string;
    compile_time?: string;
    is_dll?: boolean;
    sections?: { name: string; entropy: number }[];
    imports?: string[];
  };
}

const STAGES = ['UPLOAD', 'SANDBOX', 'MONITOR', 'PARSE', 'AI ANALYZE', 'REPORT'];

interface Props {
  currentStage: number;
  stageDone: boolean[];
  agentStatuses: AgentStatuses;
  reportStages: ReportStages;
  terminalLogs: string[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function stageClass(i: number, currentStage: number, stageDone: boolean[]) {
  if (stageDone[i]) return 'stage done';
  if (currentStage === i) return 'stage active';
  return 'stage';
}

// ── Agent node ────────────────────────────────────────────────────────────────

function AgentNode({ label, status, detail, compact }: {
  label: string; status: AgentStatus; detail?: string; compact?: boolean;
}) {
  const borderColor = status === 'complete' ? '#00ff88' : status === 'running' ? '#ffcc00' : 'rgba(0,245,255,0.15)';
  const textColor   = status === 'complete' ? '#00ff88' : status === 'running' ? '#ffcc00' : 'var(--text-dim)';
  const icon = status === 'complete' ? '✓' : status === 'running' ? '►' : '○';

  return (
    <div style={{
      border: `1px solid ${borderColor}`,
      borderRadius: 3,
      padding: compact ? '4px 6px' : '6px 10px',
      background: status === 'running' ? 'rgba(255,204,0,0.04)' : status === 'complete' ? 'rgba(0,255,136,0.04)' : '#010814',
      textAlign: 'center',
      flex: 1,
      transition: 'border-color 0.4s ease, background 0.4s ease',
      minWidth: 0,
    }}>
      <div style={{ fontSize: compact ? 7 : 8, color: textColor, fontFamily: "'Orbitron', monospace", letterSpacing: 1 }}>
        <span style={{ marginRight: 4 }}>{icon}</span>{label}
      </div>
      {status === 'running' && (
        <div style={{ fontSize: 7, color: '#ffcc00', marginTop: 2 }}><span className="blink">processing...</span></div>
      )}
      {status === 'complete' && detail && (
        <div style={{ fontSize: 7, color: 'var(--text-dim)', marginTop: 2, lineHeight: 1.3, wordBreak: 'break-word' }}>{detail}</div>
      )}
    </div>
  );
}

function Pipe() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', height: 14, alignItems: 'center' }}>
      <div style={{ width: 1, height: '100%', background: 'rgba(0,245,255,0.2)' }} />
    </div>
  );
}

function ForkLines() {
  // A horizontal crossbar from 25% to 75% with drop-lines at each end
  return (
    <div style={{ position: 'relative', height: 14, width: '100%' }}>
      {/* vertical from ingestion down */}
      <div style={{ position: 'absolute', left: '50%', top: 0, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
      {/* horizontal bar */}
      <div style={{ position: 'absolute', left: '25%', right: '25%', top: 7, height: 1, background: 'rgba(0,245,255,0.2)' }} />
      {/* left drop */}
      <div style={{ position: 'absolute', left: '25%', top: 7, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
      {/* right drop */}
      <div style={{ position: 'absolute', right: '25%', top: 7, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
    </div>
  );
}

function JoinLines() {
  return (
    <div style={{ position: 'relative', height: 14, width: '100%' }}>
      {/* left rise */}
      <div style={{ position: 'absolute', left: '25%', top: 0, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
      {/* right rise */}
      <div style={{ position: 'absolute', right: '25%', top: 0, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
      {/* horizontal bar */}
      <div style={{ position: 'absolute', left: '25%', right: '25%', top: 7, height: 1, background: 'rgba(0,245,255,0.2)' }} />
      {/* vertical down to next node */}
      <div style={{ position: 'absolute', left: '50%', top: 7, width: 1, height: 7, background: 'rgba(0,245,255,0.2)' }} />
    </div>
  );
}

// ── AGENTS tab ────────────────────────────────────────────────────────────────

function AgentsTab({ agentStatuses }: { agentStatuses: AgentStatuses }) {
  const a = agentStatuses;
  const vtSkipped = a.virustotal.status === 'idle' && a.virustotal.detail === 'skipped';
  return (
    <div style={{ padding: '8px 4px 4px' }}>
      {/* VirusTotal enrichment (shown above ingestion) */}
      <AgentNode
        label="VIRUSTOTAL"
        status={vtSkipped ? 'idle' : a.virustotal.status}
        detail={vtSkipped ? 'not configured' : a.virustotal.detail}
        compact
      />
      <Pipe />

      {/* Ingestion */}
      <AgentNode label="INGESTION AGENT" status={a.ingestion.status} detail={a.ingestion.detail} />
      <ForkLines />

      {/* Parallel pair */}
      <div style={{ display: 'flex', gap: 6 }}>
        <AgentNode label="STATIC ANALYSIS" status={a.static_analysis.status} detail={a.static_analysis.detail} compact />
        <AgentNode label="MITRE MAPPING"   status={a.mitre_mapping.status}   detail={a.mitre_mapping.detail}   compact />
      </div>
      <JoinLines />

      {/* Remediation */}
      <AgentNode label="REMEDIATION AGENT" status={a.remediation.status} detail={a.remediation.detail} />
      <Pipe />

      {/* Report */}
      <AgentNode label="REPORT GENERATION" status={a.report.status} detail={a.report.detail} />

      {/* Sub-stage indicators for report */}
      {(a.report.status === 'running' || a.report.status === 'complete') && (
        <div style={{ marginTop: 8, paddingLeft: 8 }}>
          <div style={{ fontSize: 7, color: 'var(--text-dim)', marginBottom: 4, letterSpacing: 1 }}>REPORT SUB-STAGES</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['THREAT ID', 'EXEC SUM', 'TECHNICAL', 'REMEDIATION'].map((lbl, i) => {
              const stageKey = `stage${i + 1}` as keyof ReportStages;
              const done = !!(agentStatuses.report.status === 'complete' ||
                             (i === 0 && agentStatuses.report.detail));
              const color = done ? '#00ff88' : 'rgba(0,245,255,0.2)';
              return (
                <div key={i} style={{
                  flex: 1, textAlign: 'center', padding: '2px 0',
                  border: `1px solid ${color}`, borderRadius: 2,
                  fontSize: 6, color, letterSpacing: 0.5,
                }}>
                  {lbl}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── LOGS tab ──────────────────────────────────────────────────────────────────

function LogsTab({ terminalLogs }: { terminalLogs: string[] }) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [terminalLogs]);

  return (
    <div className="log-terminal" ref={logRef} style={{ height: '100%', overflowY: 'auto' }}>
      {terminalLogs.map((line, i) => {
        const isCrit = line.includes('CRIT') || line.includes('✗') || line.includes('ERROR');
        const isWarn = line.includes('WARN') || line.includes('►');
        const isDone = line.includes('✓');
        const color = isCrit ? 'var(--magenta)' : isWarn ? '#ffcc00' : isDone ? '#00ff88' : 'var(--text-cyan)';
        return (
          <div key={i} className="log-line" style={{ color, fontFamily: 'monospace', fontSize: 9, lineHeight: 1.7 }}>
            {line}
          </div>
        );
      })}
      {terminalLogs.length === 0 && (
        <div className="f9 text-dim" style={{ padding: 8 }}>Awaiting pipeline events...<span className="blink">_</span></div>
      )}
    </div>
  );
}

// ── REPORTS tab — stage content ───────────────────────────────────────────────

function Stage1Content({ s }: { s: Stage1Data }) {
  const sevColor = s.severity === 'CRITICAL' ? 'var(--magenta)' : s.severity === 'HIGH' ? '#ffcc00' : '#00f5ff';
  return (
    <div style={{ fontSize: 9, lineHeight: 1.8 }}>
      <div><span style={{ color: 'var(--text-dim)' }}>Family:</span>{' '}
        <span style={{ color: 'var(--magenta)', fontFamily: "'Orbitron', monospace" }}>{s.malware_family}</span>
      </div>
      <div><span style={{ color: 'var(--text-dim)' }}>Verdict:</span>{' '}
        <span style={{ color: sevColor }}>{s.verdict}</span>
      </div>
      <div><span style={{ color: 'var(--text-dim)' }}>Risk Score:</span>{' '}
        <span style={{ color: s.risk_score >= 80 ? 'var(--magenta)' : '#ffcc00', fontFamily: "'Orbitron', monospace" }}>{s.risk_score}/100</span>
      </div>
      <div><span style={{ color: 'var(--text-dim)' }}>Severity:</span>{' '}
        <span style={{ color: sevColor }}>{s.severity}</span>
      </div>
      <div style={{ marginTop: 6, color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.6 }}>{s.one_line_summary}</div>
    </div>
  );
}

function Stage2Content({ s }: { s: Stage2Data }) {
  return (
    <div style={{ fontSize: 9 }}>
      <div style={{ color: '#7ab8cc', fontStyle: 'italic', lineHeight: 1.7, marginBottom: 8 }}>{s.executive_summary}</div>
      {s.affected_systems?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 8, letterSpacing: 1, marginBottom: 4 }}>AFFECTED SYSTEMS</div>
          {s.affected_systems.map((sys, i) => (
            <div key={i} style={{ color: '#ffcc00', padding: '1px 0' }}>▸ {sys}</div>
          ))}
        </>
      )}
      {s.business_impact && (
        <div style={{ marginTop: 8, padding: '6px 8px', background: 'rgba(255,204,0,0.04)', border: '1px solid rgba(255,204,0,0.2)', borderRadius: 2, fontSize: 9, color: '#ffcc00', lineHeight: 1.5 }}>
          <span style={{ color: 'var(--text-dim)' }}>IMPACT: </span>{s.business_impact}
        </div>
      )}
    </div>
  );
}

function Stage3Content({ s }: { s: Stage3Data }) {
  const iocs = s.iocs ?? { domains: [], ips: [], files: [], registry_keys: [] };
  return (
    <div style={{ fontSize: 9 }}>
      {s.mitre_techniques?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 8, letterSpacing: 1, marginBottom: 4 }}>MITRE ATT&amp;CK</div>
          {s.mitre_techniques.map((t, i) => (
            <div key={i} style={{ padding: '3px 0', borderBottom: '1px solid rgba(0,245,255,0.05)' }}>
              <span style={{ color: 'var(--magenta)', fontFamily: "'Orbitron', monospace", fontSize: 8 }}>{t.id}</span>
              {' '}<span style={{ color: 'var(--text-cyan)' }}>{t.name}</span>
              <span style={{ color: 'var(--text-dim)' }}> · {t.tactic}</span>
              {t.description && <div style={{ fontSize: 8, color: 'var(--text-dim)', paddingLeft: 8 }}>{t.description}</div>}
            </div>
          ))}
        </>
      )}
      {(iocs.domains.length > 0 || iocs.ips.length > 0 || iocs.files.length > 0) && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 8, letterSpacing: 1, marginTop: 10, marginBottom: 4 }}>IOCs</div>
          {iocs.domains.map((d, i) => <div key={`d${i}`} style={{ color: 'var(--magenta)', fontSize: 8 }}><span style={{ color: 'var(--text-dim)' }}>DOMAIN </span>{d}</div>)}
          {iocs.ips.map((ip, i)   => <div key={`ip${i}`} style={{ color: 'var(--magenta)', fontSize: 8 }}><span style={{ color: 'var(--text-dim)' }}>IP     </span>{ip}</div>)}
          {iocs.files.slice(0, 4).map((f, i) => <div key={`f${i}`} style={{ color: '#ffcc00', fontSize: 8, wordBreak: 'break-all' }}><span style={{ color: 'var(--text-dim)' }}>FILE   </span>{f}</div>)}
        </>
      )}
      {s.attack_chain && (
        <div style={{ marginTop: 8, padding: '6px 8px', background: '#010814', fontSize: 8, color: '#7ab8cc', lineHeight: 1.6, border: '1px solid rgba(0,245,255,0.1)', borderRadius: 2 }}>
          <div style={{ color: 'var(--text-dim)', marginBottom: 3 }}>ATTACK CHAIN</div>
          {s.attack_chain}
        </div>
      )}
    </div>
  );
}

function Stage4Content({ s }: { s: Stage4Data }) {
  const CIRCLED = ['①', '②', '③', '④', '⑤', '⑥'];
  const URGENCY_COLOR: Record<string, string> = {
    immediate: 'var(--magenta)', '24h': '#ffcc00', '72h': '#00f5ff',
  };
  const [yaraOpen, setYaraOpen] = useState(false);

  return (
    <div style={{ fontSize: 9 }}>
      {s.action_plan?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 8, letterSpacing: 1, marginBottom: 4 }}>ACTION PLAN</div>
          {s.action_plan.slice().sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99)).map((item, i) => {
            const urgColor = URGENCY_COLOR[item.urgency] ?? '#00f5ff';
            return (
              <div key={i} style={{ padding: '4px 6px', marginBottom: 3, borderLeft: `3px solid ${urgColor}`, background: 'rgba(0,245,255,0.02)', display: 'flex', gap: 6 }}>
                <span style={{ color: urgColor, fontSize: 10, flexShrink: 0 }}>{CIRCLED[i] ?? `${i+1}.`}</span>
                <div>
                  <div style={{ color: 'var(--text-cyan)' }}>{item.action}</div>
                  <div style={{ fontSize: 7, color: urgColor, letterSpacing: 1 }}>{item.urgency?.toUpperCase()}</div>
                </div>
              </div>
            );
          })}
        </>
      )}
      {s.long_term_recommendations?.length > 0 && (
        <>
          <div style={{ color: 'var(--text-dim)', fontSize: 8, letterSpacing: 1, marginTop: 8, marginBottom: 4 }}>LONG-TERM</div>
          {s.long_term_recommendations.map((r, i) => (
            <div key={i} style={{ color: '#7ab8cc', padding: '2px 0', fontSize: 8 }}>▸ {r}</div>
          ))}
        </>
      )}
      {s.yara_rule && (
        <div style={{ marginTop: 8 }}>
          <div
            onClick={() => setYaraOpen(v => !v)}
            style={{ cursor: 'pointer', fontSize: 8, color: 'var(--text-dim)', display: 'flex', justifyContent: 'space-between' }}
          >
            <span>YARA DETECTION RULE</span><span>{yaraOpen ? '▲' : '▼'}</span>
          </div>
          {yaraOpen && (
            <pre style={{ fontSize: 7, color: '#00ff88', background: '#010814', padding: 8, marginTop: 4, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', border: '1px solid rgba(0,255,136,0.15)', borderRadius: 2 }}>
              {s.yara_rule}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── REPORTS tab ───────────────────────────────────────────────────────────────

const STAGE_LABELS = [
  'Stage 1 — Threat Identity',
  'Stage 2 — Executive Summary',
  'Stage 3 — Technical Analysis',
  'Stage 4 — Remediation Plan',
];

function stageToText(num: number, reportStages: ReportStages): string {
  const divider = '='.repeat(48);
  switch (num) {
    case 1: {
      const s = reportStages.stage1;
      if (!s) return 'Stage 1 data not yet available.';
      return `THREAT IDENTITY\n${divider}\nMalware Family: ${s.malware_family}\nVerdict: ${s.verdict}\nRisk Score: ${s.risk_score}/100\nSeverity: ${s.severity}\nConfidence: ${Math.round(s.confidence * 100)}%\n\nSummary:\n${s.one_line_summary}\n`;
    }
    case 2: {
      const s = reportStages.stage2;
      if (!s) return 'Stage 2 data not yet available.';
      return `EXECUTIVE SUMMARY\n${divider}\n${s.executive_summary}\n\nAffected Systems:\n${(s.affected_systems ?? []).map(x => `  - ${x}`).join('\n')}\n\nBusiness Impact:\n${s.business_impact}\n`;
    }
    case 3: {
      const s = reportStages.stage3;
      if (!s) return 'Stage 3 data not yet available.';
      let t = `TECHNICAL ANALYSIS\n${divider}\nMITRE ATT&CK Techniques:\n`;
      (s.mitre_techniques ?? []).forEach(m => { t += `  ${m.id}  ${m.name}  [${m.tactic}]\n  ${m.description}\n\n`; });
      const iocs = s.iocs ?? { domains: [], ips: [], files: [], registry_keys: [] };
      t += `IOCs:\n  Domains: ${iocs.domains.join(', ')}\n  IPs: ${iocs.ips.join(', ')}\n  Files: ${iocs.files.join(', ')}\n\nAttack Chain:\n${s.attack_chain}\n`;
      return t;
    }
    case 4: {
      const s = reportStages.stage4;
      if (!s) return 'Stage 4 data not yet available.';
      let t = `REMEDIATION PLAN\n${divider}\nAction Plan:\n`;
      (s.action_plan ?? []).forEach((a, i) => { t += `  ${i+1}. [${a.urgency?.toUpperCase()}] ${a.action}\n`; });
      t += `\nLong-term Recommendations:\n${(s.long_term_recommendations ?? []).map(r => `  - ${r}`).join('\n')}\n\nIOCs to Block:\n${(s.iocs_to_block ?? []).map(x => `  - ${x}`).join('\n')}\n\nYARA Rule:\n${s.yara_rule}\n`;
      return t;
    }
    default: return '';
  }
}

async function downloadPDF(filename: string, text: string) {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 40;
  const usable = doc.internal.pageSize.getWidth() - margin * 2;

  doc.setFillColor(1, 8, 20);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), doc.internal.pageSize.getHeight(), 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(0, 245, 255);
  doc.text('MalwareScope Threat Report', margin, 52);

  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 150, 160);
  doc.text(`Generated: ${new Date().toLocaleString()}`, margin, 66);

  doc.setDrawColor(0, 245, 255);
  doc.setLineWidth(0.5);
  doc.line(margin, 72, margin + usable, 72);

  doc.setFontSize(9);
  doc.setTextColor(180, 220, 230);
  const lines = doc.splitTextToSize(text, usable);
  let y = 88;
  for (const line of lines) {
    if (y > doc.internal.pageSize.getHeight() - 40) {
      doc.addPage();
      doc.setFillColor(1, 8, 20);
      doc.rect(0, 0, doc.internal.pageSize.getWidth(), doc.internal.pageSize.getHeight(), 'F');
      y = 40;
    }
    doc.text(line, margin, y);
    y += 13;
  }

  doc.save(filename);
}

function ReportsTab({ reportStages }: { reportStages: ReportStages }) {
  const [openAccordion, setOpenAccordion] = useState<number | null>(1);

  const allDone = !!(reportStages.stage1 && reportStages.stage2 && reportStages.stage3 && reportStages.stage4);

  const handleDownloadCurrent = async () => {
    if (openAccordion == null) return;
    const text = stageToText(openAccordion, reportStages);
    await downloadPDF(`MalwareScope_Stage${openAccordion}.pdf`, text);
  };

  const handleDownloadFull = async () => {
    const full = [1, 2, 3, 4].map(n => stageToText(n, reportStages)).join('\n\n');
    await downloadPDF('MalwareScope_FullReport.pdf', full);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Download buttons */}
      <div style={{ display: 'flex', gap: 6, padding: '8px 0 6px', flexShrink: 0 }}>
        <button
          onClick={handleDownloadCurrent}
          disabled={openAccordion == null || !reportStages[`stage${openAccordion}` as keyof ReportStages]}
          style={{
            flex: 1, padding: '4px 6px', fontSize: 8,
            background: 'rgba(0,245,255,0.06)', border: '1px solid rgba(0,245,255,0.25)',
            color: 'var(--text-cyan)', cursor: 'pointer', borderRadius: 2, letterSpacing: 0.5,
          }}
        >
          ↓ THIS STAGE PDF
        </button>
        <button
          onClick={handleDownloadFull}
          disabled={!allDone}
          style={{
            flex: 1, padding: '4px 6px', fontSize: 8,
            background: allDone ? 'rgba(255,45,158,0.08)' : 'rgba(0,0,0,0.2)',
            border: `1px solid ${allDone ? 'rgba(255,45,158,0.3)' : 'rgba(0,245,255,0.1)'}`,
            color: allDone ? 'var(--magenta)' : 'var(--text-dim)',
            cursor: allDone ? 'pointer' : 'default', borderRadius: 2, letterSpacing: 0.5,
          }}
        >
          ↓ FULL REPORT PDF
        </button>
      </div>

      {/* Accordion sections */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {[1, 2, 3, 4].map(num => {
          const hasData = !!reportStages[`stage${num}` as keyof ReportStages];
          const isOpen = openAccordion === num;

          return (
            <div key={num} style={{ borderBottom: '1px solid rgba(0,245,255,0.1)' }}>
              {/* Header */}
              <div
                onClick={() => setOpenAccordion(isOpen ? null : num)}
                style={{
                  padding: '7px 8px', cursor: 'pointer',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  background: isOpen ? 'rgba(0,245,255,0.04)' : 'transparent',
                  userSelect: 'none',
                }}
              >
                <span style={{ fontSize: 8, color: hasData ? 'var(--text-cyan)' : 'var(--text-dim)', fontFamily: "'Orbitron', monospace", letterSpacing: 0.5 }}>
                  {hasData ? '✓' : '○'} {STAGE_LABELS[num - 1].toUpperCase()}
                </span>
                <span style={{ fontSize: 8, color: 'var(--text-dim)' }}>{isOpen ? '▲' : '▼'}</span>
              </div>

              {/* Body */}
              {isOpen && (
                <div style={{ padding: '6px 10px 10px' }}>
                  {!hasData ? (
                    <div style={{ fontSize: 9, color: 'var(--text-dim)', padding: '6px 0' }}>
                      <span className="blink">▸</span> Awaiting stage {num}...
                    </div>
                  ) : (
                    <>
                      {num === 1 && <Stage1Content s={reportStages.stage1!} />}
                      {num === 2 && <Stage2Content s={reportStages.stage2!} />}
                      {num === 3 && <Stage3Content s={reportStages.stage3!} />}
                      {num === 4 && <Stage4Content s={reportStages.stage4!} />}
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function BehavioralAnalysisPanel({ currentStage, stageDone, agentStatuses, reportStages, terminalLogs }: Props) {
  const [activeTab, setActiveTab] = useState<'agents' | 'logs' | 'reports'>('agents');

  // Auto-switch to reports tab when stage1 data arrives
  useEffect(() => {
    if (reportStages.stage1 && activeTab === 'agents') setActiveTab('reports');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportStages.stage1]);

  const tabs: Array<{ id: 'agents' | 'logs' | 'reports'; label: string }> = [
    { id: 'agents',  label: 'AGENTS'  },
    { id: 'logs',    label: 'RAW LOGS' },
    { id: 'reports', label: 'REPORTS'  },
  ];

  return (
    <Panel title="// BEHAVIORAL ANALYSIS ENGINE" className="center-panel" style={{ gridRow: 1 }}>
      {/* Stage pipeline bar */}
      <div className="stages">
        {STAGES.map((s, i) => (
          <div key={s} className={stageClass(i, currentStage, stageDone)}>{s}</div>
        ))}
      </div>

      {/* Tab row */}
      <div className="tab-row">
        {tabs.map(({ id, label }) => (
          <div
            key={id}
            className={`tab ${activeTab === id ? 'active' : ''}`}
            onClick={() => setActiveTab(id)}
          >
            {label}
            {id === 'reports' && reportStages.stage1 && (
              <span style={{ marginLeft: 4, fontSize: 7, color: '#00ff88' }}>
                {[1,2,3,4].filter(n => reportStages[`stage${n}` as keyof ReportStages]).length}/4
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {activeTab === 'agents'  && <AgentsTab agentStatuses={agentStatuses} />}
        {activeTab === 'logs'    && <LogsTab terminalLogs={terminalLogs} />}
        {activeTab === 'reports' && <ReportsTab reportStages={reportStages} />}
      </div>
    </Panel>
  );
}
