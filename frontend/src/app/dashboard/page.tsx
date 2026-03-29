'use client';

import { useCallback, useRef, useState } from 'react';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel, { type StaticResult } from '@/components/BehavioralAnalysisPanel';
import ThreatReportPanel, { type ReportData } from '@/components/ThreatReportPanel';
import SandboxSimulation from '@/components/SandboxSimulation';
import { type Finding } from '@/lib/data';

const STAGE_DURATIONS = [800, 1500, 2500, 1000, 2000, 800];
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// Map pipeline report → Finding[] for the threat report panel
function buildFindings(report: Record<string, unknown>, fullResult: Record<string, unknown>): Finding[] {
  const findings: Finding[] = [];
  const sa = fullResult?.static_analysis as Record<string, unknown> | undefined;

  if (sa?.threat_level && ['HIGH', 'CRITICAL'].includes(sa.threat_level as string)) {
    findings.push({ type: 'critical', label: 'CRITICAL', text: `Static threat level: ${sa.threat_level}` });
  }

  const techniques = (report.mitre_techniques ?? []) as Array<{ id: string; name: string; tactic: string }>;
  techniques.slice(0, 3).forEach(t => {
    findings.push({ type: 'warn', label: t.id, text: `${t.name} — ${t.tactic}` });
  });

  const iocs = (report.iocs ?? []) as string[];
  iocs.slice(0, 2).forEach(ioc => {
    findings.push({ type: 'critical', label: 'IOC', text: ioc });
  });

  if (findings.length === 0) {
    findings.push({ type: 'ok', label: 'INFO', text: 'Analysis complete. Review details below.' });
  }
  return findings;
}

// Map action_plan or containment_steps → mitigations string[]
function buildMitigations(report: Record<string, unknown>): string[] {
  const CIRCLED = ['①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧'];
  const plan = (report.action_plan ?? []) as Array<{ priority?: number; action: string }>;
  if (plan.length > 0) {
    return plan
      .slice()
      .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
      .map((step, i) => `${CIRCLED[i] ?? `${i + 1}.`} ${step.action}`)
      .slice(0, 7);
  }
  const steps = (report.containment_steps ?? []) as string[];
  return steps.map((s, i) => `${CIRCLED[i] ?? `${i + 1}.`} ${s}`).slice(0, 7);
}

export default function Dashboard() {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(6).fill(false));
  const [reportVisible, setReportVisible] = useState(false);
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [staticData, setStaticData] = useState<StaticResult | null>(null);
  const [reportPending, setReportPending] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const animDoneRef = useRef(false);
  const apiDoneRef = useRef(false);

  function tryShowReport() {
    if (animDoneRef.current && apiDoneRef.current) {
      setReportPending(false);
      setReportVisible(true);
      setAnalysisRunning(false);
      setCurrentStage(-1);
    }
  }

  const startAnalysis = useCallback(() => {
    if (analysisRunning || !fileInfo) return;

    setAnalysisRunning(true);
    setReportVisible(false);
    setReportData(null);
    setStaticData(null);
    setReportPending(false);
    setCurrentStage(-1);
    setStageDone(Array(6).fill(false));
    animDoneRef.current = false;
    apiDoneRef.current = false;

    if (fileInfo.file) {
      const formData = new FormData();
      formData.append('file', fileInfo.file);

      fetch(`${API_URL}/upload`, { method: 'POST', body: formData })
        .then(r => {
          if (!r.ok) throw new Error(`Upload error ${r.status}`);
          return r.json();
        })
        .then(({ job_id }: { job_id: string }) => {
          const wsBase = API_URL.replace(/^https?/, s => (s === 'https' ? 'wss' : 'ws'));
          const ws = new WebSocket(`${wsBase}/ws/${job_id}`);

          ws.onmessage = (ev) => {
            const msg = JSON.parse(ev.data as string) as Record<string, unknown>;

            // Static analysis complete → populate behavioral panel with real data
            if (msg.event === 'static_analysis' && msg.status === 'complete' && msg.data) {
              setStaticData(msg.data as StaticResult);
            }

            // Pipeline done → build ReportData and show report
            if (msg.event === 'done' && msg.status === 'complete' && msg.data) {
              const result = msg.data as Record<string, unknown>;
              const report = (result.report ?? {}) as Record<string, unknown>;

              const rd: ReportData = {
                malware_type: (report.malware_type as string) ?? 'UNKNOWN',
                risk_score: (report.risk_score as number) ?? 50,
                classification_confidence: Math.round(((report.confidence as number) ?? 0.9) * 100),
                behavior_confidence: Math.round((((result.static_analysis as Record<string, unknown>)?.confidence as number) ?? 0.85) * 100),
                findings: buildFindings(report, result),
                mitigations: buildMitigations(report),
                reasoning: (report.executive_summary as string) ?? '',
                mitre_techniques: (report.mitre_techniques as ReportData['mitre_techniques']) ?? [],
                iocs: (report.iocs as string[]) ?? [],
                yara_rule: (report.yara_rule as string) ?? '',
              };

              setReportData(rd);
              apiDoneRef.current = true;
              tryShowReport();
            }

            if (msg.event === 'error') {
              console.error('Analysis error:', msg.message);
              apiDoneRef.current = true;
              tryShowReport();
            }
          };

          ws.onerror = () => {
            console.error('WebSocket connection failed');
            apiDoneRef.current = true;
            tryShowReport();
          };
        })
        .catch(err => {
          console.error('Upload error:', err);
          apiDoneRef.current = true;
          tryShowReport();
        });
    } else {
      // Demo mode — no real file, animation only
      apiDoneRef.current = true;
    }

    let idx = 0;

    function nextStage() {
      if (idx >= 6) return;

      if (idx > 0) {
        setStageDone(prev => {
          const next = [...prev];
          next[idx - 1] = true;
          return next;
        });
      }

      setCurrentStage(idx);

      if (idx === 5) {
        setTimeout(() => {
          setStageDone(prev => { const n = [...prev]; n[5] = true; return n; });
          animDoneRef.current = true;

          if (apiDoneRef.current) {
            setReportPending(false);
            setReportVisible(true);
            setAnalysisRunning(false);
            setCurrentStage(-1);
          } else {
            setReportPending(true);
            setReportVisible(true);
            setAnalysisRunning(false);
            setCurrentStage(-1);
          }
        }, STAGE_DURATIONS[5]);
        return;
      }

      idx++;
      timerRef.current = setTimeout(nextStage, STAGE_DURATIONS[idx - 1]);
    }

    nextStage();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisRunning, fileInfo]);

  return (
    <>
      <Header />
      <div className="main-grid">
        <FileIntakePanel
          fileInfo={fileInfo}
          onFileLoaded={setFileInfo}
          onAnalyze={startAnalysis}
          analysisRunning={analysisRunning}
        />
        <BehavioralAnalysisPanel
          currentStage={currentStage}
          stageDone={stageDone}
          staticData={staticData}
        />
        <ThreatReportPanel
          visible={reportVisible}
          data={reportData}
          pending={reportPending}
        />
        <SandboxSimulation />
      </div>
    </>
  );
}
