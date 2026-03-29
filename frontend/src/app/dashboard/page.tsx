'use client';

import { useCallback, useRef, useState } from 'react';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel, { type StaticResult } from '@/components/BehavioralAnalysisPanel';
import ThreatReportPanel, {
  type ReportStages,
  type Stage1Data,
  type Stage2Data,
  type Stage3Data,
  type Stage4Data,
} from '@/components/ThreatReportPanel';
import SandboxSimulation from '@/components/SandboxSimulation';

const STAGE_DURATIONS = [800, 1500, 2500, 1000, 2000, 800];
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export default function Dashboard() {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(6).fill(false));
  const [reportStages, setReportStages] = useState<ReportStages>({});
  const [staticData, setStaticData] = useState<StaticResult | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const animDoneRef = useRef(false);
  const apiDoneRef = useRef(false);

  // Called when both animation and pipeline 'done' event have fired
  function tryFinish() {
    if (animDoneRef.current && apiDoneRef.current) {
      setAnalysisRunning(false);
      setCurrentStage(-1);
    }
  }

  const startAnalysis = useCallback(() => {
    if (analysisRunning || !fileInfo) return;

    setAnalysisRunning(true);
    setReportStages({});
    setStaticData(null);
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

            // Sandbox static analysis → populate behavioral panel
            if (msg.event === 'static_analysis' && msg.status === 'complete' && msg.data) {
              setStaticData(msg.data as StaticResult);
            }

            // Streaming report stages — each card renders as soon as its data arrives
            if (msg.event === 'report_stage' && msg.data) {
              const stageNum = msg.stage as number;
              const data = msg.data as Record<string, unknown>;

              setReportStages(prev => {
                switch (stageNum) {
                  case 1: return { ...prev, stage1: data as unknown as Stage1Data };
                  case 2: return { ...prev, stage2: data as unknown as Stage2Data };
                  case 3: return { ...prev, stage3: data as unknown as Stage3Data };
                  case 4: return { ...prev, stage4: data as unknown as Stage4Data };
                  default: return prev;
                }
              });
            }

            // Pipeline fully complete — hydrate any missed stages from the done payload
            if (msg.event === 'done' && msg.data) {
              const result = msg.data as Record<string, unknown>;
              const report = (result.report ?? {}) as Record<string, unknown>;

              // Fill in any stages that didn't arrive via report_stage events
              if (report.stage1 || report.stage2 || report.stage3 || report.stage4) {
                setReportStages(prev => ({
                  stage1: prev.stage1 ?? (report.stage1 as Stage1Data | undefined),
                  stage2: prev.stage2 ?? (report.stage2 as Stage2Data | undefined),
                  stage3: prev.stage3 ?? (report.stage3 as Stage3Data | undefined),
                  stage4: prev.stage4 ?? (report.stage4 as Stage4Data | undefined),
                }));
              }

              apiDoneRef.current = true;
              tryFinish();
            }

            if (msg.event === 'error') {
              console.error('Analysis error:', msg.message);
              apiDoneRef.current = true;
              tryFinish();
            }
          };

          ws.onerror = () => {
            console.error('WebSocket connection failed');
            apiDoneRef.current = true;
            tryFinish();
          };
        })
        .catch(err => {
          console.error('Upload error:', err);
          apiDoneRef.current = true;
          tryFinish();
        });
    } else {
      // Demo mode — no real file, animation runs, report panel shows demo state
      apiDoneRef.current = true;
    }

    // ── Circuit board stage animation (independent of API) ────────────────
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
          tryFinish();
        }, STAGE_DURATIONS[5]);
        return;
      }

      idx++;
      timerRef.current = setTimeout(nextStage, STAGE_DURATIONS[idx - 1]);
    }

    nextStage();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisRunning, fileInfo]);

  const hasReportData = !!(reportStages.stage1);

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
        <ThreatReportPanel stages={reportStages} />
        <SandboxSimulation />
      </div>
    </>
  );
}
