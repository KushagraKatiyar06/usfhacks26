'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Header from '@/components/Header';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import BehavioralAnalysisPanel, { type StaticResult } from '@/components/BehavioralAnalysisPanel';
import ThreatReportPanel, { type ReportData } from '@/components/ThreatReportPanel';
import SandboxSimulation from '@/components/SandboxSimulation';
import { consumePendingFileInfo } from '@/lib/analysisSession';

const STAGE_DURATIONS = [800, 1500, 2500, 1000, 2000, 800];
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export default function Dashboard() {
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [stageDone, setStageDone] = useState<boolean[]>(Array(6).fill(false));
  const [reportVisible, setReportVisible] = useState(false);
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [staticData, setStaticData] = useState<StaticResult | null>(null);
  const [dynamicJsData, setDynamicJsData] = useState<Record<string, unknown> | null>(null);
  const [reportPending, setReportPending] = useState(false);
  const [autoAnalyze, setAutoAnalyze] = useState(false);
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
    setDynamicJsData(null);
    setReportPending(false);
    setCurrentStage(-1);
    setStageDone(Array(6).fill(false));
    animDoneRef.current = false;
    apiDoneRef.current = false;

    if (fileInfo.file) {
      const formData = new FormData();
      formData.append('file', fileInfo.file);

      // Step 1 — fast static analysis (~5-10s): show real behavioral data immediately
      fetch(`${API_URL}/analyze/static`, { method: 'POST', body: formData })
        .then(r => { if (!r.ok) throw new Error(`Static API error ${r.status}`); return r.json(); })
        .then((data: { static: StaticResult; dynamic_js?: Record<string, unknown>; dynamic_pe?: unknown; file_meta: Record<string, unknown> }) => {
          setStaticData(data.static);
          setDynamicJsData(data.dynamic_js ?? null);  // real process data shows NOW

          // Step 2 — Claude pipeline (~25-35s): runs in background, report fills in when ready
          return fetch(`${API_URL}/analyze/pipeline`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_meta: data.file_meta }),
          })
            .then(r => { if (!r.ok) throw new Error(`Pipeline API error ${r.status}`); return r.json(); })
            .then((pipeline: { report: ReportData; agents?: unknown }) => {
              setReportData(pipeline.report);
              apiDoneRef.current = true;
              tryShowReport();
            });
        })
        .catch(err => {
          console.error('Analysis API error:', err);
          apiDoneRef.current = true;
          tryShowReport();
        });
    } else {
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
          setStageDone(prev => {
            const next = [...prev];
            next[5] = true;
            return next;
          });
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
  }, [analysisRunning, fileInfo]);

  useEffect(() => {
    const pendingFileInfo = consumePendingFileInfo();
    if (pendingFileInfo) {
      setFileInfo(pendingFileInfo);
      setAutoAnalyze(true);
    }
  }, []);

  useEffect(() => {
    if (!autoAnalyze || !fileInfo || analysisRunning) return;
    setAutoAnalyze(false);
    startAnalysis();
  }, [autoAnalyze, fileInfo, analysisRunning, startAnalysis]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

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
          dynamicJs={dynamicJsData as never}
        />
        <ThreatReportPanel
          visible={reportVisible}
          data={reportData}
          pending={reportPending}
        />
        <SandboxSimulation realData={dynamicJsData as never} />
      </div>
    </>
  );
}
