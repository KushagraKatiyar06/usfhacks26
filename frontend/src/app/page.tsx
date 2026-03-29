'use client';

import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import FileIntakePanel, { type FileInfo } from '@/components/FileIntakePanel';
import { setPendingFileInfo } from '@/lib/analysisSession';

const FloatingLines = dynamic(() => import('@/components/FloatingLines'), { ssr: false });

export default function Home() {
  const router = useRouter();
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);

  function handleAnalyze() {
    if (!fileInfo) return;
    setPendingFileInfo(fileInfo);
    router.push('/dashboard');
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      <div style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', opacity: 0.35 }}>
        <FloatingLines
          enabledWaves={['top', 'middle', 'bottom']}
          lineCount={5}
          lineDistance={5}
          bendRadius={5}
          bendStrength={-0.5}
          interactive={true}
          parallax={true}
          linesGradient={['#3b82f6', '#8b5cf6', '#06b6d4']}
          mixBlendMode="screen"
        />
      </div>
      <div style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none', background: 'rgba(6,12,26,0.55)' }} />

      <nav style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '20px 48px',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        background: 'rgba(6,12,26,0.8)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 200,
      }}>
        <div style={{
          fontFamily: 'Orbitron, monospace',
          fontWeight: 900,
          fontSize: '14px',
          letterSpacing: '3px',
          color: '#e2e8f0',
          textTransform: 'uppercase',
        }}>
          use<span style={{ color: '#3b82f6' }}>protechtion</span>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <Link href="/dashboard" style={{
            fontFamily: 'Orbitron, monospace',
            fontSize: '9px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: '#3b82f6',
            border: '1px solid rgba(59,130,246,0.4)',
            borderRadius: '6px',
            padding: '8px 18px',
            textDecoration: 'none',
            transition: 'all 0.2s',
          }}>
            Dashboard
          </Link>
        </div>
      </nav>

      <main style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: '72px 24px 56px',
        position: 'relative',
        zIndex: 200,
      }}>
        <div style={{
          position: 'absolute',
          top: '20%',
          left: '50%',
          transform: 'translateX(-50%)',
          width: '600px',
          height: '600px',
          background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          top: '30%',
          left: '30%',
          width: '300px',
          height: '300px',
          background: 'radial-gradient(circle, rgba(139,92,246,0.08) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          top: '25%',
          right: '25%',
          width: '250px',
          height: '250px',
          background: 'radial-gradient(circle, rgba(6,182,212,0.07) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />

        <h1 style={{
          fontFamily: 'Orbitron, monospace',
          fontWeight: 900,
          fontSize: 'clamp(42px, 8vw, 80px)',
          letterSpacing: '4px',
          textTransform: 'uppercase',
          lineHeight: 1.1,
          marginBottom: '20px',
          color: '#ffffff',
        }}>
          use<span style={{
            color: '#3b82f6',
            textShadow: '0 0 40px rgba(59,130,246,0.5)',
          }}>protechtion</span>
        </h1>

        <p style={{
          fontSize: '16px',
          color: '#94a3b8',
          maxWidth: '560px',
          lineHeight: 1.8,
          marginBottom: '20px',
          fontWeight: 400,
        }}>
          Detonate suspicious files in an isolated sandbox. Upload a specimen below to jump straight into analysis.
        </p>

        <div style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '10px',
          letterSpacing: '3px',
          textTransform: 'uppercase',
          color: '#3b82f6',
          marginBottom: '18px',
        }}>
          Specimen Intake
        </div>

        <div style={{ width: 'min(100%, 540px)' }}>
          <FileIntakePanel
            variant="landing"
            fileInfo={fileInfo}
            onFileLoaded={setFileInfo}
            onAnalyze={handleAnalyze}
            analysisRunning={false}
          />
        </div>
      </main>

      <footer style={{
        padding: '20px 48px',
        borderTop: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'relative',
        zIndex: 200,
      }}>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#475569', letterSpacing: '1px' }}>
          2026 USEPROTECHTION
        </span>
        <div style={{ display: 'flex', gap: '4px' }}>
          {['#10b981', '#3b82f6', '#8b5cf6', '#f43f5e'].map((c, i) => (
            <div key={i} style={{ width: '6px', height: '6px', borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}` }} />
          ))}
        </div>
      </footer>
    </div>
  );
}
