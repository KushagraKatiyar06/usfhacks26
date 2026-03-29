import type { Metadata } from 'next';
// Note: 'use client' must NOT be here - layout.tsx uses static metadata export
import './globals.css';

export const metadata: Metadata = {
  title: 'useprotechtion',
  description: 'AI-powered sandbox malware analysis and threat detection',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="grid-bg">{children}</body>
    </html>
  );
}
