import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  FileText,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
  Server,
  Globe,
  Cpu,
  Sparkles,
  MessageSquare,
  Copy,
  Check,
  Download,
  QrCode,
  Eye,
  ChevronDown,
  ChevronUp,
  Image as ImageIcon,
  Radio,
  Volume2,
  VolumeX,
  Search,
  ExternalLink,
  RefreshCw,
  History,
  Database,
  Zap,
} from 'lucide-react';
import { AllowedScanType, AllowedVerdictType, auth } from '../lib/firebase';

interface EvidenceIndicator {
  category: string;
  indicator: string;
  value: string;
  impact: 'positive' | 'neutral' | 'warning' | 'critical';
  scoreDelta: number;
  details: string;
}

interface AIExplanation {
  available: boolean;
  executiveSummary: string;
  technicalAssessment: string;
  keyFindings: string[];
  recommendations: {
    priority: 'Immediate' | 'High' | 'Standard';
    action: string;
    rationale: string;
  }[];
}

export type ScanStatusType = 'Live' | 'Historical' | 'Cached';

export interface ScanResultViewProps {
  scanType: AllowedScanType;
  target: string;
  scanId?: string | null;
  data: Record<string, any>;
  scanStatus?: ScanStatusType;
  onCreateReport?: (params: {
    scanId: string;
    scanType: AllowedScanType;
    target: string;
    riskScore: number;
    verdict: AllowedVerdictType;
    defaultNotes: string;
  }) => Promise<void>;
  onAskGeminiAboutScan?: (contextPrompt: string) => void;
  onStartVoiceTriage?: (topic: string) => void;
}

export const ScanResultView: React.FC<ScanResultViewProps> = ({
  scanType,
  target,
  scanId,
  data,
  scanStatus,
  onCreateReport,
  onAskGeminiAboutScan,
  onStartVoiceTriage,
}) => {
  const [creatingReport, setCreatingReport] = useState(false);
  const [reportCreated, setReportCreated] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);
  const [ocrExpanded, setOcrExpanded] = useState(true);
  const [playingTts, setPlayingTts] = useState(false);
  const [ttsAudioElement, setTtsAudioElement] = useState<HTMLAudioElement | null>(null);

  const handleReadAloudTts = async () => {
    if (playingTts && ttsAudioElement) {
      ttsAudioElement.pause();
      setPlayingTts(false);
      return;
    }

    try {
      setPlayingTts(true);
      const user = auth.currentUser;
      if (!user) {
        setPlayingTts(false);
        return;
      }
      const token = await user.getIdToken();
      const narrative = `Phishing Shield Scan Analysis for ${scanType} target ${target}. The calculated evidence risk score is ${riskScore} out of 100, resulting in a verdict of ${verdict}. ${aiExplanation?.executiveSummary || (typeof data.summary === 'string' ? data.summary : 'Detailed evidence telemetry is recorded below.')}`;

      const res = await fetch('/api/tts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ text: narrative.slice(0, 900), voiceName: 'Kore' }),
      });
      const resJson = await res.json();
      if (resJson.audioBase64) {
        const audio = new Audio(`data:audio/wav;base64,${resJson.audioBase64}`);
        setTtsAudioElement(audio);
        audio.onended = () => setPlayingTts(false);
        audio.onerror = () => setPlayingTts(false);
        audio.play();
      } else {
        setPlayingTts(false);
      }
    } catch {
      setPlayingTts(false);
    }
  };

  // Google Search Grounding State (gemini-3.8-flash with googleSearch)
  const [searchGroundingOpen, setSearchGroundingOpen] = useState(false);
  const [searchGroundingLoading, setSearchGroundingLoading] = useState(false);
  const [searchGroundingResult, setSearchGroundingResult] = useState<{
    text: string;
    sources: { uri: string; title: string }[];
    modelUsed: string;
  } | null>(null);
  const [searchGroundingError, setSearchGroundingError] = useState<string | null>(null);

  const handleQuerySearchGrounding = async () => {
    if (searchGroundingResult) {
      setSearchGroundingOpen(!searchGroundingOpen);
      return;
    }
    setSearchGroundingOpen(true);
    setSearchGroundingLoading(true);
    setSearchGroundingError(null);

    try {
      const user = auth.currentUser;
      if (!user) {
        throw new Error('Please sign in to run Google Search Grounding.');
      }
      const token = await user.getIdToken();
      const queryPrompt = `Investigate live cybersecurity threats, reputation advisories, CVE reports, and phishing campaigns associated with target: ${target} (Scan type: ${scanType}).`;

      const res = await fetch('/api/grounding/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ query: queryPrompt }),
      });
      const resData = await res.json();
      if (!res.ok) {
        throw new Error(resData.error?.message || resData.error || 'Search grounding query failed.');
      }
      setSearchGroundingResult(resData);
    } catch (err: unknown) {
      setSearchGroundingError(
        err instanceof Error ? err.message : 'Google Search Grounding query failed.'
      );
    } finally {
      setSearchGroundingLoading(false);
    }
  };

  const resolvedScanStatus: ScanStatusType =
    scanStatus ||
    (data.isCached || data.cached || data.source === 'cache'
      ? 'Cached'
      : data.isHistorical || data.historical || data.isHistory || (data.scannedAt && Date.now() - new Date(data.scannedAt).getTime() > 3600000)
        ? 'Historical'
        : 'Live');

  const riskScore: number = typeof data.riskScore === 'number' ? data.riskScore : 0;
  const verdict: AllowedVerdictType = data.verdict || (scanType === 'screenshot' ? 'LOW RISK' : 'Clean');
  const evidence: EvidenceIndicator[] = Array.isArray(data.evidence) ? data.evidence : [];
  const aiExplanation: AIExplanation | undefined = data.aiExplanation;

  const getVerdictColor = (v: string) => {
    switch (v) {
      case 'Malicious':
      case 'High Risk':
      case 'CRITICAL RISK':
      case 'HIGH RISK':
        return 'text-red-600';
      case 'Suspicious':
      case 'MEDIUM RISK':
        return 'text-amber-600';
      case 'Low Risk':
        return 'text-sky-600';
      default:
        return 'text-emerald-600';
    }
  };

  const handleCopyReportText = async () => {
    const lines = [
      `PHISHING SHIELD — SECURITY ANALYSIS REPORT`,
      `Scan Type: ${scanType.toUpperCase()}`,
      `Target: ${target}`,
      `Risk Score: ${riskScore}/100 (${verdict})`,
      `Scanned At: ${data.scannedAt || new Date().toISOString()}`,
      ``,
      `EXECUTIVE SUMMARY:`,
      aiExplanation?.executiveSummary || 'Deterministic scan completed.',
      ``,
      `EVIDENCE INDICATORS:`,
      ...evidence.map(
        (e) => `- [${e.impact.toUpperCase()} | +${e.scoreDelta}] ${e.indicator}: ${e.value} (${e.details})`
      ),
    ];
    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2500);
    } catch {
      // Ignore clipboard error
    }
  };

  const handleDownloadJsonReport = () => {
    const payload = {
      application: 'PHISHING SHIELD',
      scanId: scanId || 'live_scan',
      scanType,
      target,
      riskScore,
      verdict,
      exportedAt: new Date().toISOString(),
      telemetry: data,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeName = target.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 32) || 'report';
    a.download = `phishing-shield-${scanType}-${safeName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getImpactIndicator = (impact: string) => {
    switch (impact) {
      case 'critical':
        return {
          icon: <XCircle className="w-4 h-4 text-red-600 shrink-0" />,
          label: 'Critical Signal',
          textClass: 'text-red-700',
        };
      case 'warning':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />,
          label: 'Warning Signal',
          textClass: 'text-amber-700',
        };
      case 'positive':
        return {
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />,
          label: 'Verified Safe',
          textClass: 'text-emerald-700',
        };
      default:
        return {
          icon: <Info className="w-4 h-4 text-slate-500 shrink-0" />,
          label: 'Informational',
          textClass: 'text-slate-600',
        };
    }
  };

  const handleSaveReport = async () => {
    if (!onCreateReport || !scanId) return;
    setCreatingReport(true);
    try {
      const defaultNotes = [
        `Executive Summary: ${aiExplanation?.executiveSummary || 'Deterministic scan completed.'}`,
        `Technical Assessment: ${aiExplanation?.technicalAssessment || 'See evidence log.'}`,
        ...(aiExplanation?.recommendations?.map(
          (r) => `[${r.priority}] ${r.action} — ${r.rationale}`
        ) || []),
      ].join('\n\n');

      await onCreateReport({
        scanId,
        scanType,
        target,
        riskScore,
        verdict,
        defaultNotes,
      });
      setReportCreated(true);
    } finally {
      setCreatingReport(false);
    }
  };

  const handleAskGemini = () => {
    if (!onAskGeminiAboutScan) return;
    const triggeredEvidence = evidence
      .filter((e) => e.scoreDelta > 0)
      .map((e) => `${e.indicator}: ${e.value} (+${e.scoreDelta})`)
      .join('; ');

    const prompt = `Analyze this ${scanType.toUpperCase()} scan in detail and provide next-step SOC investigation & containment commands:
Target: ${target}
Verdict: ${verdict} (Risk Score: ${riskScore}/100)
Triggered Indicators: ${triggeredEvidence || 'None (Clean telemetry)'}
Executive Summary: ${aiExplanation?.executiveSummary || 'See telemetry'}`;

    onAskGeminiAboutScan(prompt);
  };

  return (
    <div className="space-y-6 text-white">
      {/* Top Executive Verdict Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 text-white shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono">
              {/* Visual 'scan status' badge */}
              {resolvedScanStatus === 'Live' && (
                <span
                  className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800 shadow-2xs"
                  title="Live real-time scan analysis directly querying network targets and AI engines"
                >
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                  </span>
                  <span>Live</span>
                </span>
              )}
              {resolvedScanStatus === 'Historical' && (
                <span
                  className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-sky-950/60 text-sky-400 border border-sky-800 shadow-2xs"
                  title="Historical audit record retrieved from cryptographically immutable Firestore scan ledger"
                >
                  <History className="w-3 h-3 text-sky-400" />
                  <span>Historical</span>
                </span>
              )}
              {resolvedScanStatus === 'Cached' && (
                <span
                  className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-800 shadow-2xs"
                  title="Cached scan analysis retrieved from recent telemetry store"
                >
                  <Database className="w-3 h-3 text-amber-400" />
                  <span>Cached</span>
                </span>
              )}

              <span aria-hidden="true" className="text-slate-600">|</span>
              <span className="text-slate-300">{scanType.toUpperCase()} INSPECTION</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="text-slate-400">{data.scannedAt ? new Date(data.scannedAt).toLocaleString() : 'Just now'}</span>
              {scanId && (
                <>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-slate-400">ID: {scanId.slice(0, 18)}</span>
                </>
              )}
            </div>

            <h3 className="text-lg sm:text-xl font-bold text-white break-all font-mono">
              {target}
            </h3>

            <div className="flex items-center gap-3 pt-1">
              {riskScore >= 50 ? (
                <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
              ) : riskScore >= 25 ? (
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
              )}
              <span className={`text-sm font-semibold ${getVerdictColor(verdict)}`}>
                Verdict: {verdict}
              </span>
              <span className="text-slate-600" aria-hidden="true">
                ·
              </span>
              <span className="text-xs text-slate-400">
                {evidence.filter((e) => e.scoreDelta > 0).length} risk indicator(s) triggered out of{' '}
                {evidence.length} total checks
              </span>
            </div>
          </div>

          {/* Right: Numerical Score & Save Report / Ask Gemini Actions */}
          <div className="flex flex-wrap items-center gap-4 shrink-0 border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-800">
            <div className="text-left lg:text-right pr-2">
              <p className="text-xs text-slate-400">Evidence Risk Score</p>
              <div className="flex items-center lg:justify-end gap-2.5 mt-0.5">
                <p
                  className={`text-3xl font-bold font-mono tabular-nums ${getVerdictColor(verdict)}`}
                >
                  {riskScore}
                  <span className="text-base text-slate-500 font-normal"> / 100</span>
                </p>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider inline-flex items-center gap-1 shadow-xs ${
                    riskScore >= 80
                      ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                      : riskScore >= 60
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                        : riskScore >= 30
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                  }`}
                >
                  {riskScore >= 80
                    ? 'Critical'
                    : riskScore >= 60
                      ? 'High'
                      : riskScore >= 30
                        ? 'Medium'
                        : 'Low'}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={handleCopyReportText}
                className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedReport ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-400" />
                    <span>Copy Report</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadJsonReport}
                className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                <span>Download JSON</span>
              </button>

              {/* Read Aloud with Gemini Flash TTS */}
              <button
                type="button"
                onClick={handleReadAloudTts}
                className={`px-3 py-2 text-xs font-medium rounded-lg border transition-colors flex items-center gap-1.5 cursor-pointer ${
                  playingTts
                    ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                    : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
                }`}
                title={playingTts ? 'Stop audio playback' : 'Read aloud with Gemini TTS'}
              >
                {playingTts ? (
                  <>
                    <VolumeX className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                    <span>Stop Audio</span>
                  </>
                ) : (
                  <>
                    <Volume2 className="w-3.5 h-3.5 text-slate-400" />
                    <span>Listen (TTS)</span>
                  </>
                )}
              </button>

              {/* Live Voice Triage (gemini-3.8-live) */}
              {onStartVoiceTriage && (
                <button
                  type="button"
                  onClick={() =>
                    onStartVoiceTriage(
                      `Target: ${target} (${scanType.toUpperCase()}), Verdict: ${verdict}, Risk Score: ${riskScore}/100. Findings: ${aiExplanation?.executiveSummary || (typeof data.summary === 'string' ? data.summary : 'Evidence telemetry')}`
                    )
                  }
                  className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-2xs"
                  title="Open live bidirectional voice triage session with Gemini 3.8 Live"
                >
                  <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                  <span>Live Voice Triage</span>
                </button>
              )}

              {/* Google Search Grounding Threat Intel (gemini-3.8-flash) */}
              <button
                type="button"
                onClick={handleQuerySearchGrounding}
                disabled={searchGroundingLoading}
                className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-blue-950/60 hover:bg-blue-900/80 text-blue-300 border border-blue-800 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-2xs"
                title="Query live Google Search data for active threat intelligence and phishing reports"
              >
                {searchGroundingLoading ? (
                  <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                ) : (
                  <Search className="w-3.5 h-3.5 text-blue-400" />
                )}
                <span>{searchGroundingLoading ? 'Searching...' : 'Google Search Intel'}</span>
              </button>

              {onAskGeminiAboutScan && (
                <button
                  type="button"
                  onClick={handleAskGemini}
                  className="px-4 py-2.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer shadow-sm"
                >
                  <MessageSquare className="w-4 h-4" />
                  <span>Ask Gemini AI Assistant</span>
                </button>
              )}

              {onCreateReport && scanId && (
                <button
                  type="button"
                  onClick={handleSaveReport}
                  disabled={creatingReport || reportCreated}
                  className="px-4 py-2.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 disabled:opacity-60 transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer"
                >
                  <FileText className="w-4 h-4 text-emerald-400" />
                  <span>
                    {reportCreated
                      ? 'Saved to Security Reports'
                      : creatingReport
                        ? 'Generating Report...'
                        : 'Generate Security Report'}
                  </span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Google Search Grounding Threat Intelligence Card */}
        {searchGroundingOpen && (
          <div className="mt-4 p-4 rounded-xl bg-blue-950/30 border border-blue-800 space-y-3 animate-in fade-in duration-150">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-blue-400" />
                <span className="text-xs font-bold text-white font-display">
                  Live Google Search Threat Intelligence
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700">
                  gemini-3.8-flash (with googleSearch)
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSearchGroundingOpen(false)}
                className="text-xs text-blue-400 hover:text-white cursor-pointer font-medium"
              >
                Dismiss
              </button>
            </div>

            {searchGroundingLoading && (
              <div className="flex items-center gap-2 text-xs text-blue-300 font-mono py-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-400" />
                <span>Querying Google Search Grounding for live threat advisories...</span>
              </div>
            )}

            {searchGroundingError && (
              <p className="text-xs text-red-400">{searchGroundingError}</p>
            )}

            {searchGroundingResult && (
              <div className="space-y-3">
                <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                  {searchGroundingResult.text}
                </p>

                {searchGroundingResult.sources && searchGroundingResult.sources.length > 0 && (
                  <div className="pt-2 border-t border-blue-800 space-y-1.5">
                    <span className="text-[11px] font-semibold text-blue-300 uppercase tracking-wider block">
                      Verified Web Sources & Citations:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {searchGroundingResult.sources.map((src, i) => (
                        <a
                          key={i}
                          href={src.uri}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-blue-800 text-[11px] text-blue-300 hover:text-white hover:bg-blue-900/50 transition-colors shadow-2xs truncate max-w-xs"
                        >
                          <ExternalLink className="w-3 h-3 text-blue-400 shrink-0" />
                          <span className="truncate">{src.title || src.uri}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Visual Risk Score Meter Bar */}
        <div className="mt-5 pt-4 border-t border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>0 — LOW RISK</span>
            <span>21–50 — MEDIUM RISK</span>
            <span>51–75 — HIGH RISK</span>
            <span>76–100 — CRITICAL RISK</span>
          </div>
          <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                riskScore >= 76
                  ? 'bg-red-500'
                  : riskScore >= 51
                    ? 'bg-orange-500'
                    : riskScore >= 21
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.max(2, Math.min(100, riskScore))}%` }}
            />
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SCREENSHOT SECURITY ANALYZER SPECIFIC SECTIONS                        */}
      {/* ===================================================================== */}
      {scanType === 'screenshot' && (
        <div className="space-y-6">
          {/* 01. Extracted Text (OCR Forensics) & Extracted Entities */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Eye className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-sm font-semibold text-white">
                    01. Extracted Text (OCR Forensics)
                  </h4>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400">
                    {data.ocr?.status || 'Evaluated'} · {data.ocr?.characterCount || 0} chars
                  </span>
                  <button
                    type="button"
                    onClick={() => setOcrExpanded((prev) => !prev)}
                    className="text-xs font-medium text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                  >
                    <span>{ocrExpanded ? 'Collapse' : 'Expand'}</span>
                    {ocrExpanded ? (
                      <ChevronUp className="w-3.5 h-3.5" />
                    ) : (
                      <ChevronDown className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {data.ocr?.lowClarityNotice && (
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800 flex items-start gap-2 text-xs text-amber-300">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span>{data.ocr.lowClarityNotice}</span>
                </div>
              )}

              {ocrExpanded && (
                <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 max-h-64 overflow-y-auto">
                  {data.ocr?.extractedText ? (
                    <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-words leading-relaxed">
                      {data.ocr.extractedText}
                    </pre>
                  ) : (
                    <p className="text-xs text-slate-400 font-mono">
                      No readable text was detected in this screenshot.
                    </p>
                  )}
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                <span>OCR Engine: {data.ocr?.engine || 'Multimodal OCR'}</span>
                <span>Lines Extracted: {data.ocr?.lineCount || 0}</span>
              </div>
            </div>

            {/* Extracted Entities & QR Code Detection (5 cols) */}
            <div className="lg:col-span-5 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <QrCode className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-sm font-semibold text-white">
                    02. QR Code & Extracted Entities
                  </h4>
                </div>
                <span
                  className={`text-xs font-mono font-semibold ${
                    data.qrCode?.detected ? 'text-amber-400' : 'text-slate-400'
                  }`}
                >
                  QR: {data.qrCode?.detected ? 'Detected' : 'None Detected'}
                </span>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">QR Code Matrix Scan:</span>
                  <span className="font-mono text-slate-300">
                    {data.qrCode?.payloadType || 'None'}
                  </span>
                </div>
                {data.qrCode?.detected && data.qrCode?.decodedContent && (
                  <p className="font-mono text-emerald-400 break-all bg-slate-900 p-2 rounded-lg border border-slate-800">
                    Decoded: {data.qrCode.decodedContent}
                  </p>
                )}
                <p className="text-slate-400 leading-relaxed">{data.qrCode?.riskSummary}</p>
              </div>

              <dl className="space-y-2.5 text-xs pt-1">
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">Extracted URLs</dt>
                  <dd className="font-mono text-emerald-400 text-right break-all">
                    {data.ocr?.extractedUrls?.length > 0
                      ? data.ocr.extractedUrls.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">Extracted Domains</dt>
                  <dd className="font-mono text-slate-200 text-right break-all">
                    {data.ocr?.extractedDomains?.length > 0
                      ? data.ocr.extractedDomains.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">Email Addresses</dt>
                  <dd className="font-mono text-slate-300 text-right break-all">
                    {data.ocr?.extractedEmails?.length > 0
                      ? data.ocr.extractedEmails.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 gap-1">
                  <dt className="text-slate-400 shrink-0">Phone Numbers</dt>
                  <dd className="font-mono text-slate-300 text-right break-all">
                    {data.ocr?.extractedPhones?.length > 0
                      ? data.ocr.extractedPhones.join(', ')
                      : 'None'}
                  </dd>
                </div>
              </dl>
            </div>
          </div>

          {/* 03. Visual Security Inspection & Brand Impersonation + 04. Social Engineering */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Visual UI & Brand Impersonation (6 cols) */}
            <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  03. Visual UI & Brand Impersonation Analysis
                </h4>
                <span className="text-xs font-mono text-emerald-400 font-semibold">
                  {data.visualInspection?.screenshotCategory || 'Inspected'}
                </span>
              </div>

              {/* Brand Impersonation Banner */}
              <div
                className={`p-3.5 rounded-lg border text-xs space-y-1 ${
                  data.brandImpersonation?.brandDomainMismatch
                    ? 'bg-red-950/40 border-red-800 text-red-300'
                    : data.brandImpersonation?.detectedBrand
                      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between font-semibold">
                  <span>
                    Detected Brand: {data.brandImpersonation?.detectedBrand || 'None Detected'}
                  </span>
                  <span className="font-mono">
                    {data.brandImpersonation?.impersonationRisk || 'None Detected'}
                  </span>
                </div>
                <p className="leading-relaxed">{data.brandImpersonation?.mismatchDetails}</p>
                {data.brandImpersonation?.officialDomains?.length > 0 && (
                  <p className="font-mono text-[11px] opacity-80">
                    Official Brand Domains: {data.brandImpersonation.officialDomains.join(', ')}
                  </p>
                )}
              </div>

              {/* Visual UI Element Detection Matrix */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">Sign-In / Login Form</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsLoginForm
                        ? 'text-amber-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsLoginForm ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">Password Input</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsPasswordInput
                        ? 'text-red-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsPasswordInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">OTP / 2FA Request</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsOtpInput ? 'text-red-400' : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsOtpInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">Payment / Card UI</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsPaymentCardInput
                        ? 'text-red-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsPaymentCardInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">Urgency Banner</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsUrgencyBanner
                        ? 'text-amber-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsUrgencyBanner ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60">
                  <p className="text-slate-400">Download Prompt</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsDownloadPrompt
                        ? 'text-red-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {data.visualInspection?.containsDownloadPrompt ? 'Detected' : 'Not Present'}
                  </p>
                </div>
              </div>

              {Array.isArray(data.visualInspection?.visualIndicators) &&
                data.visualInspection.visualIndicators.length > 0 && (
                  <div className="pt-2 border-t border-slate-800 space-y-1.5 text-xs">
                    <p className="font-semibold text-slate-200">Observed Visual Cues:</p>
                    <ul className="space-y-1 text-slate-400">
                      {data.visualInspection.visualIndicators.map((ind: string, i: number) => (
                        <li key={i} className="flex items-start gap-2">
                          <ArrowRight className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
            </div>

            {/* 04. Social Engineering & Scam Pattern Detection + Image Metadata (6 cols) */}
            <div className="lg:col-span-6 space-y-6">
              <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h4 className="text-sm font-semibold text-white">
                    04. Social Engineering & Scam Pattern Analysis
                  </h4>
                  <span className="text-xs font-mono font-semibold text-slate-300 tabular-nums">
                    Manipulation Score: {data.socialEngineering?.manipulationScore || 0}/100
                  </span>
                </div>

                {data.socialEngineering?.detectedScamPatterns?.length > 0 ? (
                  <div className="p-3 rounded-lg bg-red-950/40 border border-red-800 space-y-1 text-xs">
                    <p className="font-semibold text-red-200">Matched Scam Signatures:</p>
                    <p className="font-mono text-red-300">
                      {data.socialEngineering.detectedScamPatterns.join(' · ')}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-slate-400">
                    No high-confidence social engineering scam signatures matched.
                  </p>
                )}

                <dl className="space-y-2 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                    <dt className="text-slate-400">Urgency / Time Pressure</dt>
                    <dd className="font-mono text-slate-200 text-right">
                      {data.socialEngineering?.urgencyIndicators?.length > 0
                        ? data.socialEngineering.urgencyIndicators.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                    <dt className="text-slate-400">Fear / Suspension Threats</dt>
                    <dd className="font-mono text-slate-200 text-right">
                      {data.socialEngineering?.fearOrThreatLanguage?.length > 0
                        ? data.socialEngineering.fearOrThreatLanguage.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                    <dt className="text-slate-400">Authority Impersonation</dt>
                    <dd className="font-mono text-slate-200 text-right">
                      {data.socialEngineering?.authorityImpersonation?.length > 0
                        ? data.socialEngineering.authorityImpersonation.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                    <dt className="text-slate-400">Credential / OTP Cues</dt>
                    <dd className="font-mono text-slate-200 text-right">
                      {data.socialEngineering?.credentialHarvestingRequests?.length > 0
                        ? data.socialEngineering.credentialHarvestingRequests.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 gap-2">
                    <dt className="text-slate-400">Financial / Reward Cues</dt>
                    <dd className="font-mono text-slate-200 text-right">
                      {[
                        ...(data.socialEngineering?.financialOrPaymentRequests || []),
                        ...(data.socialEngineering?.rewardOrLotteryScam || []),
                      ].join(', ') || 'None Detected'}
                    </dd>
                  </div>
                </dl>
              </div>

              {/* Image & EXIF Metadata Verification Card */}
              {data.metadata && (
                <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center gap-2">
                      <ImageIcon className="w-4 h-4 text-slate-400" />
                      <h4 className="text-sm font-semibold text-white">
                        05. Image & EXIF Metadata Forensics
                      </h4>
                    </div>
                    <span className="text-xs font-mono text-slate-400">
                      {data.metadata.format} · {data.metadata.formattedFileSize}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                    <div>
                      <p className="text-slate-400">Dimensions</p>
                      <p className="font-mono font-medium text-white mt-0.5">
                        {data.metadata.dimensions}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">Color Profile</p>
                      <p className="font-mono font-medium text-white mt-0.5">
                        {data.metadata.colorSpace} ({data.metadata.channels}ch)
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">EXIF Software</p>
                      <p className="font-mono font-medium text-white mt-0.5 truncate">
                        {data.metadata.exifSoftware}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">EXIF Device</p>
                      <p className="font-mono text-slate-300 mt-0.5 truncate">
                        {data.metadata.exifDeviceMakeModel}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">EXIF Timestamp</p>
                      <p className="font-mono text-slate-300 mt-0.5">{data.metadata.exifDateTime}</p>
                    </div>
                    <div>
                      <p className="text-slate-400">Confidence</p>
                      <p className="font-mono text-emerald-400 font-semibold mt-0.5">
                        {data.confidenceScore || 88}%
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 06. Automated URL, Domain, DNS & RDAP Analysis for Extracted URLs */}
          {Array.isArray(data.urlAnalyses) && data.urlAnalyses.length > 0 && (
            <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-sm font-semibold text-white">
                    06. Automated URL, Domain, DNS & RDAP Pipeline (Extracted from Screenshot)
                  </h4>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  {data.urlAnalyses.length} URL(s) Analyzed Live
                </span>
              </div>

              <div className="space-y-4">
                {data.urlAnalyses.map((u: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3 text-xs"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] font-semibold">
                            Source: {u.source}
                          </span>
                          <span className="font-mono font-bold text-white break-all">
                            {u.url}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`font-mono font-bold ${getVerdictColor(u.verdict)}`}>
                          {u.verdict} ({u.riskScore}/100)
                        </span>
                      </div>
                    </div>

                    {u.brandMismatchWithVisual && (
                      <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-800 text-red-300 font-medium flex items-start gap-2">
                        <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                        <span>{u.brandMismatchWithVisual}</span>
                      </div>
                    )}

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div>
                        <p className="text-slate-400">Registered Domain</p>
                        <p className="font-mono font-semibold text-white mt-0.5">
                          {u.registeredDomain} (.{u.tld})
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-400">HTTPS & Transport</p>
                        <p className="font-mono font-medium text-white mt-0.5">
                          {u.usesHttps ? 'HTTPS (Encrypted)' : 'HTTP (Unencrypted)'}
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-400">RDAP Domain Age</p>
                        <p className="font-mono font-semibold text-emerald-400 mt-0.5">
                          {u.domainAge || 'Unavailable'}
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-400">Resolved Public IP</p>
                        <p className="font-mono font-medium text-white mt-0.5">
                          {u.resolvedIp} ({u.ipCountry})
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-800 text-[11px] text-slate-400 font-mono">
                      <div>Registrar: {u.registrar || 'Unavailable'}</div>
                      <div>SPF: {u.spfRecord || 'Not Present'}</div>
                      <div>DMARC: {u.dmarcRecord || 'Not Present'}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* URL SCAN SPECIFIC SECTIONS                                            */}
      {/* ===================================================================== */}
      {scanType === 'url' && data.domainAnalysis && (
        <div className="space-y-6">
          {/* Domain -> DNS -> IP Resolution Flow */}
          <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-sm font-semibold text-white">
                01. Domain → DNS → Public IP Resolution Chain
              </h4>
              <span className="text-xs text-slate-400 font-mono">
                Live Infrastructure Resolution
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center pt-2">
              <div className="space-y-1">
                <p className="text-xs text-slate-400">Submitted Hostname</p>
                <p className="text-sm font-mono font-semibold text-white break-all">
                  {data.domainAnalysis.hostname}
                </p>
                <p className="text-xs text-slate-500">
                  Subdomain: {data.domainAnalysis.subdomain} ({data.domainAnalysis.subdomainCount})
                </p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-800 md:pl-4">
                <p className="text-xs text-slate-400">Extracted Registered Domain</p>
                <p className="text-sm font-mono font-semibold text-emerald-400 break-all">
                  {data.domainAnalysis.registeredDomain}
                </p>
                <p className="text-xs text-slate-500">TLD: .{data.domainAnalysis.tld}</p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-800 md:pl-4">
                <p className="text-xs text-slate-400">DNS Resolution</p>
                <p className="text-sm font-mono font-semibold text-white">
                  {data.dnsAnalysis?.resolvable ? 'Resolved (Active)' : 'NXDOMAIN / Unresolvable'}
                </p>
                <p className="text-xs text-slate-500 font-mono tabular-nums">
                  {data.dnsAnalysis?.nsRecords?.length || 0} NS ·{' '}
                  {data.dnsAnalysis?.mxRecords?.length || 0} MX records
                </p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-800 md:pl-4">
                <p className="text-xs text-slate-400">Associated Public IP</p>
                <p className="text-sm font-mono font-semibold text-white tabular-nums">
                  {data.ipAnalysis?.ip || 'Unavailable'}
                </p>
                <p className="text-xs text-slate-500 truncate">
                  {data.ipAnalysis
                    ? `${data.ipAnalysis.asn} · ${data.ipAnalysis.country}`
                    : 'No A/AAAA record'}
                </p>
              </div>
            </div>
          </div>

          {/* Domain Age (RDAP) & URL Syntax Split */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Domain Age & RDAP Registration (5 cols) */}
            <div className="lg:col-span-5 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  02. Domain Age & RDAP Registration
                </h4>
                <Globe className="w-4 h-4 text-slate-400" />
              </div>

              <dl className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                  <dt className="text-slate-400">Domain Created</dt>
                  <dd className="font-mono text-white tabular-nums">
                    {data.domainAnalysis.rdap?.creationDate || 'Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                  <dt className="text-slate-400">Current Date</dt>
                  <dd className="font-mono text-slate-300 tabular-nums">
                    {data.domainAnalysis.rdap?.currentDate ||
                      new Date().toISOString().split('T')[0]}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                  <dt className="text-slate-400 font-medium">Calculated Domain Age</dt>
                  <dd className="font-mono font-semibold text-emerald-400 tabular-nums">
                    {data.domainAnalysis.rdap?.formattedAge &&
                    data.domainAnalysis.rdap.formattedAge !== 'Unavailable'
                      ? data.domainAnalysis.rdap.formattedAge
                      : 'Domain age: Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                  <dt className="text-slate-400">Registry Expiration</dt>
                  <dd className="font-mono text-slate-300 tabular-nums">
                    {data.domainAnalysis.rdap?.expirationDate || 'Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-4">
                  <dt className="text-slate-400 shrink-0">Registrar</dt>
                  <dd className="font-mono text-slate-300 text-right truncate">
                    {data.domainAnalysis.rdap?.registrar || 'Unavailable'}
                  </dd>
                </div>
              </dl>

              <p className="text-[11px] text-slate-400 leading-relaxed pt-1">
                Policy Note: Domain age is evaluated strictly as a contextual evidence indicator and
                never classifies a website as malicious on its own.
              </p>
            </div>

            {/* URL Syntax, TLS & Lexical Inspection (7 cols) */}
            <div className="lg:col-span-7 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  03. URL Syntax, Lexical & Transport Inspection
                </h4>
                {data.syntax?.usesHttps ? (
                  <Lock className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Unlock className="w-4 h-4 text-amber-400" />
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div className="space-y-1">
                  <p className="text-slate-400">Transport Protocol</p>
                  <p className="font-mono font-medium text-white">
                    {data.syntax?.protocol} (Port {data.syntax?.port})
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-400">URL / Host Length</p>
                  <p className="font-mono font-medium text-white tabular-nums">
                    {data.syntax?.urlLength} chars / {data.syntax?.hostnameLength} host
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-400">Host / Path Entropy</p>
                  <p className="font-mono font-medium text-white tabular-nums">
                    {data.syntax?.hostEntropy} / {data.syntax?.pathEntropy} bits
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-400">IP Literal Hostname</p>
                  <p className="font-mono font-medium text-white">
                    {data.syntax?.isIpHostname ? 'Yes (Raw IP)' : 'No (Domain Name)'}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-400">URL Shortener</p>
                  <p className="font-mono font-medium text-white">
                    {data.syntax?.isUrlShortener ? 'Detected' : 'Not a Shortener'}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-400">Punycode / IDN</p>
                  <p className="font-mono font-medium text-white">
                    {data.syntax?.isPunycode
                      ? `Yes (${data.syntax.unicodeHostname})`
                      : 'ASCII Standard'}
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 space-y-2 text-xs">
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-400">TLS X.509 Certificate:</span>
                  <span className="font-mono text-slate-200">
                    {data.tlsInspection?.available
                      ? `Issuer: ${data.tlsInspection.issuer} · Valid until ${data.tlsInspection.validTo} (${data.tlsInspection.daysRemaining}d remaining)`
                      : data.tlsInspection?.reason || 'Unavailable'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-400">Suspicious Keywords:</span>
                  <span className="font-mono text-slate-200">
                    {data.syntax?.suspiciousKeywords?.length > 0
                      ? data.syntax.suspiciousKeywords.join(', ')
                      : 'None Detected'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-400">Homograph / Brand Indicators:</span>
                  <span className="font-mono text-slate-200">
                    {data.syntax?.homographIndicators?.length > 0
                      ? data.syntax.homographIndicators.join('; ')
                      : 'None Detected'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-400">Redirect Chain Behavior:</span>
                  <span className="font-mono text-slate-200">
                    {data.redirectTrace?.checked
                      ? `${data.redirectTrace.hops.length} hop(s) → ${data.redirectTrace.finalUrl}`
                      : data.redirectTrace?.statusNote || 'Unavailable'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* DNS Analysis & Associated IP Reputation Split */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* DNS Records (6 cols) */}
            <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">04. Live DNS Zone Records</h4>
                <Server className="w-4 h-4 text-slate-400" />
              </div>

              <dl className="space-y-2.5 text-xs">
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">A Records (IPv4)</dt>
                  <dd className="font-mono text-white text-right break-all tabular-nums">
                    {data.dnsAnalysis?.aRecords?.length > 0
                      ? data.dnsAnalysis.aRecords.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">AAAA Records (IPv6)</dt>
                  <dd className="font-mono text-slate-300 text-right break-all tabular-nums">
                    {data.dnsAnalysis?.aaaaRecords?.length > 0
                      ? data.dnsAnalysis.aaaaRecords.slice(0, 2).join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">Nameservers (NS)</dt>
                  <dd className="font-mono text-slate-200 text-right break-all">
                    {data.dnsAnalysis?.nsRecords?.length > 0
                      ? data.dnsAnalysis.nsRecords.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">Mail Exchange (MX)</dt>
                  <dd className="font-mono text-slate-200 text-right break-all">
                    {data.dnsAnalysis?.mxRecords?.length > 0
                      ? data.dnsAnalysis.mxRecords.slice(0, 3).join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-800/80 gap-1">
                  <dt className="text-slate-400 shrink-0">SPF Policy</dt>
                  <dd className="font-mono text-slate-300 text-right break-all">
                    {data.dnsAnalysis?.spfRecord || 'Not Present'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 gap-1">
                  <dt className="text-slate-400 shrink-0">DMARC Policy</dt>
                  <dd className="font-mono text-slate-300 text-right break-all">
                    {data.dnsAnalysis?.dmarcRecord || 'Not Present'}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Resolved Public IP Reputation & ML Features (6 cols) */}
            <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  05. Resolved IP Reputation & ML Classifier
                </h4>
                <Cpu className="w-4 h-4 text-slate-400" />
              </div>

              {data.ipAnalysis ? (
                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <p className="text-slate-400">Resolved Public IP</p>
                      <p className="font-mono font-semibold text-white tabular-nums mt-0.5">
                        {data.ipAnalysis.ip} ({data.ipAnalysis.classification})
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">ASN & ISP</p>
                      <p className="font-mono text-slate-200 mt-0.5 truncate">
                        {data.ipAnalysis.asn} · {data.ipAnalysis.organization}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">Geolocation</p>
                      <p className="font-mono text-slate-200 mt-0.5">
                        {data.ipAnalysis.country} ({data.ipAnalysis.region})
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400">Reverse DNS (PTR)</p>
                      <p className="font-mono text-slate-200 mt-0.5 truncate">
                        {data.ipAnalysis.reverseDns?.length > 0
                          ? data.ipAnalysis.reverseDns[0]
                          : 'Unconfigured'}
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400">
                  IP Reputation: Unavailable (domain did not resolve to a public A/AAAA IP).
                </p>
              )}

              {/* ML Phishing Feature Breakdown */}
              {data.mlDetection && (
                <div className="space-y-2.5 pt-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">
                      ML Phishing Classifier Probability
                    </span>
                    <span className="font-mono font-semibold text-white tabular-nums">
                      {data.mlDetection.phishingProbability}% ({data.mlDetection.classifierVerdict})
                    </span>
                  </div>
                  <div className="space-y-2 pt-1">
                    {data.mlDetection.features?.map((f: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between text-xs text-slate-400"
                      >
                        <span>{f.feature}</span>
                        <span className="font-mono text-slate-200 tabular-nums">
                          {f.rawValue} · {f.contribution}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* MESSAGE SCAN SPECIFIC SECTIONS                                        */}
      {/* ===================================================================== */}
      {scanType === 'message' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* NLP Psychological Manipulation Breakdown (6 cols) */}
            <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  01. NLP Social Engineering & Intent Analysis
                </h4>
                <span className="text-xs font-mono text-emerald-400 font-semibold">
                  {data.mlClassification?.primaryIntent || 'Evaluated'}
                </span>
              </div>

              {data.manipulationVectorScores && (
                <div className="space-y-3 text-xs">
                  {Object.entries(data.manipulationVectorScores).map(([key, val]) => {
                    const scoreNum = Number(val) || 0;
                    const labelMap: Record<string, string> = {
                      urgency: 'Urgency & Time Pressure',
                      authority: 'Authority & Impersonation',
                      fearAndCoercion: 'Fear & Account Coercion',
                      credentialHarvesting: 'Credential / MFA Harvesting',
                      financialLure: 'Financial / Payment Lure',
                    };
                    return (
                      <div key={key} className="space-y-1">
                        <div className="flex justify-between">
                          <span className="text-slate-300">{labelMap[key] || key}</span>
                          <span className="font-mono text-white font-medium tabular-nums">
                            {scoreNum}/100
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded overflow-hidden">
                          <div
                            className={`h-full ${
                              scoreNum >= 70
                                ? 'bg-red-500'
                                : scoreNum >= 35
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, scoreNum)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {Array.isArray(data.nlpSignals) && data.nlpSignals.length > 0 && (
                <div className="pt-3 border-t border-slate-800 space-y-2 text-xs">
                  <p className="font-medium text-slate-200">Matched Linguistic Triggers:</p>
                  {data.nlpSignals.map((sig: any, idx: number) => (
                    <div key={idx} className="text-slate-400">
                      <span className="text-white font-medium">{sig.category}: </span>
                      <span className="font-mono text-[11px] text-slate-300">
                        {sig.matchedPhrases.join(', ')}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Extracted Entities, Headers & Live URL Scan (6 cols) */}
            <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-sm font-semibold text-white">
                  02. Extracted Entities & Header Verification
                </h4>
                <span className="text-xs font-mono text-slate-400 tabular-nums">
                  {data.wordCount || 0} words
                </span>
              </div>

              <dl className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                  <dt className="text-slate-400">Declared Sender</dt>
                  <dd className="font-mono text-white text-right break-all">
                    {data.senderInput || 'Not Provided'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                  <dt className="text-slate-400">Header Auth (SPF / DKIM / DMARC)</dt>
                  <dd className="font-mono text-slate-300 text-right">
                    {data.headerAnalysis?.provided
                      ? `${data.headerAnalysis.spfStatus} / ${data.headerAnalysis.dkimStatus} / ${data.headerAnalysis.dmarcStatus}`
                      : 'Not Checked (No Headers Provided)'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                  <dt className="text-slate-400">Extracted URLs</dt>
                  <dd className="font-mono text-emerald-400 text-right break-all">
                    {data.extractedEntities?.urls?.length > 0
                      ? data.extractedEntities.urls.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/80 gap-2">
                  <dt className="text-slate-400">Extracted Emails / Phones</dt>
                  <dd className="font-mono text-slate-300 text-right break-all">
                    {[
                      ...(data.extractedEntities?.emails || []),
                      ...(data.extractedEntities?.phoneNumbers || []),
                    ].join(', ') || 'None'}
                  </dd>
                </div>
              </dl>

              {data.embeddedUrlScan && (
                <div className="pt-3 border-t border-slate-800 space-y-1.5 text-xs">
                  <p className="font-semibold text-white">
                    Automated Deep Scan of Embedded URL ({data.embeddedUrlScan.url}):
                  </p>
                  <p className="text-slate-300 font-mono">
                    Verdict: {data.embeddedUrlScan.verdict} ({data.embeddedUrlScan.riskScore}/100) ·
                    Domain Age: {data.embeddedUrlScan.domainAnalysis?.rdap?.formattedAge} · IP:{' '}
                    {data.embeddedUrlScan.ipAnalysis?.ip || 'Unresolved'}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* PUBLIC IP SCAN SPECIFIC SECTIONS                                      */}
      {/* ===================================================================== */}
      {scanType === 'ip' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-sm font-semibold text-white">
                01. Network Routing, ASN & Geolocation
              </h4>
              <span className="text-xs font-mono text-emerald-400 font-semibold">
                {data.classification}
              </span>
            </div>

            <dl className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <dt className="text-slate-400">IP Address & Version</dt>
                <dd className="font-mono text-white tabular-nums">
                  {data.ip} ({data.ipVersion})
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <dt className="text-slate-400">Autonomous System (ASN)</dt>
                <dd className="font-mono text-white">{data.asn}</dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <dt className="text-slate-400">Organization / ISP</dt>
                <dd className="font-mono text-slate-200 text-right">
                  {data.organization} ({data.isp})
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <dt className="text-slate-400">Country / Region / City</dt>
                <dd className="font-mono text-slate-200">
                  {data.country} · {data.region} · {data.city}
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <dt className="text-slate-400">Reverse DNS (PTR)</dt>
                <dd className="font-mono text-slate-200 break-all">
                  {data.reverseDns?.length > 0 ? data.reverseDns.join(', ') : 'None'}
                </dd>
              </div>
              <div className="flex justify-between py-1.5">
                <dt className="text-slate-400">Proxy / Datacenter Flags</dt>
                <dd className="font-mono text-slate-200">
                  Proxy/VPN: {String(data.isProxyOrVpn)} · Hosting:{' '}
                  {String(data.isHostingOrDatacenter)}
                </dd>
              </div>
            </dl>
          </div>

          <div className="lg:col-span-6 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-sm font-semibold text-white">
                02. RDAP Registry Block & Live DNSBL Matrix
              </h4>
              <Server className="w-4 h-4 text-slate-400" />
            </div>

            <dl className="space-y-2 text-xs pb-3 border-b border-slate-800">
              <div className="flex justify-between">
                <dt className="text-slate-400">RDAP Network Name & CIDR</dt>
                <dd className="font-mono text-white tabular-nums">
                  {data.rdapNetwork?.networkName} ({data.rdapNetwork?.cidr})
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-400">RDAP Registration Date</dt>
                <dd className="font-mono text-slate-300 tabular-nums">
                  {data.rdapNetwork?.registrationDate || 'Unavailable'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-400">Abuse Contact</dt>
                <dd className="font-mono text-slate-300">
                  {data.rdapNetwork?.abuseContact || 'Unavailable'}
                </dd>
              </div>
            </dl>

            <div className="space-y-2 text-xs">
              <p className="text-slate-300 font-medium">
                Real-Time DNS Blackhole List (DNSBL) Queries:
              </p>
              {Array.isArray(data.dnsblResults) && data.dnsblResults.length > 0 ? (
                data.dnsblResults.map((d: any, i: number) => (
                  <div key={i} className="flex items-center justify-between py-1">
                    <span className="text-slate-300">
                      {d.provider} <span className="text-slate-500 font-mono">({d.zone})</span>
                    </span>
                    <span
                      className={`font-mono font-semibold ${
                        d.status === 'Listed'
                          ? 'text-red-400'
                          : d.status === 'Clean'
                            ? 'text-emerald-400'
                            : 'text-slate-500'
                      }`}
                    >
                      {d.status}
                    </span>
                  </div>
                ))
              ) : (
                <p className="text-slate-500">Not Checked for non-public IP ranges.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* THREAT INTELLIGENCE SOURCES (for URL and IP scans)                    */}
      {/* ===================================================================== */}
      {(Array.isArray(data.threatIntelligence) || Array.isArray(data.externalThreatFeeds)) && (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h4 className="text-sm font-semibold text-white">
              Threat Intelligence & External Reputation Sources
            </h4>
            <span className="text-xs text-slate-400">
              Unconfigured APIs explicitly display Not Checked
            </span>
          </div>

          <div className="divide-y divide-slate-800 text-xs">
            {(data.threatIntelligence || data.externalThreatFeeds || []).map(
              (feed: any, idx: number) => (
                <div
                  key={idx}
                  className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="space-y-0.5">
                    <p className="font-medium text-white">{feed.source}</p>
                    <p className="text-slate-400">{feed.details}</p>
                  </div>
                  <div className="font-mono font-semibold shrink-0">
                    {feed.status === 'Clean' && (
                      <span className="text-emerald-400">Status: Clean</span>
                    )}
                    {feed.status === 'Flagged' && (
                      <span className="text-red-400">Status: Flagged</span>
                    )}
                    {feed.status === 'Unavailable' && (
                      <span className="text-slate-500">Status: Unavailable</span>
                    )}
                    {feed.status === 'Not Checked' && (
                      <span className="text-slate-500">Status: Not Checked</span>
                    )}
                  </div>
                </div>
              )
            )}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* EVIDENCE-BASED RISK SCORING LEDGER                                    */}
      {/* ===================================================================== */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h4 className="text-sm font-semibold text-white">
            Evidence-Based Risk Scoring Breakdown
          </h4>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            Total Risk Score: {riskScore}/100
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 pr-4 font-medium">Category & Indicator</th>
                <th className="py-2.5 px-4 font-medium">Observed Telemetry Value</th>
                <th className="py-2.5 px-4 font-medium">Signal Impact</th>
                <th className="py-2.5 pl-4 font-medium text-right">Score Weight</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {evidence.map((item, index) => {
                const impactMeta = getImpactIndicator(item.impact);
                return (
                  <tr key={index} className="hover:bg-slate-900/60 transition-colors">
                    <td className="py-3 pr-4 align-top">
                      <p className="font-medium text-white">{item.indicator}</p>
                      <p className="text-slate-400 text-[11px] mt-0.5">{item.details}</p>
                    </td>
                    <td className="py-3 px-4 align-top font-mono text-slate-300 break-all">
                      {item.value}
                    </td>
                    <td className="py-3 px-4 align-top whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        {impactMeta.icon}
                        <span className={impactMeta.textClass}>{impactMeta.label}</span>
                      </div>
                    </td>
                    <td className="py-3 pl-4 align-top text-right font-mono tabular-nums font-semibold">
                      <span
                        className={
                          item.scoreDelta > 0 ? 'text-amber-400' : 'text-slate-500'
                        }
                      >
                        {item.scoreDelta > 0 ? `+${item.scoreDelta}` : '0'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* LLM-POWERED EXPLANATION & SECURITY RECOMMENDATIONS                    */}
      {/* ===================================================================== */}
      {aiExplanation && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LLM Technical Explanation (7 cols) */}
          <div className="lg:col-span-7 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <h4 className="text-sm font-semibold text-white">
                  Gemini AI Threat Explanation
                </h4>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {aiExplanation.available ? 'Grounded in Live Scan Telemetry' : 'Unavailable'}
              </span>
            </div>

            <div className="space-y-3 text-sm text-slate-200 leading-relaxed">
              <p className="font-medium text-white">{aiExplanation.executiveSummary}</p>
              {aiExplanation.technicalAssessment &&
                aiExplanation.technicalAssessment !== 'Not Checked' &&
                aiExplanation.technicalAssessment !== 'Unavailable' && (
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {aiExplanation.technicalAssessment}
                  </p>
                )}
            </div>

            {Array.isArray(aiExplanation.keyFindings) && aiExplanation.keyFindings.length > 0 && (
              <div className="pt-3 border-t border-slate-800 space-y-2">
                <p className="text-xs font-semibold text-slate-300">Key Analytical Findings:</p>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {aiExplanation.keyFindings.map((finding, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <ArrowRight className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Actionable Security Recommendations (5 cols) */}
          <div className="lg:col-span-5 bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-sm font-semibold text-white">
                Security Recommendations
              </h4>
              <span className="text-xs text-slate-400">Defensive Playbook</span>
            </div>

            {Array.isArray(aiExplanation.recommendations) &&
            aiExplanation.recommendations.length > 0 ? (
              <div className="divide-y divide-slate-800">
                {aiExplanation.recommendations.map((rec, idx) => (
                  <div key={idx} className="py-3 first:pt-0 last:pb-0 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-white">{rec.action}</span>
                      <span
                        className={`font-mono text-[11px] font-medium ${
                          rec.priority === 'Immediate'
                            ? 'text-rose-400'
                            : rec.priority === 'High'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                        }`}
                      >
                        Priority: {rec.priority}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{rec.rationale}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-2 text-xs text-slate-400">
                <p>1. Do not enter credentials or MFA codes on untrusted or unverified domains.</p>
                <p>2. Verify sender domain alignment (SPF/DKIM/DMARC) before opening attachments.</p>
                <p>3. Block high-risk IPs or newly registered typosquatted domains at your DNS firewall.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SCAN ACCURACY FEEDBACK & FALSE POSITIVE REPORTING                     */}
      {/* ===================================================================== */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Scan Accuracy & Analyst Feedback
            </h5>
            <p className="text-xs text-slate-400 mt-0.5">
              Help calibrate the Phishing Shield threat intelligence engine. Did our assessment match your investigation?
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={async () => {
                try {
                  const token = await auth.currentUser?.getIdToken();
                  await fetch('/api/feedback', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      ...(token ? { Authorization: `Bearer ${token}` } : {}),
                    },
                    body: JSON.stringify({
                      scanId: scanId || 'live-scan',
                      scanType,
                      target,
                      feedbackType: 'accurate',
                      comment: 'Confirmed accurate classification.',
                    }),
                  });
                  alert('Thank you! Confirmed scan accuracy recorded.');
                } catch {
                  // silent
                }
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 text-slate-200 hover:bg-emerald-950/40 hover:border-emerald-600 hover:text-emerald-300 transition"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Accurate
            </button>
            <button
              type="button"
              onClick={async () => {
                const comment = prompt('Optional: Describe why this was a false positive (benign classified as threat):');
                if (comment === null) return;
                try {
                  const token = await auth.currentUser?.getIdToken();
                  await fetch('/api/feedback', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      ...(token ? { Authorization: `Bearer ${token}` } : {}),
                    },
                    body: JSON.stringify({
                      scanId: scanId || 'live-scan',
                      scanType,
                      target,
                      feedbackType: 'false_positive',
                      comment: comment || 'Reported as false positive',
                    }),
                  });
                  alert('Thank you! False positive report queued for review.');
                } catch {
                  // silent
                }
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 text-slate-200 hover:bg-amber-950/40 hover:border-amber-600 hover:text-amber-300 transition"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Possible False Positive
            </button>
            <button
              type="button"
              onClick={async () => {
                const comment = prompt('Optional: Describe why this was a false negative (missed threat):');
                if (comment === null) return;
                try {
                  const token = await auth.currentUser?.getIdToken();
                  await fetch('/api/feedback', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      ...(token ? { Authorization: `Bearer ${token}` } : {}),
                    },
                    body: JSON.stringify({
                      scanId: scanId || 'live-scan',
                      scanType,
                      target,
                      feedbackType: 'false_negative',
                      comment: comment || 'Reported as missed threat',
                    }),
                  });
                  alert('Thank you! False negative report queued for threat feed update.');
                } catch {
                  // silent
                }
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 text-slate-200 hover:bg-rose-950/40 hover:border-rose-600 hover:text-rose-300 transition"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Possible False Negative
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
