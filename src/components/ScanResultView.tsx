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
} from 'lucide-react';
import { AllowedScanType, AllowedVerdictType } from '../lib/firebase';

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

interface ScanResultViewProps {
  scanType: AllowedScanType;
  target: string;
  scanId?: string | null;
  data: Record<string, any>;
  onCreateReport?: (params: {
    scanId: string;
    scanType: AllowedScanType;
    target: string;
    riskScore: number;
    verdict: AllowedVerdictType;
    defaultNotes: string;
  }) => Promise<void>;
  onAskGeminiAboutScan?: (contextPrompt: string) => void;
}

export const ScanResultView: React.FC<ScanResultViewProps> = ({
  scanType,
  target,
  scanId,
  data,
  onCreateReport,
  onAskGeminiAboutScan,
}) => {
  const [creatingReport, setCreatingReport] = useState(false);
  const [reportCreated, setReportCreated] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);
  const [ocrExpanded, setOcrExpanded] = useState(true);

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
    <div className="space-y-6">
      {/* Top Executive Verdict Header */}
      <div className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
              <span>{scanType.toUpperCase()} INSPECTION</span>
              <span aria-hidden="true">·</span>
              <span>{data.scannedAt ? new Date(data.scannedAt).toLocaleString() : 'Live'}</span>
              {scanId && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>ID: {scanId.slice(0, 18)}</span>
                </>
              )}
            </div>

            <h3 className="text-lg sm:text-xl font-bold text-slate-900 break-all font-mono">
              {target}
            </h3>

            <div className="flex items-center gap-3 pt-1">
              {riskScore >= 50 ? (
                <ShieldAlert className="w-5 h-5 text-red-600 shrink-0" />
              ) : riskScore >= 25 ? (
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
              ) : (
                <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0" />
              )}
              <span className={`text-sm font-semibold ${getVerdictColor(verdict)}`}>
                Verdict: {verdict}
              </span>
              <span className="text-slate-300" aria-hidden="true">
                ·
              </span>
              <span className="text-xs text-slate-600">
                {evidence.filter((e) => e.scoreDelta > 0).length} risk indicator(s) triggered out of{' '}
                {evidence.length} total checks
              </span>
            </div>
          </div>

          {/* Right: Numerical Score & Save Report / Ask Gemini Actions */}
          <div className="flex flex-wrap items-center gap-4 shrink-0 border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-200">
            <div className="text-left lg:text-right pr-2">
              <p className="text-xs text-slate-500">Evidence Risk Score</p>
              <p
                className={`text-3xl font-bold font-mono tabular-nums ${getVerdictColor(verdict)}`}
              >
                {riskScore}
                <span className="text-base text-slate-400 font-normal"> / 100</span>
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={handleCopyReportText}
                className="px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedReport ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-emerald-700">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-500" />
                    <span>Copy Report</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadJsonReport}
                className="px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-slate-500" />
                <span>Download JSON</span>
              </button>

              {onAskGeminiAboutScan && (
                <button
                  type="button"
                  onClick={handleAskGemini}
                  className="px-4 py-2.5 text-xs font-semibold rounded-md bg-emerald-600 hover:bg-emerald-700 text-white transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer"
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
                  className="px-4 py-2.5 text-xs font-semibold rounded-md bg-slate-900 hover:bg-slate-800 text-white disabled:opacity-60 transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer"
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

        {/* Visual Risk Score Meter Bar */}
        <div className="mt-5 pt-4 border-t border-slate-100 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
            <span>0 — LOW RISK</span>
            <span>21–50 — MEDIUM RISK</span>
            <span>51–75 — HIGH RISK</span>
            <span>76–100 — CRITICAL RISK</span>
          </div>
          <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                riskScore >= 76
                  ? 'bg-red-600'
                  : riskScore >= 51
                    ? 'bg-orange-600'
                    : riskScore >= 21
                      ? 'bg-amber-500'
                      : 'bg-emerald-600'
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
            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <div className="flex items-center gap-2">
                  <Eye className="w-4 h-4 text-emerald-600" />
                  <h4 className="text-sm font-semibold text-slate-900">
                    01. Extracted Text (OCR Forensics)
                  </h4>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-500">
                    {data.ocr?.status || 'Evaluated'} · {data.ocr?.characterCount || 0} chars
                  </span>
                  <button
                    type="button"
                    onClick={() => setOcrExpanded((prev) => !prev)}
                    className="text-xs font-medium text-emerald-700 hover:text-emerald-800 flex items-center gap-1 cursor-pointer"
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
                <div className="p-3 rounded-md bg-amber-50 border border-amber-200 flex items-start gap-2 text-xs text-amber-800">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <span>{data.ocr.lowClarityNotice}</span>
                </div>
              )}

              {ocrExpanded && (
                <div className="bg-slate-50 border border-slate-200 rounded-md p-4 max-h-64 overflow-y-auto">
                  {data.ocr?.extractedText ? (
                    <pre className="text-xs font-mono text-slate-800 whitespace-pre-wrap break-words leading-relaxed">
                      {data.ocr.extractedText}
                    </pre>
                  ) : (
                    <p className="text-xs text-slate-500 font-mono">
                      No readable text was detected in this screenshot.
                    </p>
                  )}
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                <span>OCR Engine: {data.ocr?.engine || 'Multimodal OCR'}</span>
                <span>Lines Extracted: {data.ocr?.lineCount || 0}</span>
              </div>
            </div>

            {/* Extracted Entities & QR Code Detection (5 cols) */}
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <div className="flex items-center gap-2">
                  <QrCode className="w-4 h-4 text-emerald-600" />
                  <h4 className="text-sm font-semibold text-slate-900">
                    02. QR Code & Extracted Entities
                  </h4>
                </div>
                <span
                  className={`text-xs font-mono font-semibold ${
                    data.qrCode?.detected ? 'text-amber-600' : 'text-slate-500'
                  }`}
                >
                  QR: {data.qrCode?.detected ? 'Detected' : 'None Detected'}
                </span>
              </div>

              <div className="p-3.5 rounded-md bg-slate-50 border border-slate-200 space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-900">QR Code Matrix Scan:</span>
                  <span className="font-mono text-slate-700">
                    {data.qrCode?.payloadType || 'None'}
                  </span>
                </div>
                {data.qrCode?.detected && data.qrCode?.decodedContent && (
                  <p className="font-mono text-emerald-700 break-all bg-white p-2 rounded border border-slate-200">
                    Decoded: {data.qrCode.decodedContent}
                  </p>
                )}
                <p className="text-slate-600 leading-relaxed">{data.qrCode?.riskSummary}</p>
              </div>

              <dl className="space-y-2.5 text-xs pt-1">
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">Extracted URLs</dt>
                  <dd className="font-mono text-emerald-700 text-right break-all">
                    {data.ocr?.extractedUrls?.length > 0
                      ? data.ocr.extractedUrls.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">Extracted Domains</dt>
                  <dd className="font-mono text-slate-900 text-right break-all">
                    {data.ocr?.extractedDomains?.length > 0
                      ? data.ocr.extractedDomains.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">Email Addresses</dt>
                  <dd className="font-mono text-slate-800 text-right break-all">
                    {data.ocr?.extractedEmails?.length > 0
                      ? data.ocr.extractedEmails.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 gap-1">
                  <dt className="text-slate-500 shrink-0">Phone Numbers</dt>
                  <dd className="font-mono text-slate-800 text-right break-all">
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
            <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  03. Visual UI & Brand Impersonation Analysis
                </h4>
                <span className="text-xs font-mono text-emerald-700 font-semibold">
                  {data.visualInspection?.screenshotCategory || 'Inspected'}
                </span>
              </div>

              {/* Brand Impersonation Banner */}
              <div
                className={`p-3.5 rounded-md border text-xs space-y-1 ${
                  data.brandImpersonation?.brandDomainMismatch
                    ? 'bg-red-50 border-red-200 text-red-900'
                    : data.brandImpersonation?.detectedBrand
                      ? 'bg-amber-50 border-amber-200 text-amber-900'
                      : 'bg-slate-50 border-slate-200 text-slate-700'
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
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">Sign-In / Login Form</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsLoginForm
                        ? 'text-amber-600'
                        : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsLoginForm ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">Password Input</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsPasswordInput
                        ? 'text-red-600'
                        : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsPasswordInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">OTP / 2FA Request</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsOtpInput ? 'text-red-600' : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsOtpInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">Payment / Card UI</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsPaymentCardInput
                        ? 'text-red-600'
                        : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsPaymentCardInput ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">Urgency Banner</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsUrgencyBanner
                        ? 'text-amber-600'
                        : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsUrgencyBanner ? 'Detected' : 'Not Present'}
                  </p>
                </div>
                <div className="p-2.5 rounded border border-slate-200 bg-slate-50">
                  <p className="text-slate-500">Download Prompt</p>
                  <p
                    className={`font-mono font-semibold mt-0.5 ${
                      data.visualInspection?.containsDownloadPrompt
                        ? 'text-red-600'
                        : 'text-slate-700'
                    }`}
                  >
                    {data.visualInspection?.containsDownloadPrompt ? 'Detected' : 'Not Present'}
                  </p>
                </div>
              </div>

              {Array.isArray(data.visualInspection?.visualIndicators) &&
                data.visualInspection.visualIndicators.length > 0 && (
                  <div className="pt-2 border-t border-slate-200 space-y-1.5 text-xs">
                    <p className="font-semibold text-slate-800">Observed Visual Cues:</p>
                    <ul className="space-y-1 text-slate-600">
                      {data.visualInspection.visualIndicators.map((ind: string, i: number) => (
                        <li key={i} className="flex items-start gap-2">
                          <ArrowRight className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                          <span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
            </div>

            {/* 04. Social Engineering & Scam Pattern Detection + Image Metadata (6 cols) */}
            <div className="lg:col-span-6 space-y-6">
              <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                  <h4 className="text-sm font-semibold text-slate-900">
                    04. Social Engineering & Scam Pattern Analysis
                  </h4>
                  <span className="text-xs font-mono font-semibold text-slate-700 tabular-nums">
                    Manipulation Score: {data.socialEngineering?.manipulationScore || 0}/100
                  </span>
                </div>

                {data.socialEngineering?.detectedScamPatterns?.length > 0 ? (
                  <div className="p-3 rounded-md bg-red-50 border border-red-200 space-y-1 text-xs">
                    <p className="font-semibold text-red-900">Matched Scam Signatures:</p>
                    <p className="font-mono text-red-700">
                      {data.socialEngineering.detectedScamPatterns.join(' · ')}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-slate-600">
                    No high-confidence social engineering scam signatures matched.
                  </p>
                )}

                <dl className="space-y-2 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                    <dt className="text-slate-500">Urgency / Time Pressure</dt>
                    <dd className="font-mono text-slate-800 text-right">
                      {data.socialEngineering?.urgencyIndicators?.length > 0
                        ? data.socialEngineering.urgencyIndicators.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                    <dt className="text-slate-500">Fear / Suspension Threats</dt>
                    <dd className="font-mono text-slate-800 text-right">
                      {data.socialEngineering?.fearOrThreatLanguage?.length > 0
                        ? data.socialEngineering.fearOrThreatLanguage.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                    <dt className="text-slate-500">Authority Impersonation</dt>
                    <dd className="font-mono text-slate-800 text-right">
                      {data.socialEngineering?.authorityImpersonation?.length > 0
                        ? data.socialEngineering.authorityImpersonation.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                    <dt className="text-slate-500">Credential / OTP Cues</dt>
                    <dd className="font-mono text-slate-800 text-right">
                      {data.socialEngineering?.credentialHarvestingRequests?.length > 0
                        ? data.socialEngineering.credentialHarvestingRequests.join(', ')
                        : 'None Detected'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-1.5 gap-2">
                    <dt className="text-slate-500">Financial / Reward Cues</dt>
                    <dd className="font-mono text-slate-800 text-right">
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
                <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                    <div className="flex items-center gap-2">
                      <ImageIcon className="w-4 h-4 text-slate-500" />
                      <h4 className="text-sm font-semibold text-slate-900">
                        05. Image & EXIF Metadata Forensics
                      </h4>
                    </div>
                    <span className="text-xs font-mono text-slate-500">
                      {data.metadata.format} · {data.metadata.formattedFileSize}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                    <div>
                      <p className="text-slate-500">Dimensions</p>
                      <p className="font-mono font-medium text-slate-900 mt-0.5">
                        {data.metadata.dimensions}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">Color Profile</p>
                      <p className="font-mono font-medium text-slate-900 mt-0.5">
                        {data.metadata.colorSpace} ({data.metadata.channels}ch)
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">EXIF Software</p>
                      <p className="font-mono font-medium text-slate-900 mt-0.5 truncate">
                        {data.metadata.exifSoftware}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">EXIF Device</p>
                      <p className="font-mono text-slate-800 mt-0.5 truncate">
                        {data.metadata.exifDeviceMakeModel}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">EXIF Timestamp</p>
                      <p className="font-mono text-slate-800 mt-0.5">{data.metadata.exifDateTime}</p>
                    </div>
                    <div>
                      <p className="text-slate-500">Confidence</p>
                      <p className="font-mono text-emerald-700 font-semibold mt-0.5">
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
            <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-emerald-600" />
                  <h4 className="text-sm font-semibold text-slate-900">
                    06. Automated URL, Domain, DNS & RDAP Pipeline (Extracted from Screenshot)
                  </h4>
                </div>
                <span className="text-xs font-mono text-slate-500">
                  {data.urlAnalyses.length} URL(s) Analyzed Live
                </span>
              </div>

              <div className="space-y-4">
                {data.urlAnalyses.map((u: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg border border-slate-200 bg-slate-50 space-y-3 text-xs"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-2.5">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-800 font-mono text-[10px] font-semibold">
                            Source: {u.source}
                          </span>
                          <span className="font-mono font-bold text-slate-900 break-all">
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
                      <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-800 font-medium flex items-start gap-2">
                        <ShieldAlert className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                        <span>{u.brandMismatchWithVisual}</span>
                      </div>
                    )}

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div>
                        <p className="text-slate-500">Registered Domain</p>
                        <p className="font-mono font-semibold text-slate-900 mt-0.5">
                          {u.registeredDomain} (.{u.tld})
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-500">HTTPS & Transport</p>
                        <p className="font-mono font-medium text-slate-900 mt-0.5">
                          {u.usesHttps ? 'HTTPS (Encrypted)' : 'HTTP (Unencrypted)'}
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-500">RDAP Domain Age</p>
                        <p className="font-mono font-semibold text-emerald-700 mt-0.5">
                          {u.domainAge || 'Unavailable'}
                        </p>
                      </div>
                      <div>
                        <p className="text-slate-500">Resolved Public IP</p>
                        <p className="font-mono font-medium text-slate-900 mt-0.5">
                          {u.resolvedIp} ({u.ipCountry})
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-200 text-[11px] text-slate-600 font-mono">
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
          <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h4 className="text-sm font-semibold text-slate-900">
                01. Domain → DNS → Public IP Resolution Chain
              </h4>
              <span className="text-xs text-slate-500 font-mono">
                Live Infrastructure Resolution
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center pt-2">
              <div className="space-y-1">
                <p className="text-xs text-slate-500">Submitted Hostname</p>
                <p className="text-sm font-mono font-semibold text-slate-900 break-all">
                  {data.domainAnalysis.hostname}
                </p>
                <p className="text-xs text-slate-500">
                  Subdomain: {data.domainAnalysis.subdomain} ({data.domainAnalysis.subdomainCount})
                </p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-200 md:pl-4">
                <p className="text-xs text-slate-500">Extracted Registered Domain</p>
                <p className="text-sm font-mono font-semibold text-emerald-700 break-all">
                  {data.domainAnalysis.registeredDomain}
                </p>
                <p className="text-xs text-slate-500">TLD: .{data.domainAnalysis.tld}</p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-200 md:pl-4">
                <p className="text-xs text-slate-500">DNS Resolution</p>
                <p className="text-sm font-mono font-semibold text-slate-900">
                  {data.dnsAnalysis?.resolvable ? 'Resolved (Active)' : 'NXDOMAIN / Unresolvable'}
                </p>
                <p className="text-xs text-slate-500 font-mono tabular-nums">
                  {data.dnsAnalysis?.nsRecords?.length || 0} NS ·{' '}
                  {data.dnsAnalysis?.mxRecords?.length || 0} MX records
                </p>
              </div>

              <div className="space-y-1 md:border-l md:border-slate-200 md:pl-4">
                <p className="text-xs text-slate-500">Associated Public IP</p>
                <p className="text-sm font-mono font-semibold text-slate-900 tabular-nums">
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
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  02. Domain Age & RDAP Registration
                </h4>
                <Globe className="w-4 h-4 text-slate-500" />
              </div>

              <dl className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">Domain Created</dt>
                  <dd className="font-mono text-slate-900 tabular-nums">
                    {data.domainAnalysis.rdap?.creationDate || 'Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">Current Date</dt>
                  <dd className="font-mono text-slate-700 tabular-nums">
                    {data.domainAnalysis.rdap?.currentDate ||
                      new Date().toISOString().split('T')[0]}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-600 font-medium">Calculated Domain Age</dt>
                  <dd className="font-mono font-semibold text-emerald-700 tabular-nums">
                    {data.domainAnalysis.rdap?.formattedAge &&
                    data.domainAnalysis.rdap.formattedAge !== 'Unavailable'
                      ? data.domainAnalysis.rdap.formattedAge
                      : 'Domain age: Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <dt className="text-slate-500">Registry Expiration</dt>
                  <dd className="font-mono text-slate-700 tabular-nums">
                    {data.domainAnalysis.rdap?.expirationDate || 'Unavailable'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100 gap-4">
                  <dt className="text-slate-500 shrink-0">Registrar</dt>
                  <dd className="font-mono text-slate-800 text-right truncate">
                    {data.domainAnalysis.rdap?.registrar || 'Unavailable'}
                  </dd>
                </div>
              </dl>

              <p className="text-[11px] text-slate-500 leading-relaxed pt-1">
                Policy Note: Domain age is evaluated strictly as a contextual evidence indicator and
                never classifies a website as malicious on its own.
              </p>
            </div>

            {/* URL Syntax, TLS & Lexical Inspection (7 cols) */}
            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  03. URL Syntax, Lexical & Transport Inspection
                </h4>
                {data.syntax?.usesHttps ? (
                  <Lock className="w-4 h-4 text-emerald-600" />
                ) : (
                  <Unlock className="w-4 h-4 text-amber-600" />
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div className="space-y-1">
                  <p className="text-slate-500">Transport Protocol</p>
                  <p className="font-mono font-medium text-slate-900">
                    {data.syntax?.protocol} (Port {data.syntax?.port})
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-500">URL / Host Length</p>
                  <p className="font-mono font-medium text-slate-900 tabular-nums">
                    {data.syntax?.urlLength} chars / {data.syntax?.hostnameLength} host
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-500">Host / Path Entropy</p>
                  <p className="font-mono font-medium text-slate-900 tabular-nums">
                    {data.syntax?.hostEntropy} / {data.syntax?.pathEntropy} bits
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-500">IP Literal Hostname</p>
                  <p className="font-mono font-medium text-slate-900">
                    {data.syntax?.isIpHostname ? 'Yes (Raw IP)' : 'No (Domain Name)'}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-500">URL Shortener</p>
                  <p className="font-mono font-medium text-slate-900">
                    {data.syntax?.isUrlShortener ? 'Detected' : 'Not a Shortener'}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-slate-500">Punycode / IDN</p>
                  <p className="font-mono font-medium text-slate-900">
                    {data.syntax?.isPunycode
                      ? `Yes (${data.syntax.unicodeHostname})`
                      : 'ASCII Standard'}
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-200 space-y-2 text-xs">
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-500">TLS X.509 Certificate:</span>
                  <span className="font-mono text-slate-800">
                    {data.tlsInspection?.available
                      ? `Issuer: ${data.tlsInspection.issuer} · Valid until ${data.tlsInspection.validTo} (${data.tlsInspection.daysRemaining}d remaining)`
                      : data.tlsInspection?.reason || 'Unavailable'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-500">Suspicious Keywords:</span>
                  <span className="font-mono text-slate-800">
                    {data.syntax?.suspiciousKeywords?.length > 0
                      ? data.syntax.suspiciousKeywords.join(', ')
                      : 'None Detected'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-500">Homograph / Brand Indicators:</span>
                  <span className="font-mono text-slate-800">
                    {data.syntax?.homographIndicators?.length > 0
                      ? data.syntax.homographIndicators.join('; ')
                      : 'None Detected'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1">
                  <span className="text-slate-500">Redirect Chain Behavior:</span>
                  <span className="font-mono text-slate-800">
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
            <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">04. Live DNS Zone Records</h4>
                <Server className="w-4 h-4 text-slate-500" />
              </div>

              <dl className="space-y-2.5 text-xs">
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">A Records (IPv4)</dt>
                  <dd className="font-mono text-slate-900 text-right break-all tabular-nums">
                    {data.dnsAnalysis?.aRecords?.length > 0
                      ? data.dnsAnalysis.aRecords.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">AAAA Records (IPv6)</dt>
                  <dd className="font-mono text-slate-700 text-right break-all tabular-nums">
                    {data.dnsAnalysis?.aaaaRecords?.length > 0
                      ? data.dnsAnalysis.aaaaRecords.slice(0, 2).join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">Nameservers (NS)</dt>
                  <dd className="font-mono text-slate-800 text-right break-all">
                    {data.dnsAnalysis?.nsRecords?.length > 0
                      ? data.dnsAnalysis.nsRecords.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">Mail Exchange (MX)</dt>
                  <dd className="font-mono text-slate-800 text-right break-all">
                    {data.dnsAnalysis?.mxRecords?.length > 0
                      ? data.dnsAnalysis.mxRecords.slice(0, 3).join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 border-b border-slate-100 gap-1">
                  <dt className="text-slate-500 shrink-0">SPF Policy</dt>
                  <dd className="font-mono text-slate-700 text-right break-all">
                    {data.dnsAnalysis?.spfRecord || 'Not Present'}
                  </dd>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between py-1.5 gap-1">
                  <dt className="text-slate-500 shrink-0">DMARC Policy</dt>
                  <dd className="font-mono text-slate-700 text-right break-all">
                    {data.dnsAnalysis?.dmarcRecord || 'Not Present'}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Resolved Public IP Reputation & ML Features (6 cols) */}
            <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  05. Resolved IP Reputation & ML Classifier
                </h4>
                <Cpu className="w-4 h-4 text-slate-500" />
              </div>

              {data.ipAnalysis ? (
                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3 pb-3 border-b border-slate-200">
                    <div>
                      <p className="text-slate-500">Resolved Public IP</p>
                      <p className="font-mono font-semibold text-slate-900 tabular-nums mt-0.5">
                        {data.ipAnalysis.ip} ({data.ipAnalysis.classification})
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">ASN & ISP</p>
                      <p className="font-mono text-slate-800 mt-0.5 truncate">
                        {data.ipAnalysis.asn} · {data.ipAnalysis.organization}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">Geolocation</p>
                      <p className="font-mono text-slate-800 mt-0.5">
                        {data.ipAnalysis.country} ({data.ipAnalysis.region})
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">Reverse DNS (PTR)</p>
                      <p className="font-mono text-slate-800 mt-0.5 truncate">
                        {data.ipAnalysis.reverseDns?.length > 0
                          ? data.ipAnalysis.reverseDns[0]
                          : 'Unconfigured'}
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500">
                  IP Reputation: Unavailable (domain did not resolve to a public A/AAAA IP).
                </p>
              )}

              {/* ML Phishing Feature Breakdown */}
              {data.mlDetection && (
                <div className="space-y-2.5 pt-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-700 font-medium">
                      ML Phishing Classifier Probability
                    </span>
                    <span className="font-mono font-semibold text-slate-900 tabular-nums">
                      {data.mlDetection.phishingProbability}% ({data.mlDetection.classifierVerdict})
                    </span>
                  </div>
                  <div className="space-y-2 pt-1">
                    {data.mlDetection.features?.map((f: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between text-xs text-slate-600"
                      >
                        <span>{f.feature}</span>
                        <span className="font-mono text-slate-800 tabular-nums">
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
            <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  01. NLP Social Engineering & Intent Analysis
                </h4>
                <span className="text-xs font-mono text-emerald-700 font-semibold">
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
                          <span className="text-slate-700">{labelMap[key] || key}</span>
                          <span className="font-mono text-slate-900 font-medium tabular-nums">
                            {scoreNum}/100
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-100 rounded overflow-hidden">
                          <div
                            className={`h-full ${
                              scoreNum >= 70
                                ? 'bg-red-600'
                                : scoreNum >= 35
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-600'
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
                <div className="pt-3 border-t border-slate-200 space-y-2 text-xs">
                  <p className="font-medium text-slate-800">Matched Linguistic Triggers:</p>
                  {data.nlpSignals.map((sig: any, idx: number) => (
                    <div key={idx} className="text-slate-600">
                      <span className="text-slate-900 font-medium">{sig.category}: </span>
                      <span className="font-mono text-[11px]">
                        {sig.matchedPhrases.join(', ')}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Extracted Entities, Headers & Live URL Scan (6 cols) */}
            <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <h4 className="text-sm font-semibold text-slate-900">
                  02. Extracted Entities & Header Verification
                </h4>
                <span className="text-xs font-mono text-slate-500 tabular-nums">
                  {data.wordCount || 0} words
                </span>
              </div>

              <dl className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                  <dt className="text-slate-500">Declared Sender</dt>
                  <dd className="font-mono text-slate-900 text-right break-all">
                    {data.senderInput || 'Not Provided'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                  <dt className="text-slate-500">Header Auth (SPF / DKIM / DMARC)</dt>
                  <dd className="font-mono text-slate-800 text-right">
                    {data.headerAnalysis?.provided
                      ? `${data.headerAnalysis.spfStatus} / ${data.headerAnalysis.dkimStatus} / ${data.headerAnalysis.dmarcStatus}`
                      : 'Not Checked (No Headers Provided)'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                  <dt className="text-slate-500">Extracted URLs</dt>
                  <dd className="font-mono text-emerald-700 text-right break-all">
                    {data.extractedEntities?.urls?.length > 0
                      ? data.extractedEntities.urls.join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100 gap-2">
                  <dt className="text-slate-500">Extracted Emails / Phones</dt>
                  <dd className="font-mono text-slate-700 text-right break-all">
                    {[
                      ...(data.extractedEntities?.emails || []),
                      ...(data.extractedEntities?.phoneNumbers || []),
                    ].join(', ') || 'None'}
                  </dd>
                </div>
              </dl>

              {data.embeddedUrlScan && (
                <div className="pt-3 border-t border-slate-200 space-y-1.5 text-xs">
                  <p className="font-semibold text-slate-900">
                    Automated Deep Scan of Embedded URL ({data.embeddedUrlScan.url}):
                  </p>
                  <p className="text-slate-700 font-mono">
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
          <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h4 className="text-sm font-semibold text-slate-900">
                01. Network Routing, ASN & Geolocation
              </h4>
              <span className="text-xs font-mono text-emerald-700 font-semibold">
                {data.classification}
              </span>
            </div>

            <dl className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <dt className="text-slate-500">IP Address & Version</dt>
                <dd className="font-mono text-slate-900 tabular-nums">
                  {data.ip} ({data.ipVersion})
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <dt className="text-slate-500">Autonomous System (ASN)</dt>
                <dd className="font-mono text-slate-900">{data.asn}</dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <dt className="text-slate-500">Organization / ISP</dt>
                <dd className="font-mono text-slate-800 text-right">
                  {data.organization} ({data.isp})
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <dt className="text-slate-500">Country / Region / City</dt>
                <dd className="font-mono text-slate-800">
                  {data.country} · {data.region} · {data.city}
                </dd>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <dt className="text-slate-500">Reverse DNS (PTR)</dt>
                <dd className="font-mono text-slate-800 break-all">
                  {data.reverseDns?.length > 0 ? data.reverseDns.join(', ') : 'None'}
                </dd>
              </div>
              <div className="flex justify-between py-1.5">
                <dt className="text-slate-500">Proxy / Datacenter Flags</dt>
                <dd className="font-mono text-slate-800">
                  Proxy/VPN: {String(data.isProxyOrVpn)} · Hosting:{' '}
                  {String(data.isHostingOrDatacenter)}
                </dd>
              </div>
            </dl>
          </div>

          <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h4 className="text-sm font-semibold text-slate-900">
                02. RDAP Registry Block & Live DNSBL Matrix
              </h4>
              <Server className="w-4 h-4 text-slate-500" />
            </div>

            <dl className="space-y-2 text-xs pb-3 border-b border-slate-200">
              <div className="flex justify-between">
                <dt className="text-slate-500">RDAP Network Name & CIDR</dt>
                <dd className="font-mono text-slate-900 tabular-nums">
                  {data.rdapNetwork?.networkName} ({data.rdapNetwork?.cidr})
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">RDAP Registration Date</dt>
                <dd className="font-mono text-slate-700 tabular-nums">
                  {data.rdapNetwork?.registrationDate || 'Unavailable'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Abuse Contact</dt>
                <dd className="font-mono text-slate-700">
                  {data.rdapNetwork?.abuseContact || 'Unavailable'}
                </dd>
              </div>
            </dl>

            <div className="space-y-2 text-xs">
              <p className="text-slate-600 font-medium">
                Real-Time DNS Blackhole List (DNSBL) Queries:
              </p>
              {Array.isArray(data.dnsblResults) && data.dnsblResults.length > 0 ? (
                data.dnsblResults.map((d: any, i: number) => (
                  <div key={i} className="flex items-center justify-between py-1">
                    <span className="text-slate-700">
                      {d.provider} <span className="text-slate-400 font-mono">({d.zone})</span>
                    </span>
                    <span
                      className={`font-mono font-semibold ${
                        d.status === 'Listed'
                          ? 'text-red-600'
                          : d.status === 'Clean'
                            ? 'text-emerald-600'
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
        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <h4 className="text-sm font-semibold text-slate-900">
              Threat Intelligence & External Reputation Sources
            </h4>
            <span className="text-xs text-slate-500">
              Unconfigured APIs explicitly display Not Checked
            </span>
          </div>

          <div className="divide-y divide-slate-200 text-xs">
            {(data.threatIntelligence || data.externalThreatFeeds || []).map(
              (feed: any, idx: number) => (
                <div
                  key={idx}
                  className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="space-y-0.5">
                    <p className="font-medium text-slate-900">{feed.source}</p>
                    <p className="text-slate-600">{feed.details}</p>
                  </div>
                  <div className="font-mono font-semibold shrink-0">
                    {feed.status === 'Clean' && (
                      <span className="text-emerald-700">Status: Clean</span>
                    )}
                    {feed.status === 'Flagged' && (
                      <span className="text-red-600">Status: Flagged</span>
                    )}
                    {feed.status === 'Unavailable' && (
                      <span className="text-slate-500">Status: Unavailable</span>
                    )}
                    {feed.status === 'Not Checked' && (
                      <span className="text-slate-400">Status: Not Checked</span>
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
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-200 pb-3">
          <h4 className="text-sm font-semibold text-slate-900">
            Evidence-Based Risk Scoring Breakdown
          </h4>
          <span className="text-xs font-mono text-slate-600 tabular-nums">
            Total Risk Score: {riskScore}/100
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500">
                <th className="py-2.5 pr-4 font-medium">Category & Indicator</th>
                <th className="py-2.5 px-4 font-medium">Observed Telemetry Value</th>
                <th className="py-2.5 px-4 font-medium">Signal Impact</th>
                <th className="py-2.5 pl-4 font-medium text-right">Score Weight</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {evidence.map((item, index) => {
                const impactMeta = getImpactIndicator(item.impact);
                return (
                  <tr key={index} className="hover:bg-slate-50 transition-colors">
                    <td className="py-3 pr-4 align-top">
                      <p className="font-medium text-slate-900">{item.indicator}</p>
                      <p className="text-slate-500 text-[11px] mt-0.5">{item.details}</p>
                    </td>
                    <td className="py-3 px-4 align-top font-mono text-slate-800 break-all">
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
                          item.scoreDelta > 0 ? 'text-amber-600' : 'text-slate-400'
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
          <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-600" />
                <h4 className="text-sm font-semibold text-slate-900">
                  Gemini AI Threat Explanation
                </h4>
              </div>
              <span className="text-xs font-mono text-slate-500">
                {aiExplanation.available ? 'Grounded in Live Scan Telemetry' : 'Unavailable'}
              </span>
            </div>

            <div className="space-y-3 text-sm text-slate-800 leading-relaxed">
              <p className="font-medium text-slate-900">{aiExplanation.executiveSummary}</p>
              {aiExplanation.technicalAssessment &&
                aiExplanation.technicalAssessment !== 'Not Checked' &&
                aiExplanation.technicalAssessment !== 'Unavailable' && (
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {aiExplanation.technicalAssessment}
                  </p>
                )}
            </div>

            {Array.isArray(aiExplanation.keyFindings) && aiExplanation.keyFindings.length > 0 && (
              <div className="pt-3 border-t border-slate-200 space-y-2">
                <p className="text-xs font-semibold text-slate-800">Key Analytical Findings:</p>
                <ul className="space-y-1.5 text-xs text-slate-700">
                  {aiExplanation.keyFindings.map((finding, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <ArrowRight className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Actionable Security Recommendations (5 cols) */}
          <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h4 className="text-sm font-semibold text-slate-900">
                Security Recommendations
              </h4>
              <span className="text-xs text-slate-500">Defensive Playbook</span>
            </div>

            {Array.isArray(aiExplanation.recommendations) &&
            aiExplanation.recommendations.length > 0 ? (
              <div className="divide-y divide-slate-200">
                {aiExplanation.recommendations.map((rec, idx) => (
                  <div key={idx} className="py-3 first:pt-0 last:pb-0 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-900">{rec.action}</span>
                      <span
                        className={`font-mono text-[11px] font-medium ${
                          rec.priority === 'Immediate'
                            ? 'text-red-600'
                            : rec.priority === 'High'
                              ? 'text-amber-600'
                              : 'text-emerald-700'
                        }`}
                      >
                        Priority: {rec.priority}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">{rec.rationale}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-2 text-xs text-slate-600">
                <p>1. Do not enter credentials or MFA codes on untrusted or unverified domains.</p>
                <p>2. Verify sender domain alignment (SPF/DKIM/DMARC) before opening attachments.</p>
                <p>3. Block high-risk IPs or newly registered typosquatted domains at your DNS firewall.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
