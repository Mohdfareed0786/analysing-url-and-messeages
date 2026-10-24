import React, { useState, useRef } from 'react';
import {
  QrCode,
  Upload,
  Camera,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  RefreshCw,
  Copy,
  Check,
  Globe,
  CreditCard,
  Wifi,
  Mail,
  FileText,
} from 'lucide-react';
import { auth, type AllowedScanType, type AllowedVerdictType } from '../lib/firebase';
import { ScanResultView } from './ScanResultView';

interface QrScannerWorkspaceProps {
  onScanComplete: (result: {
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  }) => void;
  onAskGeminiAboutScan?: (contextPrompt: string) => void;
  onStartVoiceTriage?: (topic: string) => void;
  onCreateReport?: (params: {
    scanId: string;
    scanType: AllowedScanType;
    target: string;
    riskScore: number;
    verdict: AllowedVerdictType;
    defaultNotes: string;
  }) => Promise<void>;
}

export const QrScannerWorkspace: React.FC<QrScannerWorkspaceProps> = ({
  onScanComplete,
  onAskGeminiAboutScan,
  onStartVoiceTriage,
  onCreateReport,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [result, setResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setErrorMsg('Please upload a valid image file containing a QR code.');
      return;
    }
    setErrorMsg(null);
    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('Please select a QR code image to analyze.');
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);
    setResult(null);

    try {
      const token = await auth.currentUser?.getIdToken();
      const formData = new FormData();
      formData.append('image', selectedFile);

      const response = await fetch('/api/scan-qr', {
        method: 'POST',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: formData,
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error?.message || 'Failed to scan QR code.');
      }

      const scanResult = {
        scanId: null,
        target: data.target || selectedFile.name,
        data,
      };

      setResult(scanResult);
      onScanComplete(scanResult);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'QR code analysis error.');
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
            <QrCode className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">QR Code Security Scanner (Quishing Defense)</h2>
            <p className="text-xs text-slate-400">
              Inspect QR codes safely without triggering redirects, app installations, or payment triggers
            </p>
          </div>
        </div>
      </div>

      {/* Upload Box */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition ${
              previewUrl
                ? 'border-blue-500/50 bg-blue-600/5'
                : 'border-slate-700 hover:border-blue-500 hover:bg-slate-900/60'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileChange(e.target.files[0]);
                }
              }}
              accept="image/*"
              className="hidden"
            />

            {previewUrl ? (
              <div className="space-y-3">
                <img
                  src={previewUrl}
                  alt="QR preview"
                  className="max-h-56 mx-auto rounded-lg shadow-sm border border-slate-700 object-contain"
                />
                <div className="text-xs text-slate-300 font-mono">
                  {selectedFile?.name}
                </div>
                <p className="text-[11px] text-slate-400">Click to choose a different QR image</p>
              </div>
            ) : (
              <div className="space-y-2">
                <QrCode className="w-10 h-10 text-slate-500 mx-auto" />
                <p className="text-sm font-semibold text-slate-200">
                  Upload QR Code image
                </p>
                <p className="text-xs text-slate-400">
                  Accepts PNG, JPG, JPEG, WEBP screenshots, photos, or digital flyers
                </p>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-slate-400">
              Zero Execution Policy: Destinations are analyzed statically. Links are never auto-opened.
            </span>
            <button
              type="submit"
              disabled={!selectedFile || isScanning}
              className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold text-white shadow-sm transition ${
                !selectedFile || isScanning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-blue-600 hover:bg-blue-500'
              }`}
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-blue-300" />
                  Decoding & Scanning Payload...
                </>
              ) : (
                <>
                  <QrCode className="w-4 h-4 text-blue-200" />
                  Decode & Inspect QR
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Decoded QR Details Banner */}
      {result && result.data?.decodedPayload && (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <div className="p-1 rounded bg-blue-600/20 text-blue-400 border border-blue-500/30">
                {result.data.payloadType === 'url' ? (
                  <Globe className="w-4 h-4" />
                ) : result.data.payloadType === 'upi' ? (
                  <CreditCard className="w-4 h-4" />
                ) : result.data.payloadType === 'wifi' ? (
                  <Wifi className="w-4 h-4" />
                ) : result.data.payloadType === 'email' ? (
                  <Mail className="w-4 h-4" />
                ) : (
                  <FileText className="w-4 h-4" />
                )}
              </div>
              <h3 className="text-xs font-bold uppercase text-slate-200 tracking-wider">
                Decoded QR Payload ({result.data.payloadType?.toUpperCase() || 'RAW'})
              </h3>
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(result.data.decodedPayload)}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-white cursor-pointer"
            >
              {copiedPayload ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedPayload ? 'Copied' : 'Copy Payload'}
            </button>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg font-mono text-xs text-emerald-400 break-all select-all">
            {result.data.decodedPayload}
          </div>
        </div>
      )}

      {/* Result View */}
      {result && (
        <ScanResultView
          scanType="qr"
          target={result.target}
          scanId={result.scanId}
          data={result.data}
          scanStatus="Live"
          onCreateReport={onCreateReport}
          onAskGeminiAboutScan={onAskGeminiAboutScan}
          onStartVoiceTriage={onStartVoiceTriage}
        />
      )}
    </div>
  );
};
