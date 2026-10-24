import React, { useState, useRef } from 'react';
import {
  Upload,
  Image as ImageIcon,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  FileText,
  ExternalLink,
  ShieldAlert,
  Search,
  RefreshCw,
  QrCode,
  Eye,
} from 'lucide-react';
import { auth, type ScanRecordDoc, type AllowedScanType, type AllowedVerdictType } from '../lib/firebase';
import { ScanResultView } from './ScanResultView';

interface ScreenshotScannerWorkspaceProps {
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

export const ScreenshotScannerWorkspace: React.FC<ScreenshotScannerWorkspaceProps> = ({
  onScanComplete,
  onAskGeminiAboutScan,
  onStartVoiceTriage,
  onCreateReport,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (file: File) => {
    const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      setErrorMsg('Unsupported file format. Please upload a PNG, JPG, or WEBP image.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg('Image file size exceeds the 10 MB limit.');
      return;
    }

    setErrorMsg(null);
    setSelectedFile(file);
    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('Please select a screenshot image to analyze.');
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);
    setResult(null);

    try {
      const token = await auth.currentUser?.getIdToken();
      const formData = new FormData();
      formData.append('image', selectedFile);

      const response = await fetch('/api/scan-screenshot', {
        method: 'POST',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: formData,
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error?.message || 'Screenshot analysis failed.');
      }

      const scanResult = {
        scanId: null,
        target: selectedFile.name,
        data,
      };

      setResult(scanResult);
      onScanComplete(scanResult);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Screenshot analysis error.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
            <ImageIcon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Screenshot & Image Threat Analyzer</h2>
            <p className="text-xs text-slate-400">
              Multimodal optical character recognition (OCR), visual brand impersonation detection, and hidden URL extraction
            </p>
          </div>
        </div>
      </div>

      {/* Upload Box */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
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
              accept="image/png,image/jpeg,image/webp"
              className="hidden"
            />

            {previewUrl ? (
              <div className="space-y-3">
                <img
                  src={previewUrl}
                  alt="Upload preview"
                  className="max-h-64 mx-auto rounded-lg shadow-sm border border-slate-700 object-contain"
                />
                <div className="text-xs text-slate-300 font-mono">
                  {selectedFile?.name} ({(selectedFile?.size ? selectedFile.size / 1024 : 0).toFixed(1)} KB)
                </div>
                <p className="text-[11px] text-slate-400">Click or drag a new image to replace</p>
              </div>
            ) : (
              <div className="space-y-2">
                <Upload className="w-10 h-10 text-slate-500 mx-auto" />
                <p className="text-sm font-semibold text-slate-200">
                  Drop screenshot here, or browse files
                </p>
                <p className="text-xs text-slate-400">
                  Supported formats: PNG, JPG, JPEG, WEBP (Max 10 MB)
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
              Safe processing: Images are analyzed securely in-memory without persistent public hosting.
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
                  Analyzing Vision & OCR...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-blue-200" />
                  Run Vision Analysis
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Result Display */}
      {result && (
        <ScanResultView
          scanType="screenshot"
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
