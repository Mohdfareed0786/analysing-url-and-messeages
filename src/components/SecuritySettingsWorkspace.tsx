import React, { useState, useEffect } from 'react';
import {
  Settings,
  Server,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Key,
  ShieldCheck,
  Lock,
  Trash2,
  Download,
  Info,
} from 'lucide-react';
import { auth } from '../lib/firebase';

interface ServiceStatus {
  id?: string;
  name: string;
  status: string;
  provider?: string;
  detail: string;
}

export const SecuritySettingsWorkspace: React.FC = () => {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchSystemStatus = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const token = await auth.currentUser?.getIdToken();
      const response = await fetch('/api/system-status', {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });

      if (!response.ok) {
        throw new Error(`Status check failed (${response.status})`);
      }

      const data = await response.json();
      setServices(data.services || []);
      setLastChecked(data.timestamp || new Date().toISOString());
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to query system status.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemStatus();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
              <Settings className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Security Settings & Engine Status</h2>
              <p className="text-xs text-slate-400">
                Live operational health of all 12 platform threat analysis subsystems and API integrations
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={fetchSystemStatus}
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-slate-900 border border-slate-700 text-slate-200 hover:bg-slate-800 transition shadow-sm cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
            Refresh Health
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* 12-Subsystem Operational Grid */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white">Threat Detection Subsystems</h3>
            <p className="text-xs text-slate-400">
              Verified server health, API key presence, and threat database connectivity
            </p>
          </div>
          {lastChecked && (
            <span className="text-xs font-mono text-slate-400">
              Checked {new Date(lastChecked).toLocaleTimeString()}
            </span>
          )}
        </div>

        {loading && services.length === 0 ? (
          <div className="py-12 text-center space-y-2">
            <RefreshCw className="w-6 h-6 animate-spin text-blue-400 mx-auto" />
            <p className="text-xs text-slate-400 font-medium">Querying platform status...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {services.map((svc, i) => {
              const isOp = svc.status === 'Operational';
              const isNotConfig = svc.status.toLowerCase().includes('not configured');

              return (
                <div
                  key={svc.id || i}
                  className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 hover:border-slate-700 transition"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-bold text-white leading-tight">
                      {svc.name}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold whitespace-nowrap ${
                        isOp
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          : isNotConfig
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-red-500/15 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {isOp ? (
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                      )}
                      {svc.status}
                    </span>
                  </div>

                  {svc.provider && (
                    <p className="text-[11px] font-mono text-slate-400">
                      Engine: {svc.provider}
                    </p>
                  )}

                  <p className="text-xs text-slate-300 leading-relaxed">{svc.detail}</p>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Privacy & Data Retention Guidelines */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-white">Privacy & Data Retention Policy</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-300">
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1.5">
            <h4 className="font-semibold text-white">Zero Persistent Image Storage</h4>
            <p className="leading-relaxed text-slate-400">
              Uploaded screenshots and QR images are processed entirely in server RAM for OCR and vision heuristics, and are never saved to public cloud storage buckets.
            </p>
          </div>

          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1.5">
            <h4 className="font-semibold text-white">Strict SSRF Protection</h4>
            <p className="leading-relaxed text-slate-400">
              URL fetches reject loopback, IPv6 link-local, private RFC 1918 subnets, and cloud metadata endpoints (169.254.169.254) before and after redirects.
            </p>
          </div>

          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1.5">
            <h4 className="font-semibold text-white">Authenticated Scan Vault</h4>
            <p className="leading-relaxed text-slate-400">
              Scan records and reports are secured by Firestore Security Rules. Only the authenticated user who initiated a scan can query, update, or purge it.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
