import React from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  MessageSquareWarning,
  Network,
  QrCode,
  Image as ImageIcon,
  ArrowRight,
  TrendingUp,
  Activity,
  FileText,
  Search,
  ExternalLink,
} from 'lucide-react';
import type { ScanRecordDoc, AllowedScanType, AllowedVerdictType } from '../lib/firebase';

interface DashboardOverviewProps {
  scans: ScanRecordDoc[];
  reportsCount: number;
  onNavigate: (section: any) => void;
  onSelectScan: (scan: ScanRecordDoc) => void;
  onLaunchVoice?: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  scans,
  reportsCount,
  onNavigate,
  onSelectScan,
  onLaunchVoice,
}) => {
  const totalScans = scans.length;

  const highRiskScans = scans.filter((s) => s.riskScore >= 60);
  const mediumRiskScans = scans.filter((s) => s.riskScore >= 30 && s.riskScore < 60);
  const cleanScans = scans.filter((s) => s.riskScore < 30);

  const urlScansCount = scans.filter((s) => s.scanType === 'url').length;
  const msgScansCount = scans.filter((s) => s.scanType === 'message').length;
  const ipScansCount = scans.filter((s) => s.scanType === 'ip').length;
  const screenshotScansCount = scans.filter((s) => s.scanType === 'screenshot').length;
  const qrScansCount = scans.filter((s) => (s.scanType as string) === 'qr').length;

  const recentScans = scans.slice(0, 5);

  return (
    <div className="space-y-8">
      {/* Hero Welcome Banner */}
      <div className="relative overflow-hidden bg-gradient-to-r from-blue-950 via-slate-900 to-slate-950 rounded-2xl p-6 sm:p-8 text-white shadow-lg border border-slate-800">
        <div className="relative z-10 max-w-3xl space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/20 text-blue-300 text-xs font-semibold tracking-wide border border-blue-500/30">
            <Shield className="w-3.5 h-3.5 text-blue-400" />
            PHISHING SHIELD PLATFORM · "Detect. Analyze. Protect."
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Your Digital Shield Against Phishing & Online Scams
          </h2>
          <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
            Multi-modal threat intelligence combining lexical heuristics, ICANN RDAP registration history, DNSBL reputation feeds, OCR vision, and explainable AI risk scoring.
          </p>
          <div className="pt-2 flex flex-wrap gap-3">
            {onLaunchVoice && (
              <button
                type="button"
                onClick={onLaunchVoice}
                className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-lg shadow-sm transition cursor-pointer"
              >
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
                </span>
                Live Voice Session
              </button>
            )}
            <button
              type="button"
              onClick={() => onNavigate('url-scanner')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg shadow-sm transition cursor-pointer"
            >
              <Globe className="w-4 h-4" />
              Scan Suspicious URL
            </button>
            <button
              type="button"
              onClick={() => onNavigate('message-scanner')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-sm font-semibold rounded-lg border border-slate-700 transition cursor-pointer"
            >
              <MessageSquareWarning className="w-4 h-4 text-amber-400" />
              Analyze Message
            </button>
            <button
              type="button"
              onClick={() => onNavigate('screenshot-scanner')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-sm font-semibold rounded-lg border border-slate-700 transition cursor-pointer"
            >
              <ImageIcon className="w-4 h-4 text-emerald-400" />
              Scan Screenshot
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Total Recorded Scans
            </span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <p className="mt-3 text-2xl font-bold font-mono text-white tabular-nums">
            {totalScans}
          </p>
          <p className="mt-1 text-xs text-slate-400">Real verified scans in your vault</p>
        </div>

        <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              High / Critical Threats
            </span>
            <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <p className="mt-3 text-2xl font-bold font-mono text-red-400 tabular-nums">
            {highRiskScans.length}
          </p>
          <p className="mt-1 text-xs text-slate-400">
            {totalScans > 0
              ? `${Math.round((highRiskScans.length / totalScans) * 100)}% of total scans`
              : 'Zero threats detected yet'}
          </p>
        </div>

        <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Clean / Low Risk
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <p className="mt-3 text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {cleanScans.length}
          </p>
          <p className="mt-1 text-xs text-slate-400">
            {totalScans > 0
              ? `${Math.round((cleanScans.length / totalScans) * 100)}% verified safe`
              : 'No scans analyzed yet'}
          </p>
        </div>

        <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Security Reports
            </span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <p className="mt-3 text-2xl font-bold font-mono text-indigo-400 tabular-nums">
            {reportsCount}
          </p>
          <p className="mt-1 text-xs text-slate-400">Documented SOC incident reports</p>
        </div>
      </div>

      {/* Vector Distribution and Quick Launchers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Vector Breakdown */}
        <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Scan Vectors Breakdown</h3>
            <span className="text-xs font-mono text-slate-400">{totalScans} events</span>
          </div>

          {totalScans === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs">
              No scans recorded yet. Run a URL, message, or screenshot scan to populate vector metrics.
            </div>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-blue-400" /> URLs
                  </span>
                  <span className="font-mono text-slate-400">
                    {urlScansCount} ({Math.round((urlScansCount / totalScans) * 100)}%)
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full"
                    style={{ width: `${(urlScansCount / totalScans) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <MessageSquareWarning className="w-3.5 h-3.5 text-amber-400" /> Messages
                  </span>
                  <span className="font-mono text-slate-400">
                    {msgScansCount} ({Math.round((msgScansCount / totalScans) * 100)}%)
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-amber-500 rounded-full"
                    style={{ width: `${(msgScansCount / totalScans) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <ImageIcon className="w-3.5 h-3.5 text-emerald-400" /> Screenshots
                  </span>
                  <span className="font-mono text-slate-400">
                    {screenshotScansCount} ({Math.round((screenshotScansCount / totalScans) * 100)}%)
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full"
                    style={{ width: `${(screenshotScansCount / totalScans) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <QrCode className="w-3.5 h-3.5 text-indigo-400" /> QR Codes
                  </span>
                  <span className="font-mono text-slate-400">
                    {qrScansCount} ({Math.round((qrScansCount / totalScans) * 100)}%)
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-500 rounded-full"
                    style={{ width: `${(qrScansCount / totalScans) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-purple-400" /> Public IPs
                  </span>
                  <span className="font-mono text-slate-400">
                    {ipScansCount} ({Math.round((ipScansCount / totalScans) * 100)}%)
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-purple-500 rounded-full"
                    style={{ width: `${(ipScansCount / totalScans) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Quick Launchpad */}
        <div className="lg:col-span-2 bg-[#0b1325] border border-slate-800/80 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Security Scanners & Modules</h3>
            <span className="text-xs text-slate-400">Select any engine to begin analysis</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            <button
              type="button"
              onClick={() => onNavigate('url-scanner')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-blue-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <Globe className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Scan URL</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">TLS, homographs & redirects</p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('message-scanner')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-amber-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <MessageSquareWarning className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Scan Message</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">Urgency, KYC & UPI lures</p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('screenshot-scanner')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-emerald-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <ImageIcon className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Scan Screenshot</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">OCR vision & fake UI alerts</p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('qr-scanner')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-indigo-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <QrCode className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Scan QR Code</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">Quishing & malicious payloads</p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('ip-scanner')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-purple-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <Network className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Scan Public IP</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">ASN, Bogon, DNSBL checks</p>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('domain-intel')}
              className="text-left p-3.5 rounded-lg border border-slate-800 hover:border-sky-500 hover:bg-slate-900/80 transition group"
            >
              <div className="w-8 h-8 rounded-md bg-sky-500/10 text-sky-400 border border-sky-500/20 flex items-center justify-center mb-2 group-hover:scale-105 transition">
                <Globe className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-white">Domain Intelligence</h4>
              <p className="text-[11px] text-slate-400 mt-0.5">DNS & real RDAP registry age</p>
            </button>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-[#0b1325] border border-slate-800/80 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Investigations</h3>
            <p className="text-xs text-slate-400">Your latest authenticated security analyses</p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('scan-history')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300"
          >
            View Full History
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentScans.length === 0 ? (
          <div className="py-10 text-center space-y-2 border border-dashed border-slate-800 rounded-lg">
            <Shield className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs font-semibold text-slate-300">No scans recorded in your vault</p>
            <p className="text-[11px] text-slate-500">
              Launch a scan above to start building your threat investigation history.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/90 text-slate-400 font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Target</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3 text-right">Risk Score</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentScans.map((scan) => {
                  const isHigh = scan.riskScore >= 60;
                  const isMed = scan.riskScore >= 30 && scan.riskScore < 60;
                  return (
                    <tr key={scan.scanId} className="hover:bg-slate-900/50 transition">
                      <td className="py-3 px-3">
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 uppercase">
                          {scan.scanType}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-200 max-w-xs truncate">
                        {scan.target}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                            isHigh
                              ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                              : isMed
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {scan.verdict}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right font-mono font-bold tabular-nums">
                        <span
                          className={
                            isHigh
                              ? 'text-red-400'
                              : isMed
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          }
                        >
                          {scan.riskScore}/100
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          type="button"
                          onClick={() => {
                            onSelectScan(scan);
                            onNavigate('scan-history');
                          }}
                          className="px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:text-blue-400 hover:bg-slate-800 rounded transition"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
