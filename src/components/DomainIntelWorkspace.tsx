import React, { useState } from 'react';
import {
  Globe,
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
  Server,
  Calendar,
  Building,
  ShieldCheck,
  ShieldAlert,
  ExternalLink,
  ChevronRight,
  Database,
  Hash,
} from 'lucide-react';
import { auth, type AllowedScanType, type AllowedVerdictType } from '../lib/firebase';
import { ScanResultView } from './ScanResultView';

interface DomainIntelWorkspaceProps {
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

export const DomainIntelWorkspace: React.FC<DomainIntelWorkspaceProps> = ({
  onScanComplete,
  onAskGeminiAboutScan,
  onStartVoiceTriage,
  onCreateReport,
}) => {
  const [domainInput, setDomainInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'rdap' | 'certificate' | 'threat'>('overview');
  const [result, setResult] = useState<{
    scanId: string | null;
    target: string;
    data: Record<string, any>;
  } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanDomain = domainInput.trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!cleanDomain) {
      setErrorMsg('Please enter a valid domain name (e.g., example.com).');
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);
    setResult(null);

    try {
      const token = await auth.currentUser?.getIdToken();
      const response = await fetch('/api/scan-domain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ domain: cleanDomain }),
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error?.message || 'Domain inspection failed.');
      }

      const scanResult = {
        scanId: null,
        target: cleanDomain,
        data,
      };

      setResult(scanResult);
      onScanComplete(scanResult);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to retrieve domain intelligence.');
    } finally {
      setIsScanning(false);
    }
  };

  const domainData = result?.data;
  const rdap = domainData?.rdap;
  const dnsRecords = domainData?.dnsRecords;
  const cert = domainData?.certificate;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Domain Intelligence & RDAP Registry Inspector</h2>
            <p className="text-xs text-slate-400">
              Live authoritative DNS, ICANN RDAP domain age verification, and TLS certificate telemetry
            </p>
          </div>
        </div>
      </div>

      {/* Domain Search Bar */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="Enter domain (e.g. google.com, paypal-verify-security.com)"
                className="w-full pl-10 pr-4 py-2.5 text-xs bg-slate-900 border border-slate-700 rounded-lg font-mono text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 transition"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !domainInput.trim()}
              className={`inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold text-white shadow-sm transition whitespace-nowrap ${
                isScanning || !domainInput.trim()
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-blue-600 hover:bg-blue-500'
              }`}
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-blue-300" />
                  Querying RDAP & DNS...
                </>
              ) : (
                <>
                  <Globe className="w-4 h-4 text-blue-200" />
                  Inspect Domain
                </>
              )}
            </button>
          </div>

          {errorMsg && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
            <span>Authoritative ICANN bootstrap registry lookup. Registration dates are never invented.</span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setDomainInput('paypal-login-alert-security.xyz')}
                className="text-blue-400 hover:text-blue-300 underline font-mono cursor-pointer"
              >
                Sample Suspicious
              </button>
              <span>•</span>
              <button
                type="button"
                onClick={() => setDomainInput('github.com')}
                className="text-blue-400 hover:text-blue-300 underline font-mono cursor-pointer"
              >
                Sample Legitimate
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Domain Detailed Deep-Dive Panels if result exists */}
      {domainData && (
        <div className="space-y-6">
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Registration Age
              </span>
              <p className="mt-1 text-base font-bold font-mono text-white">
                {rdap?.domainAgeDays !== null && rdap?.domainAgeDays !== undefined
                  ? `${rdap.domainAgeDays} days (${Math.floor(rdap.domainAgeDays / 365)}y ${Math.floor((rdap.domainAgeDays % 365) / 30)}m)`
                  : 'Unavailable'}
              </p>
              <p className="text-[11px] text-slate-400">
                {rdap?.registrationDate
                  ? `Registered ${new Date(rdap.registrationDate).toLocaleDateString()}`
                  : 'RDAP registry record not exposed'}
              </p>
            </div>

            <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Registrar
              </span>
              <p className="mt-1 text-base font-bold text-white truncate">
                {rdap?.registrar || 'Registration data unavailable'}
              </p>
              <p className="text-[11px] text-slate-400">
                IANA ID: {rdap?.ianaId || 'N/A'}
              </p>
            </div>

            <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Resolved IPs
              </span>
              <p className="mt-1 text-base font-bold font-mono text-white">
                {domainData.resolvedIps?.length || 0} IPs
              </p>
              <p className="text-[11px] text-slate-400 font-mono truncate">
                {domainData.resolvedIps?.[0] || 'No A records'}
              </p>
            </div>

            <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-4 shadow-sm">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                TLS Certificate
              </span>
              <p className="mt-1 text-base font-bold text-white flex items-center gap-1.5">
                {cert?.hasHttps ? (
                  <>
                    <Lock className="w-4 h-4 text-emerald-400" />
                    <span className="text-emerald-400">Valid HTTPS</span>
                  </>
                ) : (
                  <>
                    <Unlock className="w-4 h-4 text-amber-400" />
                    <span className="text-amber-400">No TLS Handshake</span>
                  </>
                )}
              </p>
              <p className="text-[11px] text-slate-400 truncate">
                {cert?.issuer || 'Certificate unavailable'}
              </p>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex border-b border-slate-800 gap-4 overflow-x-auto">
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                className={`pb-2 text-xs font-semibold whitespace-nowrap transition border-b-2 cursor-pointer ${
                  activeTab === 'overview'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Overview & Risk Verdict
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('dns')}
                className={`pb-2 text-xs font-semibold whitespace-nowrap transition border-b-2 cursor-pointer ${
                  activeTab === 'dns'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                DNS Records ({dnsRecords ? Object.keys(dnsRecords).length : 0})
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('rdap')}
                className={`pb-2 text-xs font-semibold whitespace-nowrap transition border-b-2 cursor-pointer ${
                  activeTab === 'rdap'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                RDAP Registry Telemetry
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('certificate')}
                className={`pb-2 text-xs font-semibold whitespace-nowrap transition border-b-2 cursor-pointer ${
                  activeTab === 'certificate'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                TLS Certificate
              </button>
            </div>

            {/* Tab: DNS */}
            {activeTab === 'dns' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
                    <span className="text-xs font-bold uppercase text-slate-300">A Records (IPv4)</span>
                    {dnsRecords?.a?.length ? (
                      <ul className="space-y-1 font-mono text-xs text-emerald-400">
                        {dnsRecords.a.map((ip: string, i: number) => (
                          <li key={i}>{ip}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-slate-500">None found</p>
                    )}
                  </div>

                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
                    <span className="text-xs font-bold uppercase text-slate-300">AAAA Records (IPv6)</span>
                    {dnsRecords?.aaaa?.length ? (
                      <ul className="space-y-1 font-mono text-xs text-emerald-400">
                        {dnsRecords.aaaa.map((ip: string, i: number) => (
                          <li key={i}>{ip}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-slate-500">None found</p>
                    )}
                  </div>

                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
                    <span className="text-xs font-bold uppercase text-slate-300">MX Mail Exchangers</span>
                    {dnsRecords?.mx?.length ? (
                      <ul className="space-y-1 font-mono text-xs text-slate-300">
                        {dnsRecords.mx.map((mx: any, i: number) => (
                          <li key={i}>
                            {mx.exchange} (Priority: {mx.priority})
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-slate-500">None found</p>
                    )}
                  </div>

                  <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
                    <span className="text-xs font-bold uppercase text-slate-300">Name Servers (NS)</span>
                    {dnsRecords?.ns?.length ? (
                      <ul className="space-y-1 font-mono text-xs text-slate-300">
                        {dnsRecords.ns.map((ns: string, i: number) => (
                          <li key={i}>{ns}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-slate-500">None found</p>
                    )}
                  </div>

                  <div className="md:col-span-2 p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
                    <span className="text-xs font-bold uppercase text-slate-300">TXT Records (SPF & Verification)</span>
                    {dnsRecords?.txt?.length ? (
                      <ul className="space-y-1.5 font-mono text-xs text-slate-300 break-all">
                        {dnsRecords.txt.map((txt: string, i: number) => (
                          <li key={i} className="p-2 bg-slate-950 rounded border border-slate-800">
                            {txt}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-slate-500">None found</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Tab: RDAP */}
            {activeTab === 'rdap' && (
              <div className="space-y-4">
                <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-3">
                  <h4 className="text-xs font-bold uppercase text-slate-300">ICANN RDAP Registration Records</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="text-slate-400">Registration Date:</span>
                      <p className="font-mono font-medium text-white">
                        {rdap?.registrationDate || 'Registration data unavailable'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Expiration Date:</span>
                      <p className="font-mono font-medium text-white">
                        {rdap?.expirationDate || 'Registration data unavailable'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Last Updated:</span>
                      <p className="font-mono font-medium text-white">
                        {rdap?.updatedDate || 'Unavailable'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Registrar:</span>
                      <p className="font-medium text-white">{rdap?.registrar || 'Unavailable'}</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab: Certificate */}
            {activeTab === 'certificate' && (
              <div className="space-y-4">
                <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-3">
                  <h4 className="text-xs font-bold uppercase text-slate-300">TLS X.509 Certificate Profile</h4>
                  {cert?.hasHttps ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="text-slate-400">Subject:</span>
                        <p className="font-mono font-medium text-white">{cert.subject || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="text-slate-400">Issuer Authority:</span>
                        <p className="font-medium text-white">{cert.issuer || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="text-slate-400">Valid From:</span>
                        <p className="font-mono font-medium text-white">{cert.validFrom || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="text-slate-400">Valid To:</span>
                        <p className="font-mono font-medium text-white">{cert.validTo || 'N/A'}</p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-amber-400">No active TLS handshake detected on port 443.</p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Full ScanResultView */}
          <ScanResultView
            scanType="domain"
            target={result.target}
            scanId={result.scanId}
            data={result.data}
            scanStatus="Live"
            onCreateReport={onCreateReport}
            onAskGeminiAboutScan={onAskGeminiAboutScan}
            onStartVoiceTriage={onStartVoiceTriage}
          />
        </div>
      )}
    </div>
  );
};
