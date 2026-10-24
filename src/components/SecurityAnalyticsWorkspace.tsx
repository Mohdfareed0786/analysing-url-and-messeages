import React, { useMemo } from 'react';
import {
  BarChart3,
  TrendingUp,
  PieChart as PieIcon,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Layers,
  Database,
  Calendar,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  PieChart,
  Pie,
  Legend,
} from 'recharts';
import type { ScanRecordDoc } from '../lib/firebase';

interface SecurityAnalyticsWorkspaceProps {
  scans: ScanRecordDoc[];
}

export const SecurityAnalyticsWorkspace: React.FC<SecurityAnalyticsWorkspaceProps> = ({ scans }) => {
  const totalScans = scans.length;

  // Verdict distribution
  const verdictDistribution = useMemo(() => {
    let clean = 0;
    let low = 0;
    let med = 0;
    let high = 0;
    let crit = 0;

    scans.forEach((s) => {
      const score = s.riskScore || 0;
      if (score < 30) clean++;
      else if (score < 50) low++;
      else if (score < 70) med++;
      else if (score < 85) high++;
      else crit++;
    });

    return [
      { name: 'Clean (0-29)', value: clean, color: '#10b981' },
      { name: 'Low Risk (30-49)', value: low, color: '#3b82f6' },
      { name: 'Medium (50-69)', value: med, color: '#f59e0b' },
      { name: 'High Risk (70-84)', value: high, color: '#f97316' },
      { name: 'Critical (85-100)', value: crit, color: '#ef4444' },
    ];
  }, [scans]);

  // Vector counts
  const vectorDistribution = useMemo(() => {
    const counts: Record<string, number> = {
      url: 0,
      message: 0,
      ip: 0,
      screenshot: 0,
      qr: 0,
      domain: 0,
    };

    scans.forEach((s) => {
      const type = (s.scanType as string) || 'url';
      counts[type] = (counts[type] || 0) + 1;
    });

    return Object.entries(counts).map(([type, count]) => ({
      type: type.toUpperCase(),
      count,
    }));
  }, [scans]);

  // Indicator frequency (aggregate findings across scans)
  const topIndicators = useMemo(() => {
    const indicatorCounts: Record<string, { count: number; impact: string }> = {};

    scans.forEach((s) => {
      const findings = (s.analysisData as any)?.evidence || (s.analysisData as any)?.findings;
      if (Array.isArray(findings)) {
        findings.forEach((item: any) => {
          const name = item.indicator || item.category || 'Threat Flag';
          if (!indicatorCounts[name]) {
            indicatorCounts[name] = { count: 0, impact: item.impact || 'warning' };
          }
          indicatorCounts[name].count += 1;
        });
      }
    });

    return Object.entries(indicatorCounts)
      .map(([name, data]) => ({ name, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [scans]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/15 text-blue-400 flex items-center justify-center border border-blue-500/30">
            <BarChart3 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Security Telemetry & Threat Analytics</h2>
            <p className="text-xs text-slate-400">
              Aggregated empirical metrics, vector frequency distributions, and telemetry calculated from your scan records
            </p>
          </div>
        </div>
      </div>

      {totalScans === 0 ? (
        <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-12 text-center space-y-3 shadow-sm">
          <Database className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-white">No Scan Data Available Yet</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Analytics are computed exclusively from real scan records in your database. Run investigations across URLs, messages, screenshots, or domains to view telemetry charts.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Risk Level Distribution Bar Chart */}
          <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Risk Tier Distribution</h3>
              <span className="text-xs font-mono text-slate-400">{totalScans} total scans</span>
            </div>

            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={verdictDistribution}>
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={0} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#070d19',
                      border: '1px solid #1e293b',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {verdictDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Scan Vector Activity */}
          <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Scan Volume by Vector</h3>
              <span className="text-xs font-mono text-slate-400">Multimodal Coverage</span>
            </div>

            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={vectorDistribution} layout="vertical">
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis
                    dataKey="type"
                    type="category"
                    tick={{ fontSize: 11, fill: '#cbd5e1', fontWeight: 600 }}
                    width={90}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#070d19',
                      border: '1px solid #1e293b',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top Threat Indicators Detected */}
          <div className="lg:col-span-2 bg-[#0b1325] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">Most Frequent Threat Indicators Detected</h3>
                <p className="text-xs text-slate-400">Heuristics triggered across your scan history</p>
              </div>
              <span className="text-xs font-mono text-slate-400">Evidence Count</span>
            </div>

            {topIndicators.length === 0 ? (
              <p className="text-xs text-slate-500 py-4">No risk indicators recorded yet.</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {topIndicators.map((ind, i) => (
                  <div key={i} className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                    <div className="space-y-0.5">
                      <p className="text-xs font-semibold text-slate-200 truncate max-w-[180px]">
                        {ind.name}
                      </p>
                      <span className="text-[10px] font-mono uppercase text-slate-400">
                        Impact: {ind.impact}
                      </span>
                    </div>
                    <span className="px-2 py-1 rounded bg-blue-600/20 text-blue-400 border border-blue-500/30 text-xs font-mono font-bold">
                      {ind.count}x
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
