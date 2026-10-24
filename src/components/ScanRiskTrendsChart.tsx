import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  Calendar,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  Activity,
  Filter,
} from 'lucide-react';
import { ScanRecordDoc } from '../lib/firebase';

interface ScanRiskTrendsChartProps {
  scans: ScanRecordDoc[];
  selectedDate?: string | null;
  onSelectDate?: (dateIso: string | null) => void;
  onInspectScan?: (scan: ScanRecordDoc) => void;
}

type TimeRangePreset = '7D' | '14D' | '30D' | '60D' | '90D' | 'ALL' | 'CUSTOM';

interface AggregatedTrendPoint {
  dateKey: string; // YYYY-MM-DD
  displayDate: string; // MMM DD
  timestamp: number;
  avgRisk: number;
  maxRisk: number;
  minRisk: number;
  scanCount: number;
  criticalCount: number;
  highCount: number;
  suspiciousCount: number;
  cleanCount: number;
  targets: string[];
}

export const ScanRiskTrendsChart: React.FC<ScanRiskTrendsChartProps> = ({
  scans,
  selectedDate,
  onSelectDate,
}) => {
  const [rangePreset, setRangePreset] = useState<TimeRangePreset>('30D');
  const [customStartDate, setCustomStartDate] = useState<string>('');
  const [customEndDate, setCustomEndDate] = useState<string>('');
  const [includeDemoData, setIncludeDemoData] = useState<boolean>(false);
  const [selectedVector, setSelectedVector] = useState<'all' | 'url' | 'message' | 'ip'>('all');

  // Synthetic benchmark reference points to visualize trends if user has few live scans
  const demoScans = useMemo<ScanRecordDoc[]>(() => {
    if (!includeDemoData && scans.length > 2) return [];

    const now = new Date();
    const demoItems: ScanRecordDoc[] = [];
    const sampleTargets = [
      { t: 'http://auth-verify-security.org', type: 'url' as const, baseScore: 82, v: 'HIGH RISK' as const },
      { t: 'https://paypal-invoice-notice.support', type: 'url' as const, baseScore: 92, v: 'CRITICAL RISK' as const },
      { t: 'Urgent Wire: CEO transfer $45,000 requested', type: 'message' as const, baseScore: 78, v: 'HIGH RISK' as const },
      { t: '185.220.101.5 (Tor Exit Relay DNSBL)', type: 'ip' as const, baseScore: 65, v: 'HIGH RISK' as const },
      { t: 'https://github.com/login', type: 'url' as const, baseScore: 5, v: 'Clean' as const },
      { t: '1.1.1.1 (Cloudflare DNS)', type: 'ip' as const, baseScore: 0, v: 'Clean' as const },
      { t: 'Your Google Drive quota is 85% full notice', type: 'message' as const, baseScore: 28, v: 'MEDIUM RISK' as const },
      { t: 'http://neverssl.com (Insecure HTTP)', type: 'url' as const, baseScore: 40, v: 'MEDIUM RISK' as const },
    ];

    for (let dayOffset = 30; dayOffset >= 0; dayOffset--) {
      // Simulate 1 to 3 scans on select days
      const d = new Date(now.getTime() - dayOffset * 86400000);
      const isBurstDay = dayOffset % 5 === 0;
      const count = isBurstDay ? 3 : dayOffset % 2 === 0 ? 1 : 2;

      for (let i = 0; i < count; i++) {
        const sample = sampleTargets[(dayOffset + i) % sampleTargets.length];
        const jitter = Math.floor(Math.sin(dayOffset + i) * 8);
        const score = Math.max(0, Math.min(100, sample.baseScore + jitter));
        demoItems.push({
          scanId: `benchmark_${dayOffset}_${i}`,
          userId: 'benchmark_uid',
          scanType: sample.type,
          target: sample.t,
          riskScore: score,
          verdict: sample.v,
          summary: `Benchmark telemetry scan point (${sample.v}).`,
          analysisData: { isBenchmark: true, target: sample.t, riskScore: score },
          status: 'completed',
          createdAt: {
            toDate: () => d,
            toMillis: () => d.getTime(),
          } as any,
        });
      }
    }
    return demoItems;
  }, [includeDemoData, scans.length]);

  const allApplicableScans = useMemo(() => {
    const combined = [...scans, ...demoScans];
    if (selectedVector === 'all') return combined;
    return combined.filter((s) => s.scanType === selectedVector);
  }, [scans, demoScans, selectedVector]);

  // Determine active date boundaries based on preset or custom range
  const { startDate, endDate } = useMemo(() => {
    const end = new Date();
    end.setHours(23, 59, 59, 999);

    if (rangePreset === 'CUSTOM' && customStartDate && customEndDate) {
      const s = new Date(customStartDate);
      s.setHours(0, 0, 0, 0);
      const e = new Date(customEndDate);
      e.setHours(23, 59, 59, 999);
      return { startDate: s, endDate: e };
    }

    if (rangePreset === 'ALL') {
      let earliestTime = end.getTime() - 90 * 86400000;
      allApplicableScans.forEach((scan) => {
        const time = scan.createdAt?.toDate ? scan.createdAt.toDate().getTime() : scan.createdAt ? new Date(scan.createdAt as any).getTime() : 0;
        if (time && time < earliestTime) earliestTime = time;
      });
      return { startDate: new Date(earliestTime), endDate: end };
    }

    const daysMap: Record<string, number> = {
      '7D': 7,
      '14D': 14,
      '30D': 30,
      '60D': 60,
      '90D': 90,
    };
    const days = daysMap[rangePreset] || 30;
    const start = new Date(end.getTime() - (days - 1) * 86400000);
    start.setHours(0, 0, 0, 0);
    return { startDate: start, endDate: end };
  }, [rangePreset, customStartDate, customEndDate, allApplicableScans]);

  // Aggregate scans into chronological daily trend points
  const chartData = useMemo<AggregatedTrendPoint[]>(() => {
    const dailyMap = new Map<string, {
      dateObj: Date;
      scores: number[];
      criticalCount: number;
      highCount: number;
      suspiciousCount: number;
      cleanCount: number;
      targets: string[];
    }>();

    // Initialize all days in the range so the line chart shows a smooth continuous timeline
    const cur = new Date(startDate.getTime());
    while (cur <= endDate) {
      const dateKey = cur.toISOString().slice(0, 10);
      dailyMap.set(dateKey, {
        dateObj: new Date(cur.getTime()),
        scores: [],
        criticalCount: 0,
        highCount: 0,
        suspiciousCount: 0,
        cleanCount: 0,
        targets: [],
      });
      cur.setDate(cur.getDate() + 1);
    }

    // Populate actual scan telemetry
    allApplicableScans.forEach((scan) => {
      let scanDate: Date | null = null;
      if (scan.createdAt?.toDate) {
        scanDate = scan.createdAt.toDate();
      } else if (scan.createdAt) {
        scanDate = new Date(scan.createdAt as any);
      }
      if (!scanDate || isNaN(scanDate.getTime())) {
        scanDate = new Date();
      }

      if (scanDate >= startDate && scanDate <= endDate) {
        const key = scanDate.toISOString().slice(0, 10);
        const dayEntry = dailyMap.get(key);
        if (dayEntry) {
          const score = typeof scan.riskScore === 'number' ? scan.riskScore : 0;
          dayEntry.scores.push(score);
          if (score >= 75) dayEntry.criticalCount++;
          else if (score >= 50) dayEntry.highCount++;
          else if (score >= 25) dayEntry.suspiciousCount++;
          else dayEntry.cleanCount++;

          if (scan.target && dayEntry.targets.length < 3) {
            dayEntry.targets.push(scan.target);
          }
        }
      }
    });

    const points: AggregatedTrendPoint[] = [];
    dailyMap.forEach((val, dateKey) => {
      const scores = val.scores;
      const count = scores.length;
      const avg = count > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / count) : 0;
      const max = count > 0 ? Math.max(...scores) : 0;
      const min = count > 0 ? Math.min(...scores) : 0;

      const dateObj = val.dateObj;
      const displayDate = dateObj.toLocaleDateString([], {
        month: 'short',
        day: 'numeric',
      });

      points.push({
        dateKey,
        displayDate,
        timestamp: dateObj.getTime(),
        avgRisk: avg,
        maxRisk: max,
        minRisk: min,
        scanCount: count,
        criticalCount: val.criticalCount,
        highCount: val.highCount,
        suspiciousCount: val.suspiciousCount,
        cleanCount: val.cleanCount,
        targets: val.targets,
      });
    });

    return points.sort((a, b) => a.timestamp - b.timestamp);
  }, [allApplicableScans, startDate, endDate]);

  // Overall statistics for the selected time range
  const stats = useMemo(() => {
    const pointsWithScans = chartData.filter((p) => p.scanCount > 0);
    const totalScans = pointsWithScans.reduce((acc, p) => acc + p.scanCount, 0);

    let peakRisk = 0;
    let criticalTotal = 0;
    let highTotal = 0;
    let scoreSum = 0;

    pointsWithScans.forEach((p) => {
      if (p.maxRisk > peakRisk) peakRisk = p.maxRisk;
      criticalTotal += p.criticalCount;
      highTotal += p.highCount;
      scoreSum += p.avgRisk * p.scanCount;
    });

    const averageRisk = totalScans > 0 ? Math.round(scoreSum / totalScans) : 0;

    // Split period into two halves to compute velocity trend
    const midIdx = Math.floor(chartData.length / 2);
    const firstHalf = chartData.slice(0, midIdx).filter((p) => p.scanCount > 0);
    const secondHalf = chartData.slice(midIdx).filter((p) => p.scanCount > 0);

    const firstHalfAvg =
      firstHalf.length > 0
        ? firstHalf.reduce((a, p) => a + p.avgRisk, 0) / firstHalf.length
        : 0;
    const secondHalfAvg =
      secondHalf.length > 0
        ? secondHalf.reduce((a, p) => a + p.avgRisk, 0) / secondHalf.length
        : 0;

    const diff = Math.round(secondHalfAvg - firstHalfAvg);

    return {
      totalScans,
      averageRisk,
      peakRisk,
      criticalTotal,
      highTotal,
      trendDiff: diff,
    };
  }, [chartData]);

  // Custom Recharts Tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload || !payload.length) return null;
    const data: AggregatedTrendPoint = payload[0].payload;

    return (
      <div className="bg-slate-900 text-white p-3.5 rounded-lg shadow-xl border border-slate-700 text-xs space-y-2 max-w-xs font-sans">
        <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 font-mono">
          <span className="font-bold text-slate-200">{data.dateKey}</span>
          <span className="text-[11px] text-emerald-400 font-semibold">
            {data.scanCount} scan{data.scanCount === 1 ? '' : 's'}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <span className="text-slate-400 text-[11px] block">Peak Risk Score:</span>
            <span
              className={`font-mono font-bold text-sm ${
                data.maxRisk >= 75
                  ? 'text-red-400'
                  : data.maxRisk >= 50
                    ? 'text-orange-400'
                    : data.maxRisk >= 25
                      ? 'text-amber-400'
                      : 'text-emerald-400'
              }`}
            >
              {data.maxRisk} / 100
            </span>
          </div>

          <div>
            <span className="text-slate-400 text-[11px] block">Average Risk Score:</span>
            <span className="font-mono font-bold text-sm text-slate-200">
              {data.avgRisk} / 100
            </span>
          </div>
        </div>

        {data.scanCount > 0 && (
          <div className="pt-1.5 border-t border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold">
              Threat Breakdown:
            </span>
            <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
              {data.criticalCount > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                  {data.criticalCount} Critical
                </span>
              )}
              {data.highCount > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800">
                  {data.highCount} High
                </span>
              )}
              {data.suspiciousCount > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                  {data.suspiciousCount} Suspicious
                </span>
              )}
              {data.cleanCount > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {data.cleanCount} Clean
                </span>
              )}
            </div>
          </div>
        )}

        {data.targets.length > 0 && (
          <div className="pt-1 border-t border-slate-800 text-[10px] text-slate-400 truncate">
            <span className="font-medium text-slate-300">Sample Target: </span>
            <span className="font-mono">{data.targets[0]}</span>
          </div>
        )}

        <div className="text-[10px] text-emerald-300 pt-1 text-center font-medium">
          Click point to filter audit ledger to this date
        </div>
      </div>
    );
  };

  return (
    <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-6 shadow-xs text-white">
      {/* 1. Header Toolbar with Range Filters */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            <h3 className="text-lg font-bold text-white font-display tracking-tight">
              Risk Score Trends Over Time
            </h3>
            <span className="text-[10px] font-mono font-semibold uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded-full">
              Recharts Line Visualization
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Temporal security risk score trajectory and threat spike analysis across your authenticated audit records.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Vector Filter Dropdown */}
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedVector}
              onChange={(e) => setSelectedVector(e.target.value as any)}
              className="text-xs bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer"
              title="Filter by threat vector"
            >
              <option value="all" className="bg-slate-900 text-white">All Vectors</option>
              <option value="url" className="bg-slate-900 text-white">URLs only</option>
              <option value="message" className="bg-slate-900 text-white">Messages only</option>
              <option value="ip" className="bg-slate-900 text-white">IPs only</option>
            </select>
          </div>

          {/* Date Range Preset Selector */}
          <div className="inline-flex rounded-lg shadow-2xs border border-slate-800 p-0.5 bg-slate-900/60 text-xs">
            {(['7D', '14D', '30D', '60D', '90D', 'ALL'] as TimeRangePreset[]).map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => setRangePreset(preset)}
                className={`px-2.5 py-1 font-medium rounded transition-colors cursor-pointer text-[11px] ${
                  rangePreset === preset
                    ? 'bg-blue-600 text-white shadow-xs font-semibold'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {preset}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setRangePreset('CUSTOM')}
              className={`px-2.5 py-1 font-medium rounded transition-colors cursor-pointer text-[11px] ${
                rangePreset === 'CUSTOM'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              Custom
            </button>
          </div>

          {/* Benchmark Reference Toggle */}
          <button
            type="button"
            onClick={() => setIncludeDemoData(!includeDemoData)}
            className={`px-2.5 py-1 text-xs font-medium rounded-lg border transition-colors cursor-pointer flex items-center gap-1.5 ${
              includeDemoData
                ? 'bg-blue-950/60 text-blue-300 border-blue-700'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:bg-slate-800 hover:text-white'
            }`}
            title="Toggle benchmark reference scans to inspect temporal analytics patterns"
          >
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span>Benchmark Overlay</span>
          </button>
        </div>
      </div>

      {/* Custom Date Range Picker when CUSTOM is selected */}
      {rangePreset === 'CUSTOM' && (
        <div className="flex flex-wrap items-center gap-3 p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-xs">
          <Calendar className="w-4 h-4 text-slate-400" />
          <span className="font-medium text-slate-300">Custom Date Range:</span>
          <div className="flex items-center gap-2">
            <label className="text-slate-400 text-[11px]">Start:</label>
            <input
              type="date"
              value={customStartDate}
              onChange={(e) => setCustomStartDate(e.target.value)}
              className="px-2 py-1 text-xs border border-slate-700 rounded-md bg-slate-900 text-white focus:outline-none focus:border-blue-500"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-slate-400 text-[11px]">End:</label>
            <input
              type="date"
              value={customEndDate}
              onChange={(e) => setCustomEndDate(e.target.value)}
              className="px-2 py-1 text-xs border border-slate-700 rounded-md bg-slate-900 text-white focus:outline-none focus:border-blue-500"
            />
          </div>
          {(customStartDate || customEndDate) && (
            <button
              type="button"
              onClick={() => {
                setCustomStartDate('');
                setCustomEndDate('');
              }}
              className="text-slate-400 hover:text-white cursor-pointer flex items-center gap-1 text-[11px]"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      )}

      {/* Selected Date Filter Callout */}
      {selectedDate && (
        <div className="flex items-center justify-between px-3.5 py-2 bg-blue-950/40 border border-blue-800 rounded-lg text-xs text-blue-300">
          <div className="flex items-center gap-2 font-mono">
            <Calendar className="w-4 h-4 text-blue-400" />
            <span>
              Timeline Filter Active: <strong>{selectedDate}</strong>
            </span>
          </div>
          {onSelectDate && (
            <button
              type="button"
              onClick={() => onSelectDate(null)}
              className="text-blue-400 hover:text-white font-medium underline cursor-pointer"
            >
              Clear Date Filter
            </button>
          )}
        </div>
      )}

      {/* 2. Top Metric Telemetry Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <span className="text-[11px] font-medium text-slate-400">Period Average Risk</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span
              className={`text-2xl font-bold font-mono tabular-nums ${
                stats.averageRisk >= 50
                  ? 'text-red-400'
                  : stats.averageRisk >= 25
                    ? 'text-amber-400'
                    : 'text-emerald-400'
              }`}
            >
              {stats.averageRisk}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Weighted severity across period</span>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <span className="text-[11px] font-medium text-slate-400">Peak Threat Spike</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span
              className={`text-2xl font-bold font-mono tabular-nums ${
                stats.peakRisk >= 75
                  ? 'text-red-400'
                  : stats.peakRisk >= 50
                    ? 'text-orange-400'
                    : 'text-emerald-400'
              }`}
            >
              {stats.peakRisk}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Highest detected risk score</span>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <span className="text-[11px] font-medium text-slate-400">High & Critical Threats</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono tabular-nums text-white">
              {stats.criticalTotal + stats.highTotal}
            </span>
            <span className="text-xs text-slate-400">scans ({stats.totalScans} total)</span>
          </div>
          <span className="text-[10px] text-slate-500 mt-1">
            {stats.criticalTotal} critical · {stats.highTotal} high
          </span>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <span className="text-[11px] font-medium text-slate-400">Trend Trajectory</span>
          <div className="flex items-center gap-1.5 mt-1">
            {stats.trendDiff > 0 ? (
              <>
                <TrendingUp className="w-5 h-5 text-red-400" />
                <span className="text-xl font-bold font-mono text-red-400">
                  +{stats.trendDiff}%
                </span>
              </>
            ) : stats.trendDiff < 0 ? (
              <>
                <TrendingDown className="w-5 h-5 text-emerald-400" />
                <span className="text-xl font-bold font-mono text-emerald-400">
                  {stats.trendDiff}%
                </span>
              </>
            ) : (
              <span className="text-xl font-bold font-mono text-slate-300">Stable</span>
            )}
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Velocity vs earlier period</span>
        </div>
      </div>

      {/* 3. Recharts Line Chart Container */}
      <div className="h-[340px] w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={chartData}
            margin={{ top: 10, right: 30, left: 0, bottom: 20 }}
            onClick={(e: any) => {
              if (e && e.activePayload && e.activePayload.length && onSelectDate) {
                const point: AggregatedTrendPoint = e.activePayload[0].payload;
                onSelectDate(point.dateKey);
              }
            }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis
              dataKey="displayDate"
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
              dy={10}
            />
            <YAxis
              domain={[0, 100]}
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
              ticks={[0, 25, 50, 75, 100]}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend
              verticalAlign="top"
              align="right"
              wrapperStyle={{ paddingBottom: '12px', fontSize: '11px' }}
            />

            {/* Threshold Reference Lines */}
            <ReferenceLine
              y={75}
              stroke="#ef4444"
              strokeDasharray="4 4"
              strokeWidth={1}
              label={{
                value: 'Critical Risk (75)',
                fill: '#ef4444',
                fontSize: 10,
                position: 'insideTopRight',
              }}
            />
            <ReferenceLine
              y={50}
              stroke="#f97316"
              strokeDasharray="4 4"
              strokeWidth={1}
              label={{
                value: 'High Risk (50)',
                fill: '#f97316',
                fontSize: 10,
                position: 'insideTopRight',
              }}
            />
            <ReferenceLine
              y={25}
              stroke="#eab308"
              strokeDasharray="4 4"
              strokeWidth={1}
              label={{
                value: 'Suspicious (25)',
                fill: '#eab308',
                fontSize: 10,
                position: 'insideTopRight',
              }}
            />

            {/* Peak Risk Line */}
            <Line
              type="monotone"
              dataKey="maxRisk"
              name="Peak Threat Score"
              stroke="#ef4444"
              strokeWidth={2.5}
              dot={{ r: 3, fill: '#ef4444' }}
              activeDot={{ r: 6, fill: '#dc2626', stroke: '#fff', strokeWidth: 2 }}
            />

            {/* Average Risk Line */}
            <Line
              type="monotone"
              dataKey="avgRisk"
              name="Average Risk Score"
              stroke="#10b981"
              strokeWidth={2}
              dot={{ r: 2.5, fill: '#10b981' }}
              activeDot={{ r: 5, fill: '#059669', stroke: '#fff', strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* 4. Chart Footer / Explanatory Legend */}
      <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 pt-3 border-t border-slate-800 gap-2">
        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-red-500 inline-block" />
            <span>Peak Threat Score (0–100)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-emerald-500 inline-block" />
            <span>Average Risk Score (0–100)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0 border-t border-dashed border-red-500 inline-block" />
            <span>Critical Threshold (75)</span>
          </div>
        </div>

        <div className="text-[11px] font-mono text-slate-500">
          Showing {chartData.length} days horizon ({startDate.toISOString().slice(0, 10)} to {endDate.toISOString().slice(0, 10)})
        </div>
      </div>
    </div>
  );
};
