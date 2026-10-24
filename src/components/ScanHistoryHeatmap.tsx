import React, { useState, useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import {
  Calendar,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Flame,
  Info,
  Layers,
  BarChart3,
  Filter,
  X,
  Sparkles,
} from 'lucide-react';
import { ScanRecordDoc } from '../lib/firebase';

export interface ScanHistoryHeatmapProps {
  scans: ScanRecordDoc[];
  selectedDate: string | null;
  onSelectDate: (dateIso: string | null) => void;
  onInspectScan?: (scan: ScanRecordDoc) => void;
  riskCategoryFilter?: RiskCategoryFilter;
  onRiskCategoryChange?: (category: RiskCategoryFilter) => void;
}

type HeatmapMetric = 'maxRisk' | 'avgRisk' | 'scanCount';
type HeatmapView = 'calendar' | 'vectorMatrix';
export type RiskCategoryFilter = 'all' | 'high' | 'medium' | 'low';

interface DayAggregate {
  dateStr: string; // YYYY-MM-DD
  dateObj: Date;
  scans: ScanRecordDoc[];
  count: number;
  maxScore: number;
  avgScore: number;
  criticalCount: number;
  highCount: number;
  suspiciousCount: number;
  cleanCount: number;
  vectorMax: Record<string, number>;
  vectorCounts: Record<string, number>;
}

export const ScanHistoryHeatmap: React.FC<ScanHistoryHeatmapProps> = ({
  scans,
  selectedDate,
  onSelectDate,
  onInspectScan,
  riskCategoryFilter: externalRiskFilter,
  onRiskCategoryChange,
}) => {
  const [metric, setMetric] = useState<HeatmapMetric>('maxRisk');
  const [view, setView] = useState<HeatmapView>('calendar');
  const [timeWindowDays, setTimeWindowDays] = useState<number>(60);
  const [internalRiskFilter, setInternalRiskFilter] = useState<RiskCategoryFilter>('all');
  const riskCategoryFilter = externalRiskFilter !== undefined ? externalRiskFilter : internalRiskFilter;

  const handleRiskCategoryChange = (cat: RiskCategoryFilter) => {
    setInternalRiskFilter(cat);
    onRiskCategoryChange?.(cat);
  };

  const [includeDemoBaseline, setIncludeDemoBaseline] = useState<boolean>(false);
  const [hoveredDay, setHoveredDay] = useState<{
    data: DayAggregate;
    x: number;
    y: number;
  } | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(800);

  // Measure container width for responsive SVG
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 0) {
          setContainerWidth(Math.floor(entry.contentRect.width));
        }
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Demo synthetic baseline scans for temporal trend demonstration when real scan count is small
  const demoScans = useMemo<ScanRecordDoc[]>(() => {
    if (!includeDemoBaseline && scans.length >= 8) return [];
    const simulated: ScanRecordDoc[] = [];
    const now = new Date();
    const seedPoints = [
      { daysAgo: 1, type: 'url' as const, score: 78, verdict: 'High Risk' as const, target: 'https://auth-sec-token-portal.top/login' },
      { daysAgo: 1, type: 'message' as const, score: 85, verdict: 'Malicious' as const, target: 'URGENT: Verify wallet seed phrase immediately' },
      { daysAgo: 2, type: 'url' as const, score: 12, verdict: 'Clean' as const, target: 'https://github.com' },
      { daysAgo: 3, type: 'ip' as const, score: 20, verdict: 'Low Risk' as const, target: '142.250.190.46' },
      { daysAgo: 4, type: 'url' as const, score: 92, verdict: 'Malicious' as const, target: 'http://paypal-security-update.xyz/verify' },
      { daysAgo: 6, type: 'message' as const, score: 65, verdict: 'High Risk' as const, target: 'Your parcel delivery has unpaid customs duty fee' },
      { daysAgo: 7, type: 'url' as const, score: 15, verdict: 'Low Risk' as const, target: 'http://neverssl.com' },
      { daysAgo: 9, type: 'url' as const, score: 35, verdict: 'Suspicious' as const, target: 'http://fast-cdn-redirector.click/ad' },
      { daysAgo: 12, type: 'message' as const, score: 88, verdict: 'Malicious' as const, target: 'Account suspension warning: Click to reset credentials' },
      { daysAgo: 14, type: 'url' as const, score: 10, verdict: 'Clean' as const, target: 'https://google.com' },
      { daysAgo: 18, type: 'ip' as const, score: 72, verdict: 'High Risk' as const, target: '185.220.101.5' },
      { daysAgo: 22, type: 'url' as const, score: 45, verdict: 'Suspicious' as const, target: 'https://secure-login-gateway.space/auth' },
      { daysAgo: 28, type: 'message' as const, score: 95, verdict: 'Malicious' as const, target: 'Wire transfer routing instructions update attached' },
      { daysAgo: 35, type: 'url' as const, score: 25, verdict: 'Suspicious' as const, target: 'http://link-short-cdn.io/p' },
      { daysAgo: 42, type: 'ip' as const, score: 80, verdict: 'High Risk' as const, target: '45.154.255.88' },
      { daysAgo: 49, type: 'url' as const, score: 15, verdict: 'Low Risk' as const, target: 'https://example.com' },
    ];

    seedPoints.forEach((pt, idx) => {
      const d = new Date(now.getTime() - pt.daysAgo * 86400000);
      simulated.push({
        scanId: `demo_seed_${idx}`,
        userId: 'demo',
        scanType: pt.type,
        target: pt.target,
        riskScore: pt.score,
        verdict: pt.verdict,
        summary: `Baseline simulated risk score ${pt.score}/100.`,
        analysisData: {},
        status: 'completed',
        createdAt: {
          toDate: () => d,
          toMillis: () => d.getTime(),
          seconds: Math.floor(d.getTime() / 1000),
          nanoseconds: 0,
        } as any,
      });
    });

    return simulated;
  }, [includeDemoBaseline, scans.length]);

  const allApplicableScans = useMemo(() => {
    return [...scans, ...demoScans];
  }, [scans, demoScans]);

  // Filter scans by risk score category ('all', 'high', 'medium', 'low')
  const filteredScansByRiskCategory = useMemo(() => {
    if (riskCategoryFilter === 'all') return allApplicableScans;
    return allApplicableScans.filter((scan) => {
      const score = scan.riskScore ?? 0;
      if (riskCategoryFilter === 'high') {
        return score >= 50;
      }
      if (riskCategoryFilter === 'medium') {
        return score >= 25 && score < 50;
      }
      if (riskCategoryFilter === 'low') {
        return score < 25;
      }
      return true;
    });
  }, [allApplicableScans, riskCategoryFilter]);

  // Aggregate scans by date string (YYYY-MM-DD)
  const dayAggregates = useMemo<Map<string, DayAggregate>>(() => {
    const map = new Map<string, DayAggregate>();

    filteredScansByRiskCategory.forEach((scan) => {
      let dateObj: Date | null = null;
      if (scan.createdAt?.toDate) {
        dateObj = scan.createdAt.toDate();
      } else if (scan.createdAt) {
        dateObj = new Date(scan.createdAt as any);
      }
      if (!dateObj || isNaN(dateObj.getTime())) {
        dateObj = new Date();
      }

      const dateStr = dateObj.toISOString().slice(0, 10);
      const existing = map.get(dateStr) || {
        dateStr,
        dateObj: new Date(dateStr + 'T00:00:00Z'),
        scans: [],
        count: 0,
        maxScore: 0,
        avgScore: 0,
        criticalCount: 0,
        highCount: 0,
        suspiciousCount: 0,
        cleanCount: 0,
        vectorMax: { url: 0, message: 0, ip: 0, screenshot: 0 },
        vectorCounts: { url: 0, message: 0, ip: 0, screenshot: 0 },
      };

      existing.scans.push(scan);
      existing.count += 1;
      existing.maxScore = Math.max(existing.maxScore, scan.riskScore);
      if (scan.riskScore >= 75) existing.criticalCount += 1;
      else if (scan.riskScore >= 50) existing.highCount += 1;
      else if (scan.riskScore >= 25) existing.suspiciousCount += 1;
      else existing.cleanCount += 1;

      const vectorKey = scan.scanType || 'url';
      existing.vectorCounts[vectorKey] = (existing.vectorCounts[vectorKey] || 0) + 1;
      existing.vectorMax[vectorKey] = Math.max(
        existing.vectorMax[vectorKey] || 0,
        scan.riskScore
      );

      map.set(dateStr, existing);
    });

    // Compute averages
    map.forEach((item) => {
      const sum = item.scans.reduce((acc, s) => acc + s.riskScore, 0);
      item.avgScore = item.scans.length > 0 ? Math.round(sum / item.scans.length) : 0;
    });

    return map;
  }, [filteredScansByRiskCategory]);

  // Overall Temporal Analytics
  const temporalStats = useMemo(() => {
    const now = new Date();
    const activeDays = Array.from(dayAggregates.values());

    let peakScore = 0;
    let peakDate: string | null = null;
    let totalScoreSum = 0;
    let totalScanCount = 0;
    let highRiskDays = 0;
    let cleanDays = 0;

    activeDays.forEach((day) => {
      if (day.maxScore > peakScore) {
        peakScore = day.maxScore;
        peakDate = day.dateStr;
      }
      totalScoreSum += day.scans.reduce((a, b) => a + b.riskScore, 0);
      totalScanCount += day.count;
      if (day.maxScore >= 50) highRiskDays += 1;
      else if (day.maxScore < 25) cleanDays += 1;
    });

    // Compare recent 14 days vs prior 14 days for trend direction
    const d14Ago = new Date(now.getTime() - 14 * 86400000).toISOString().slice(0, 10);
    const d28Ago = new Date(now.getTime() - 28 * 86400000).toISOString().slice(0, 10);

    let recentSum = 0;
    let recentCount = 0;
    let priorSum = 0;
    let priorCount = 0;

    activeDays.forEach((d) => {
      if (d.dateStr >= d14Ago) {
        recentSum += d.scans.reduce((a, b) => a + b.riskScore, 0);
        recentCount += d.count;
      } else if (d.dateStr >= d28Ago) {
        priorSum += d.scans.reduce((a, b) => a + b.riskScore, 0);
        priorCount += d.count;
      }
    });

    const recentAvg = recentCount > 0 ? recentSum / recentCount : 0;
    const priorAvg = priorCount > 0 ? priorSum / priorCount : 0;
    const delta = priorAvg > 0 ? ((recentAvg - priorAvg) / priorAvg) * 100 : 0;

    return {
      peakScore,
      peakDate,
      totalScans: totalScanCount,
      overallAvg: totalScanCount > 0 ? Math.round(totalScoreSum / totalScanCount) : 0,
      highRiskDays,
      cleanDays,
      activeDaysCount: activeDays.length,
      trendPercent: Math.round(delta),
      isEscalating: recentAvg > priorAvg && recentCount > 0,
      recentAvg: Math.round(recentAvg),
    };
  }, [dayAggregates]);

  // Color Interpolator for Security Risk (0=Clean/Emerald -> 50=Amber -> 80=Orange -> 100=Crimson/Red)
  const getSecurityColor = (val: number, metricType: HeatmapMetric, count: number) => {
    if (count === 0) return '#1e293b'; // slate-800 empty
    if (metricType === 'scanCount') {
      // Activity density: soft emerald to deep emerald/cyan
      const countScale = d3
        .scaleSequential(d3.interpolateBlues)
        .domain([1, Math.max(5, ...Array.from(dayAggregates.values()).map((d) => d.count))]);
      return countScale(val);
    }
    // Risk Score: 0 to 100
    if (val < 25) return '#10b981'; // emerald-500
    if (val < 50) return '#eab308'; // yellow-500
    if (val < 75) return '#f97316'; // orange-500
    return '#dc2626'; // red-600
  };

  // Render D3 Heatmap
  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove(); // Clear previous render

    const width = Math.max(containerWidth, 680);
    const now = new Date();

    if (view === 'calendar') {
      // =====================================================================
      // 1. CALENDAR VIEW (Rolling Days Grid, grouped by weeks and days)
      // =====================================================================
      const numDays = timeWindowDays;
      const cellSize = Math.max(14, Math.min(22, Math.floor((width - 90) / Math.ceil(numDays / 7))));
      const cellGap = 3;
      const leftMargin = 40;
      const topMargin = 30;

      // Generate date array from (now - numDays) up to today
      const dates: Date[] = [];
      for (let i = numDays - 1; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 86400000);
        dates.push(d);
      }

      // Calculate week indices and day-of-week (0=Sun, 1=Mon, ..., 6=Sat)
      const firstDate = dates[0];
      const startDayOfWeek = firstDate.getDay(); // 0-6

      // Group by weeks
      const gridData = dates.map((d, index) => {
        const offsetIndex = index + startDayOfWeek;
        const weekIndex = Math.floor(offsetIndex / 7);
        const dayOfWeek = d.getDay(); // 0 to 6
        const dateStr = d.toISOString().slice(0, 10);
        const aggregate = dayAggregates.get(dateStr) || {
          dateStr,
          dateObj: d,
          scans: [],
          count: 0,
          maxScore: 0,
          avgScore: 0,
          criticalCount: 0,
          highCount: 0,
          suspiciousCount: 0,
          cleanCount: 0,
          vectorMax: {},
          vectorCounts: {},
        };
        return {
          d,
          dateStr,
          weekIndex,
          dayOfWeek,
          aggregate,
        };
      });

      const totalWeeks = Math.max(...gridData.map((g) => g.weekIndex)) + 1;
      const svgHeight = topMargin + 7 * (cellSize + cellGap) + 30;

      svg
        .attr('viewBox', `0 0 ${Math.max(width, leftMargin + totalWeeks * (cellSize + cellGap) + 30)} ${svgHeight}`)
        .attr('width', '100%')
        .attr('height', svgHeight);

      const g = svg.append('g').attr('transform', `translate(${leftMargin}, ${topMargin})`);

      // Day-of-week labels (Mon, Wed, Fri)
      const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      [1, 3, 5].forEach((dayIdx) => {
        g.append('text')
          .attr('x', -8)
          .attr('y', dayIdx * (cellSize + cellGap) + cellSize / 2)
          .attr('text-anchor', 'end')
          .attr('alignment-baseline', 'middle')
          .attr('font-size', '10px')
          .attr('font-family', 'sans-serif')
          .attr('fill', '#94a3b8')
          .text(dayNames[dayIdx]);
      });

      // Month labels on top axis
      let lastMonth = -1;
      gridData.forEach((item) => {
        const m = item.d.getMonth();
        if (m !== lastMonth && item.dayOfWeek === 1) {
          lastMonth = m;
          const monthName = item.d.toLocaleString('default', { month: 'short' });
          g.append('text')
            .attr('x', item.weekIndex * (cellSize + cellGap))
            .attr('y', -10)
            .attr('font-size', '11px')
            .attr('font-weight', '600')
            .attr('font-family', 'sans-serif')
            .attr('fill', '#64748b')
            .text(monthName);
        }
      });

      // Render Day Cells
      const cells = g
        .selectAll('.day-cell')
        .data(gridData)
        .enter()
        .append('rect')
        .attr('class', 'day-cell')
        .attr('x', (d) => d.weekIndex * (cellSize + cellGap))
        .attr('y', (d) => d.dayOfWeek * (cellSize + cellGap))
        .attr('width', cellSize)
        .attr('height', cellSize)
        .attr('rx', 3)
        .attr('ry', 3)
        .attr('fill', (d) => {
          const val =
            metric === 'maxRisk'
              ? d.aggregate.maxScore
              : metric === 'avgRisk'
                ? d.aggregate.avgScore
                : d.aggregate.count;
          return getSecurityColor(val, metric, d.aggregate.count);
        })
        .attr('stroke', (d) => {
          if (selectedDate === d.dateStr) return '#38bdf8'; // bright cyan selected ring
          if (d.aggregate.count > 0 && d.aggregate.maxScore >= 75) return '#f43f5e';
          return d.aggregate.count > 0 ? '#475569' : '#1e293b';
        })
        .attr('stroke-width', (d) => (selectedDate === d.dateStr ? 2.5 : 1))
        .attr('cursor', (d) => (d.aggregate.count > 0 ? 'pointer' : 'default'))
        .style('transition', 'all 0.15s ease-in-out');

      // Interactivity & Tooltips
      cells
        .on('mouseenter', function (event, d) {
          d3.select(this)
            .attr('stroke', '#0f172a')
            .attr('stroke-width', 2.5)
            .style('filter', 'drop-shadow(0 2px 4px rgba(0,0,0,0.15))');

          const bounds = svgRef.current?.getBoundingClientRect();
          if (bounds) {
            setHoveredDay({
              data: d.aggregate,
              x: event.clientX,
              y: event.clientY,
            });
          }
        })
        .on('mousemove', function (event) {
          setHoveredDay((prev) => (prev ? { ...prev, x: event.clientX, y: event.clientY } : null));
        })
        .on('mouseleave', function (_event, d) {
          d3.select(this)
            .attr('stroke', selectedDate === d.dateStr ? '#0f172a' : d.aggregate.count > 0 && d.aggregate.maxScore >= 75 ? '#f43f5e' : d.aggregate.count > 0 ? '#cbd5e1' : '#e2e8f0')
            .attr('stroke-width', selectedDate === d.dateStr ? 2.5 : 1)
            .style('filter', 'none');
          setHoveredDay(null);
        })
        .on('click', (_event, d) => {
          if (d.aggregate.count > 0) {
            onSelectDate(selectedDate === d.dateStr ? null : d.dateStr);
          }
        });
    } else {
      // =====================================================================
      // 2. VECTOR MATRIX VIEW (Threat Vectors vs Dates)
      // =====================================================================
      const vectors: { key: string; label: string }[] = [
        { key: 'url', label: 'URL / Domain' },
        { key: 'message', label: 'Phishing Message' },
        { key: 'ip', label: 'Public IP / DNSBL' },
        { key: 'screenshot', label: 'Visual Screenshot' },
      ];

      const daysToShow = Math.min(30, timeWindowDays);
      const activeDateStrs: string[] = [];
      for (let i = daysToShow - 1; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 86400000);
        activeDateStrs.push(d.toISOString().slice(0, 10));
      }

      const leftMargin = 120;
      const topMargin = 35;
      const cellW = Math.max(16, Math.floor((width - leftMargin - 40) / daysToShow));
      const cellH = 26;
      const cellGap = 3;
      const svgHeight = topMargin + vectors.length * (cellH + cellGap) + 40;

      svg
        .attr('viewBox', `0 0 ${width} ${svgHeight}`)
        .attr('width', '100%')
        .attr('height', svgHeight);

      const g = svg.append('g').attr('transform', `translate(${leftMargin}, ${topMargin})`);

      // Vector row labels
      vectors.forEach((vec, idx) => {
        g.append('text')
          .attr('x', -10)
          .attr('y', idx * (cellH + cellGap) + cellH / 2)
          .attr('text-anchor', 'end')
          .attr('alignment-baseline', 'middle')
          .attr('font-size', '11px')
          .attr('font-weight', '500')
          .attr('font-family', 'sans-serif')
          .attr('fill', '#475569')
          .text(vec.label);
      });

      // Date column labels (every 3rd or 4th day)
      activeDateStrs.forEach((dateStr, idx) => {
        if (idx % Math.ceil(daysToShow / 10) === 0 || idx === activeDateStrs.length - 1) {
          const shortDate = dateStr.slice(5); // MM-DD
          g.append('text')
            .attr('x', idx * (cellW + cellGap) + cellW / 2)
            .attr('y', -8)
            .attr('text-anchor', 'middle')
            .attr('font-size', '10px')
            .attr('font-family', 'sans-serif')
            .attr('fill', '#94a3b8')
            .text(shortDate);
        }
      });

      // Matrix Cells
      vectors.forEach((vec, rowIdx) => {
        activeDateStrs.forEach((dateStr, colIdx) => {
          const aggregate = dayAggregates.get(dateStr);
          const score = aggregate?.vectorMax[vec.key] ?? 0;
          const count = aggregate?.vectorCounts[vec.key] ?? 0;

          const rect = g
            .append('rect')
            .attr('x', colIdx * (cellW + cellGap))
            .attr('y', rowIdx * (cellH + cellGap))
            .attr('width', cellW)
            .attr('height', cellH)
            .attr('rx', 3)
            .attr('ry', 3)
            .attr('fill', getSecurityColor(score, 'maxRisk', count))
            .attr('stroke', selectedDate === dateStr ? '#0f172a' : count > 0 ? '#cbd5e1' : '#f1f5f9')
            .attr('stroke-width', selectedDate === dateStr ? 2.5 : 1)
            .attr('cursor', count > 0 ? 'pointer' : 'default');

          if (count > 0) {
            rect
              .on('mouseenter', function (event) {
                d3.select(this).attr('stroke', '#0f172a').attr('stroke-width', 2);
                if (aggregate) {
                  setHoveredDay({
                    data: aggregate,
                    x: event.clientX,
                    y: event.clientY,
                  });
                }
              })
              .on('mousemove', (event) => {
                setHoveredDay((prev) => (prev ? { ...prev, x: event.clientX, y: event.clientY } : null));
              })
              .on('mouseleave', function () {
                d3.select(this)
                  .attr('stroke', selectedDate === dateStr ? '#0f172a' : '#cbd5e1')
                  .attr('stroke-width', selectedDate === dateStr ? 2.5 : 1);
                setHoveredDay(null);
              })
              .on('click', () => {
                onSelectDate(selectedDate === dateStr ? null : dateStr);
              });
          }
        });
      });
    }
  }, [
    dayAggregates,
    containerWidth,
    metric,
    view,
    timeWindowDays,
    selectedDate,
    riskCategoryFilter,
  ]);

  // Scans belonging to selected date for quick ledger preview
  const selectedDateScans = useMemo(() => {
    if (!selectedDate) return [];
    return dayAggregates.get(selectedDate)?.scans || [];
  }, [selectedDate, dayAggregates]);

  return (
    <div className="bg-[#0b1325] border border-slate-800 rounded-xl p-6 space-y-6 text-white shadow-xs">
      {/* 1. Header & Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Calendar className="w-5 h-5 text-emerald-400" />
            <h3 className="text-lg font-bold text-white font-display">
              Temporal Risk Heatmap & Threat Velocity
            </h3>
            <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 font-semibold border border-emerald-800">
              D3 Engine
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Categorizes historical scan severity over time. Hover cells to reveal daily risk
            distributions or click any date to filter the audit ledger below.
          </p>
        </div>

        {/* Heatmap Tooling Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* View Mode Toggle */}
          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-900/60 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setView('calendar')}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                view === 'calendar'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
              title="Calendar Grid View"
            >
              <Calendar className="w-3.5 h-3.5" />
              <span>Calendar</span>
            </button>
            <button
              type="button"
              onClick={() => setView('vectorMatrix')}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                view === 'vectorMatrix'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
              title="Threat Vectors vs Date Matrix"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Vector Matrix</span>
            </button>
          </div>

          {/* Metric Selector */}
          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-900/60 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setMetric('maxRisk')}
              className={`px-2 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                metric === 'maxRisk'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              Peak Risk
            </button>
            <button
              type="button"
              onClick={() => setMetric('avgRisk')}
              className={`px-2 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                metric === 'avgRisk'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              Avg Score
            </button>
            <button
              type="button"
              onClick={() => setMetric('scanCount')}
              className={`px-2 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                metric === 'scanCount'
                  ? 'bg-blue-600 text-white shadow-xs font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              Scan Volume
            </button>
          </div>

          {/* Risk Score Category Dropdown Filter */}
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={riskCategoryFilter}
              onChange={(e) => handleRiskCategoryChange(e.target.value as RiskCategoryFilter)}
              className="text-xs bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer"
              title="Toggle Risk Score Category Filter"
              aria-label="Filter by Risk Score Category"
            >
              <option value="all" className="bg-slate-900 text-white">All Categories</option>
              <option value="high" className="bg-slate-900 text-white">High Risk (50–100)</option>
              <option value="medium" className="bg-slate-900 text-white">Medium Risk (25–49)</option>
              <option value="low" className="bg-slate-900 text-white">Low Risk (0–24)</option>
            </select>
          </div>

          {/* Time Window Dropdown */}
          <select
            value={timeWindowDays}
            onChange={(e) => setTimeWindowDays(Number(e.target.value))}
            className="text-xs bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value={30} className="bg-slate-900 text-white">Past 30 Days</option>
            <option value={60} className="bg-slate-900 text-white">Past 60 Days</option>
            <option value={90} className="bg-slate-900 text-white">Past 90 Days</option>
          </select>

          {/* Synthetic Baseline Toggle */}
          <button
            type="button"
            onClick={() => setIncludeDemoBaseline(!includeDemoBaseline)}
            className={`px-2.5 py-1 text-xs font-medium rounded-lg border transition-colors cursor-pointer flex items-center gap-1.5 ${
              includeDemoBaseline
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

      {/* Active Category Filter Callout */}
      {riskCategoryFilter !== 'all' && (
        <div className="flex items-center justify-between px-3.5 py-2 bg-slate-900/60 border border-slate-800 rounded-lg text-xs text-slate-300">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-blue-400" />
            <span>
              Category Filter Active: <strong className="uppercase text-white">{riskCategoryFilter}</strong> ({filteredScansByRiskCategory.length} matching scans displayed)
            </span>
          </div>
          <button
            type="button"
            onClick={() => handleRiskCategoryChange('all')}
            className="text-xs font-medium text-blue-400 hover:text-blue-300 cursor-pointer flex items-center gap-1 underline"
          >
            <X className="w-3 h-3" />
            <span>Reset to All Categories</span>
          </button>
        </div>
      )}

      {/* 2. Top Metric Cards: Temporal Trend Telemetry */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Trend Indicator */}
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-400 uppercase">
              14-Day Velocity
            </span>
            {temporalStats.isEscalating ? (
              <TrendingUp className="w-4 h-4 text-red-400" />
            ) : (
              <TrendingDown className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-xl font-bold font-mono ${
                temporalStats.isEscalating ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {temporalStats.trendPercent > 0 ? `+${temporalStats.trendPercent}%` : `${temporalStats.trendPercent}%`}
            </span>
            <span className="text-[11px] text-slate-400">
              {temporalStats.isEscalating ? 'Escalating Threat' : 'Cooling Trend'}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">
            Current avg: {temporalStats.recentAvg}/100 vs prior period
          </p>
        </div>

        {/* Peak Threat Spike */}
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-400 uppercase">
              Peak Historical Threat
            </span>
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-rose-400">
              {temporalStats.peakScore}/100
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              {temporalStats.peakDate || 'None'}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Highest severity logged across timeline</p>
        </div>

        {/* High Risk Days Count */}
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-400 uppercase">
              Elevated Threat Days
            </span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-amber-400">
              {temporalStats.highRiskDays}
            </span>
            <span className="text-[11px] text-slate-400">
              of {temporalStats.activeDaysCount} active days
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Days with max risk score ≥ 50/100</p>
        </div>

        {/* Clean Days Inoculation */}
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-slate-400 uppercase">
              Verified Clean Days
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-emerald-400">
              {temporalStats.cleanDays}
            </span>
            <span className="text-[11px] text-slate-400">Days</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">100% benign / verified clean telemetry</p>
        </div>
      </div>

      {/* 3. D3 SVG Heatmap Container */}
      <div ref={containerRef} className="relative overflow-x-auto pt-2">
        <svg ref={svgRef} className="w-full block select-none" />

        {/* Selected Date Filter Banner */}
        {selectedDate && (
          <div className="mt-3 p-3 bg-blue-950/40 border border-blue-800 rounded-lg flex items-center justify-between text-xs text-blue-300">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-blue-400" />
              <span>
                <strong>Filtering Ledger by Date:</strong> {selectedDate} ({selectedDateScans.length} scans found)
              </span>
            </div>
            <button
              type="button"
              onClick={() => onSelectDate(null)}
              className="inline-flex items-center gap-1 font-semibold text-blue-400 hover:text-white px-2 py-0.5 rounded hover:bg-blue-900/50 transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              <span>Reset Date Filter</span>
            </button>
          </div>
        )}

        {/* Dynamic Floating D3 Tooltip */}
        {hoveredDay && (
          <div
            className="fixed z-50 pointer-events-none bg-[#070d19] text-white rounded-lg p-3 shadow-2xl text-xs space-y-1.5 border border-slate-700 max-w-xs transition-opacity duration-75"
            style={{
              left: `${hoveredDay.x + 14}px`,
              top: `${hoveredDay.y - 12}px`,
            }}
          >
            <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1">
              <span className="font-bold text-white">{hoveredDay.data.dateStr}</span>
              <span className="font-mono text-[10px] text-slate-400">
                {hoveredDay.data.count} scan{hoveredDay.data.count === 1 ? '' : 's'}
              </span>
            </div>

            {hoveredDay.data.count > 0 ? (
              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Peak Risk Score:</span>
                  <span
                    className={`font-mono font-bold ${
                      hoveredDay.data.maxScore >= 75
                        ? 'text-red-400'
                        : hoveredDay.data.maxScore >= 50
                          ? 'text-orange-400'
                          : hoveredDay.data.maxScore >= 25
                            ? 'text-amber-300'
                            : 'text-emerald-400'
                    }`}
                  >
                    {hoveredDay.data.maxScore}/100
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Average Risk Score:</span>
                  <span className="font-mono text-slate-200">{hoveredDay.data.avgScore}/100</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Risk Severity Breakdown:</span>
                  <span className="font-mono text-[10px] text-slate-300">
                    {hoveredDay.data.criticalCount > 0 && `${hoveredDay.data.criticalCount} Crit · `}
                    {hoveredDay.data.highCount > 0 && `${hoveredDay.data.highCount} High · `}
                    {hoveredDay.data.suspiciousCount > 0 && `${hoveredDay.data.suspiciousCount} Susp · `}
                    {hoveredDay.data.cleanCount} Clean
                  </span>
                </div>
                <div className="pt-1 text-[10px] text-blue-400 border-t border-slate-800 font-sans">
                  Click cell to filter ledger below to this date
                </div>
              </div>
            ) : (
              <p className="text-[11px] text-slate-400">No scans logged on this date.</p>
            )}
          </div>
        )}
      </div>

      {/* 4. Heatmap Legend */}
      <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800 gap-2">
        <div className="flex items-center gap-2">
          <span>Risk Level:</span>
          <div className={`flex items-center gap-1.5 transition-opacity ${riskCategoryFilter !== 'all' ? 'opacity-40' : ''}`}>
            <span className="w-3.5 h-3.5 rounded bg-slate-800 border border-slate-700 inline-block" />
            <span className="text-[11px]">0 Scans</span>
          </div>
          <div className={`flex items-center gap-1.5 transition-opacity ${riskCategoryFilter !== 'all' && riskCategoryFilter !== 'low' ? 'opacity-30' : ''}`}>
            <span className="w-3.5 h-3.5 rounded bg-emerald-500 inline-block" />
            <span className="text-[11px]">Clean / Low (0-24)</span>
          </div>
          <div className={`flex items-center gap-1.5 transition-opacity ${riskCategoryFilter !== 'all' && riskCategoryFilter !== 'medium' ? 'opacity-30' : ''}`}>
            <span className="w-3.5 h-3.5 rounded bg-yellow-500 inline-block" />
            <span className="text-[11px]">Medium (25-49)</span>
          </div>
          <div className={`flex items-center gap-1.5 transition-opacity ${riskCategoryFilter !== 'all' && riskCategoryFilter !== 'high' ? 'opacity-30' : ''}`}>
            <span className="w-3.5 h-3.5 rounded bg-orange-500 inline-block" />
            <span className="text-[11px]">High (50-74)</span>
          </div>
          <div className={`flex items-center gap-1.5 transition-opacity ${riskCategoryFilter !== 'all' && riskCategoryFilter !== 'high' ? 'opacity-30' : ''}`}>
            <span className="w-3.5 h-3.5 rounded bg-red-600 inline-block" />
            <span className="text-[11px]">Critical (75-100)</span>
          </div>
        </div>

        <div className="text-[11px] text-slate-500 font-mono">
          Showing {timeWindowDays} days temporal horizon · Active vectors: URL, Message, IP, Screenshot
          {riskCategoryFilter !== 'all' && ` · Filter: ${riskCategoryFilter.toUpperCase()}`}
        </div>
      </div>
    </div>
  );
};
