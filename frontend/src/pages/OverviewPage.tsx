import { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
  Cloud,
  Boxes,
  AlertOctagon,
  AlertTriangle,
  Info,
  Activity,
  ArrowUpRight,
  Play,
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { dashboardApi, scansApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { AWSAccount, DashboardOverview, NavSection } from '../types';

interface OverviewPageProps {
  accounts: AWSAccount[];
  selectedAccountId: number | null;
  onNavigate: (section: NavSection) => void;
}

export default function OverviewPage({
  accounts,
  selectedAccountId,
  onNavigate,
}: OverviewPageProps) {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadOverview = useCallback(async () => {
    try {
      const res = await dashboardApi.getOverview();
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  const handleRunScan = async () => {
    const targetId = selectedAccountId ?? accounts[0]?.id;
    if (!targetId) {
      onNavigate('accounts');
      return;
    }
    setScanning(true);
    setError(null);
    try {
      await scansApi.run(targetId);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-slate-400 text-sm animate-pulse">
        Loading real-time security posture telemetry...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 m-6 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
        {error || 'Dashboard unavailable'}
      </div>
    );
  }

  const severityChartData = [
    { name: 'Critical', count: data.findings_by_severity.CRITICAL, fill: '#f43f5e' },
    { name: 'High', count: data.findings_by_severity.HIGH, fill: '#f97316' },
    { name: 'Medium', count: data.findings_by_severity.MEDIUM, fill: '#eab308' },
    { name: 'Low', count: data.findings_by_severity.LOW, fill: '#38bdf8' },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Posture Overview</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Live database telemetry • Default Mode:{' '}
            <span className="font-mono text-cyan-400 uppercase">{data.aws_mode}</span>
          </p>
        </div>

        {user?.role !== 'VIEWER' && (
          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-semibold text-xs flex items-center gap-2 transition shadow-lg shadow-cyan-500/20 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            {scanning
              ? 'Running Security Scan...'
              : accounts.length === 0
              ? 'Connect AWS Account'
              : 'Run Security Scan'}
          </button>
        )}
      </div>

      {!data.has_scan_data && (
        <div className="bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-transparent border border-cyan-500/30 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Ready for Your First CSPM Security Scan
            </h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl">
              {accounts.length === 0
                ? 'Step 1: Connect a Sandbox Mock AWS account (₹0) in Cloud Accounts. Step 2: Run a security scan to discover resources and calculate your Security Score.'
                : 'Your AWS account is connected! Click "Run Security Scan" above to discover S3, IAM, EC2, Security Group, EBS, and CloudTrail resources.'}
            </p>
          </div>
          {accounts.length === 0 && (
            <button
              onClick={() => onNavigate('accounts')}
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition cursor-pointer"
            >
              Go to Cloud Accounts <ArrowUpRight className="w-4 h-4" />
            </button>
          )}
        </div>
      )}

      {/* Top KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Overall Security Score</span>
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">
            {data.security_score !== null ? `${data.security_score}%` : 'N/A'}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {data.has_scan_data ? 'Weighted across open findings' : 'Awaiting initial scan'}
          </p>
        </div>

        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>AWS Accounts Connected</span>
            <Cloud className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">
            {data.aws_accounts_connected}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">STS Read-Only / Mock accounts</p>
        </div>

        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Monitored Resources</span>
            <Boxes className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">
            {data.monitored_resources}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">S3, IAM, EC2, VPC, CloudTrail</p>
        </div>

        <div
          onClick={() => onNavigate('findings')}
          className="bg-[#0E172A] border border-slate-800 hover:border-cyan-500/40 rounded-2xl p-5 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Open Security Findings</span>
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">
            {data.total_open_findings}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {data.findings_by_severity.CRITICAL} Critical • {data.findings_by_severity.HIGH} High
          </p>
        </div>
      </div>

      {/* Severity Breakdown & Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Open Findings by Severity
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#070D19',
                    borderColor: '#1e293b',
                    borderRadius: '12px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-white mb-2">Risk Distribution</h3>
          {[
            { label: 'Critical Risk', count: data.findings_by_severity.CRITICAL, color: 'text-rose-400 bg-rose-500/10 border-rose-500/20', icon: AlertOctagon },
            { label: 'High Risk', count: data.findings_by_severity.HIGH, color: 'text-orange-400 bg-orange-500/10 border-orange-500/20', icon: AlertTriangle },
            { label: 'Medium Risk', count: data.findings_by_severity.MEDIUM, color: 'text-amber-400 bg-amber-500/10 border-amber-500/20', icon: AlertTriangle },
            { label: 'Low Risk', count: data.findings_by_severity.LOW, color: 'text-sky-400 bg-sky-500/10 border-sky-500/20', icon: Info },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.label}
                onClick={() => onNavigate('findings')}
                className="flex items-center justify-between p-3 rounded-xl bg-[#070D19] border border-slate-800/80 hover:border-slate-700 cursor-pointer"
              >
                <span className="flex items-center gap-2.5 text-xs text-slate-300">
                  <span className={`p-1.5 rounded-lg border ${item.color}`}>
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  {item.label}
                </span>
                <span className="font-mono text-sm font-bold text-white">{item.count}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
