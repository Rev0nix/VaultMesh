import { useEffect, useState } from 'react';
import { Scale, CheckCircle2, XCircle, Info } from 'lucide-react';
import { complianceApi } from '../services/api';

export default function CompliancePage() {
  const [data, setData] = useState<Awaited<ReturnType<typeof complianceApi.getSummary>> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    complianceApi
      .getSummary()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-xs text-slate-400 animate-pulse">Evaluating compliance controls...</div>;
  if (!data) return null;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Compliance Framework Mapping</h1>
        <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          {data.disclaimer}
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Control Readiness</span>
          <div className="text-3xl font-bold font-mono text-cyan-400 mt-1">{data.summary.readiness_percentage}%</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Mapped Controls</span>
          <div className="text-3xl font-bold font-mono text-white mt-1">{data.summary.total_controls}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Passing Controls</span>
          <div className="text-3xl font-bold font-mono text-emerald-400 mt-1">{data.summary.passing_controls}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Failing Controls</span>
          <div className="text-3xl font-bold font-mono text-rose-400 mt-1">{data.summary.failing_controls}</div>
        </div>
      </div>

      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 space-y-3">
        <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <Scale className="w-4 h-4 text-cyan-400" /> Mapped Controls
        </h2>
        {data.controls.map((c) => (
          <div
            key={`${c.framework}-${c.control_id}`}
            className="p-4 rounded-xl bg-[#070D19] border border-slate-800 flex flex-wrap items-center justify-between gap-4"
          >
            <div>
              <div className="flex items-center gap-2 text-[11px] font-mono">
                <span className="text-cyan-400">{c.framework}</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-300">{c.control_id}</span>
              </div>
              <p className="text-sm font-medium text-white mt-1">{c.title}</p>
            </div>
            <span
              className={`px-3 py-1 rounded-full font-mono text-xs font-semibold inline-flex items-center gap-1.5 border ${
                c.status === 'PASS'
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
              }`}
            >
              {c.status === 'PASS' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
              {c.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
