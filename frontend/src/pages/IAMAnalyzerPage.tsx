import { useEffect, useState } from 'react';
import { KeyRound, ShieldAlert, CheckCircle2, AlertTriangle } from 'lucide-react';
import { analyzersApi } from '../services/api';
import type { IAMAnalysisResponse } from '../types';

export default function IAMAnalyzerPage() {
  const [data, setData] = useState<IAMAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    analyzersApi
      .getIam()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-8 text-xs text-slate-400 animate-pulse">Analyzing IAM principals &amp; policies...</div>;
  }

  if (!data) return null;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">IAM Least-Privilege Analyzer</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Evaluates wildcard (*:*) permissions, administrative privilege blast radius, MFA enforcement, and trust policies.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">IAM Principals Scanned</span>
          <div className="text-3xl font-bold font-mono text-white mt-1">{data.summary.total_principals}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Wildcard / Admin Principals</span>
          <div className="text-3xl font-bold font-mono text-rose-400 mt-1">{data.summary.wildcard_admin_principals}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Console Users Missing MFA</span>
          <div className="text-3xl font-bold font-mono text-amber-400 mt-1">{data.summary.users_missing_mfa}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Risky Trust Policies</span>
          <div className="text-3xl font-bold font-mono text-cyan-400 mt-1">{data.summary.risky_trust_policies}</div>
        </div>
      </div>

      {data.principals.length === 0 ? (
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-10 text-center text-xs text-slate-400">
          No IAM principals discovered yet. Run a Security Scan from the Overview page first.
        </div>
      ) : (
        <div className="space-y-4">
          {data.principals.map((p) => (
            <div key={p.id} className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                    <KeyRound className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-bold text-white">{p.name}</h3>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {p.principal_type}
                      </span>
                      {p.is_mock && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300">
                          MOCK
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] font-mono text-slate-400 mt-0.5">{p.arn}</p>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-xs text-slate-400 block">Privilege Blast Radius</span>
                  <span
                    className={`font-mono text-sm font-bold ${
                      p.risk_level === 'CRITICAL'
                        ? 'text-rose-400'
                        : p.risk_level === 'HIGH'
                        ? 'text-orange-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {p.risk_score}/100 ({p.risk_level})
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-[#070D19] border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                    Detected Privilege Risks
                  </span>
                  {p.issues.length === 0 ? (
                    <p className="text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" /> Least-privilege compliant
                    </p>
                  ) : (
                    p.issues.map((iss, idx) => (
                      <p key={idx} className="text-rose-300 flex items-start gap-1.5">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" /> {iss}
                      </p>
                    ))
                  )}
                </div>

                <div className="bg-[#070D19] border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                    Least-Privilege Recommendations
                  </span>
                  {p.recommendations.map((rec, idx) => (
                    <p key={idx} className="text-slate-300 flex items-start gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" /> {rec}
                    </p>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
