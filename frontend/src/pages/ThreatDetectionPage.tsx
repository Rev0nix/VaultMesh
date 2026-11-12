import { useCallback, useEffect, useState } from 'react';
import { Radar, Play, AlertOctagon, Globe, UserCheck, Terminal } from 'lucide-react';
import { threatsApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { AWSAccount, ThreatEventItem } from '../types';

interface ThreatDetectionPageProps {
  accounts: AWSAccount[];
  selectedAccountId: number | null;
}

export default function ThreatDetectionPage({
  accounts,
  selectedAccountId,
}: ThreatDetectionPageProps) {
  const { user } = useAuth();
  const [threats, setThreats] = useState<ThreatEventItem[]>([]);
  const [selected, setSelected] = useState<ThreatEventItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);

  const loadThreats = useCallback(async () => {
    setLoading(true);
    try {
      const list = await threatsApi.list();
      setThreats(list);
      if (list.length > 0) {
        setSelected((prev) => (prev ? list.find((t) => t.id === prev.id) || list[0] : list[0]));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadThreats();
  }, [loadThreats]);

  const handleAnalyze = async () => {
    const targetId = selectedAccountId ?? accounts[0]?.id;
    if (!targetId) return;
    setAnalyzing(true);
    try {
      await threatsApi.analyze(targetId);
      await loadThreats();
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">CloudTrail Threat Detection</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Explainable rule-based behavioral detection across authentication spikes, CloudTrail tampering, and IAM privilege escalation.
          </p>
        </div>

        {accounts.length > 0 && user?.role !== 'VIEWER' && (
          <button
            onClick={handleAnalyze}
            disabled={analyzing}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-semibold text-xs flex items-center gap-2 transition cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            {analyzing ? 'Analyzing CloudTrail Stream...' : 'Analyze CloudTrail Events'}
          </button>
        )}
      </div>

      {loading ? (
        <div className="text-xs text-slate-400 animate-pulse">Loading CloudTrail threat telemetry...</div>
      ) : threats.length === 0 ? (
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-10 text-center">
          <Radar className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
          <p className="text-sm font-semibold text-white">No Threat Alerts Recorded Yet</p>
          <p className="text-xs text-slate-400 mt-1">
            Click <strong>Analyze CloudTrail Events</strong> to evaluate recent management events against behavioral detection rules.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          <div className="xl:col-span-6 space-y-3">
            {threats.map((t) => {
              const isSelected = selected?.id === t.id;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelected(t)}
                  className={`p-4 rounded-2xl border transition cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/40'
                      : 'bg-[#0E172A] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                        t.severity === 'CRITICAL'
                          ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                          : 'bg-orange-500/15 text-orange-300 border-orange-500/30'
                      }`}
                    >
                      {t.severity}
                    </span>
                    <span className="text-[11px] font-mono text-cyan-400">{t.rule_triggered}</span>
                  </div>
                  <h3 className="text-sm font-semibold text-white">{t.event_name}</h3>
                  <p className="text-xs text-slate-300 mt-1">{t.explanation}</p>
                  <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400 mt-2">
                    <span className="flex items-center gap-1">
                      <Globe className="w-3 h-3 text-rose-400" /> {t.source_ip}
                    </span>
                    <span>{t.region}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {selected && (
            <div className="xl:col-span-6 bg-[#0E172A] border border-slate-800 rounded-2xl p-6 space-y-4 h-fit">
              <div className="flex items-center gap-2 text-rose-400 text-xs font-mono">
                <AlertOctagon className="w-4 h-4" />
                {selected.rule_triggered}
              </div>
              <h2 className="text-base font-bold text-white">{selected.event_name}</h2>
              <p className="text-xs text-slate-300 leading-relaxed">{selected.explanation}</p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs bg-[#070D19] border border-slate-800 rounded-xl p-3.5">
                <div>
                  <span className="text-slate-500 block text-[11px]">Actor Principal ARN</span>
                  <span className="font-mono text-slate-200 break-all flex items-center gap-1 mt-0.5">
                    <UserCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    {selected.actor_arn}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Source IP Address</span>
                  <span className="font-mono text-amber-300 mt-0.5 block">{selected.source_ip}</span>
                </div>
              </div>

              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Raw CloudTrail Event Payload
                </h4>
                <pre className="bg-[#070D19] border border-slate-800 rounded-xl p-3.5 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-72">
                  {JSON.stringify(selected.raw_event, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
