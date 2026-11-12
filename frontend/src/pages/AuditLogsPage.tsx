import { useEffect, useState } from 'react';
import { ScrollText } from 'lucide-react';
import { auditApi } from '../services/api';

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<Awaited<ReturnType<typeof auditApi.getLogs>>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auditApi
      .getLogs()
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-xs text-slate-400 animate-pulse">Loading audit trail...</div>;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Immutable Audit Logs</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Chronological security record of authentication, AWS connections, security scans, finding transitions, and remediation approvals.
        </p>
      </div>

      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 overflow-x-auto">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <ScrollText className="w-4 h-4 text-cyan-400" /> Recorded Events ({logs.length})
        </h2>
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 px-3">Timestamp (UTC)</th>
              <th className="py-2.5 px-3">Actor</th>
              <th className="py-2.5 px-3">Action</th>
              <th className="py-2.5 px-3">Target</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                  {new Date(log.created_at).toLocaleString()}
                </td>
                <td className="py-2.5 px-3 text-slate-200">{log.actor_email}</td>
                <td className="py-2.5 px-3 font-mono text-cyan-300">{log.action}</td>
                <td className="py-2.5 px-3 font-mono text-slate-300">
                  {log.target_type}:{log.target_id}
                </td>
                <td className="py-2.5 px-3 font-mono text-slate-400">{log.ip_address}</td>
                <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                  {JSON.stringify(log.details)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
