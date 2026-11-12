import { useEffect, useState } from 'react';
import { Network, Globe, ShieldAlert } from 'lucide-react';
import { analyzersApi } from '../services/api';
import type { NetworkAnalysisResponse } from '../types';

export default function NetworkSecurityPage() {
  const [data, setData] = useState<NetworkAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    analyzersApi
      .getNetwork()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-8 text-xs text-slate-400 animate-pulse">Analyzing VPC security group ingress rules...</div>;
  }

  if (!data) return null;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Network &amp; Security Group Analyzer</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Audits inbound firewall rules for 0.0.0.0/0 exposure across SSH (22), RDP (3389), and database ports.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">VPC Security Groups</span>
          <div className="text-3xl font-bold font-mono text-white mt-1">{data.summary.total_security_groups}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Public 0.0.0.0/0 Ingress Rules</span>
          <div className="text-3xl font-bold font-mono text-amber-400 mt-1">{data.summary.public_ingress_rules}</div>
        </div>
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-5">
          <span className="text-xs text-slate-400">Exposed Admin / DB Ports</span>
          <div className="text-3xl font-bold font-mono text-rose-400 mt-1">{data.summary.critical_admin_or_db_exposures}</div>
        </div>
      </div>

      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          Evaluated Ingress Rules ({data.ingress_rules.length})
        </h2>

        {data.ingress_rules.length === 0 ? (
          <p className="text-xs text-slate-400 py-6 text-center">
            No Security Group rules discovered yet. Run a Security Scan from Overview first.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Security Group</th>
                  <th className="py-2.5 px-3">Protocol / Port</th>
                  <th className="py-2.5 px-3">Service</th>
                  <th className="py-2.5 px-3">Source CIDR</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Guidance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.ingress_rules.map((rule, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="py-3 px-3">
                      <span className="font-semibold text-white block">{rule.security_group_name}</span>
                      <span className="font-mono text-[11px] text-slate-400">{rule.security_group_id}</span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-200">
                      {rule.protocol} : {rule.port_range}
                    </td>
                    <td className="py-3 px-3 font-mono text-cyan-300">{rule.service_label}</td>
                    <td className="py-3 px-3 font-mono">
                      <span className="inline-flex items-center gap-1 text-amber-300">
                        {rule.is_public && <Globe className="w-3.5 h-3.5 text-rose-400" />}
                        {rule.source_cidr}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded-full font-mono text-[10px] border ${
                          rule.risk_level === 'CRITICAL'
                            ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                            : rule.risk_level === 'HIGH'
                            ? 'bg-orange-500/15 text-orange-300 border-orange-500/30'
                            : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                        }`}
                      >
                        {rule.risk_level}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300 max-w-md">
                      <span className="inline-flex items-start gap-1.5">
                        <ShieldAlert className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                        {rule.recommendation}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
