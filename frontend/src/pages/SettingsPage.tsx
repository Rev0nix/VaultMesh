import { useEffect, useState } from 'react';
import { Users, ShieldCheck } from 'lucide-react';
import { auditApi } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function SettingsPage() {
  const { user } = useAuth();
  const [team, setTeam] = useState<Awaited<ReturnType<typeof auditApi.getTeam>>>([]);

  useEffect(() => {
    auditApi.getTeam().then(setTeam).catch(() => {});
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Organization &amp; RBAC Settings</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Manage Role-Based Access Control (ADMIN, SECURITY_ANALYST, VIEWER) and verify VaultMesh security controls.
        </p>
      </div>

      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" /> Organization Members ({team.length})
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Name</th>
                <th className="py-2.5 px-3">Email</th>
                <th className="py-2.5 px-3">RBAC Role</th>
                <th className="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {team.map((m) => (
                <tr key={m.id}>
                  <td className="py-2.5 px-3 text-white font-medium">
                    {m.full_name} {m.id === user?.id && <span className="text-cyan-400">(You)</span>}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{m.email}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                      {m.role}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-emerald-400 font-mono">
                    {m.is_active ? 'ACTIVE' : 'DISABLED'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 text-xs space-y-2">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" /> Active Platform Security Guardrails
        </h2>
        <p className="text-slate-300">• Password Hashing: <span className="font-mono text-cyan-300">bcrypt (12 rounds)</span></p>
        <p className="text-slate-300">• AWS Credential Strategy: <span className="font-mono text-cyan-300">STS Temporary Credentials + ExternalId (Zero static keys stored)</span></p>
        <p className="text-slate-300">• Remediation Safety: <span className="font-mono text-cyan-300">Dry-Run Default + Explicit Confirmation Gate</span></p>
      </div>
    </div>
  );
}
