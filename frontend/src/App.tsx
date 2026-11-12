import { useEffect, useState } from 'react';
import { Shield, CheckCircle2, AlertTriangle, Server } from 'lucide-react';

interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
  aws_mode: string;
  timestamp: string;
}

export default function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('http://localhost:8000/api/v1/health')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data: HealthStatus) => setHealth(data))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <div className="min-h-screen bg-[#070D19] text-slate-100 flex items-center justify-center p-6">
      <div className="max-w-lg w-full bg-[#0E172A] border border-slate-800 rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">VaultMesh</h1>
            <p className="text-xs text-cyan-400 font-medium">
              Secure Your Cloud. Detect Threats. Control Everything.
            </p>
          </div>
        </div>

        <div className="bg-[#070D19] border border-slate-800/80 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Backend Telemetry Link
            </span>
            {health ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded-full border border-amber-500/20">
                <AlertTriangle className="w-3.5 h-3.5" /> Offline
              </span>
            )}
          </div>

          {health ? (
            <dl className="grid grid-cols-2 gap-3 text-sm mt-4">
              <div>
                <dt className="text-slate-500 text-xs">API Version</dt>
                <dd className="font-mono text-slate-200">{health.version}</dd>
              </div>
              <div>
                <dt className="text-slate-500 text-xs">AWS Mode</dt>
                <dd className="font-mono text-cyan-400 uppercase">{health.aws_mode}</dd>
              </div>
              <div className="col-span-2">
                <dt className="text-slate-500 text-xs">UTC Heartbeat</dt>
                <dd className="font-mono text-xs text-slate-300">{health.timestamp}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-xs text-slate-400 mt-2">
              Waiting for FastAPI on <code className="text-cyan-400">localhost:8000</code>
              {error ? ` (${error})` : '...'}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
