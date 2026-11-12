import { useEffect, useState, type FormEvent } from 'react';
import {
  Cloud,
  Plus,
  CheckCircle2,
  RefreshCw,
  Trash2,
  ShieldCheck,
  KeyRound,
  AlertCircle,
  Copy,
  Check,
} from 'lucide-react';
import { accountsApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { AWSAccount } from '../types';

interface CloudAccountsPageProps {
  accounts: AWSAccount[];
  onAccountsChanged: () => Promise<void>;
}

export default function CloudAccountsPage({
  accounts,
  onAccountsChanged,
}: CloudAccountsPageProps) {
  const { user } = useAuth();
  const [mode, setMode] = useState<'mock' | 'live'>('mock');
  const [awsAccountId, setAwsAccountId] = useState('123456789012');
  const [alias, setAlias] = useState('AWS Security Sandbox (Mock)');
  const [roleArn, setRoleArn] = useState('');
  const [externalId, setExternalId] = useState('');
  const [defaultRegion, setDefaultRegion] = useState('ap-south-1');
  const [permissionsJson, setPermissionsJson] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);
  const [validatingId, setValidatingId] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    accountsApi
      .getOnboardingTemplate()
      .then((tpl) => {
        setExternalId(tpl.generated_external_id);
        setPermissionsJson(JSON.stringify(tpl.permissions_policy, null, 2));
      })
      .catch(() => {});
  }, []);

  const handleModeSwitch = (nextMode: 'mock' | 'live') => {
    setMode(nextMode);
    setFeedback(null);
    if (nextMode === 'mock') {
      setAwsAccountId('123456789012');
      setAlias('AWS Security Sandbox (Mock)');
      setRoleArn('');
    } else {
      setAwsAccountId('');
      setAlias('Production AWS Account');
    }
  };

  const handleConnect = async (e: FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    setSubmitting(true);
    try {
      await accountsApi.create({
        aws_account_id: awsAccountId.trim(),
        alias: alias.trim(),
        is_mock: mode === 'mock',
        role_arn: mode === 'live' ? roleArn.trim() : undefined,
        external_id: externalId || undefined,
        default_region: defaultRegion,
        regions: [defaultRegion, 'us-east-1'],
      });
      setFeedback({
        type: 'ok',
        text: `Account ${awsAccountId} connected and verified via STS!`,
      });
      await onAccountsChanged();
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : 'Failed to connect account',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevalidate = async (id: number) => {
    setValidatingId(id);
    setFeedback(null);
    try {
      const res = await accountsApi.validate(id);
      setFeedback({ type: 'ok', text: `${res.message} (${res.caller_arn})` });
      await onAccountsChanged();
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : 'Validation failed',
      });
    } finally {
      setValidatingId(null);
    }
  };

  const handleDelete = async (id: number) => {
    setFeedback(null);
    try {
      await accountsApi.remove(id);
      setFeedback({ type: 'ok', text: 'AWS account disconnected.' });
      await onAccountsChanged();
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : 'Failed to disconnect account',
      });
    }
  };

  const copyPolicy = () => {
    navigator.clipboard.writeText(permissionsJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Cloud Accounts &amp; AWS STS</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Onboard accounts using temporary STS AssumeRole credentials or ₹0 offline Sandbox Mock mode. Never enter AWS root keys.
        </p>
      </div>

      {feedback && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-center gap-2.5 ${
            feedback.type === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          {feedback.type === 'ok' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0" />
          )}
          <span>{feedback.text}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Connect Account Form */}
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            Connect AWS Account
          </h2>

          <div className="grid grid-cols-2 bg-[#070D19] p-1 rounded-xl border border-slate-800 mb-5">
            <button
              type="button"
              onClick={() => handleModeSwitch('mock')}
              className={`py-2 text-xs font-semibold rounded-lg transition cursor-pointer ${
                mode === 'mock'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sandbox Mock Mode (₹0)
            </button>
            <button
              type="button"
              onClick={() => handleModeSwitch('live')}
              className={`py-2 text-xs font-semibold rounded-lg transition cursor-pointer ${
                mode === 'live'
                  ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Live AWS IAM Role (STS)
            </button>
          </div>

          <form onSubmit={handleConnect} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-300 mb-1">12-Digit AWS Account ID</label>
                <input
                  type="text"
                  required
                  maxLength={12}
                  pattern="\d{12}"
                  value={awsAccountId}
                  onChange={(e) => setAwsAccountId(e.target.value)}
                  placeholder="123456789012"
                  className="w-full bg-[#070D19] border border-slate-800 rounded-xl px-3.5 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-300 mb-1">Primary Region</label>
                <select
                  value={defaultRegion}
                  onChange={(e) => setDefaultRegion(e.target.value)}
                  className="w-full bg-[#070D19] border border-slate-800 rounded-xl px-3.5 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="ap-south-1">ap-south-1 (Mumbai)</option>
                  <option value="us-east-1">us-east-1 (N. Virginia)</option>
                  <option value="eu-west-1">eu-west-1 (Ireland)</option>
                  <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-300 mb-1">Account Alias</label>
              <input
                type="text"
                required
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                placeholder="Production AWS"
                className="w-full bg-[#070D19] border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            {mode === 'live' && (
              <>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">IAM Role ARN</label>
                  <input
                    type="text"
                    required
                    value={roleArn}
                    onChange={(e) => setRoleArn(e.target.value)}
                    placeholder="arn:aws:iam::123456789012:role/VaultMeshSecurityAuditRole"
                    className="w-full bg-[#070D19] border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs text-slate-300 mb-1">
                    STS ExternalId (Confused Deputy Protection)
                  </label>
                  <input
                    type="text"
                    value={externalId}
                    onChange={(e) => setExternalId(e.target.value)}
                    className="w-full bg-[#070D19] border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </>
            )}

            <button
              type="submit"
              disabled={submitting || user?.role === 'VIEWER'}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-semibold py-2.5 rounded-xl text-xs flex items-center justify-center gap-2 transition cursor-pointer"
            >
              <ShieldCheck className="w-4 h-4" />
              {submitting ? 'Verifying STS Identity...' : 'Verify & Connect Account'}
            </button>
          </form>
        </div>

        {/* Right: Least-Privilege IAM Policy Reference */}
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-blue-400" />
              Least-Privilege Read-Only IAM Policy
            </h2>
            <button
              type="button"
              onClick={copyPolicy}
              className="text-xs px-2.5 py-1 rounded-lg bg-[#070D19] border border-slate-800 text-slate-300 hover:text-cyan-400 flex items-center gap-1.5 cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Attach this read-only policy to <code className="text-cyan-400">VaultMeshSecurityAuditRole</code> in AWS IAM. Zero write/delete permissions are requested.
          </p>
          <pre className="flex-1 bg-[#070D19] border border-slate-800 rounded-xl p-3.5 text-[11px] font-mono text-slate-300 overflow-auto max-h-64">
            {permissionsJson || 'Loading IAM policy template...'}
          </pre>
        </div>
      </div>

      {/* Connected Accounts Table */}
      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Cloud className="w-4 h-4 text-cyan-400" />
          Connected AWS Environments ({accounts.length})
        </h2>

        {accounts.length === 0 ? (
          <p className="text-xs text-slate-400 py-6 text-center">
            No AWS accounts connected yet. Use the form above to connect the Sandbox Mock account in one click!
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Alias</th>
                  <th className="py-2.5 px-3">Account ID</th>
                  <th className="py-2.5 px-3">Mode</th>
                  <th className="py-2.5 px-3">Primary Region</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {accounts.map((acc) => (
                  <tr key={acc.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-3 font-medium text-white">{acc.alias}</td>
                    <td className="py-3 px-3 font-mono text-slate-300">{acc.aws_account_id}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded-full font-mono text-[10px] border ${
                          acc.is_mock
                            ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                            : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                        }`}
                      >
                        {acc.is_mock ? 'MOCK SANDBOX' : 'LIVE STS'}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">{acc.default_region}</td>
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-mono">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {acc.connection_status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right space-x-2">
                      <button
                        onClick={() => handleRevalidate(acc.id)}
                        disabled={validatingId === acc.id}
                        title="Re-verify STS Connection"
                        className="px-2.5 py-1 rounded-lg bg-[#070D19] border border-slate-700 text-slate-200 hover:border-cyan-500 inline-flex items-center gap-1 cursor-pointer"
                      >
                        <RefreshCw
                          className={`w-3 h-3 ${validatingId === acc.id ? 'animate-spin text-cyan-400' : ''}`}
                        />
                        Validate
                      </button>
                      {user?.role === 'ADMIN' && (
                        <button
                          onClick={() => handleDelete(acc.id)}
                          title="Disconnect Account"
                          className="p-1.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 inline-flex items-center cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
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
