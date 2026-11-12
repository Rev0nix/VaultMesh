import { useCallback, useEffect, useState } from 'react';
import {
  ShieldAlert,
  Filter,
  CheckCircle2,
  ShieldOff,
  RotateCcw,
  ExternalLink,
  Terminal,
  FileCode2,
  Play,
} from 'lucide-react';
import { findingsApi, scansApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { AWSAccount, Finding, FindingStatus } from '../types';

interface FindingsPageProps {
  accounts: AWSAccount[];
  selectedAccountId: number | null;
  globalSearch: string;
}

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  LOW: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  INFO: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

export default function FindingsPage({
  accounts,
  selectedAccountId,
  globalSearch,
}: FindingsPageProps) {
  const { user } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [serviceFilter, setServiceFilter] = useState('');
  const [notesDraft, setNotesDraft] = useState('');
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [updating, setUpdating] = useState(false);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    try {
      const list = await findingsApi.list({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        service: serviceFilter || undefined,
        search: globalSearch || undefined,
      });
      setFindings(list);
      if (list.length > 0) {
        setSelectedFinding((prev) => {
          const updated = prev ? list.find((f) => f.id === prev.id) : null;
          const target = updated || list[0];
          setNotesDraft(target.investigation_notes || '');
          return target;
        });
      } else {
        setSelectedFinding(null);
      }
    } finally {
      setLoading(false);
    }
  }, [severityFilter, statusFilter, serviceFilter, globalSearch]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  const handleRunScan = async () => {
    const targetId = selectedAccountId ?? accounts[0]?.id;
    if (!targetId) return;
    setScanning(true);
    try {
      await scansApi.run(targetId);
      await loadFindings();
    } finally {
      setScanning(false);
    }
  };

  const handleStatusUpdate = async (nextStatus: FindingStatus) => {
    if (!selectedFinding) return;
    setUpdating(true);
    try {
      const updated = await findingsApi.update(selectedFinding.id, {
        status: nextStatus,
        investigation_notes: notesDraft,
      });
      setSelectedFinding(updated);
      await loadFindings();
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Prioritized CSPM posture violations with evidence, CLI/Terraform fixes, and audit-logged status workflows.
          </p>
        </div>

        {accounts.length > 0 && user?.role !== 'VIEWER' && (
          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-semibold text-xs flex items-center gap-2 transition cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            {scanning ? 'Scanning Cloud Resources...' : 'Run Security Scan'}
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center gap-3 text-xs">
        <span className="text-slate-400 flex items-center gap-1.5 font-medium">
          <Filter className="w-3.5 h-3.5 text-cyan-400" /> Filters:
        </span>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#070D19] border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[#070D19] border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
          <option value="RISK_ACCEPTED">Risk Accepted</option>
        </select>

        <select
          value={serviceFilter}
          onChange={(e) => setServiceFilter(e.target.value)}
          className="bg-[#070D19] border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Services</option>
          <option value="S3">S3</option>
          <option value="IAM">IAM</option>
          <option value="EC2">EC2 &amp; VPC</option>
          <option value="CLOUDTRAIL">CloudTrail</option>
        </select>
      </div>

      {loading ? (
        <div className="text-xs text-slate-400 animate-pulse">Querying findings repository...</div>
      ) : findings.length === 0 ? (
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-10 text-center">
          <ShieldAlert className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
          <p className="text-sm font-semibold text-white">No Security Findings Match Your Filters</p>
          <p className="text-xs text-slate-400 mt-1">
            Connect an AWS account (Mock or Live) and click <strong>Run Security Scan</strong> to evaluate cloud posture rules.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          {/* Left List */}
          <div className="xl:col-span-6 space-y-2.5">
            {findings.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => {
                    setSelectedFinding(f);
                    setNotesDraft(f.investigation_notes || '');
                  }}
                  className={`p-4 rounded-2xl border transition cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/40'
                      : 'bg-[#0E172A] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                          SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO
                        }`}
                      >
                        {f.severity}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">{f.finding_uid}</span>
                      {f.is_mock && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                          MOCK
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#070D19] text-cyan-300 border border-slate-800">
                      {f.status}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-white">{f.title}</h3>
                  <p className="text-[11px] font-mono text-slate-400 truncate mt-1">
                    {f.resource.resource_arn}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Right Inspector Drawer */}
          {selectedFinding && (
            <div className="xl:col-span-6 bg-[#0E172A] border border-slate-800 rounded-2xl p-6 space-y-5 h-fit">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <span className="text-[11px] font-mono text-cyan-400">{selectedFinding.rule_id}</span>
                  <h2 className="text-base font-bold text-white mt-0.5">{selectedFinding.title}</h2>
                </div>
                {selectedFinding.aws_doc_url && (
                  <a
                    href={selectedFinding.aws_doc_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-cyan-400 hover:underline inline-flex items-center gap-1 shrink-0"
                  >
                    AWS Docs <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.description}</p>

              {/* Evidence JSON */}
              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Captured Configuration Evidence
                </h4>
                <pre className="bg-[#070D19] border border-slate-800 rounded-xl p-3 text-[11px] font-mono text-amber-300 overflow-x-auto">
                  {JSON.stringify(selectedFinding.evidence, null, 2)}
                </pre>
              </div>

              {/* CLI & Terraform Remediation */}
              {selectedFinding.remediation_cli && (
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" /> AWS CLI Remediation
                  </h4>
                  <pre className="bg-[#070D19] border border-slate-800 rounded-xl p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                    {selectedFinding.remediation_cli}
                  </pre>
                </div>
              )}

              {selectedFinding.remediation_terraform && (
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                    <FileCode2 className="w-3.5 h-3.5 text-blue-400" /> Terraform IaC Fix
                  </h4>
                  <pre className="bg-[#070D19] border border-slate-800 rounded-xl p-3 text-[11px] font-mono text-emerald-300 overflow-x-auto">
                    {selectedFinding.remediation_terraform}
                  </pre>
                </div>
              )}

              {/* Investigation Notes & Status Actions */}
              {user?.role !== 'VIEWER' && (
                <div className="pt-3 border-t border-slate-800 space-y-3">
                  <div>
                    <label className="block text-xs text-slate-300 mb-1">
                      Analyst Investigation Notes
                    </label>
                    <textarea
                      rows={2}
                      value={notesDraft}
                      onChange={(e) => setNotesDraft(e.target.value)}
                      placeholder="Document verification details or risk acceptance justification..."
                      className="w-full bg-[#070D19] border border-slate-800 rounded-xl p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      disabled={updating}
                      onClick={() => handleStatusUpdate('RESOLVED')}
                      className="px-3 py-1.5 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/30 text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" /> Mark Resolved
                    </button>
                    <button
                      disabled={updating}
                      onClick={() => handleStatusUpdate('RISK_ACCEPTED')}
                      className="px-3 py-1.5 rounded-xl bg-amber-500/20 border border-amber-500/30 text-amber-300 hover:bg-amber-500/30 text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                    >
                      <ShieldOff className="w-3.5 h-3.5" /> Accept Risk
                    </button>
                    <button
                      disabled={updating}
                      onClick={() => handleStatusUpdate('OPEN')}
                      className="px-3 py-1.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" /> Reopen
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
