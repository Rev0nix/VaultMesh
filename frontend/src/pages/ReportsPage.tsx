import { useState } from 'react';
import { FileBarChart2, FileText, FileJson, Download } from 'lucide-react';
import { reportsApi } from '../services/api';

export default function ReportsPage() {
  const [downloading, setDownloading] = useState<'pdf' | 'json' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async (fmt: 'pdf' | 'json') => {
    setDownloading(fmt);
    setError(null);
    try {
      await reportsApi.download(fmt);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed');
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Executive Security Reports</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Generate downloadable PDF and machine-readable JSON security posture reports containing executive summaries, evidence, and remediation steps.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl">
        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 w-fit">
            <FileText className="w-6 h-6" />
          </div>
          <h2 className="text-base font-bold text-white">Executive PDF Assessment Report</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Formatted audit report featuring Security Score, severity breakdown, affected AWS resource ARNs, and prioritized remediation instructions.
          </p>
          <button
            onClick={() => handleExport('pdf')}
            disabled={downloading !== null}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-semibold text-xs inline-flex items-center gap-2 cursor-pointer"
          >
            <Download className="w-4 h-4" />
            {downloading === 'pdf' ? 'Generating PDF...' : 'Download PDF Report'}
          </button>
        </div>

        <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 w-fit">
            <FileJson className="w-6 h-6" />
          </div>
          <h2 className="text-base font-bold text-white">Structured JSON Telemetry Export</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Complete JSON payload containing raw evidence blocks, AWS CLI remediation snippets, CloudTrail threat events, and scan metadata for SIEM ingestion.
          </p>
          <button
            onClick={() => handleExport('json')}
            disabled={downloading !== null}
            className="px-4 py-2.5 rounded-xl bg-[#070D19] border border-slate-700 hover:border-cyan-500 text-white font-semibold text-xs inline-flex items-center gap-2 cursor-pointer"
          >
            <FileBarChart2 className="w-4 h-4 text-cyan-400" />
            {downloading === 'json' ? 'Exporting JSON...' : 'Download JSON Report'}
          </button>
        </div>
      </div>
    </div>
  );
}
