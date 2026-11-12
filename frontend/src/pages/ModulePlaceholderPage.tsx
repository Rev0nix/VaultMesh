import { Layers } from 'lucide-react';

interface ModulePlaceholderPageProps {
  title: string;
  stageNumber: number;
  description: string;
}

export default function ModulePlaceholderPage({
  title,
  stageNumber,
  description,
}: ModulePlaceholderPageProps) {
  return (
    <div className="p-6">
      <div className="bg-[#0E172A] border border-slate-800 rounded-2xl p-10 text-center max-w-xl mx-auto mt-10">
        <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto mb-4">
          <Layers className="w-6 h-6" />
        </div>
        <span className="text-[11px] font-mono uppercase tracking-wider px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
          Scheduled for Stage {stageNumber}
        </span>
        <h2 className="text-xl font-bold text-white mt-3">{title}</h2>
        <p className="text-xs text-slate-400 mt-2 leading-relaxed">{description}</p>
      </div>
    </div>
  );
}
