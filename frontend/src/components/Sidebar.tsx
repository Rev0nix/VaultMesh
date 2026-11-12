import {
  LayoutDashboard,
  Cloud,
  ShieldAlert,
  Radar,
  KeyRound,
  Network,
  Scale,
  ScrollText,
  FileBarChart2,
  Settings,
  Shield,
} from 'lucide-react';
import type { NavSection } from '../types';

interface SidebarProps {
  activeSection: NavSection;
  onSelect: (section: NavSection) => void;
}

const NAV_ITEMS: { id: NavSection; label: string; icon: typeof LayoutDashboard; badge?: string }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'accounts', label: 'Cloud Accounts', icon: Cloud },
  { id: 'findings', label: 'Security Findings', icon: ShieldAlert },
  { id: 'threats', label: 'Threat Detection', icon: Radar },
  { id: 'iam', label: 'IAM Analyzer', icon: KeyRound },
  { id: 'network', label: 'Network Security', icon: Network },
  { id: 'compliance', label: 'Compliance', icon: Scale },
  { id: 'audit', label: 'Audit Logs', icon: ScrollText },
  { id: 'reports', label: 'Reports', icon: FileBarChart2 },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function Sidebar({ activeSection, onSelect }: SidebarProps) {
  return (
    <aside className="w-64 bg-[#0B1222] border-r border-slate-800/90 flex flex-col shrink-0">
      {/* Logo */}
      <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-800/90">
        <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-white tracking-tight text-base block leading-none">
            VaultMesh
          </span>
          <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">
            Cloud Security
          </span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeSection === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelect(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
              }`}
            >
              <span className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Budget & Mode Footer */}
      <div className="p-4 border-t border-slate-800/90">
        <div className="bg-[#070D19] border border-slate-800 rounded-xl p-3 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span>Runtime Cost</span>
            <span className="font-mono text-emerald-400 font-semibold">₹0 / mo</span>
          </div>
          <p className="text-[11px] text-slate-500">Local SQLite + Safe STS Mode</p>
        </div>
      </div>
    </aside>
  );
}
