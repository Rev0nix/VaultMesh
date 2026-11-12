import { Bell, Cloud, Globe, LogOut, Search } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import type { AWSAccount } from '../types';

interface TopNavbarProps {
  accounts: AWSAccount[];
  selectedAccountId: number | null;
  onAccountChange: (id: number) => void;
  selectedRegion: string;
  onRegionChange: (region: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
}

const AWS_REGIONS = [
  { code: 'ap-south-1', label: 'ap-south-1 (Mumbai)' },
  { code: 'us-east-1', label: 'us-east-1 (N. Virginia)' },
  { code: 'eu-west-1', label: 'eu-west-1 (Ireland)' },
  { code: 'ap-southeast-1', label: 'ap-southeast-1 (Singapore)' },
];

export default function TopNavbar({
  accounts,
  selectedAccountId,
  onAccountChange,
  selectedRegion,
  onRegionChange,
  searchQuery,
  onSearchChange,
}: TopNavbarProps) {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 bg-[#0B1222]/90 backdrop-blur border-b border-slate-800/90 px-6 flex items-center justify-between gap-4 shrink-0">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 bg-[#070D19] border border-slate-800 rounded-xl px-3 py-1.5 text-xs">
          <Cloud className="w-3.5 h-3.5 text-cyan-400" />
          {accounts.length === 0 ? (
            <span className="font-mono text-slate-400">No Account Connected</span>
          ) : (
            <select
              value={selectedAccountId ?? accounts[0].id}
              onChange={(e) => onAccountChange(Number(e.target.value))}
              className="bg-transparent text-slate-200 font-mono focus:outline-none cursor-pointer"
            >
              {accounts.map((acc) => (
                <option key={acc.id} value={acc.id} className="bg-[#0B1222]">
                  {acc.alias} ({acc.aws_account_id})
                </option>
              ))}
            </select>
          )}
        </div>

        <div className="flex items-center gap-2 bg-[#070D19] border border-slate-800 rounded-xl px-3 py-1.5 text-xs">
          <Globe className="w-3.5 h-3.5 text-blue-400" />
          <select
            value={selectedRegion}
            onChange={(e) => onRegionChange(e.target.value)}
            className="bg-transparent text-slate-200 font-mono focus:outline-none cursor-pointer"
          >
            {AWS_REGIONS.map((r) => (
              <option key={r.code} value={r.code} className="bg-[#0B1222]">
                {r.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="relative max-w-xs w-full hidden md:block">
        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search ARNs, findings, rules..."
          className="w-full bg-[#070D19] border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
        />
      </div>

      <div className="flex items-center gap-3">
        <button
          title="Notifications"
          className="p-2 rounded-xl bg-[#070D19] border border-slate-800 text-slate-400 hover:text-cyan-400 transition cursor-pointer"
        >
          <Bell className="w-4 h-4" />
        </button>

        {user && (
          <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-semibold text-white leading-tight">{user.full_name}</p>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                {user.role}
              </span>
            </div>
            <button
              onClick={logout}
              title="Sign Out"
              className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 transition cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
