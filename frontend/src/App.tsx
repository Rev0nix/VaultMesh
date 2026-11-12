import { useCallback, useEffect, useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import AuthPage from './pages/AuthPage';
import Sidebar from './components/Sidebar';
import TopNavbar from './components/TopNavbar';
import OverviewPage from './pages/OverviewPage';
import CloudAccountsPage from './pages/CloudAccountsPage';
import FindingsPage from './pages/FindingsPage';
import IAMAnalyzerPage from './pages/IAMAnalyzerPage';
import NetworkSecurityPage from './pages/NetworkSecurityPage';
import ThreatDetectionPage from './pages/ThreatDetectionPage';
import ModulePlaceholderPage from './pages/ModulePlaceholderPage';
import { accountsApi } from './services/api';
import type { AWSAccount, NavSection } from './types';

function VaultMeshShell() {
  const { user, loading } = useAuth();
  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [accounts, setAccounts] = useState<AWSAccount[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<number | null>(null);
  const [selectedRegion, setSelectedRegion] = useState('ap-south-1');
  const [searchQuery, setSearchQuery] = useState('');

  const loadAccounts = useCallback(async () => {
    if (!user) return;
    try {
      const list = await accountsApi.list();
      setAccounts(list);
      if (list.length > 0 && selectedAccountId === null) {
        setSelectedAccountId(list[0].id);
      }
    } catch {
      // handled in UI
    }
  }, [user, selectedAccountId]);

  useEffect(() => {
    loadAccounts();
  }, [loadAccounts]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070D19] flex items-center justify-center text-cyan-400 text-sm font-mono">
        Verifying VaultMesh session...
      </div>
    );
  }

  if (!user) {
    return <AuthPage />;
  }

  const renderSection = () => {
    switch (activeSection) {
      case 'overview':
        return (
          <OverviewPage
            accounts={accounts}
            selectedAccountId={selectedAccountId}
            onNavigate={setActiveSection}
          />
        );
      case 'accounts':
        return (
          <CloudAccountsPage
            accounts={accounts}
            onAccountsChanged={loadAccounts}
          />
        );
      case 'findings':
        return (
          <FindingsPage
            accounts={accounts}
            selectedAccountId={selectedAccountId}
            globalSearch={searchQuery}
          />
        );
      case 'threats':
        return (
          <ThreatDetectionPage
            accounts={accounts}
            selectedAccountId={selectedAccountId}
          />
        );
      case 'iam':
        return <IAMAnalyzerPage />;
      case 'network':
        return <NetworkSecurityPage />;
      case 'compliance':
        return (
          <ModulePlaceholderPage
            title="Compliance Frameworks Mapping"
            stageNumber={11}
            description="Informational control mapping for CIS AWS Foundations Benchmark, NIST CSF, and AWS Well-Architected."
          />
        );
      case 'audit':
        return (
          <ModulePlaceholderPage
            title="Immutable Audit Logs"
            stageNumber={10}
            description="Chronological security trail of logins, scan triggers, finding status updates, and remediation approvals."
          />
        );
      case 'reports':
        return (
          <ModulePlaceholderPage
            title="Executive PDF & JSON Reports"
            stageNumber={11}
            description="Generate downloadable security assessment reports with executive summaries, evidence, and remediation steps."
          />
        );
      case 'settings':
        return (
          <ModulePlaceholderPage
            title="Organization & RBAC Settings"
            stageNumber={10}
            description="Manage team roles (ADMIN, SECURITY_ANALYST, VIEWER), JWT session policies, and AWS mode settings."
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#070D19] text-slate-100 flex">
      <Sidebar activeSection={activeSection} onSelect={setActiveSection} />
      <div className="flex-1 flex flex-col min-w-0">
        <TopNavbar
          accounts={accounts}
          selectedAccountId={selectedAccountId}
          onAccountChange={setSelectedAccountId}
          selectedRegion={selectedRegion}
          onRegionChange={setSelectedRegion}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
        />
        <main className="flex-1 overflow-y-auto">{renderSection()}</main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <VaultMeshShell />
    </AuthProvider>
  );
}
