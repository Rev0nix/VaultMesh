import { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import AuthPage from './pages/AuthPage';
import Sidebar from './components/Sidebar';
import TopNavbar from './components/TopNavbar';
import OverviewPage from './pages/OverviewPage';
import ModulePlaceholderPage from './pages/ModulePlaceholderPage';
import type { NavSection } from './types';

function VaultMeshShell() {
  const { user, loading } = useAuth();
  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [selectedRegion, setSelectedRegion] = useState('ap-south-1');
  const [searchQuery, setSearchQuery] = useState('');

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
        return <OverviewPage onNavigate={setActiveSection} />;
      case 'accounts':
        return (
          <ModulePlaceholderPage
            title="Cloud Accounts & AWS STS Onboarding"
            stageNumber={5}
            description="Connect AWS accounts via read-only IAM Roles (sts:AssumeRole + ExternalId) or activate Sandbox Mock Mode."
          />
        );
      case 'findings':
        return (
          <ModulePlaceholderPage
            title="Security Findings & Posture Engine"
            stageNumber={6}
            description="Inspect S3, IAM, EC2, Security Group, EBS, and CloudTrail vulnerabilities with evidence and status workflows."
          />
        );
      case 'threats':
        return (
          <ModulePlaceholderPage
            title="CloudTrail Threat Detection"
            stageNumber={9}
            description="Rule-based behavioral detection for brute-force logins, StopLogging tampering, and privilege escalation."
          />
        );
      case 'iam':
        return (
          <ModulePlaceholderPage
            title="IAM Least-Privilege Analyzer"
            stageNumber={8}
            description="Detect wildcard (*) policies, AdministratorAccess attachment, and risky cross-account trust relationships."
          />
        );
      case 'network':
        return (
          <ModulePlaceholderPage
            title="Network & Security Group Analyzer"
            stageNumber={8}
            description="Audit 0.0.0.0/0 inbound ingress rules, exposed SSH (22), RDP (3389), and database ports."
          />
        );
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
          selectedRegion={selectedRegion}
          onRegionChange={setSelectedRegion}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          awsMode="mock"
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
