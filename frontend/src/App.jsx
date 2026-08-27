import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
import ScrollToTop from './components/layout/ScrollToTop';
import ProtectedRoute from './components/auth/ProtectedRoute';
import LoginPage from './pages/LoginPage';
import SignUpPage from './pages/SignUpPage';
import WorkspacePage from './pages/WorkspacePage';
import AssetRegistryPage from './pages/AssetRegistryPage';
import ScanRunsPage from './pages/ScanRunsPage';
import ScannerAgentsPage from './pages/ScannerAgentsPage';
import CommandCenter from './pages/CommandCenter';
import FindingsQueue from './pages/FindingsQueue';
import Finding360 from './pages/Finding360';
import RizTracePage from './pages/RizTracePage';
import AssetView from './pages/AssetView';
import SLAMonitor from './pages/SLAMonitor';
import SecurityIntelligence from './pages/SecurityIntelligence';
import Helpdesk from './pages/Helpdesk';
import AboutUs from './pages/AboutUs';

export default function App() {
  return (
    <Router>
      <ScrollToTop />
      <Routes>
        {/* Public Authentication & Platform Info Routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignUpPage />} />
        <Route path="/about" element={<Layout><AboutUs /></Layout>} />
        <Route path="/helpdesk" element={<Layout><Helpdesk /></Layout>} />

        {/* Protected Application Routes */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  {/* Phase 1 Workspace Operations */}
                  <Route path="/" element={<WorkspacePage />} />
                  <Route path="/workspace" element={<WorkspacePage />} />
                  <Route path="/asset-registry" element={<AssetRegistryPage />} />
                  <Route path="/scan-runs" element={<ScanRunsPage />} />
                  <Route path="/scanner-agents" element={<ScannerAgentsPage />} />

                  {/* Core Intelligence & Decision Pipeline (Preserved M1-M8) */}
                  <Route path="/command-center" element={<CommandCenter />} />
                  <Route path="/findings" element={<FindingsQueue />} />
                  <Route path="/findings/:id" element={<Finding360 />} />
                  <Route path="/findings/:id/riztrace" element={<RizTracePage />} />
                  <Route path="/assets" element={<AssetView />} />
                  <Route path="/sla" element={<SLAMonitor />} />
                  <Route path="/intelligence" element={<SecurityIntelligence />} />
                  <Route path="/analytics" element={<SecurityIntelligence />} />
                  <Route path="/helpdesk" element={<Helpdesk />} />
                  <Route path="/about" element={<AboutUs />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </Router>
  );
}
