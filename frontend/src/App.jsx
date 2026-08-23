import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import ScrollToTop from './components/layout/ScrollToTop';
import CommandCenter       from './pages/CommandCenter';
import FindingsQueue       from './pages/FindingsQueue';
import Finding360          from './pages/Finding360';
import RizTracePage        from './pages/RizTracePage';
import AssetView           from './pages/AssetView';
import SLAMonitor          from './pages/SLAMonitor';
import SecurityIntelligence from './pages/SecurityIntelligence';
import Helpdesk            from './pages/Helpdesk';
import AboutUs             from './pages/AboutUs';

export default function App() {
  return (
    <Router>
      <ScrollToTop />
      <Layout>
        <Routes>
          <Route path="/"                         element={<CommandCenter />} />
          <Route path="/findings"                  element={<FindingsQueue />} />
          <Route path="/findings/:id"              element={<Finding360 />} />
          <Route path="/findings/:id/riztrace"     element={<RizTracePage />} />
          <Route path="/assets"                    element={<AssetView />} />
          <Route path="/sla"                       element={<SLAMonitor />} />
          <Route path="/intelligence"              element={<SecurityIntelligence />} />
          <Route path="/analytics"                 element={<SecurityIntelligence />} />
          <Route path="/helpdesk"                  element={<Helpdesk />} />
          <Route path="/about"                     element={<AboutUs />} />
        </Routes>
      </Layout>
    </Router>
  );
}

