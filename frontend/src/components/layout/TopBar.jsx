import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';

const PAGE_META = {
  '/':          { title: 'Command Center',     subtitle: 'From vulnerability signals to security decisions.' },
  '/findings':  { title: 'Findings Queue',     subtitle: 'Prioritized analyst work queue.' },
  '/assets':    { title: 'Asset View',         subtitle: 'Vulnerability exposure by asset.' },
  '/sla':       { title: 'SLA Monitor',        subtitle: 'Track remediation deadlines.' },
  '/analytics': { title: 'Analytics',          subtitle: 'Security intelligence insights.' },
  '/helpdesk':  { title: 'Help Desk',          subtitle: 'SOC Analyst Help Desk & Knowledge Base' },
  '/about':     { title: 'Platform Specs',     subtitle: 'RizIntel 8-Module Engine Specification' },
};

export default function TopBar() {
  const location = useLocation();
  const [time, setTime]   = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const basePath = '/' + (location.pathname.split('/')[1] ?? '');
  const meta = PAGE_META[basePath] ?? PAGE_META['/'];

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title">{meta.title}</span>
        <span className="topbar-subtitle">{meta.subtitle}</span>
      </div>
      <div className="topbar-right">
        <span className="topbar-time">
          {time.toLocaleTimeString('en-IN', { hour12: false })}
        </span>
        <span className="topbar-badge">
          <span className="status-dot pulse" />
          Live Dashboard
        </span>
      </div>
    </header>
  );
}
