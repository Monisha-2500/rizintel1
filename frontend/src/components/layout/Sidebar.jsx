import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, ListChecks, Server, Clock, BarChart3, ShieldAlert
} from 'lucide-react';

const NAV_ITEMS = [
  { label: 'Command Center',    path: '/',          icon: LayoutDashboard },
  { label: 'Findings Queue',    path: '/findings',  icon: ListChecks },
  { label: 'Assets',            path: '/assets',    icon: Server },
  { label: 'SLA Monitor',       path: '/sla',       icon: Clock },
  { label: 'Analytics',         path: '/analytics', icon: BarChart3 },
];

export default function Sidebar() {
  const navigate  = useNavigate();
  const location  = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">
          Riz<span>Intel</span>
        </div>
        <div className="sidebar-brand-tagline">Resolve with Intelligence.</div>
        <div className="sidebar-team">Team RIZZOLVE · M8</div>
      </div>

      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Navigation</div>
        {NAV_ITEMS.map(({ label, path, icon: Icon }) => {
          const isActive = path === '/'
            ? location.pathname === '/'
            : location.pathname.startsWith(path);
          return (
            <button
              key={path}
              id={`nav-${label.toLowerCase().replace(/\s+/g, '-')}`}
              className={`sidebar-nav-item${isActive ? ' active' : ''}`}
              onClick={() => navigate(path)}
            >
              <Icon className="nav-icon" size={15} />
              {label}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ShieldAlert size={14} color="rgba(255,255,255,0.4)" />
          <span className="sidebar-footer-label">Schema v1.0</span>
        </div>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', marginTop: 4 }}>
          M8 Command Center
        </div>
      </div>
    </aside>
  );
}
