import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, ListChecks, Server, Clock,
  BarChart3, Bell, Shield, Moon, Sun,
  AlertTriangle, ShieldAlert, Clock4, TrendingUp,
  CheckCircle2, X, CheckCheck, Info
} from 'lucide-react';

import {
  ROLES,
  getCurrentUser,
  setCurrentUser,
  DATA_MODES,
  getDataMode,
  setDataMode
} from '../../services/findingsService';

const NAV_ITEMS = [
  { label: 'Command Center', path: '/', icon: LayoutDashboard },
  { label: 'Findings', path: '/findings', icon: ListChecks },
  { label: 'Assets', path: '/assets', icon: Server },
  { label: 'SLA Monitor', path: '/sla', icon: Clock },
  { label: 'Security Intelligence', path: '/intelligence', icon: BarChart3 },
];

/* ── Mock notifications relevant to the security platform ── */
const INITIAL_NOTIFICATIONS = [
  {
    id: 'n1',
    type: 'critical',
    icon: ShieldAlert,
    title: 'Critical Finding Detected',
    message: 'SQL Injection (CVE-2026-1234) on asset-pay-001 — risk score 94. Immediate patching required.',
    time: '2 min ago',
    read: false,
    link: '/findings',
  },
  {
    id: 'n2',
    type: 'sla',
    icon: Clock4,
    title: 'SLA Breach Warning',
    message: 'Finding DEDUP-0003 is approaching SLA deadline. 1 hour remaining before breach escalation.',
    time: '18 min ago',
    read: false,
    link: '/sla',
  },
  {
    id: 'n3',
    type: 'escalation',
    icon: TrendingUp,
    title: 'Finding Escalated to L2',
    message: 'RCE vulnerability DEDUP-0005 auto-escalated after SLA breach. Assigned to senior analyst.',
    time: '45 min ago',
    read: false,
    link: '/findings',
  },
  {
    id: 'n4',
    type: 'info',
    icon: Info,
    title: 'Scan Pipeline Complete',
    message: 'ZAP, Nuclei & OpenVAS scans finished for ASSET-WEB-003. 4 new findings ingested.',
    time: '1 hr ago',
    read: true,
    link: '/',
  },
  {
    id: 'n5',
    type: 'resolved',
    icon: CheckCircle2,
    title: 'Finding Resolved',
    message: 'XSS vulnerability DEDUP-0008 marked as remediated by analyst. Awaiting verification scan.',
    time: '3 hrs ago',
    read: true,
    link: '/findings',
  },
];

const TYPE_COLORS = {
  critical:   { bg: '#FEF2F2', accent: '#EF4444', darkBg: '#3B1111' },
  sla:        { bg: '#FFFBEB', accent: '#F59E0B', darkBg: '#3B2E10' },
  escalation: { bg: '#FFF7ED', accent: '#F97316', darkBg: '#3B2810' },
  info:       { bg: '#EFF6FF', accent: '#3B82F6', darkBg: '#111B33' },
  resolved:   { bg: '#F0FDF4', accent: '#22C55E', darkBg: '#113B1E' },
};

export default function TopNavigation() {
  const navigate = useNavigate();
  const location = useLocation();
  const bellRef = useRef(null);
  const roleMenuRef = useRef(null);

  const [currentUser, setCurUser] = useState(() => getCurrentUser());
  const [showRoleMenu, setShowRoleMenu] = useState(false);
  const [dataMode, setMode] = useState(() => getDataMode());

  useEffect(() => {
    const handleAuthChange = () => {
      setCurUser(getCurrentUser());
    };
    const handleDataModeChange = (e) => {
      setMode(e.detail?.mode || getDataMode());
    };
    window.addEventListener('rizintel-auth-change', handleAuthChange);
    window.addEventListener('rizintel-datamode-change', handleDataModeChange);
    return () => {
      window.removeEventListener('rizintel-auth-change', handleAuthChange);
      window.removeEventListener('rizintel-datamode-change', handleDataModeChange);
    };
  }, []);

  const handleToggleDataMode = () => {
    const nextMode = dataMode === DATA_MODES.INTEGRATED ? DATA_MODES.MOCK : DATA_MODES.INTEGRATED;
    setDataMode(nextMode);
    setMode(nextMode);
  };

  const handleSelectRole = (roleId) => {
    const names = {
      VIEWER: 'Auditor View',
      ANALYST: 'SA Analyst',
      SECURITY_LEAD: 'SOC Lead',
      ADMIN: 'Sec Admin',
    };
    setCurrentUser(roleId, names[roleId] || 'User');
    setShowRoleMenu(false);
  };

  const [darkMode, setDarkMode] = useState(() => {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        const saved = window.localStorage.getItem('rizintel-theme');
        if (saved) return saved === 'dark';
      }
      return typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch {
      return false;
    }
  });

  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState(INITIAL_NOTIFICATIONS);

  const unreadCount = notifications.filter(n => !n.read).length;

  /* ── Dark mode toggle ── */
  useEffect(() => {
    try {
      const root = document.documentElement;
      if (darkMode) {
        root.setAttribute('data-theme', 'dark');
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.setItem('rizintel-theme', 'dark');
        }
      } else {
        root.removeAttribute('data-theme');
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.setItem('rizintel-theme', 'light');
        }
      }
    } catch {
      // Graceful fallback
    }
  }, [darkMode]);

  const toggleTheme = () => setDarkMode(prev => !prev);

  /* ── Close dropdowns on outside click ── */
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (bellRef.current && !bellRef.current.contains(e.target)) {
        setShowNotifications(false);
      }
      if (roleMenuRef.current && !roleMenuRef.current.contains(e.target)) {
        setShowRoleMenu(false);
      }
    };
    if (showNotifications || showRoleMenu) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showNotifications, showRoleMenu]);


  /* ── Notification actions ── */
  const markAsRead = useCallback((id) => {
    setNotifications(prev =>
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  const dismissNotification = useCallback((id, e) => {
    e.stopPropagation();
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const handleNotificationClick = useCallback((notification) => {
    markAsRead(notification.id);
    setShowNotifications(false);
    if (notification.link) {
      navigate(notification.link);
    }
  }, [markAsRead, navigate]);

  const isActive = (path) => path === '/'
    ? location.pathname === '/'
    : location.pathname.startsWith(path);

  /* ── Time-ago helper for relative display ── */
  const formatTimeLabel = (time) => time;

  return (
    <header className="top-nav-wrapper">
      <nav className="top-nav" role="navigation" aria-label="Main navigation">
        {/* Brand Logo & Subtitle */}
        <div className="nav-left-group">
          <button className="nav-brand" onClick={() => navigate('/')} style={{ background: 'none', border: 'none', textAlign: 'left' }}>
            <div className="nav-brand-logo-box">
              <Shield size={19} color="white" />
            </div>
            <div className="nav-brand-text">
              <span className="nav-brand-name">RizIntel</span>
              <span className="nav-brand-tagline">Resolve with Intelligence</span>
            </div>
          </button>
        </div>

        {/* Navigation Pills */}
        <div className="nav-links">
          {NAV_ITEMS.map(({ label, path, icon: Icon }) => (
            <button
              key={path}
              id={`nav-${path === '/' ? 'home' : path.replace('/', '')}`}
              className={`nav-pill${isActive(path) ? ' active' : ''}`}
              onClick={() => navigate(path)}
            >
              <Icon size={15} className="nav-pill-icon" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Right Controls */}
        <div className="nav-right">
          {/* Data Mode Switch (Live Integrated vs Safe Mock Fallback) */}
          <div className="data-mode-toggle-wrap">
            <button
              id="data-mode-switch-btn"
              className={`data-mode-pill ${dataMode === DATA_MODES.INTEGRATED ? 'mode-live' : 'mode-mock'}`}
              onClick={handleToggleDataMode}
              title={`Active Data Mode: ${dataMode === DATA_MODES.INTEGRATED ? 'Real Integrated Pipeline (M1→M7 APIs)' : 'Mock Dataset (Fallback)'}. Click to switch mode.`}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '20px',
                fontSize: '11.5px',
                fontWeight: '600',
                cursor: 'pointer',
                border: dataMode === DATA_MODES.INTEGRATED ? '1px solid rgba(34, 197, 94, 0.45)' : '1px solid rgba(148, 163, 184, 0.35)',
                backgroundColor: dataMode === DATA_MODES.INTEGRATED ? (darkMode ? 'rgba(34, 197, 94, 0.15)' : 'rgba(34, 197, 94, 0.08)') : (darkMode ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.08)'),
                color: dataMode === DATA_MODES.INTEGRATED ? '#16A34A' : '#64748B',
                transition: 'all 0.2s ease',
              }}
            >
              <span
                style={{
                  width: '7px',
                  height: '7px',
                  borderRadius: '50%',
                  backgroundColor: dataMode === DATA_MODES.INTEGRATED ? '#22C55E' : '#94A3B8',
                  boxShadow: dataMode === DATA_MODES.INTEGRATED ? '0 0 6px #22C55E' : 'none',
                }}
              />
              <span>{dataMode === DATA_MODES.INTEGRATED ? 'Live M1→M7' : 'Mock Fallback'}</span>
            </button>
          </div>

          {/* Dark Mode Toggle */}
          <button
            className="nav-icon-btn nav-theme-toggle"
            title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            onClick={toggleTheme}
            id="nav-theme-toggle-btn"
            aria-label="Toggle dark mode"
          >
            {darkMode ? (
              <Sun size={16} color="#FBBF24" />
            ) : (
              <Moon size={16} color="#6366F1" />
            )}
          </button>

          {/* Bell Notifications */}
          <div className="nav-bell-wrapper" ref={bellRef}>
            <button
              className={`nav-icon-btn${showNotifications ? ' notif-active' : ''}`}
              title="Notifications"
              id="nav-notifications-btn"
              onClick={() => setShowNotifications(prev => !prev)}
              aria-expanded={showNotifications}
              aria-haspopup="true"
            >
              <Bell size={17} />
              {unreadCount > 0 && (
                <span className="nav-bell-badge">{unreadCount}</span>
              )}
            </button>

            {/* ── Notification Dropdown Panel ── */}
            {showNotifications && (
              <div className="notif-dropdown" role="menu" aria-label="Notifications">
                {/* Header */}
                <div className="notif-header">
                  <div className="notif-header-left">
                    <h3 className="notif-title">Notifications</h3>
                    {unreadCount > 0 && (
                      <span className="notif-unread-pill">{unreadCount} new</span>
                    )}
                  </div>
                  {unreadCount > 0 && (
                    <button
                      className="notif-mark-all-btn"
                      onClick={markAllRead}
                      title="Mark all as read"
                    >
                      <CheckCheck size={14} />
                      <span>Mark all read</span>
                    </button>
                  )}
                </div>

                {/* Notification list */}
                <div className="notif-list">
                  {notifications.length === 0 ? (
                    <div className="notif-empty">
                      <Bell size={28} strokeWidth={1.2} />
                      <p>All caught up!</p>
                      <span>No notifications right now.</span>
                    </div>
                  ) : (
                    notifications.map((n) => {
                      const colors = TYPE_COLORS[n.type] || TYPE_COLORS.info;
                      const IconComp = n.icon;
                      return (
                        <div
                          key={n.id}
                          className={`notif-item${n.read ? '' : ' notif-unread'}`}
                          onClick={() => handleNotificationClick(n)}
                          role="menuitem"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') handleNotificationClick(n);
                          }}
                        >
                          <div
                            className="notif-icon-wrap"
                            style={{
                              background: darkMode ? colors.darkBg : colors.bg,
                              color: colors.accent,
                            }}
                          >
                            <IconComp size={16} />
                          </div>
                          <div className="notif-content">
                            <div className="notif-item-header">
                              <span className="notif-item-title">{n.title}</span>
                              {!n.read && <span className="notif-dot" />}
                            </div>
                            <p className="notif-item-message">{n.message}</p>
                            <span className="notif-item-time">{formatTimeLabel(n.time)}</span>
                          </div>
                          <button
                            className="notif-dismiss-btn"
                            onClick={(e) => dismissNotification(n.id, e)}
                            title="Dismiss"
                            aria-label="Dismiss notification"
                          >
                            <X size={13} />
                          </button>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          {/* RBAC User Profile & Role Switcher */}
          <div className="nav-user-wrapper" ref={roleMenuRef}>
            <button
              className="nav-user-profile"
              onClick={() => setShowRoleMenu(prev => !prev)}
              title="Click to switch RBAC Role"
              aria-label="Switch User Role"
            >
              <div className={`nav-avatar role-${currentUser.role.toLowerCase()}`}>
                {currentUser.role === 'VIEWER' ? 'VR' :
                 currentUser.role === 'SECURITY_LEAD' ? 'SL' :
                 currentUser.role === 'ADMIN' ? 'AD' : 'SA'}
              </div>
              <div className="nav-user-info">
                <span className="nav-user-name">{currentUser.name}</span>
                <span className={`nav-user-role-badge badge-${currentUser.config.badge}`}>
                  {currentUser.config.shortLabel}
                </span>
              </div>
            </button>

            {/* Role Dropdown */}
            {showRoleMenu && (
              <div className="role-dropdown-panel fade-in">
                <div className="role-dropdown-header">
                  <div className="role-dropdown-title">
                    <Shield size={14} className="text-purple" />
                    <span>Role-Based Access Control (RBAC)</span>
                  </div>
                  <p className="role-dropdown-subtitle">Switch active identity to test backend-enforced permissions</p>
                </div>

                <div className="role-options-list">
                  {Object.values(ROLES).map(r => {
                    const isSelected = r.id === currentUser.role;
                    return (
                      <button
                        key={r.id}
                        className={`role-option-card ${r.id.toLowerCase()}${isSelected ? ' active' : ''}`}
                        onClick={() => handleSelectRole(r.id)}
                      >
                        <div className="role-card-top">
                          <span className={`role-pill badge-${r.badge}`}>{r.shortLabel}</span>
                          {isSelected && <span className="role-active-check">Active ✓</span>}
                        </div>
                        <p className="role-card-desc">{r.description}</p>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </nav>
    </header>
  );
}

