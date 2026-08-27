import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import {
  Building2, Play, LayoutDashboard, ListChecks, Server, Clock,
  BarChart3, Bell, Shield, Moon, Sun,
  AlertTriangle, ShieldAlert, Clock4, TrendingUp,
  CheckCircle2, X, CheckCheck, Info, LogOut, Lock, UserCheck, Key
} from 'lucide-react';

import {
  ROLES,
  getCurrentUser,
  logout,
  DATA_MODES,
  RUNTIME_STATUS,
  getDataMode,
  setDataMode,
  getRuntimeStatus,
  getFindings,
} from '../../services/findingsService';

const NAV_ITEMS = [
  { label: 'Workspace', path: '/', icon: Building2 },
  { label: 'Asset Registry', path: '/asset-registry', icon: Server },
  { label: 'Scan Runs', path: '/scan-runs', icon: Play },
  { label: 'Scanner Agents', path: '/scanner-agents', icon: Key },
  { label: 'Command Center', path: '/command-center', icon: LayoutDashboard },
  { label: 'Findings', path: '/findings', icon: ListChecks },
  { label: 'SLA Monitor', path: '/sla', icon: Clock },
  { label: 'Security Intelligence', path: '/intelligence', icon: BarChart3 },
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
  const [runtimeStatus, setRuntime] = useState(() => getRuntimeStatus());
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    const handleAuthChange = () => {
      setCurUser(getCurrentUser());
      loadNotifications();
    };
    const handleDataModeChange = (e) => {
      setMode(e.detail?.mode || getDataMode());
      setRuntime(getRuntimeStatus());
      loadNotifications();
    };
    const handleRuntimeStatusChange = (e) => {
      setRuntime(e.detail?.status || getRuntimeStatus());
      setMode(e.detail?.mode || getDataMode());
    };

    async function loadNotifications() {
      try {
        const findings = await getFindings().catch(() => []);
        const items = [];

        if (Array.isArray(findings) && findings.length > 0) {
          findings.forEach((f, idx) => {
            const isCritical = (f.risk_level || '').toUpperCase() === 'CRITICAL' || (f.risk_score || 0) >= 80;
            const isSlaWarning = (f.sla_status || '').toUpperCase() === 'BREACHED' || (f.sla_status || '').toUpperCase() === 'WARNING';
            const isEscalated = (f.workflow?.status || '').toUpperCase() === 'ESCALATED';
            const isResolved = (f.workflow?.status || '').toUpperCase() === 'RESOLVED';

            if (isCritical) {
              items.push({
                id: `notif-crit-${f.id || idx}`,
                type: 'critical',
                icon: ShieldAlert,
                title: 'Critical Finding Detected',
                message: `${f.title || 'Critical vulnerability'} on ${f.asset_id || 'target asset'} — risk score ${f.risk_score || 90}. Immediate patching required.`,
                time: 'Recent',
                read: false,
                link: '/findings',
              });
            } else if (isSlaWarning) {
              items.push({
                id: `notif-sla-${f.id || idx}`,
                type: 'sla',
                icon: Clock4,
                title: 'SLA Breach Warning',
                message: `Finding ${f.id || ''} status is ${f.sla_status}. Action required before escalation.`,
                time: 'Recent',
                read: false,
                link: '/sla',
              });
            } else if (isEscalated) {
              items.push({
                id: `notif-esc-${f.id || idx}`,
                type: 'escalation',
                icon: TrendingUp,
                title: 'Finding Escalated',
                message: `Finding ${f.id || ''} has been escalated for senior analyst review.`,
                time: 'Recent',
                read: false,
                link: '/findings',
              });
            } else if (isResolved) {
              items.push({
                id: `notif-res-${f.id || idx}`,
                type: 'resolved',
                icon: CheckCircle2,
                title: 'Finding Resolved',
                message: `Vulnerability ${f.id || ''} marked as remediated.`,
                time: 'Recent',
                read: true,
                link: '/findings',
              });
            }
          });
        }

        setNotifications(items);
      } catch {
        setNotifications([]);
      }
    }

    loadNotifications();

    window.addEventListener('rizintel-auth-change', handleAuthChange);
    window.addEventListener('rizintel-datamode-change', handleDataModeChange);
    window.addEventListener('rizintel-runtimestatus-change', handleRuntimeStatusChange);
    return () => {
      window.removeEventListener('rizintel-auth-change', handleAuthChange);
      window.removeEventListener('rizintel-datamode-change', handleDataModeChange);
      window.removeEventListener('rizintel-runtimestatus-change', handleRuntimeStatusChange);
    };
  }, []);

  const [showNotifications, setShowNotifications] = useState(false);
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

  const handleToggleDataMode = () => {
    const nextMode = dataMode === DATA_MODES.INTEGRATED ? DATA_MODES.MOCK : DATA_MODES.INTEGRATED;
    setDataMode(nextMode);
    setMode(nextMode);
    setRuntime(getRuntimeStatus());
  };

  const handleLogout = () => {
    setShowRoleMenu(false);
    logout();
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  /* ── Dark mode toggle ── */
  useEffect(() => {
    try {
      const root = document.documentElement;
      if (darkMode) {
        root.setAttribute('data-theme', 'dark');
        root.classList.add('dark');
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.setItem('rizintel-theme', 'dark');
        }
      } else {
        root.removeAttribute('data-theme');
        root.classList.remove('dark');
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
          {/* Data Mode Switch (Live Integrated vs Honest Mock Fallback) */}
          <div className="data-mode-toggle-wrap">
            {(() => {
              const statusConfig = {
                [RUNTIME_STATUS.LIVE]: {
                  label: 'Pipeline Live',
                  dotColor: '#22C55E',
                  glow: '0 0 6px #22C55E',
                  border: '1px solid rgba(34, 197, 94, 0.45)',
                  bg: darkMode ? 'rgba(34, 197, 94, 0.15)' : 'rgba(34, 197, 94, 0.08)',
                  color: '#16A34A',
                  className: 'mode-live',
                  title: 'Active Data Mode: Pipeline Live (Connected to live pipeline APIs). Click to switch to Mock.',
                },
                [RUNTIME_STATUS.MOCK]: {
                  label: 'Mock Data',
                  dotColor: '#94A3B8',
                  glow: 'none',
                  border: '1px solid rgba(148, 163, 184, 0.35)',
                  bg: darkMode ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.08)',
                  color: '#64748B',
                  className: 'mode-mock',
                  title: 'Active Data Mode: Mock Data (Offline demo dataset). Click to switch to Live.',
                },
                [RUNTIME_STATUS.FALLBACK]: {
                  label: 'Mock Fallback',
                  dotColor: '#F59E0B',
                  glow: '0 0 6px #F59E0B',
                  border: '1px solid rgba(245, 158, 11, 0.45)',
                  bg: darkMode ? 'rgba(245, 158, 11, 0.15)' : 'rgba(245, 158, 11, 0.08)',
                  color: '#D97706',
                  className: 'mode-fallback',
                  title: 'Active Data Mode: Mock Fallback (Live backend API unavailable, showing fallback mock data). Click to retry.',
                },
                [RUNTIME_STATUS.CONNECTING]: {
                  label: 'Connecting...',
                  dotColor: '#3B82F6',
                  glow: '0 0 6px #3B82F6',
                  border: '1px solid rgba(59, 130, 246, 0.45)',
                  bg: darkMode ? 'rgba(59, 130, 246, 0.15)' : 'rgba(59, 130, 246, 0.08)',
                  color: '#2563EB',
                  className: 'mode-connecting',
                  title: 'Connecting to live backend pipeline...',
                },
                [RUNTIME_STATUS.ERROR]: {
                  label: 'Live Unavailable',
                  dotColor: '#EF4444',
                  glow: '0 0 6px #EF4444',
                  border: '1px solid rgba(239, 68, 68, 0.45)',
                  bg: darkMode ? 'rgba(239, 68, 68, 0.15)' : 'rgba(239, 68, 68, 0.08)',
                  color: '#DC2626',
                  className: 'mode-error',
                  title: 'Live backend pipeline unavailable. Click to switch to Mock.',
                },
              };

              const currentConfig = statusConfig[runtimeStatus] || statusConfig[RUNTIME_STATUS.FALLBACK];

              return (
                <button
                  id="data-mode-switch-btn"
                  className={`data-mode-pill ${currentConfig.className}`}
                  onClick={handleToggleDataMode}
                  title={currentConfig.title}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '4px 10px',
                    borderRadius: '20px',
                    fontSize: '11.5px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    border: currentConfig.border,
                    backgroundColor: currentConfig.bg,
                    color: currentConfig.color,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <span
                    style={{
                      width: '7px',
                      height: '7px',
                      borderRadius: '50%',
                      backgroundColor: currentConfig.dotColor,
                      boxShadow: currentConfig.glow,
                    }}
                  />
                  <span>{currentConfig.label}</span>
                </button>
              );
            })()}
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

          {/* RBAC User Profile & Authenticated Session Menu */}
          <div className="nav-user-wrapper" ref={roleMenuRef}>
            <button
              className="nav-user-profile"
              onClick={() => setShowRoleMenu(prev => !prev)}
              title="Click to view Authenticated Identity"
              aria-label="View User Profile"
              id="nav-user-profile-btn"
            >
              <div className={`nav-avatar role-${(currentUser?.role || 'ANALYST').toLowerCase()}`}>
                {currentUser?.role === 'VIEWER' ? 'VR' :
                 currentUser?.role === 'SECURITY_LEAD' ? 'SL' :
                 currentUser?.role === 'ADMIN' ? 'AD' : 'SA'}
              </div>
              <div className="nav-user-info">
                <span className="nav-user-name">{currentUser?.name || 'User'}</span>
                <span className={`nav-user-role-badge badge-${currentUser?.config?.badge || 'blue'}`}>
                  {currentUser?.config?.shortLabel || currentUser?.role || 'ANALYST'}
                </span>
              </div>
            </button>

            {/* Authenticated Profile Dropdown */}
            {showRoleMenu && (
              <div className="role-dropdown-panel auth-profile-panel fade-in" role="menu">
                <div className="role-dropdown-header">
                  <div className="role-dropdown-title">
                    <Shield size={14} className="text-purple" />
                    <span>Authenticated Identity</span>
                  </div>
                  <p className="role-dropdown-subtitle">Verified by HMAC-SHA256 JWT Token</p>
                </div>

                {/* Active User Card */}
                <div className="auth-profile-details">
                  <div className="auth-user-header">
                    <div className={`nav-avatar large role-${(currentUser?.role || 'ANALYST').toLowerCase()}`}>
                      {currentUser?.role === 'VIEWER' ? 'VR' :
                       currentUser?.role === 'SECURITY_LEAD' ? 'SL' :
                       currentUser?.role === 'ADMIN' ? 'AD' : 'SA'}
                    </div>
                    <div className="auth-user-text">
                      <div className="auth-name-row">
                        <span className="auth-display-name">{currentUser?.name || 'User'}</span>
                        <span className={`role-pill badge-${currentUser?.config?.badge || 'blue'}`}>
                          {currentUser?.config?.shortLabel || currentUser?.role || 'ANALYST'}
                        </span>
                      </div>
                      <span className="auth-user-email">{currentUser?.email || `${(currentUser?.name || 'user').toLowerCase().replace(/\s+/g, '.')}@rizintel.demo`}</span>
                    </div>
                  </div>

                  <div className="auth-permissions-summary">
                    <span className="permissions-title">RBAC Authority Scope:</span>
                    <p className="permissions-desc">{currentUser?.config?.description || 'Standard analyst permissions.'}</p>
                  </div>
                </div>

                {/* Logout Button */}
                <div className="auth-menu-footer">
                  <button
                    className="auth-signout-btn"
                    onClick={handleLogout}
                    id="btn-nav-logout"
                  >
                    <LogOut size={14} />
                    <span>Sign Out</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </nav>
    </header>
  );
}

