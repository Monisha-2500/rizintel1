import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Shield, Lock, Mail, ArrowRight, AlertCircle,
  Loader2, KeyRound, Eye, EyeOff, Radio,
  GitMerge, ShieldCheck, UserCheck, User, Briefcase,
  BarChart3, Crown
} from 'lucide-react';
import {
  register,
  isAuthenticated
} from '../services/findingsService';
import Footer from '../components/layout/Footer';

export default function SignUpPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  // Redirect destination after successful registration (default to /workspace)
  const from = location.state?.from?.pathname || '/workspace';

  useEffect(() => {
    if (isAuthenticated()) {
      navigate(from, { replace: true });
    }
  }, [navigate, from]);

  const clearError = () => {
    if (errorMessage) setErrorMessage('');
  };

  const validateInputs = () => {
    const cleanName = name.trim();
    if (!cleanName) {
      return 'Please enter your full name.';
    }

    const cleanEmail = email.trim();
    if (!cleanEmail || !cleanEmail.includes('@') || !cleanEmail.includes('.')) {
      return 'Please enter a valid work email address.';
    }

    if (!role) {
      return 'Please select your workspace role.';
    }

    if (!password) {
      return 'Please enter a password.';
    }

    if (password.length < 8) {
      return 'Password must be at least 8 characters long.';
    }

    if (!/[A-Z]/.test(password)) {
      return 'Password must contain at least one uppercase letter.';
    }

    if (!/[a-z]/.test(password)) {
      return 'Password must contain at least one lowercase letter.';
    }

    if (!/[0-9]/.test(password)) {
      return 'Password must contain at least one number.';
    }

    if (password !== confirmPassword) {
      return 'Passwords do not match.';
    }

    return null;
  };

  const handleSignUp = async (e) => {
    if (e) e.preventDefault();

    const validationError = validateInputs();
    if (validationError) {
      setErrorMessage(validationError);
      return;
    }

    setLoading(true);
    setErrorMessage('');

    try {
      await register(name.trim(), email.trim(), password, role);
      navigate(from, { replace: true });
    } catch (err) {
      if (err.isNetworkError || (err.status && err.status >= 500) || err.message?.toLowerCase().includes('failed to fetch')) {
        setErrorMessage('RizIntel authentication service is currently unavailable. Please try again.');
      } else if (err.message && err.message.toLowerCase().includes('already exists')) {
        setErrorMessage('An account with this email already exists.');
      } else {
        setErrorMessage(err.message || 'Registration failed. Please check your information and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  // Informational 2x2 Access Role Definitions with icons and descriptions
  const accessRoles = [
    {
      role: 'VIEWER',
      label: 'VIEWER',
      name: 'Auditor View',
      icon: User,
      color: '#64748B',
      bgColor: '#F1F5F9',
      badgeClass: 'viewer',
      desc: 'Read-only access to dashboards, assets and insights.'
    },
    {
      role: 'ANALYST',
      label: 'ANALYST',
      name: 'SA Analyst',
      icon: BarChart3,
      color: '#2563EB',
      bgColor: '#EFF6FF',
      badgeClass: 'analyst',
      desc: 'Investigate findings, create notes and manage workflows.'
    },
    {
      role: 'SECURITY_LEAD',
      label: 'SECURITY LEAD',
      name: 'SOC Lead',
      icon: Shield,
      color: '#7C3AED',
      bgColor: '#F5F3FF',
      badgeClass: 'lead',
      desc: 'Oversee risk, SLAs and remediation across the organization.'
    },
    {
      role: 'ADMIN',
      label: 'ADMIN',
      name: 'Security Admin',
      icon: Crown,
      color: '#DC2626',
      bgColor: '#FEF2F2',
      badgeClass: 'admin',
      desc: 'Manage users, roles, integrations and system settings.'
    },
  ];

  return (
    <div className="login-portal-wrapper">
      <div className="login-portal-outer">
        <div className="login-portal-container fade-in">
          {/* Left Column: Product Branding, Visual Pipeline & ACCESS ROLES Overview */}
          <div className="login-brand-panel signup-left-panel">
            <div className="login-brand-header">
              <div className="login-brand-logo-box">
                <Shield size={28} color="#4F46E5" />
              </div>
              <div className="login-brand-titles">
                <h1 className="login-brand-title">RizIntel</h1>
                <span className="login-brand-tagline">Resolve with Intelligence.</span>
              </div>
            </div>

            <div className="login-brand-hero">
              <h2 className="login-hero-heading">
                Turn multi-scanner vulnerability noise into prioritized, explainable security decisions.
              </h2>

              {/* Decorative Pipeline Graphic */}
              <div className="login-pipeline-flow" aria-hidden="true">
                <div className="pipeline-step">
                  <div className="pipeline-icon-badge">
                    <Radio size={18} />
                  </div>
                  <div className="pipeline-step-title">Scanner Signals</div>
                  <div className="pipeline-step-desc">Unified findings ingestion</div>
                </div>

                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step">
                  <div className="pipeline-icon-badge">
                    <GitMerge size={18} />
                  </div>
                  <div className="pipeline-step-title">Correlation</div>
                  <div className="pipeline-step-desc">Deduplication & grouping</div>
                </div>

                <div className="pipeline-arrow">→</div>

                <div className="pipeline-step active">
                  <div className="pipeline-icon-badge">
                    <ShieldCheck size={18} />
                  </div>
                  <div className="pipeline-step-title">Prioritized Risk</div>
                  <div className="pipeline-step-desc">Actionable decision engine</div>
                </div>
              </div>
            </div>

            <div className="login-brand-footer">
              <UserCheck size={15} />
              <span>Built for modern SOC, Application Security & Risk teams.</span>
            </div>

            {/* Informational Access Roles Section (Compact 2x2 Grid on Left Column) */}
            <div className="signup-left-roles-section" data-testid="access-roles-section">
              <div className="demo-helper-divider left-aligned">
                <span>ACCESS ROLES</span>
                <span className="divider-subtitle">Role-based workspace access</span>
              </div>
              <div className="signup-left-roles-grid">
                {accessRoles.map((r) => {
                  const RoleIcon = r.icon;
                  return (
                    <div key={r.role} className={`role-card-compact ${r.badgeClass}`}>
                      <div className="role-card-icon-box" style={{ background: r.bgColor }}>
                        <RoleIcon size={16} color={r.color} />
                      </div>
                      <div className="role-card-body">
                        <span className="role-card-badge" style={{ color: r.color }}>{r.label}</span>
                        <h4 className="role-card-title">{r.name}</h4>
                        <p className="role-card-desc">{r.desc}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Column: Spacious Registration Card */}
          <div className="login-card-container">
            <div className="login-portal-card signup-card">
              <div className="login-card-header">
                <h2 className="login-card-title">Create your account</h2>
                <p className="login-card-subtitle">Set up your RizIntel security workspace access</p>
              </div>

              {/* Accessible Error Alert Banner (Only visible after failed attempt) */}
              {errorMessage && (
                <div className="login-error-banner fade-in" role="alert" aria-live="assertive">
                  <AlertCircle size={16} className="error-icon" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {/* Registration Form */}
              <form onSubmit={handleSignUp} className="login-form signup-form" noValidate>
                <div className="login-field-group">
                  <label className="login-label" htmlFor="name-input">
                    Full Name
                  </label>
                  <div className="login-input-wrapper">
                    <User size={16} className="login-input-icon" />
                    <input
                      id="name-input"
                      type="text"
                      className="login-input-field"
                      placeholder="Enter your full name"
                      value={name}
                      onChange={(e) => { setName(e.target.value); clearError(); }}
                      disabled={loading}
                      required
                      autoComplete="name"
                    />
                  </div>
                </div>

                <div className="login-field-group">
                  <label className="login-label" htmlFor="email-input">
                    Work Email
                  </label>
                  <div className="login-input-wrapper">
                    <Mail size={16} className="login-input-icon" />
                    <input
                      id="email-input"
                      type="email"
                      className="login-input-field"
                      placeholder="name@company.com"
                      value={email}
                      onChange={(e) => { setEmail(e.target.value); clearError(); }}
                      disabled={loading}
                      required
                      autoComplete="email"
                    />
                  </div>
                </div>

                <div className="login-field-group">
                  <label className="login-label" htmlFor="role-select">
                    Workspace Role
                  </label>
                  <div className="login-input-wrapper">
                    <Briefcase size={16} className="login-input-icon" />
                    <select
                      id="role-select"
                      className="login-input-field select-field"
                      value={role}
                      onChange={(e) => { setRole(e.target.value); clearError(); }}
                      disabled={loading}
                      required
                    >
                      <option value="" disabled>Select your workspace role</option>
                      <option value="ANALYST">Security Analyst</option>
                      <option value="SECURITY_LEAD">Security Lead</option>
                      <option value="VIEWER">Viewer / Auditor</option>
                      <option value="ADMIN">Administrator</option>
                    </select>
                  </div>
                </div>

                {/* 2-Column Row for Password & Confirm Password */}
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10, width: '100%', boxSizing: 'border-box' }}>
                  <div className="login-field-group">
                    <label className="login-label" htmlFor="password-input">
                      Password
                    </label>
                    <div className="login-input-wrapper">
                      <KeyRound size={16} className="login-input-icon" />
                      <input
                        id="password-input"
                        type={showPassword ? 'text' : 'password'}
                        className="login-input-field password-field"
                        placeholder="••••••••••••"
                        value={password}
                        onChange={(e) => { setPassword(e.target.value); clearError(); }}
                        disabled={loading}
                        required
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        className="password-toggle-btn"
                        onClick={() => setShowPassword(!showPassword)}
                        disabled={loading}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        title={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div className="login-field-group">
                    <label className="login-label" htmlFor="confirm-password-input">
                      Confirm Password
                    </label>
                    <div className="login-input-wrapper">
                      <KeyRound size={16} className="login-input-icon" />
                      <input
                        id="confirm-password-input"
                        type={showConfirmPassword ? 'text' : 'password'}
                        className="login-input-field password-field"
                        placeholder="••••••••••••"
                        value={confirmPassword}
                        onChange={(e) => { setConfirmPassword(e.target.value); clearError(); }}
                        disabled={loading}
                        required
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        className="password-toggle-btn"
                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        disabled={loading}
                        aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                        title={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                      >
                        {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>
                </div>
                <span className="field-hint-text" style={{ marginTop: '-4px' }}>
                  8+ characters with uppercase, lowercase & number
                </span>

                {/* Primary CTA */}
                <button
                  type="submit"
                  id="btn-signup-submit"
                  className="login-submit-btn signup-submit-btn"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="spin" />
                      <span>Creating Account…</span>
                    </>
                  ) : (
                    <>
                      <span>Create Account</span>
                      <ArrowRight size={16} />
                    </>
                  )}
                </button>
              </form>

              {/* Navigation Link to Login */}
              <div className="login-account-toggle signup-account-toggle">
                <span>Already have an account? </span>
                <button
                  type="button"
                  className="toggle-link-btn"
                  onClick={() => navigate('/login')}
                >
                  Sign in
                </button>
              </div>

              {/* Security Footer Notice */}
              <div className="login-footer-security">
                <Lock size={12} />
                <span>Secure authentication with role-based access control.</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Feature Cards Row (Identical to Login) */}
        <div className="login-bottom-features">
          <div className="feature-card">
            <div className="feature-icon"><Shield size={16} color="#4F46E5" /></div>
            <div className="feature-info">
              <div className="feature-title">Enterprise Ready</div>
              <div className="feature-desc">Built for scale and reliability</div>
            </div>
          </div>
          <div className="feature-card">
            <div className="feature-icon"><Lock size={16} color="#4F46E5" /></div>
            <div className="feature-info">
              <div className="feature-title">Secure by Design</div>
              <div className="feature-desc">End-to-end encryption</div>
            </div>
          </div>
          <div className="feature-card">
            <div className="feature-icon"><UserCheck size={16} color="#4F46E5" /></div>
            <div className="feature-info">
              <div className="feature-title">Role-Based Access</div>
              <div className="feature-desc">Least privilege access control</div>
            </div>
          </div>
        </div>

        {/* Authentic Application Footer Component */}
        <Footer />
      </div>
    </div>
  );
}
