import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Shield, Lock, Mail, ArrowRight, AlertCircle,
  Loader2, KeyRound, Eye, EyeOff, Radio,
  GitMerge, ShieldCheck, UserCheck
} from 'lucide-react';
import {
  login,
  isAuthenticated
} from '../services/findingsService';
import Footer from '../components/layout/Footer';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  // Redirect destination after successful login (default to /workspace)
  const from = location.state?.from?.pathname || '/workspace';

  useEffect(() => {
    if (isAuthenticated()) {
      navigate(from, { replace: true });
    }
  }, [navigate, from]);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      setErrorMessage('Please enter both email and password.');
      return;
    }

    setLoading(true);
    setErrorMessage('');

    try {
      await login(trimmedEmail, password);
      navigate(from, { replace: true });
    } catch (err) {
      if (err.isNetworkError || (err.status && err.status >= 500) || err.message?.toLowerCase().includes('failed to fetch')) {
        setErrorMessage('RizIntel authentication service is currently unavailable. Please try again.');
      } else {
        setErrorMessage('Unable to sign in. Check your credentials and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
    if (errorMessage) setErrorMessage('');
  };

  const handlePasswordChange = (e) => {
    setPassword(e.target.value);
    if (errorMessage) setErrorMessage('');
  };

  // Informational Role Definitions (Production RBAC documentation)
  const accessRoles = [
    { role: 'VIEWER', label: 'VIEWER', name: 'Auditor View', badgeClass: 'viewer' },
    { role: 'ANALYST', label: 'ANALYST', name: 'SA Analyst', badgeClass: 'analyst' },
    { role: 'SECURITY_LEAD', label: 'SECURITY LEAD', name: 'SOC Lead', badgeClass: 'lead' },
    { role: 'ADMIN', label: 'ADMIN', name: 'Security Admin', badgeClass: 'admin' },
  ];

  return (
    <div className="login-portal-wrapper">
      <div className="login-portal-outer">
        <div className="login-portal-container fade-in">
          {/* Left Column: Product Branding & Visual Pipeline */}
          <div className="login-brand-panel">
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
          </div>

          {/* Right Column: Centered Authentication Card */}
          <div className="login-card-container">
            <div className="login-portal-card">
              <div className="login-card-header">
                <h2 className="login-card-title">Welcome back</h2>
                <p className="login-card-subtitle">Sign in to your security workspace</p>
              </div>

              {/* Accessible Error Alert Banner (Only visible after failed attempt) */}
              {errorMessage && (
                <div className="login-error-banner fade-in" role="alert" aria-live="assertive">
                  <AlertCircle size={16} className="error-icon" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {/* Login Form */}
              <form onSubmit={handleLogin} className="login-form" noValidate>
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
                      onChange={handleEmailChange}
                      disabled={loading}
                      required
                      autoComplete="email"
                    />
                  </div>
                </div>

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
                      onChange={handlePasswordChange}
                      disabled={loading}
                      required
                      autoComplete="current-password"
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

                <button
                  type="submit"
                  id="btn-login-submit"
                  className="login-submit-btn"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="spin" />
                      <span>Verifying Credentials…</span>
                    </>
                  ) : (
                    <>
                      <span>Sign In</span>
                      <ArrowRight size={16} />
                    </>
                  )}
                </button>
              </form>

              {/* Navigation Link to Sign Up */}
              <div className="login-account-toggle">
                <span>New to RizIntel? </span>
                <button
                  type="button"
                  className="toggle-link-btn"
                  onClick={() => navigate('/signup')}
                >
                  Create an account
                </button>
              </div>

              {/* Informational Access Roles Section (Production RBAC Overview) */}
              <div className="login-demo-helper-section" data-testid="access-roles-section">
                <div className="demo-helper-divider">
                  <span>ACCESS ROLES</span>
                  <span className="divider-subtitle">Role-based workspace access</span>
                </div>
                <div className="demo-users-chips-grid">
                  {accessRoles.map((r) => (
                    <div key={r.role} className={`demo-user-chip ${r.badgeClass} info-only`}>
                      <span className="demo-chip-role">{r.label}</span>
                      <span className="demo-chip-name">{r.name}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Footer Notice */}
              <div className="login-footer-security">
                <Lock size={12} />
                <span>Secure authentication with role-based access control.</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Feature Cards Row */}
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
