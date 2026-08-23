import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, HelpCircle, Info } from 'lucide-react';

export default function Footer() {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <footer className="footer-slim-wrapper">
      <div className="footer-glow-bar" />
      <div className="footer-slim-container">
        
        {/* Left Side: Brand Logo and Copyright */}
        <div className="footer-slim-left" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>
          <div className="footer-logo-icon-slim">
            <Shield size={14} />
          </div>
          <span className="footer-brand-name-slim">RizIntel</span>
          <span className="footer-slim-separator">•</span>
          <span className="footer-copyright-slim">
            © {new Date().getFullYear()} RizIntel Security Systems, Inc. All rights reserved.
          </span>
        </div>

        {/* Right Side: 2 Navigation Links */}
        <div className="footer-slim-right">
          <button 
            className={`footer-slim-link ${location.pathname === '/helpdesk' ? 'active' : ''}`} 
            onClick={() => navigate('/helpdesk')}
          >
            <HelpCircle size={14} />
            <span>Helpdesk</span>
          </button>
          
          <span className="footer-slim-separator">|</span>
          
          <button 
            className={`footer-slim-link ${location.pathname === '/about' ? 'active' : ''}`} 
            onClick={() => navigate('/about')}
          >
            <Info size={14} />
            <span>Know More / About Us</span>
          </button>
        </div>

      </div>
    </footer>
  );
}
