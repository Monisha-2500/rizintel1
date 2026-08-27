import React, { useState, useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { isAuthenticated } from '../../services/findingsService';

export default function ProtectedRoute({ children }) {
  const location = useLocation();
  const [authed, setAuthed] = useState(() => isAuthenticated());

  useEffect(() => {
    const handleAuthChange = () => {
      setAuthed(isAuthenticated());
    };
    const handleUnauthorized = () => {
      setAuthed(false);
    };

    window.addEventListener('rizintel-auth-change', handleAuthChange);
    window.addEventListener('rizintel-unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('rizintel-auth-change', handleAuthChange);
      window.removeEventListener('rizintel-unauthorized', handleUnauthorized);
    };
  }, []);

  if (!authed) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
