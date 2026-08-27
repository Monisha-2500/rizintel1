import { describe, it, expect, beforeEach, vi } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import LoginPage from '../src/pages/LoginPage';
import SignUpPage from '../src/pages/SignUpPage';
import ProtectedRoute from '../src/components/auth/ProtectedRoute';
import * as findingsService from '../src/services/findingsService';

function LocationDisplay() {
  const location = useLocation();
  return <div data-testid="location-display">{location.pathname}</div>;
}

describe('RizIntel Authentication & Sign-Up Hardening Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  // ── LOGIN TESTS ─────────────────────────────────────────────────────────────
  it('1. renders login page with ACCESS ROLES section and security label', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Welcome back/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Work Email$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Password$/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Sign In$/i })).toBeInTheDocument();
    expect(screen.getByText('Secure authentication with role-based access control.')).toBeInTheDocument();
    expect(screen.getByText('ACCESS ROLES')).toBeInTheDocument();
    expect(screen.getByText('New to RizIntel?')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create an account' })).toBeInTheDocument();
  });

  it('2. invalid login credentials show generic safe error message', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);
    const err = new Error('401 Unauthorized');
    err.status = 401;
    vi.spyOn(findingsService, 'login').mockRejectedValue(err);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Work Email$/i), { target: { value: 'wrong@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'wrongpass' } });
    fireEvent.click(screen.getByRole('button', { name: /^Sign In$/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Unable to sign in. Check your credentials and try again.');
  });

  it('3. login password visibility toggle works', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    );

    const passwordInput = screen.getByLabelText(/^Password$/i);
    const toggleBtn = screen.getByRole('button', { name: 'Show password' });

    expect(passwordInput).toHaveAttribute('type', 'password');
    fireEvent.click(toggleBtn);
    expect(passwordInput).toHaveAttribute('type', 'text');
  });

  it('4. login loading state disables button to prevent duplicate submissions', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);
    let resolveLogin;
    const promise = new Promise((res) => { resolveLogin = res; });
    vi.spyOn(findingsService, 'login').mockReturnValue(promise);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Work Email$/i), { target: { value: 'analyst@rizintel.demo' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'Analyst2026!' } });

    const submitBtn = screen.getByRole('button', { name: /^Sign In$/i });
    fireEvent.click(submitBtn);

    expect(submitBtn).toBeDisabled();
    expect(screen.getByText(/Verifying Credentials/i)).toBeInTheDocument();
    resolveLogin({ access_token: 'token', user: {} });
  });

  it('5. successful login redirects to /workspace', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);
    vi.spyOn(findingsService, 'login').mockResolvedValue({
      access_token: 'jwt-123',
      user: { email: 'user@example.com', role: 'ANALYST' }
    });

    render(
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/workspace" element={<LocationDisplay />} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Work Email$/i), { target: { value: 'user@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'Secret123!' } });
    fireEvent.click(screen.getByRole('button', { name: /^Sign In$/i }));

    await waitFor(() => {
      expect(screen.getByTestId('location-display')).toHaveTextContent('/workspace');
    });
  });

  it('6. login error clears when user types in inputs', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);
    const err = new Error('401 Unauthorized');
    err.status = 401;
    vi.spyOn(findingsService, 'login').mockRejectedValue(err);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    );

    const emailInput = screen.getByLabelText(/^Work Email$/i);
    fireEvent.change(emailInput, { target: { value: 'wrong@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'wrongpass' } });
    fireEvent.click(screen.getByRole('button', { name: /^Sign In$/i }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();

    // User types in email input
    fireEvent.change(emailInput, { target: { value: 'fixed@example.com' } });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  // ── SIGN UP TESTS ────────────────────────────────────────────────────────────
  it('7. renders registration page with Workspace Role dropdown', () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);

    render(
      <MemoryRouter initialEntries={['/signup']}>
        <SignUpPage />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Create your account/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Full Name$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Work Email$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Workspace Role$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Password$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Confirm Password$/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Create Account$/i })).toBeInTheDocument();
  });

  it('8. registration validates required workspace role selection', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);

    render(
      <MemoryRouter initialEntries={['/signup']}>
        <SignUpPage />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Full Name$/i), { target: { value: 'Jane Doe' } });
    fireEvent.change(screen.getByLabelText(/^Work Email$/i), { target: { value: 'jane@company.com' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create Account$/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Please select your workspace role.');
  });

  it('9. successful registration calls service with selected role and redirects', async () => {
    vi.spyOn(findingsService, 'isAuthenticated').mockReturnValue(false);
    const registerSpy = vi.spyOn(findingsService, 'register').mockResolvedValue({
      access_token: 'new-user-jwt',
      user: { email: 'jane@company.com', role: 'ANALYST' }
    });

    render(
      <MemoryRouter initialEntries={['/signup']}>
        <Routes>
          <Route path="/signup" element={<SignUpPage />} />
          <Route path="/workspace" element={<LocationDisplay />} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Full Name$/i), { target: { value: 'Jane Doe' } });
    fireEvent.change(screen.getByLabelText(/^Work Email$/i), { target: { value: 'jane@company.com' } });
    fireEvent.change(screen.getByLabelText(/^Workspace Role$/i), { target: { value: 'ANALYST' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'Secure123!' } });
    fireEvent.change(screen.getByLabelText(/^Confirm Password$/i), { target: { value: 'Secure123!' } });

    fireEvent.click(screen.getByRole('button', { name: /^Create Account$/i }));

    await waitFor(() => {
      expect(registerSpy).toHaveBeenCalledWith('Jane Doe', 'jane@company.com', 'Secure123!', 'ANALYST');
      expect(screen.getByTestId('location-display')).toHaveTextContent('/workspace');
    });
  });
});
