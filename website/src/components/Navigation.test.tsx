import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Navigation, { initialsOf } from './Navigation';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';

function renderNavigation(info: Partial<InfoRes.AsObject> = {}) {
  AppState.setInfo({ isAdmin: false, ...info } as InfoRes.AsObject);
  return render(
    <MemoryRouter>
      <Navigation />
    </MemoryRouter>,
  );
}

function openAccountMenu() {
  fireEvent.click(screen.getByLabelText('Your account'));
}

beforeEach(() => {
  localStorage.clear();
  AppState.setDarkMode(false);
});

afterEach(cleanup);

describe('Navigation', () => {
  it('does not underline the app name', () => {
    renderNavigation();
    expect(screen.getByText('wg-access-server').closest('a')?.className).toContain('underlineNone');
  });

  // The session cookie is HttpOnly, so it cannot tell whether somebody is
  // signed in - the loaded server info can.
  it('offers the account menu once the server info has loaded', () => {
    renderNavigation();
    expect(screen.getByLabelText('Your account')).toBeTruthy();
    expect(screen.queryByTitle('Sign in')).toBeNull();
  });

  it('shows the initials of the account on the button', () => {
    renderNavigation({ subject: 'alice', userDisplayName: 'Alice Example' });
    expect(screen.getByLabelText('Your account').textContent).toBe('AE');
  });

  it('falls back to the subject for the initials', () => {
    renderNavigation({ subject: 'bob', userDisplayName: '' });
    expect(screen.getByLabelText('Your account').textContent).toBe('BO');
  });

  it('computes initials from names of any shape', () => {
    expect(initialsOf('Alice Example')).toBe('AE');
    expect(initialsOf('Alice Maria Example')).toBe('AE');
    expect(initialsOf('alice')).toBe('AL');
    expect(initialsOf('a')).toBe('A');
    expect(initialsOf('alice.example@example.test')).toBe('AT');
    expect(initialsOf('')).toBe('?');
    expect(initialsOf('😀x')).toBe('😀X');
  });

  describe('menu header', () => {
    it('leaves the focus to the first item, not to the header', async () => {
      renderNavigation({ subject: 'alice', userDisplayName: 'Alice Example', userProvider: 'simple' });
      openAccountMenu();
      const settings = await screen.findByRole('menuitem', { name: /Account settings/ });
      await waitFor(() => expect(document.activeElement).toBe(settings));
    });

    it('names the account and how it signed in', () => {
      renderNavigation({ subject: 'alice', userDisplayName: 'Alice Example', userProvider: 'example-oidc' });
      openAccountMenu();

      const header = screen.getByTestId('account-header');
      expect(header.textContent).toContain('Alice Example');
      expect(header.textContent).toContain('Signed in with example-oidc');
      expect(screen.queryByText('Admin')).toBeNull();
    });

    it('uses the subject when the provider gave no name', () => {
      renderNavigation({ subject: 'bob', userDisplayName: '', userProvider: 'simple' });
      openAccountMenu();

      expect(screen.getByTestId('account-header').textContent).toContain('bob');
      expect(screen.getByTestId('account-header').textContent).toContain('Signed in with simple');
    });

    it('marks an admin', () => {
      renderNavigation({ subject: 'root', isAdmin: true, userProvider: 'simple' });
      openAccountMenu();

      expect(screen.getByTestId('account-header').textContent).toContain('Admin');
    });

    it('is not something to click', () => {
      renderNavigation({ subject: 'bob', userProvider: 'simple' });
      openAccountMenu();

      expect(screen.getByTestId('account-header').closest('a, button, [role="menuitem"]')).toBeNull();
    });
  });

  it('keeps the account settings behind one entry', () => {
    renderNavigation({ passwordChangeEnabled: true, apiTokensEnabled: true });
    openAccountMenu();

    expect(screen.getByText('Account settings').closest('a')?.getAttribute('href')).toBe('/account');
    // the tabs of the account page are not entries of the menu any more
    expect(screen.queryByText('Password and two-factor')).toBeNull();
    expect(screen.queryByText('API tokens')).toBeNull();
    expect(screen.queryByText('Where you are signed in')).toBeNull();
    expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).toEqual(['Account settings', 'Sign out']);
  });

  // signing out takes a POST, which another site cannot send in the user's name
  it('signs out with a form post', () => {
    renderNavigation();
    openAccountMenu();

    const form = screen.getByTitle('Sign out').closest('form');
    expect(form?.getAttribute('action')).toBe('/signout');
    expect(form?.getAttribute('method')).toBe('post');
    expect(screen.getByTitle('Sign out').getAttribute('type')).toBe('submit');
  });

  // the admin pages are a place in the app, not a setting of your account
  it('keeps the admin devices button in the bar', () => {
    renderNavigation({ isAdmin: true });
    expect(screen.getByTitle('All devices').closest('a')?.getAttribute('href')).toBe('/admin/all-devices');
  });

  it('does not offer the admin devices button to everybody else', () => {
    renderNavigation({ isAdmin: false });
    expect(screen.queryByTitle('All devices')).toBeNull();
  });

  describe('theme button', () => {
    it('sits in the bar, not in the menu', () => {
      renderNavigation();
      expect(screen.getByLabelText('Switch to dark mode')).toBeTruthy();

      openAccountMenu();
      expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).not.toContain('Switch to dark mode');
    });

    it('switches and says what it would switch to', () => {
      renderNavigation();

      fireEvent.click(screen.getByLabelText('Switch to dark mode'));

      expect(AppState.darkMode).toBe(true);
      expect(screen.getByLabelText('Switch to light mode')).toBeTruthy();
      expect(screen.queryByLabelText('Switch to dark mode')).toBeNull();
    });

    // the OS says light (matchMedia is false in the test setup): only a
    // deviation from it is worth storing
    it('stores only a deviation from the OS setting', () => {
      renderNavigation();

      fireEvent.click(screen.getByLabelText('Switch to dark mode'));
      expect(localStorage.getItem('customDarkMode')).toBe('true');

      fireEvent.click(screen.getByLabelText('Switch to light mode'));
      expect(localStorage.getItem('customDarkMode')).toBeNull();
    });

    it('applies the stored choice on load', () => {
      localStorage.setItem('customDarkMode', 'true');
      renderNavigation();

      expect(AppState.darkMode).toBe(true);
      expect(screen.getByLabelText('Switch to light mode')).toBeTruthy();
    });
  });
});
