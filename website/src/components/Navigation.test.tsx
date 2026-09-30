import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Navigation from './Navigation';
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
  fireEvent.click(screen.getByTitle('Your account'));
}

describe('Navigation', () => {
  it('does not underline the app name', () => {
    renderNavigation();
    expect(screen.getByText('wg-access-server').closest('a')?.className).toContain('underlineNone');
  });

  // The session cookie is HttpOnly, so it cannot tell whether somebody is
  // signed in - the loaded server info can.
  it('offers the account menu once the server info has loaded', () => {
    renderNavigation();
    expect(screen.getByTitle('Your account')).toBeTruthy();
    expect(screen.queryByTitle('Sign in')).toBeNull();
  });

  // Everything about your own account used to sit in the bar as a row of
  // icons you had to hover one by one.
  it('keeps the account settings behind one button', () => {
    renderNavigation({ passwordChangeEnabled: true, apiTokensEnabled: true });

    expect(screen.queryByText('API tokens')).toBeNull();

    openAccountMenu();

    expect(screen.getByText('Password and two-factor').closest('a')?.getAttribute('href')).toBe('/password');
    expect(screen.getByText('Where you are signed in').closest('a')?.getAttribute('href')).toBe('/sessions');
    expect(screen.getByText('API tokens').closest('a')?.getAttribute('href')).toBe('/tokens');
    expect(screen.getByText(/Switch to (light|dark) mode/)).toBeTruthy();
  });

  it('leaves out what the server has turned off', () => {
    renderNavigation({ passwordChangeEnabled: false, apiTokensEnabled: false });

    openAccountMenu();

    expect(screen.queryByText('Password and two-factor')).toBeNull();
    expect(screen.queryByText('API tokens')).toBeNull();
    expect(screen.getByText('Where you are signed in')).toBeTruthy();
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
});
