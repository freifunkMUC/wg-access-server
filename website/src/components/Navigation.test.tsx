import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Navigation from './Navigation';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';

function renderNavigation() {
  return render(
    <MemoryRouter>
      <Navigation />
    </MemoryRouter>,
  );
}

describe('Navigation', () => {
  // The session cookie is HttpOnly, so it cannot tell whether somebody is
  // signed in - the loaded server info can.
  // signing out takes a POST, which another site cannot send in the user's name
  it('offers to sign out once the server info has loaded', () => {
    AppState.setInfo({ isAdmin: false } as InfoRes.AsObject);
    renderNavigation();
    const form = screen.getByTitle('Sign out').closest('form');
    expect(form?.getAttribute('action')).toBe('/signout');
    expect(form?.getAttribute('method')).toBe('post');
    expect(screen.queryByTitle('Sign in')).toBeNull();
  });

  it('does not underline the app name', () => {
    AppState.setInfo({ isAdmin: false } as InfoRes.AsObject);
    renderNavigation();
    expect(screen.getByText('wg-access-server').closest('a')?.className).toContain('underlineNone');
  });
});
