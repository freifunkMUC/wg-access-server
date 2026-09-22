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
  it('offers to sign out once the server info has loaded', () => {
    AppState.setInfo({ isAdmin: false } as InfoRes.AsObject);
    renderNavigation();
    expect(screen.getByTitle('Logout').closest('a')?.getAttribute('href')).toBe('/signout');
    expect(screen.queryByTitle('Login')).toBeNull();
  });

  it('does not underline the app name', () => {
    AppState.setInfo({ isAdmin: false } as InfoRes.AsObject);
    renderNavigation();
    expect(screen.getByText('wg-access-server').closest('a')?.className).toContain('underlineNone');
  });
});
