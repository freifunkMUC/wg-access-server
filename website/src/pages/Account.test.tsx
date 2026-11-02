import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { AppRoutes } from '../App';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';

// The pages have their own tests; here they only have to say which one is shown.
vi.mock('./Password', () => ({ Password: () => <div>password page</div> }));
vi.mock('./Sessions', () => ({ Sessions: () => <div>sessions page</div> }));
vi.mock('./ApiTokens', () => ({ ApiTokens: () => <div>tokens page</div> }));

function Where() {
  return <div data-testid="where">{useLocation().pathname}</div>;
}

// the real routes of App.tsx, so that a broken redirect fails here
function renderAt(path: string, info: Partial<InfoRes.AsObject> = {}) {
  AppState.setInfo({ isAdmin: false, ...info } as InfoRes.AsObject);
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
      <Where />
    </MemoryRouter>,
  );
}

const everything = { passwordChangeEnabled: true, apiTokensEnabled: true };

beforeEach(() => cleanup());
afterEach(cleanup);

describe('Account', () => {
  it('offers the tabs the server has turned on', () => {
    renderAt('/account/sessions', everything);

    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Password and two-factor',
      'Sessions',
      'API tokens',
    ]);
    expect(screen.getByRole('tab', { name: 'Sessions' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('sessions page')).toBeTruthy();
  });

  it('links each tab to its own route', () => {
    renderAt('/account/sessions', everything);

    expect(screen.getByRole('tab', { name: 'Password and two-factor' }).getAttribute('href')).toBe('/account/password');
    expect(screen.getByRole('tab', { name: 'Sessions' }).getAttribute('href')).toBe('/account/sessions');
    expect(screen.getByRole('tab', { name: 'API tokens' }).getAttribute('href')).toBe('/account/tokens');
  });

  it('switches the page with the tab', () => {
    renderAt('/account/sessions', everything);

    fireEvent.click(screen.getByRole('tab', { name: 'API tokens' }));

    expect(screen.getByTestId('where').textContent).toBe('/account/tokens');
    expect(screen.getByText('tokens page')).toBeTruthy();
    expect(screen.queryByText('sessions page')).toBeNull();
  });

  it('opens the first tab on /account', () => {
    renderAt('/account', everything);
    expect(screen.getByTestId('where').textContent).toBe('/account/password');
    expect(screen.getByText('password page')).toBeTruthy();
  });

  it('hides the password tab where the server keeps no password', () => {
    renderAt('/account', { passwordChangeEnabled: false, apiTokensEnabled: true });

    expect(screen.queryByRole('tab', { name: 'Password and two-factor' })).toBeNull();
    expect(screen.getByTestId('where').textContent).toBe('/account/sessions');
  });

  it('hides the tokens tab and sends a link to it to the first tab', () => {
    renderAt('/account/tokens', { passwordChangeEnabled: false, apiTokensEnabled: false });

    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(['Sessions']);
    expect(screen.getByTestId('where').textContent).toBe('/account/sessions');
    expect(screen.queryByText('tokens page')).toBeNull();
  });

  it('does not show the password page where it is turned off', () => {
    renderAt('/account/password', { passwordChangeEnabled: false });

    expect(screen.getByTestId('where').textContent).toBe('/account/sessions');
    expect(screen.queryByText('password page')).toBeNull();
  });

  it.each([
    ['/password', '/account/password'],
    ['/sessions', '/account/sessions'],
    ['/tokens', '/account/tokens'],
  ])('redirects the old route %s to %s', (from, to) => {
    renderAt(from, everything);
    expect(screen.getByTestId('where').textContent).toBe(to);
  });
});
