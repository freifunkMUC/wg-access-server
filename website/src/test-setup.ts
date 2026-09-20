import { afterEach, beforeEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// jsdom implements neither of these, and the app asks for both on startup:
// AppState reads the colour scheme preference and remembers the choice.
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

// Dialogs mount themselves into their own container next to the one React
// Testing Library renders into and unmount when they close, so cleaning up
// the test's container is enough. Emptying the whole body instead breaks
// MUI's focus restore on the next unmount.
beforeEach(() => {
  // MUI's focus trap remembers whatever was focused when a dialog opened and
  // focuses it again when the dialog closes. After a previous test's DOM is
  // gone, jsdom leaves nothing focusable behind, so point it at the body.
  document.body.tabIndex = -1;
  document.body.focus();
});

afterEach(cleanup);
