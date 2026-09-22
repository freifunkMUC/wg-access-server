import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import Button from '@mui/material/Button';
import { ThemeProvider } from '@mui/material/styles';
import { appTheme } from './Theme';

// MUI writes button labels in capitals unless told otherwise. The UI uses
// sentence case everywhere, so a label must show the way it is written.
describe('appTheme', () => {
  for (const dark of [false, true]) {
    it(`keeps the case of button labels (${dark ? 'dark' : 'light'})`, () => {
      render(
        <ThemeProvider theme={appTheme(dark)}>
          <Button>Add a device</Button>
        </ThemeProvider>,
      );
      expect(getComputedStyle(screen.getByRole('button')).textTransform).toBe('none');
    });
  }
});
