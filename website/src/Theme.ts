import { createTheme } from '@mui/material/styles';

// One theme for the app and for the dialogs rendered outside of it.
// Buttons and tabs keep the case their label is written in: the UI uses
// sentence case throughout ("Add a device", "Sign in"), like the sign-in page.
export function appTheme(dark: boolean) {
  return createTheme({
    palette: {
      mode: dark ? 'dark' : 'light',
    },
    components: {
      MuiButton: { styleOverrides: { root: { textTransform: 'none' } } },
      MuiTab: { styleOverrides: { root: { textTransform: 'none' } } },
    },
  });
}
