import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import TextField from '@mui/material/TextField';
import { ThemeProvider } from '@mui/material/styles';
import { appTheme } from '../Theme';
import { AppState } from '../AppState';
import React from 'react';
import { createRoot } from 'react-dom/client';

export function present<T>(content: (close: (result: T) => void) => React.ReactNode) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container!); 

  return new Promise<T>((resolve) => {
    const close = (result: T) => {
      root.unmount();
      resolve(result);
    };
    root.render(<>{content(close)}</>);
  });
}

export function confirm(msg: string): Promise<boolean> {
  const darkLightTheme = appTheme(AppState.darkMode);

  return present<boolean>((close) => (
    <ThemeProvider theme={darkLightTheme}>
      <Dialog open={true} onClose={() => close(false)}>
        <DialogTitle>Confirm</DialogTitle>
        <DialogContent>
          <DialogContentText>{msg}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => close(false)} variant="contained" color="primary" autoFocus>
            Cancel
          </Button>
          <Button onClick={() => close(true)} variant="outlined" color="secondary">
            OK
          </Button>
        </DialogActions>
      </Dialog>
    </ThemeProvider>
  ));
}

/**
 * Asks the user for a single line of text. Resolves with null when the dialog
 * is cancelled or nothing was entered.
 */
export function prompt(msg: string, initialValue = ''): Promise<string | null> {
  const darkLightTheme = appTheme(AppState.darkMode);

  return present<string | null>((close) => {
    let value = initialValue;
    const submit = () => close(value.trim() === '' ? null : value.trim());

    return (
      <ThemeProvider theme={darkLightTheme}>
        <Dialog open={true} onClose={() => close(null)} fullWidth maxWidth="xs">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              submit();
            }}
          >
            <DialogTitle>{msg}</DialogTitle>
            <DialogContent>
              <TextField
                autoFocus
                fullWidth
                variant="standard"
                defaultValue={initialValue}
                onChange={(event) => (value = event.currentTarget.value)}
                slotProps={{ htmlInput: { 'aria-label': msg } }}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={() => close(null)} variant="contained" color="primary">
                Cancel
              </Button>
              <Button type="submit" variant="outlined" color="secondary">
                OK
              </Button>
            </DialogActions>
          </form>
        </Dialog>
      </ThemeProvider>
    );
  });
}
