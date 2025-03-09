import React from 'react';
import { createRoot } from 'react-dom/client';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';

interface Props {
  intent: 'success' | 'info' | 'warning' | 'error';
  text: string;
}

export function toast(props: Props) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container!);


  const onClose = () => {
    root.unmount();
    document.body.removeChild(container);
  };

  root.render(
    <Snackbar
      open={true}
      autoHideDuration={3000}
      onClose={onClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
    >
      <Alert severity={props.intent} elevation={6} variant="filled" onClose={onClose}>
        {props.text}
      </Alert>
    </Snackbar>    
  );
}
