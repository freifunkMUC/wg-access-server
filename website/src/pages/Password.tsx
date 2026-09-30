import React, { useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { AppState } from '../AppState';
import { toast } from '../components/Toast';
import { errorMessage } from '../Util';

// what the server refuses anything shorter than; saying so before the request
// is nicer than being told afterwards
export const minPasswordLength = 10;

export const Password = observer(function Password() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [error, setError] = useState<string>();
  const [working, setWorking] = useState(false);

  if (!AppState.info?.passwordChangeEnabled) {
    return <Alert severity="info">Your password is not kept by this server - change it where you sign in.</Alert>;
  }

  const tooShort = next.length > 0 && next.length < minPasswordLength;
  const mismatch = repeat.length > 0 && next !== repeat;
  const ready = current.length > 0 && next.length >= minPasswordLength && next === repeat;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!ready || working) {
      return;
    }
    setWorking(true);
    setError(undefined);
    try {
      const res = await grpc.users.changePassword({ currentPassword: current, newPassword: next });
      toast({
        text: res.sessionsEnded
          ? `Password changed - ${res.sessionsEnded} other session${res.sessionsEnded === 1 ? '' : 's'} signed out`
          : 'Password changed',
        intent: 'success',
      });
      setCurrent('');
      setNext('');
      setRepeat('');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setWorking(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 480, mx: 'auto' }}>
      <Typography variant="h5" sx={{ mb: 2 }}>
        Change your password
      </Typography>

      <Typography variant="body2" sx={{ mb: 2 }}>
        This is the password you sign in with. Changing it signs out every other browser you are signed in with - the
        one you are using stays. Your devices keep connecting either way: a tunnel does not use your password.
      </Typography>

      <form onSubmit={submit}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        <TextField
          fullWidth
          required
          margin="dense"
          type="password"
          label="Current password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
        <TextField
          fullWidth
          required
          margin="dense"
          type="password"
          label="New password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          error={tooShort}
          helperText={tooShort ? `At least ${minPasswordLength} characters` : ' '}
        />
        <TextField
          fullWidth
          required
          margin="dense"
          type="password"
          label="Repeat the new password"
          autoComplete="new-password"
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          error={mismatch}
          helperText={mismatch ? 'The two do not match' : ' '}
        />
        <Button type="submit" variant="contained" disabled={!ready || working} sx={{ mt: 1 }}>
          Change password
        </Button>
      </form>
    </Box>
  );
});
