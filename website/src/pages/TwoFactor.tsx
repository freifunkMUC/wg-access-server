import React, { useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { AppState } from '../AppState';
import { QRCode } from '../components/QRCode';
import { toast } from '../components/Toast';
import { errorMessage } from '../Util';

// how few recovery codes are worth pointing out
export const fewRecoveryCodes = 3;

// TwoFactor is the second factor of the built-in sign-in: setting it up,
// turning it off, and the recovery codes that are shown exactly once.
export const TwoFactor = observer(function TwoFactor() {
  // the enrolment in progress, if any
  const [setup, setSetup] = useState<{ secret: string; uri: string }>();
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [recovery, setRecovery] = useState<string[]>();
  const [error, setError] = useState<string>();
  const [working, setWorking] = useState(false);

  const enabled = !!AppState.info?.twoFactorEnabled;
  const left = AppState.info?.recoveryCodesLeft ?? 0;

  const refreshInfo = async () => {
    try {
      AppState.setInfo(await grpc.server.info({}));
    } catch (e) {
      console.error('Failed to reload the server info:', e);
    }
  };

  const start = async () => {
    setError(undefined);
    setWorking(true);
    try {
      const res = await grpc.users.startTwoFactor({});
      setSetup({ secret: res.secret, uri: res.uri });
      setCode('');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setWorking(false);
    }
  };

  const confirm = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(undefined);
    setWorking(true);
    try {
      const res = await grpc.users.confirmTwoFactor({ code });
      setRecovery(res.recoveryCodes);
      setSetup(undefined);
      setCode('');
      toast({ text: 'Two-factor authentication is on', intent: 'success' });
      await refreshInfo();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setWorking(false);
    }
  };

  const disable = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(undefined);
    setWorking(true);
    try {
      await grpc.users.disableTwoFactor({ password });
      setPassword('');
      setRecovery(undefined);
      toast({ text: 'Two-factor authentication is off', intent: 'success' });
      await refreshInfo();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setWorking(false);
    }
  };

  if (!AppState.info?.passwordChangeEnabled) {
    return null;
  }

  return (
    <Box sx={{ mt: 5 }}>
      <Typography variant="h5" sx={{ mb: 2 }}>
        Two-factor authentication
        {enabled && <Chip label="On" color="success" size="small" sx={{ ml: 1 }} />}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {recovery && (
        <Alert severity="warning" sx={{ mb: 2 }} data-testid="recovery-codes">
          <Typography sx={{ mb: 1 }}>
            Write these recovery codes down and keep them somewhere safe. Each signs you in once, and this is the only
            time they are shown - the server keeps only their hashes.
          </Typography>
          <Box component="pre" sx={{ m: 0, fontFamily: 'monospace' }}>
            {recovery.join('\n')}
          </Box>
        </Alert>
      )}

      {!enabled && !setup && (
        <>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Ask for a code from an authenticator app on top of your password. Somebody who learns your password then
            still cannot sign in as you.
          </Typography>
          <Button variant="contained" disabled={working} onClick={start}>
            Set up two-factor
          </Button>
        </>
      )}

      {setup && (
        <form onSubmit={confirm}>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Scan this with your authenticator app, then type the code it shows to finish. Nothing is asked of you until
            you do.
          </Typography>
          <QRCode content={setup.uri} />
          <Typography variant="body2" sx={{ mt: 2 }}>
            Cannot scan it? Enter this secret by hand:
          </Typography>
          <Box component="code" data-testid="totp-secret" sx={{ wordBreak: 'break-all' }}>
            {setup.secret}
          </Box>
          <Stack direction="row" spacing={1} sx={{ mt: 2, alignItems: 'flex-start' }}>
            <TextField
              required
              label="Code from the app"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              slotProps={{ htmlInput: { inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 6 } }}
            />
            <Button type="submit" variant="contained" disabled={working || code.length < 6} sx={{ mt: 1 }}>
              Turn it on
            </Button>
            <Button disabled={working} onClick={() => setSetup(undefined)} sx={{ mt: 1 }}>
              Cancel
            </Button>
          </Stack>
        </form>
      )}

      {enabled && (
        <>
          <Typography variant="body2" sx={{ mb: 2 }}>
            You are asked for a code from your authenticator app when you sign in.{' '}
            {left > 0
              ? `${left} recovery code${left === 1 ? '' : 's'} left.`
              : 'No recovery codes left - turn it off and on again to get new ones.'}
            {left > 0 && left <= fewRecoveryCodes && ' Turn it off and on again to get a new set.'}
          </Typography>
          <form onSubmit={disable}>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
              <TextField
                required
                type="password"
                label="Your password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                helperText="Asked for, so that a browser you left signed in cannot turn it off"
              />
              <Button type="submit" variant="outlined" color="error" disabled={working} sx={{ mt: 1 }}>
                Turn it off
              </Button>
            </Stack>
          </form>
        </>
      )}
    </Box>
  );
});
