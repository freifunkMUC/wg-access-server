import React, { useCallback, useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import { observer } from 'mobx-react';
import { grpc, toDate } from '../Api';
import { AppState } from '../AppState';
import { confirm, prompt } from '../components/Present';
import { toast } from '../components/Toast';
import { decodeCreationOptions, encodeCredential, passkeysSupported } from '../components/webauthn';
import { Passkey } from '../sdk/users_pb';
import { errorMessage, lastSeen } from '../Util';

// Passkeys is the other second factor: a credential the browser holds, which
// only this site can ask for.
export const Passkeys = observer(function Passkeys() {
  const [passkeys, setPasskeys] = useState<Passkey.AsObject[]>();
  const [name, setName] = useState('');
  const [error, setError] = useState<string>();
  const [working, setWorking] = useState(false);

  const load = useCallback(async () => {
    try {
      setPasskeys((await grpc.users.listPasskeys({})).items);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refreshInfo = async () => {
    try {
      AppState.setInfo(await grpc.server.info({}));
    } catch (e) {
      console.error('Failed to reload the server info:', e);
    }
  };

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(undefined);
    setWorking(true);
    try {
      const begun = await grpc.users.beginPasskey({});
      const options = decodeCreationOptions(JSON.parse(begun.options));
      const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('The browser made no passkey');
      }
      await grpc.users.finishPasskey({ credential: encodeCredential(credential), name });
      toast({ text: 'Passkey added', intent: 'success' });
      setName('');
      await load();
      await refreshInfo();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setWorking(false);
    }
  };

  // Renaming touches nothing but the label: the credential stays as it is, so
  // a passkey whose name no longer fits need not be removed and registered
  // again.
  const rename = async (passkey: Passkey.AsObject) => {
    const name = await prompt('What should this passkey be called?', passkey.name);
    if (name === null || name === passkey.name) {
      return;
    }
    try {
      await grpc.users.renamePasskey({ id: passkey.id, name });
      toast({ text: `Now called "${name}"`, intent: 'success' });
      await load();
    } catch (e) {
      toast({ text: 'Failed to rename the passkey: ' + errorMessage(e), intent: 'error' });
    }
  };

  const remove = async (passkey: Passkey.AsObject) => {
    const last = (passkeys?.length ?? 0) === 1 && !AppState.info?.twoFactorEnabled;
    const warning = last ? ' It is your last one, so you will sign in with your password alone again.' : '';
    if (!(await confirm(`Remove the passkey "${passkey.name}"?${warning}`))) {
      return;
    }
    try {
      await grpc.users.deletePasskey({ id: passkey.id });
      toast({ text: `"${passkey.name}" removed`, intent: 'success' });
      await load();
      await refreshInfo();
    } catch (e) {
      toast({ text: 'Failed to remove the passkey: ' + errorMessage(e), intent: 'error' });
    }
  };

  if (!AppState.info?.passwordChangeEnabled) {
    return null;
  }

  return (
    <Box sx={{ mt: 5 }}>
      <Typography variant="h5" sx={{ mb: 2 }}>
        Passkeys
      </Typography>

      <Typography variant="body2" sx={{ mb: 2 }}>
        A passkey is held by this device or your phone and can only be used on this site - a page pretending to be this
        one cannot ask for it, and there is nothing to read out to somebody on the telephone. It is asked for after your
        password.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {!passkeysSupported() && (
        <Alert severity="info" sx={{ mb: 2 }}>
          This browser cannot add a passkey here. They need a page served over HTTPS.
        </Alert>
      )}

      {passkeys && passkeys.length > 0 && (
        <TableContainer sx={{ mb: 2 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Added</TableCell>
                <TableCell>Last used</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {passkeys.map((passkey) => (
                <TableRow key={passkey.id}>
                  <TableCell>{passkey.name}</TableCell>
                  <TableCell>{passkey.createdAt ? toDate(passkey.createdAt).toLocaleDateString() : ''}</TableCell>
                  <TableCell>{lastSeen(passkey.lastUsedAt)}</TableCell>
                  <TableCell align="right">
                    <IconButton
                      aria-label={`Rename ${passkey.name}`}
                      title="Rename"
                      onClick={() => void rename(passkey)}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton
                      aria-label={`Remove ${passkey.name}`}
                      title="Remove"
                      onClick={() => void remove(passkey)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <form onSubmit={add}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
          <TextField
            label="Name"
            placeholder="e.g. the key on my keyring"
            value={name}
            onChange={(e) => setName(e.target.value)}
            helperText="What it is, so you can tell it from the others later"
            slotProps={{ htmlInput: { maxLength: 64 } }}
          />
          <Button type="submit" variant="contained" disabled={working || !passkeysSupported()} sx={{ mt: 1 }}>
            Add a passkey
          </Button>
        </Stack>
      </form>
    </Box>
  );
});
