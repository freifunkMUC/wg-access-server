import React, { useCallback, useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import IconButton from '@mui/material/IconButton';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import AddIcon from '@mui/icons-material/Add';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import { observer } from 'mobx-react';
import { dateToTimestamp, grpc, toDate } from '../Api';
import { AppState } from '../AppState';
import { confirm } from '../components/Present';
import { toast } from '../components/Toast';
import { Token } from '../sdk/tokens_pb';
import { errorMessage, lastSeen } from '../Util';

// Lifetimes offered when creating a token, in days. 0 is "never expires".
export const lifetimes = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: '1 year' },
  { days: 0, label: 'Never' },
];

export function expiryFor(days: number, now: Date = new Date()): Date | undefined {
  if (days === 0) {
    return undefined;
  }
  return new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
}

function formatDate(timestamp: Token.AsObject['createdAt']): string {
  return timestamp ? toDate(timestamp).toLocaleDateString() : '';
}

function expires(token: Token.AsObject): string {
  if (!token.expiresAt) {
    return 'Never';
  }
  const at = toDate(token.expiresAt);
  return at <= new Date() ? 'Expired' : at.toLocaleDateString();
}

export const ApiTokens = observer(function ApiTokens() {
  const [mine, setMine] = useState<Token.AsObject[]>();
  const [all, setAll] = useState<Token.AsObject[]>();
  const [error, setError] = useState<string>();
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<string>();
  const isAdmin = !!AppState.info?.isAdmin;

  const load = useCallback(async () => {
    try {
      setMine((await grpc.tokens.listTokens({})).items);
      if (isAdmin) {
        setAll((await grpc.tokens.listAllTokens({})).items);
      }
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [isAdmin]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (token: Token.AsObject, showOwner?: boolean) => {
    const whose = showOwner ? ` of ${token.ownerName || token.owner}` : '';
    if (!(await confirm(`Revoke the token "${token.name}"${whose}? Scripts using it stop working immediately.`))) {
      return;
    }
    try {
      await grpc.tokens.deleteToken({ id: token.id });
      toast({ text: `Token "${token.name}" revoked`, intent: 'success' });
    } catch (e) {
      toast({ text: 'Failed to revoke the token: ' + errorMessage(e), intent: 'error' });
    }
    await load();
  };

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>
          API tokens
        </Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>
          Create token
        </Button>
      </Box>

      <Typography variant="body2" sx={{ mb: 2 }}>
        A token lets a script use the API as you, without a browser session. Send it in the{' '}
        <code>Authorization</code> header:
      </Typography>
      <Box component="pre" sx={{ p: 1, mb: 3, overflowX: 'auto', bgcolor: 'action.hover', borderRadius: 1 }}>
        {`curl -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' -d '{}' \\\n  ${window.location.origin}/api/proto.Devices/ListDevices`}
      </Box>

      <TokenTable tokens={mine} onRevoke={revoke} emptyText="You have no API tokens." />

      {isAdmin && (
        <>
          <Typography variant="h6" sx={{ mt: 4, mb: 1 }}>
            All tokens
          </Typography>
          <TokenTable tokens={all} onRevoke={revoke} showOwner emptyText="Nobody has an API token." />
        </>
      )}

      {creating && (
        <CreateTokenDialog
          onClose={() => setCreating(false)}
          onCreated={(created) => {
            setCreating(false);
            setSecret(created);
            void load();
          }}
        />
      )}
      {secret && <SecretDialog secret={secret} onClose={() => setSecret(undefined)} />}
    </Box>
  );
});

interface TokenTableProps {
  tokens?: Token.AsObject[];
  onRevoke: (token: Token.AsObject, showOwner?: boolean) => void;
  showOwner?: boolean;
  emptyText: string;
}

function TokenTable({ tokens, onRevoke, showOwner, emptyText }: TokenTableProps) {
  if (!tokens) {
    return null;
  }
  if (tokens.length === 0) {
    return <Typography color="text.secondary">{emptyText}</Typography>;
  }
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            {showOwner && <TableCell>Owner</TableCell>}
            <TableCell>Name</TableCell>
            <TableCell>Created</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell>Last used</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {tokens.map((token) => (
            <TableRow key={token.id}>
              {showOwner && <TableCell>{token.ownerName || token.owner}</TableCell>}
              <TableCell>{token.name}</TableCell>
              <TableCell>{formatDate(token.createdAt)}</TableCell>
              <TableCell>{expires(token)}</TableCell>
              <TableCell>{lastSeen(token.lastUsedAt)}</TableCell>
              <TableCell align="right">
                <IconButton aria-label={`Revoke ${token.name}`} title="Revoke" onClick={() => onRevoke(token, showOwner)}>
                  <DeleteIcon />
                </IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

interface CreateTokenDialogProps {
  onClose: () => void;
  onCreated: (secret: string) => void;
}

export function CreateTokenDialog({ onClose, onCreated }: CreateTokenDialogProps) {
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [error, setError] = useState<string>();

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const expiresAt = expiryFor(days);
    try {
      const res = await grpc.tokens.createToken({
        name,
        expiresAt: expiresAt ? dateToTimestamp(expiresAt) : undefined,
      });
      onCreated(res.secret);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <form onSubmit={submit}>
        <DialogTitle>Create API token</DialogTitle>
        <DialogContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <TextField
            autoFocus
            required
            fullWidth
            margin="dense"
            label="Name"
            helperText="What the token is for, e.g. the script using it"
            value={name}
            onChange={(e) => setName(e.target.value)}
            slotProps={{ htmlInput: { maxLength: 100 } }}
          />
          <FormControl fullWidth margin="dense">
            <InputLabel id="token-lifetime">Expires after</InputLabel>
            <Select
              labelId="token-lifetime"
              label="Expires after"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              {lifetimes.map((l) => (
                <MenuItem key={l.days} value={l.days}>
                  {l.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained">
            Create
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}

function SecretDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      toast({ text: 'Token copied', intent: 'success' });
    } catch {
      toast({ text: 'Copying failed - please select the token and copy it by hand', intent: 'warning' });
    }
  };

  return (
    <Dialog open fullWidth maxWidth="sm">
      <DialogTitle>Your new API token</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          Copy the token now. It is not stored and cannot be shown again.
        </Alert>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box
            component="code"
            data-testid="token-secret"
            sx={{ flexGrow: 1, p: 1, bgcolor: 'action.hover', borderRadius: 1, wordBreak: 'break-all' }}
          >
            {secret}
          </Box>
          <IconButton aria-label="Copy token" title="Copy" onClick={copy}>
            <ContentCopyIcon />
          </IconButton>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button variant="contained" onClick={onClose}>
          Done
        </Button>
      </DialogActions>
    </Dialog>
  );
}
