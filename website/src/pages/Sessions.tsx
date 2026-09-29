import React, { useCallback, useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import LogoutIcon from '@mui/icons-material/Logout';
import { observer } from 'mobx-react';
import { grpc, toDate } from '../Api';
import { confirm } from '../components/Present';
import { toast } from '../components/Toast';
import { Session } from '../sdk/sessions_pb';
import { errorMessage, lastSeen } from '../Util';

// browsers and platforms recognised in a user agent, longest-lived names
// first: Edge and Chromium both claim to be Chrome, and Chrome claims to be
// Safari, so the order decides what a browser is called.
const browsers = [
  { name: 'Edge', match: /Edg[e|A|iOS]?\//i },
  { name: 'Opera', match: /OPR\/|Opera\//i },
  { name: 'Samsung Internet', match: /SamsungBrowser\//i },
  { name: 'Firefox', match: /Firefox\/|FxiOS\//i },
  { name: 'Chrome', match: /Chrome\/|CriOS\//i },
  { name: 'Safari', match: /Safari\//i },
];

const platforms = [
  { name: 'iPhone', match: /iPhone/i },
  { name: 'iPad', match: /iPad/i },
  { name: 'Android', match: /Android/i },
  { name: 'Windows', match: /Windows/i },
  { name: 'macOS', match: /Macintosh|Mac OS X/i },
  { name: 'Linux', match: /Linux|X11/i },
];

// describeAgent turns a user agent into something a person can match against
// the devices in front of them. It is deliberately rough: the point is to tell
// two sessions apart, not to identify a browser exactly. Anything unknown is
// shown as it came, because a truthful string nobody parsed beats a wrong
// guess - and a session one cannot recognise is one nobody dares to end.
export function describeAgent(userAgent: string): string {
  const agent = userAgent.trim();
  if (agent === '') {
    return 'Unknown browser';
  }
  const browser = browsers.find((b) => b.match.test(agent));
  const platform = platforms.find((p) => p.match.test(agent));
  if (!browser && !platform) {
    return agent.length > 60 ? agent.slice(0, 60) + '…' : agent;
  }
  if (!browser) {
    return platform!.name;
  }
  return platform ? `${browser.name} on ${platform.name}` : browser.name;
}

function signedIn(timestamp: Session.AsObject['createdAt']): string {
  return timestamp ? toDate(timestamp).toLocaleString() : '';
}

export const Sessions = observer(function Sessions() {
  const [sessions, setSessions] = useState<Session.AsObject[]>();
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    try {
      setSessions((await grpc.sessions.listSessions({})).items);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const end = async (session: Session.AsObject) => {
    if (!(await confirm(`Sign out of ${describeAgent(session.userAgent)}? It has to sign in again.`))) {
      return;
    }
    try {
      await grpc.sessions.deleteSession({ id: session.id });
      toast({ text: 'Signed out', intent: 'success' });
    } catch (e) {
      toast({ text: 'Failed to sign out: ' + errorMessage(e), intent: 'error' });
    }
    await load();
  };

  const endOthers = async () => {
    if (!(await confirm('Sign out everywhere else? Only this browser stays signed in.'))) {
      return;
    }
    try {
      const res = await grpc.sessions.deleteOtherSessions({});
      toast({ text: `Signed out of ${res.ended} other session${res.ended === 1 ? '' : 's'}`, intent: 'success' });
    } catch (e) {
      toast({ text: 'Failed to sign out: ' + errorMessage(e), intent: 'error' });
    }
    await load();
  };

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  const others = (sessions ?? []).filter((session) => !session.current).length;

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>
          Signed in
        </Typography>
        <Button variant="contained" startIcon={<LogoutIcon />} disabled={others === 0} onClick={endOthers}>
          Sign out everywhere else
        </Button>
      </Box>

      <Typography variant="body2" sx={{ mb: 2 }}>
        Every browser you signed in with is listed here. Ending a session signs that browser out at once - do that for
        one you do not recognise, or for a computer you left signed in.
      </Typography>

      {sessions && <SessionTable sessions={sessions} onEnd={end} />}
    </Box>
  );
});

interface SessionTableProps {
  sessions: Session.AsObject[];
  onEnd: (session: Session.AsObject) => void;
}

function SessionTable({ sessions, onEnd }: SessionTableProps) {
  if (sessions.length === 0) {
    // an API token reaches this page without a session of its own
    return <Typography color="text.secondary">You have no browser sessions.</Typography>;
  }
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Browser</TableCell>
            <TableCell>IP address</TableCell>
            <TableCell>Signed in</TableCell>
            <TableCell>Last used</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {sessions.map((session) => (
            <TableRow key={session.id}>
              <TableCell>
                {describeAgent(session.userAgent)}
                {session.current && <Chip label="This browser" size="small" color="primary" sx={{ ml: 1 }} />}
              </TableCell>
              <TableCell>{session.remoteAddr}</TableCell>
              <TableCell>{signedIn(session.createdAt)}</TableCell>
              <TableCell>{lastSeen(session.lastSeenAt)}</TableCell>
              <TableCell align="right">
                {/* the session doing the asking is ended by signing out, which
                    is in the navigation and also clears the cookie */}
                {!session.current && (
                  <IconButton
                    aria-label={`Sign out of ${describeAgent(session.userAgent)}`}
                    title="Sign out"
                    onClick={() => onEnd(session)}
                  >
                    <LogoutIcon />
                  </IconButton>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
