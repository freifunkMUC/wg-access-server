import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import InputAdornment from '@mui/material/InputAdornment';
import MenuItem from '@mui/material/MenuItem';
import Stack from '@mui/material/Stack';
import TablePagination from '@mui/material/TablePagination';
import TextField from '@mui/material/TextField';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableSortLabel from '@mui/material/TableSortLabel';
import Typography from '@mui/material/Typography';
import SearchIcon from '@mui/icons-material/Search';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import Avatar from '@mui/material/Avatar';
import { observer } from 'mobx-react';
import React from 'react';
import { dateToTimestamp, grpc, toDate } from '../../Api';
import { AppState } from '../../AppState';
import { confirm } from '../../components/Present';
import { toast } from '../../components/Toast';
import { Device, SetDeviceAccessReq } from '../../sdk/devices_pb';
import { User } from '../../sdk/users_pb';
import { accessRank, deviceAccess, errorMessage, lastSeen } from '../../Util';
import { useLoaded } from '../../hooks';
import numeral from 'numeral';
import { Loading } from '../../components/Loading';
import { Error } from '../../components/Error';

// count writes "1 device" and "2 devices", so that what an action reports
// back reads like a sentence.
export function count(n: number, thing: string): string {
  return `${n} ${thing}${n === 1 ? '' : 's'}`;
}

type SortColumn = keyof Device.AsObject | 'download' | 'upload' | 'connected' | 'access';

export const AllDevices = observer(function AllDevices() {
  const [sortBy, setSortBy] = React.useState<SortColumn>('lastHandshakeTime');
  const [sortOrder, setSortOrder] = React.useState<'asc' | 'desc'>('desc');
  // what the device table shows of what was loaded
  const [deviceQuery, setDeviceQuery] = React.useState('');
  const [deviceState, setDeviceState] = React.useState<DeviceState>('all');
  const [devicePage, setDevicePage] = React.useState(0);
  const [devicesPerPage, setDevicesPerPage] = React.useState(25);
  // ... and of the users
  const [userQuery, setUserQuery] = React.useState('');
  const [userPage, setUserPage] = React.useState(0);
  const [usersPerPage, setUsersPerPage] = React.useState(25);
  // the device whose expiry date is being changed, if any
  const [expiryDevice, setExpiryDevice] = React.useState<Device.AsObject>();
  // ... and the one whose networks are being changed
  const [routesDevice, setRoutesDevice] = React.useState<Device.AsObject>();

  const userResource = useLoaded(async () => {
    try {
      const result = await grpc.users.listUsers({});
      AppState.clearLoadingError();
      return result.items;
    } catch (error) {
      console.error('An error occurred:', error);
      AppState.setLoadingError(errorMessage(error));
      return null;
    }
  });

  const deviceResource = useLoaded(async () => {
    try {
      const res = await grpc.devices.listAllDevices({});
      AppState.clearLoadingError();
      return res.items;
    } catch (error) {
      console.error('An error occurred:', error);
      AppState.setLoadingError(errorMessage(error));
      return null;
    }
  });

  const requestSort = (column: SortColumn) => {
    const isAsc = sortBy === column && sortOrder === 'asc';
    setSortOrder(isAsc ? 'desc' : 'asc');
    setSortBy(column);
  };

  const matchingDevices = sortDevices(
    filterDevices(deviceResource.current, deviceQuery, deviceState),
    sortBy,
    sortOrder,
  );

  // a search that leaves fewer rows than the page we are on would show an
  // empty table, so every change of what is looked for starts at the front
  React.useEffect(() => setDevicePage(0), [deviceQuery, deviceState]);
  React.useEffect(() => setUserPage(0), [userQuery]);

  const deleteUser = async (user: User.AsObject) => {
    if (await confirm('Are you sure you want to delete all devices from ' + user.name + '?')) {
      try {
        await grpc.users.deleteUser({
          name: user.name,
        });
        await userResource.refresh();
        await deviceResource.refresh();
      } catch (error) {
        console.error('Failed to delete user:', error);
        toast({ text: 'Failed to delete the user: ' + errorMessage(error), intent: 'error' });
      }
    }
  };

  // revokeAccess takes every way in from somebody at once, without deleting
  // anything: their devices keep their keys and addresses, so lifting the
  // blocks gives the access back without them setting up a client anew.
  const revokeAccess = async (user: User.AsObject) => {
    const whom = user.displayName || user.name;
    if (
      !(await confirm(
        `Take ${whom}'s access away? Their devices stop connecting, their API tokens are revoked and ` +
          'they are signed out everywhere. Nothing is deleted - you can unblock the devices later.',
      ))
    ) {
      return;
    }
    try {
      const res = await grpc.users.revokeAccess({ name: user.name });
      toast({
        text: `${whom}: ${count(res.devicesBlocked, 'device')} blocked, ${count(
          res.tokensDeleted,
          'API token',
        )} revoked, ${count(res.sessionsEnded, 'session')} ended`,
        intent: 'success',
      });
      await deviceResource.refresh();
    } catch (error) {
      console.error('Failed to revoke access:', error);
      toast({ text: 'Failed to take the access away: ' + errorMessage(error), intent: 'error' });
    }
  };

  // setAccess sends one change - blocking a device, or its expiry date - and
  // leaves the other as it is, so two admins working at the same time do not
  // undo each other.
  const setAccess = async (device: Device.AsObject, change: Partial<SetDeviceAccessReq.AsObject>, done: string) => {
    try {
      await grpc.devices.setDeviceAccess({
        name: device.name,
        owner: { value: device.owner },
        clearExpiresAt: false,
        ...change,
      });
      toast({ text: done, intent: 'success' });
      await deviceResource.refresh();
    } catch (error) {
      console.error('Failed to change the access of the device:', error);
      toast({ text: 'Failed to change the access of the device: ' + errorMessage(error), intent: 'error' });
    }
  };

  const toggleBlocked = (device: Device.AsObject) => {
    const blocked = !device.disabled;
    return setAccess(
      device,
      { disabled: { value: blocked } },
      blocked
        ? `${device.name} is blocked and cannot connect any more`
        : `${device.name} may connect again - the configuration the user has keeps working`,
    );
  };

  const setRoutes = async (device: Device.AsObject, routes: string[]) => {
    try {
      await grpc.devices.setDeviceRoutes({ name: device.name, owner: { value: device.owner }, routes });
      toast({
        text: routes.length
          ? `${device.name} now carries the traffic for ${routes.join(', ')}`
          : `${device.name} no longer carries traffic for other networks`,
        intent: 'success',
      });
      await deviceResource.refresh();
      return true;
    } catch (error) {
      console.error('Failed to change the routes of the device:', error);
      toast({ text: 'Failed to change the networks: ' + errorMessage(error), intent: 'error' });
      return false;
    }
  };

  const deleteDevice = async (device: Device.AsObject) => {
    if (await confirm('Are you sure you want to delete ' + device.name + ' from ' + device.ownerName + '?')) {
      try {
        await grpc.devices.deleteDevice({
          name: device.name,
          owner: { value: device.owner },
        });
        await deviceResource.refresh();
      } catch (error) {
        console.error('Failed to delete device:', error);
        toast({ text: 'Failed to delete the device: ' + errorMessage(error), intent: 'error' });
      }
    }
  };

  if (AppState.loadingError) {
    return <Error message={AppState.loadingError} />;
  }
  if (!deviceResource.current || !userResource.current) {
    return <Loading />;
  }
  const allDevices = deviceResource.current;
  const allUsers = userResource.current;
  const matchingUsers = filterUsers(allUsers, userQuery);
  const devices = matchingDevices.slice(devicePage * devicesPerPage, (devicePage + 1) * devicesPerPage);
  const users = matchingUsers.slice(userPage * usersPerPage, (userPage + 1) * usersPerPage);

  // show the provider column when there is more than 1 provider in use, i.e.
  // not all devices are from the same auth provider. Taken from all of them,
  // so that a column does not come and go while somebody searches.
  const showProviderCol =
    allDevices.length >= 2 && allDevices.some((d) => d.ownerProvider !== allDevices[0].ownerProvider);

  return (
    <div style={{ display: 'grid', gridGap: 25, gridAutoFlow: 'row' }}>
      <Typography variant="h5" component="h5">
        Devices
        <Typography component="span">
          {' '}
          ({allDevices.filter((p) => p.connected).length} of {allDevices.length} online
          {matchingDevices.length !== allDevices.length && `, ${matchingDevices.length} shown`})
        </Typography>
      </Typography>

      <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap', rowGap: 2 }}>
        <TextField
          size="small"
          label="Search devices"
          placeholder="name, owner, address"
          value={deviceQuery}
          onChange={(event) => setDeviceQuery(event.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            },
          }}
          sx={{ minWidth: 280 }}
        />
        <TextField
          select
          size="small"
          label="Show"
          value={deviceState}
          onChange={(event) => setDeviceState(event.target.value as DeviceState)}
          sx={{ minWidth: 180 }}
        >
          <MenuItem value="all">All devices</MenuItem>
          <MenuItem value="connected">Connected</MenuItem>
          <MenuItem value="blocked">Blocked or expired</MenuItem>
          <MenuItem value="routing">Carrying networks</MenuItem>
        </TextField>
      </Stack>

      <TableContainer>
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell></TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'ownerName'}
                  direction={sortBy === 'ownerName' ? sortOrder : 'asc'}
                  onClick={() => requestSort('ownerName')}
                >
                  Owner
                </TableSortLabel>
              </TableCell>
              {showProviderCol && (
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'ownerProvider'}
                    direction={sortBy === 'ownerProvider' ? sortOrder : 'asc'}
                    onClick={() => requestSort('ownerProvider')}
                  >
                    Auth provider
                  </TableSortLabel>
                </TableCell>
              )}
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'name'}
                  direction={sortBy === 'name' ? sortOrder : 'asc'}
                  onClick={() => requestSort('name')}
                >
                  Device
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'connected'}
                  direction={sortBy === 'connected' ? sortOrder : 'asc'}
                  onClick={() => requestSort('connected')}
                >
                  Connected
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'address'}
                  direction={sortBy === 'address' ? sortOrder : 'asc'}
                  onClick={() => requestSort('address')}
                >
                  Local address
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'endpoint'}
                  direction={sortBy === 'endpoint' ? sortOrder : 'asc'}
                  onClick={() => requestSort('endpoint')}
                >
                  Last endpoint
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'download'}
                  direction={sortBy === 'download' ? sortOrder : 'asc'}
                  onClick={() => requestSort('download')}
                >
                  Download
                </TableSortLabel>
                {' / '}
                <TableSortLabel
                  active={sortBy === 'upload'}
                  direction={sortBy === 'upload' ? sortOrder : 'asc'}
                  onClick={() => requestSort('upload')}
                >
                  Upload
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'lastHandshakeTime'}
                  direction={sortBy === 'lastHandshakeTime' ? sortOrder : 'asc'}
                  onClick={() => requestSort('lastHandshakeTime')}
                >
                  Last seen
                </TableSortLabel>
              </TableCell>
              <TableCell>Networks</TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortBy === 'access'}
                  direction={sortBy === 'access' ? sortOrder : 'asc'}
                  onClick={() => requestSort('access')}
                >
                  Access
                </TableSortLabel>
              </TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {devices.map((device, i) => (
              <TableRow key={i}>
                <TableCell>
                  <Avatar style={{ backgroundColor: device.connected ? '#76de8a' : '#bdbdbd' }}>
                    {/* <DonutSmallIcon /> */}
                    {device.connected ? <WifiIcon /> : <WifiOffIcon />}
                  </Avatar>
                </TableCell>
                <TableCell component="th" scope="row">
                  {device.ownerName || device.ownerEmail || device.owner}
                </TableCell>
                {showProviderCol && <TableCell>{device.ownerProvider}</TableCell>}
                <TableCell>{device.name}</TableCell>
                <TableCell>{device.connected ? 'yes' : 'no'}</TableCell>
                <TableCell>{device.address}</TableCell>
                <TableCell>{device.endpoint}</TableCell>
                <TableCell>
                  {numeral(device.transmitBytes).format('0b')} / {numeral(device.receiveBytes).format('0b')}
                </TableCell>
                <TableCell>{lastSeen(device.lastHandshakeTime)}</TableCell>
                <TableCell>{device.routes?.length ? device.routes.join(', ') : '-'}</TableCell>
                <TableCell>
                  <AccessCell device={device} />
                </TableCell>
                <TableCell>
                  <Stack direction="row" spacing={1}>
                    <Button
                      variant="outlined"
                      color={device.disabled ? 'primary' : 'secondary'}
                      onClick={() => toggleBlocked(device)}
                    >
                      {device.disabled ? 'Unblock' : 'Block'}
                    </Button>
                    <Button variant="outlined" color="secondary" onClick={() => setExpiryDevice(device)}>
                      Expiry
                    </Button>
                    <Button variant="outlined" color="secondary" onClick={() => setRoutesDevice(device)}>
                      Networks
                    </Button>
                    <Button variant="outlined" color="secondary" onClick={() => deleteDevice(device)}>
                      Delete
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
            {devices.length === 0 && (
              <TableRow>
                <TableCell colSpan={12}>
                  <Typography color="text.secondary">No device matches what you are looking for.</Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={matchingDevices.length}
          page={devicePage}
          onPageChange={(_, page) => setDevicePage(page)}
          rowsPerPage={devicesPerPage}
          rowsPerPageOptions={[25, 50, 100]}
          onRowsPerPageChange={(event) => {
            setDevicesPerPage(parseInt(event.target.value, 10));
            setDevicePage(0);
          }}
        />
      </TableContainer>

      <Typography variant="h5" component="h5">
        Users
        <Typography component="span">
          {' '}
          ({allUsers.length}
          {matchingUsers.length !== allUsers.length && `, ${matchingUsers.length} shown`})
        </Typography>
      </Typography>

      <TextField
        size="small"
        label="Search users"
        placeholder="name or policy"
        value={userQuery}
        onChange={(event) => setUserQuery(event.target.value)}
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          },
        }}
        sx={{ maxWidth: 360 }}
      />

      <TableContainer>
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Last login</TableCell>
              <TableCell>Policies</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user, i) => (
              <TableRow key={i}>
                <TableCell component="th" scope="row">
                  {user.displayName || user.name}
                </TableCell>
                <TableCell>{lastSeen(user.lastLogin)}</TableCell>
                <TableCell>{user.policies?.length ? user.policies.join(', ') : '-'}</TableCell>
                <TableCell>
                  <Stack direction="row" spacing={1}>
                    {/* not on your own row: it would block your own devices
                        and sign you out halfway through, so the server
                        refuses it and the button has nothing to do */}
                    {user.name !== AppState.info?.subject && (
                      <Button
                        variant="outlined"
                        color="warning"
                        onClick={() => revokeAccess(user)}
                        title="Block their devices, revoke their tokens and sign them out"
                      >
                        Revoke access
                      </Button>
                    )}
                    <Button variant="outlined" color="secondary" onClick={() => deleteUser(user)}>
                      Delete
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
            {users.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography color="text.secondary">No user matches what you are looking for.</Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={matchingUsers.length}
          page={userPage}
          onPageChange={(_, page) => setUserPage(page)}
          rowsPerPage={usersPerPage}
          rowsPerPageOptions={[25, 50, 100]}
          onRowsPerPageChange={(event) => {
            setUsersPerPage(parseInt(event.target.value, 10));
            setUserPage(0);
          }}
        />
      </TableContainer>

      <Typography variant="h5" component="h5">
        Server Info
      </Typography>
      <code>
        <pre>{JSON.stringify(AppState.info, null, 2)}</pre>
      </code>

      {routesDevice && (
        <RoutesDialog
          device={routesDevice}
          onClose={() => setRoutesDevice(undefined)}
          onSubmit={async (routes) => {
            const device = routesDevice;
            if (await setRoutes(device, routes)) {
              setRoutesDevice(undefined);
            }
          }}
        />
      )}

      {expiryDevice && (
        <ExpiryDialog
          device={expiryDevice}
          onClose={() => setExpiryDevice(undefined)}
          onSubmit={async (change, done) => {
            const device = expiryDevice;
            setExpiryDevice(undefined);
            await setAccess(device, change, done);
          }}
        />
      )}
    </div>
  );
});

// AccessCell says whether a device may connect. A device with unlimited access
// is the normal case and shows nothing, so the eye is drawn to the others.
function AccessCell({ device }: { device: Device.AsObject }) {
  const access = deviceAccess(device);
  if (!access) {
    return <>-</>;
  }
  return (
    <Chip
      size="small"
      color={access.blocked ? 'error' : 'warning'}
      label={access.label}
      title={device.expiresAt ? 'Access ends ' + toDate(device.expiresAt).toLocaleString() : undefined}
    />
  );
}

interface ExpiryDialogProps {
  device: Device.AsObject;
  onClose: () => void;
  onSubmit: (change: Partial<SetDeviceAccessReq.AsObject>, done: string) => void;
}

// ExpiryDialog asks for the day a device's access ends. A date is what an admin
// handing out temporary access thinks in; the time of day is the end of it, so
// the device works through the day the admin picked.
export function ExpiryDialog({ device, onClose, onSubmit }: ExpiryDialogProps) {
  const [day, setDay] = React.useState(device.expiresAt ? isoDay(toDate(device.expiresAt)) : '');

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const at = endOfDay(day);
    if (!at) {
      return;
    }
    onSubmit({ expiresAt: dateToTimestamp(at) }, `${device.name} may connect until ${at.toLocaleString()}`);
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <form onSubmit={submit}>
        <DialogTitle>Access of {device.name}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            The device loses its access at the end of the day you pick. It keeps its key and its address, so it works
            again without the user setting it up anew if you extend the date.
          </DialogContentText>
          <TextField
            autoFocus
            fullWidth
            type="date"
            label="Access ends"
            value={day}
            onChange={(event) => setDay(event.target.value)}
            slotProps={{ inputLabel: { shrink: true }, htmlInput: { min: isoDay(new Date()) } }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          {device.expiresAt && (
            <Button
              color="secondary"
              onClick={() => onSubmit({ clearExpiresAt: true }, `The access of ${device.name} no longer expires`)}
            >
              Remove expiry
            </Button>
          )}
          <Button type="submit" variant="contained" disabled={!endOfDay(day)}>
            Save
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}

interface RoutesDialogProps {
  device: Device.AsObject;
  onClose: () => void;
  onSubmit: (routes: string[]) => void;
}

// RoutesDialog asks which networks live behind a device - what turns it into a
// site-to-site link or a subnet router. It stays open when the server refuses
// one of them, so the admin can correct it instead of typing it all again.
export function RoutesDialog({ device, onClose, onSubmit }: RoutesDialogProps) {
  const [value, setValue] = React.useState((device.routes ?? []).join(', '));

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    onSubmit(parseRoutes(value));
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <form onSubmit={submit}>
        <DialogTitle>Networks behind {device.name}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            The server sends traffic for these networks to this device, and accepts traffic from them through it. Use it
            for a router that carries a whole site. Leave it empty for an ordinary device.
          </DialogContentText>
          <TextField
            autoFocus
            fullWidth
            multiline
            label="Networks"
            placeholder="192.168.5.0/24, 2001:db8:5::/48"
            helperText="In CIDR notation, separated by commas or new lines"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained">
            Save
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}

// parseRoutes splits what was typed into networks. What they are is decided by
// the server - it knows the VPN's own networks, the server's own, and what
// another device already carries.
export function parseRoutes(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((route) => route.trim())
    .filter((route) => route !== '');
}

// isoDay formats a date the way the date input expects it, in local time - not
// toISOString, which would name the previous day west of UTC.
export function isoDay(date: Date): string {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

// endOfDay turns the picked day into the moment access ends: its last second,
// in the admin's own time zone. It returns undefined for an empty or unparsable
// input, and for a day that has already passed - the server refuses those, and
// blocking a device is how access is ended now.
export function endOfDay(day: string, now: Date = new Date()): Date | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) {
    return undefined;
  }
  const at = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), 23, 59, 59);
  if (Number.isNaN(at.getTime()) || at <= now) {
    return undefined;
  }
  return at;
}

// DeviceState is what the table is narrowed down to besides the search.
export type DeviceState = 'all' | 'connected' | 'blocked' | 'routing';

// filterDevices keeps the devices a search and a state filter leave. The
// search looks at everything an admin is likely to have in front of them: the
// name of the device, who it belongs to however they are named, its addresses
// and the networks behind it.
export function filterDevices(
  devices: Device.AsObject[] | null | undefined,
  query: string,
  state: DeviceState,
  now: Date = new Date(),
): Device.AsObject[] {
  if (!devices) {
    return [];
  }

  const needle = query.trim().toLowerCase();
  return devices.filter((device) => {
    switch (state) {
      case 'connected':
        if (!device.connected) return false;
        break;
      case 'blocked':
        if (!deviceAccess(device, now)?.blocked) return false;
        break;
      case 'routing':
        if (!device.routes?.length) return false;
        break;
    }

    if (needle === '') {
      return true;
    }
    return [
      device.name,
      device.owner,
      device.ownerName,
      device.ownerEmail,
      device.ownerProvider,
      device.address,
      device.endpoint,
      ...(device.routes ?? []),
    ].some((field) => field?.toLowerCase().includes(needle));
  });
}

// filterUsers keeps the users a search leaves, by what they are called and by
// the policies they are in - "who is in contractors" is a question an admin
// asks of this table.
export function filterUsers(users: User.AsObject[] | null | undefined, query: string): User.AsObject[] {
  if (!users) {
    return [];
  }

  const needle = query.trim().toLowerCase();
  if (needle === '') {
    return users;
  }
  return users.filter((user) =>
    [user.name, user.displayName, ...(user.policies ?? [])].some((field) => field?.toLowerCase().includes(needle)),
  );
}

// sortDevices orders the table by the column its header was last clicked on.
export function sortDevices(
  devices: Device.AsObject[] | null | undefined,
  sortBy: SortColumn,
  sortOrder: 'asc' | 'desc',
): Device.AsObject[] {
  if (!devices) {
    return [];
  }

  // sortBy also covers the derived columns handled below, which are not keys
  // of Device.AsObject, so look the value up dynamically and keep only what
  // the comparisons further down can actually handle.
  const valueOf = (device: Device.AsObject): string | number | undefined => {
    if (sortBy === 'lastHandshakeTime') {
      return device.lastHandshakeTime ? device.lastHandshakeTime.seconds : 0;
    }
    if (sortBy === 'download') {
      return device.transmitBytes;
    }
    if (sortBy === 'upload') {
      return device.receiveBytes;
    }
    if (sortBy === 'connected') {
      return device.connected ? 1 : 0;
    }
    if (sortBy === 'access') {
      return accessRank(device);
    }
    const raw = (device as unknown as Record<string, unknown>)[sortBy];
    return typeof raw === 'string' || typeof raw === 'number' ? raw : undefined;
  };

  return [...devices].sort((a, b) => {
    const aValue = valueOf(a);
    const bValue = valueOf(b);

    if (aValue === bValue) return 0;
    if (aValue === undefined) return sortOrder === 'asc' ? 1 : -1;
    if (bValue === undefined) return sortOrder === 'asc' ? -1 : 1;

    if (typeof aValue === 'string' && typeof bValue === 'string') {
      return sortOrder === 'asc' ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    }
    if (bValue < aValue) {
      return sortOrder === 'asc' ? 1 : -1;
    }
    if (bValue > aValue) {
      return sortOrder === 'asc' ? -1 : 1;
    }
    return 0;
  });
}
