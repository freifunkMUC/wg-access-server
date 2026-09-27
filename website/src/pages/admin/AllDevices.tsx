import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableSortLabel from '@mui/material/TableSortLabel';
import Typography from '@mui/material/Typography';
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

type SortColumn = keyof Device.AsObject | 'download' | 'upload' | 'connected' | 'access';

export const AllDevices = observer(function AllDevices() {
  const [sortBy, setSortBy] = React.useState<SortColumn>('lastHandshakeTime');
  const [sortOrder, setSortOrder] = React.useState<'asc' | 'desc'>('desc');
  // the device whose expiry date is being changed, if any
  const [expiryDevice, setExpiryDevice] = React.useState<Device.AsObject>();

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

  const sortedDevices = sortDevices(deviceResource.current, sortBy, sortOrder);

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
  const users = userResource.current;
  const devices = sortedDevices;

  // show the provider column
  // when there is more than 1 provider in use
  // i.e. not all devices are from the same auth provider.
  const showProviderCol = devices.length >= 2 && devices.some((d) => d.ownerProvider !== devices[0].ownerProvider);

  return (
    <div style={{ display: 'grid', gridGap: 25, gridAutoFlow: 'row' }}>
      <Typography variant="h5" component="h5">
        Devices
        <Typography component="span">
          {' '}
          ({devices.filter((p) => p.connected).length} of {devices.length} online)
        </Typography>
      </Typography>
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
                    <Button variant="outlined" color="secondary" onClick={() => deleteDevice(device)}>
                      Delete
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h5" component="h5">
        Users
        <Typography component="span"> ({users.length})</Typography>
      </Typography>
      <TableContainer>
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user, i) => (
              <TableRow key={i}>
                <TableCell component="th" scope="row">
                  {user.displayName || user.name}
                </TableCell>
                <TableCell>
                  <Button variant="outlined" color="secondary" onClick={() => deleteUser(user)}>
                    Delete
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h5" component="h5">
        Server Info
      </Typography>
      <code>
        <pre>{JSON.stringify(AppState.info, null, 2)}</pre>
      </code>

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
