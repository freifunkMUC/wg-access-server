import Button from '@mui/material/Button';
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
import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { confirm } from '../../components/Present';
import { toast } from '../../components/Toast';
import { Device } from '../../sdk/devices_pb';
import { User } from '../../sdk/users_pb';
import { errorMessage, lastSeen } from '../../Util';
import { useLoaded } from '../../hooks';
import numeral from 'numeral';
import { Loading } from '../../components/Loading';
import { Error } from '../../components/Error';

type SortColumn = keyof Device.AsObject | 'download' | 'upload' | 'connected';

export const AllDevices = observer(function AllDevices() {
  const [sortBy, setSortBy] = React.useState<SortColumn>('lastHandshakeTime');
  const [sortOrder, setSortOrder] = React.useState<'asc' | 'desc'>('desc');

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
                  <Button variant="outlined" color="secondary" onClick={() => deleteDevice(device)}>
                    Delete
                  </Button>
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
    </div>
  );
});

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
