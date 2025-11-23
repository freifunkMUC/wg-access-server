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
import { makeObservable, observable, action, computed } from 'mobx';
import { observer } from 'mobx-react';
import React from 'react';
import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { confirm } from '../../components/Present';
import { Device } from '../../sdk/devices_pb';
import { User } from '../../sdk/users_pb';
import { lastSeen, lazy } from '../../Util';
import numeral from 'numeral';
import { Loading } from '../../components/Loading';
import { Error } from '../../components/Error';

export const AllDevices = observer(
  class AllDevices extends React.Component {
    sortBy: keyof Device.AsObject | 'download' | 'upload' | 'connected' = 'lastHandshakeTime';

    sortOrder: 'asc' | 'desc' = 'desc';

    constructor(props: any) {
      super(props);
      makeObservable(this, {
        sortBy: observable,
        sortOrder: observable,
        handleRequestSort: action,
        sortedDevices: computed,
      });
    }

    users = lazy(async () => {
      try {
        const result = await grpc.users.listUsers({});
        return result.items;
      } catch (error: any) {
        console.error('An error occurred:', error);
        AppState.loadingError = error.message;
        return null;
      }
    });

    devices = lazy(async () => {
      try {
        const res = await grpc.devices.listAllDevices({});
        return res.items;
      } catch (error: any) {
        console.error('An error occurred:', error);
        AppState.loadingError = error.message;
        return null;
      }
    });

    handleRequestSort = (property: keyof Device.AsObject | 'download' | 'upload' | 'connected') => {
      const isAsc = this.sortBy === property && this.sortOrder === 'asc';
      this.sortOrder = isAsc ? 'desc' : 'asc';
      this.sortBy = property;
    };

    get sortedDevices() {
      if (!this.devices.current) return [];

      const devices = [...this.devices.current];

      return devices.sort((a, b) => {
        let aValue: any = (a as any)[this.sortBy];
        let bValue: any = (b as any)[this.sortBy];

        if (this.sortBy === 'lastHandshakeTime') {
          aValue = a.lastHandshakeTime ? a.lastHandshakeTime.seconds : 0;
          bValue = b.lastHandshakeTime ? b.lastHandshakeTime.seconds : 0;
        } else if (this.sortBy === 'download') {
          aValue = a.transmitBytes;
          bValue = b.transmitBytes;
        } else if (this.sortBy === 'upload') {
          aValue = a.receiveBytes;
          bValue = b.receiveBytes;
        } else if (this.sortBy === 'connected') {
          aValue = a.connected ? 1 : 0;
          bValue = b.connected ? 1 : 0;
        }

        // Handle null/undefined values
        if (aValue === bValue) return 0;
        if (aValue === null || aValue === undefined) return this.sortOrder === 'asc' ? 1 : -1;
        if (bValue === null || bValue === undefined) return this.sortOrder === 'asc' ? -1 : 1;

        // String comparison
        if (typeof aValue === 'string' && typeof bValue === 'string') {
          return this.sortOrder === 'asc'
            ? aValue.localeCompare(bValue)
            : bValue.localeCompare(aValue);
        }

        // Default comparison
        if (bValue < aValue) {
          return this.sortOrder === 'asc' ? 1 : -1;
        }
        if (bValue > aValue) {
          return this.sortOrder === 'asc' ? -1 : 1;
        }
        return 0;
      });
    }

    deleteUser = async (user: User.AsObject) => {
      if (await confirm('Are you sure you want to delete all devices from ' + user.name + '?')) {
        await grpc.users.deleteUser({
          name: user.name,
        });
        await this.users.refresh();
        await this.devices.refresh();
      }
    };

    deleteDevice = async (device: Device.AsObject) => {
      if (await confirm('Are you sure you want to delete ' + device.name + ' from ' + device.ownerName + '?')) {
        await grpc.devices.deleteDevice({
          name: device.name,
          owner: { value: device.owner },
        });
        await this.devices.refresh();
      }
    };

    render() {
      if (!this.devices.current || !this.users.current) {
        return <Loading />;
      }
      if (AppState.loadingError) {
        return <Error message={AppState.loadingError} />;
      }
      const users = this.users.current;
      const devices = this.sortedDevices;

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
                      active={this.sortBy === 'ownerName'}
                      direction={this.sortBy === 'ownerName' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('ownerName')}
                    >
                      Owner
                    </TableSortLabel>
                  </TableCell>
                  {showProviderCol && (
                    <TableCell>
                      <TableSortLabel
                        active={this.sortBy === 'ownerProvider'}
                        direction={this.sortBy === 'ownerProvider' ? this.sortOrder : 'asc'}
                        onClick={() => this.handleRequestSort('ownerProvider')}
                      >
                        Auth Provider
                      </TableSortLabel>
                    </TableCell>
                  )}
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'name'}
                      direction={this.sortBy === 'name' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('name')}
                    >
                      Device
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'connected'}
                      direction={this.sortBy === 'connected' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('connected')}
                    >
                      Connected
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'address'}
                      direction={this.sortBy === 'address' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('address')}
                    >
                      Local Address
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'endpoint'}
                      direction={this.sortBy === 'endpoint' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('endpoint')}
                    >
                      Last Endpoint
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'download'}
                      direction={this.sortBy === 'download' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('download')}
                    >
                      Download
                    </TableSortLabel>
                    {' / '}
                    <TableSortLabel
                      active={this.sortBy === 'upload'}
                      direction={this.sortBy === 'upload' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('upload')}
                    >
                      Upload
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={this.sortBy === 'lastHandshakeTime'}
                      direction={this.sortBy === 'lastHandshakeTime' ? this.sortOrder : 'asc'}
                      onClick={() => this.handleRequestSort('lastHandshakeTime')}
                    >
                      Last Seen
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
                      <Button variant="outlined" color="secondary" onClick={() => this.deleteDevice(device)}>
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
                      <Button variant="outlined" color="secondary" onClick={() => this.deleteUser(user)}>
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
    }
  },
);
