import React from 'react';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Avatar from '@mui/material/Avatar';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import numeral from 'numeral';
import { lastSeen } from '../Util';
import { AppState } from '../AppState';
import { PopoverDisplay } from './PopoverDisplay';
import { Device } from '../sdk/devices_pb';
import { grpc } from '../Api';
import { observer } from 'mobx-react';
import { confirm, prompt } from './Present';
import { toast } from './Toast';
import { errorMessage } from '../Util';
import { IconButton, Skeleton, Typography } from '@mui/material';

interface Props {
  device: Device.AsObject;
  // called whenever the device changed, so the list can reload
  onChange: () => void;
}

export const DeviceListItem = observer(
  class DeviceListItem extends React.Component<Props> {
    removeDevice = async () => {
      if (await confirm('Are you sure you want to delete ' + this.props.device.name + '?')) {
        try {
          await grpc.devices.deleteDevice({
            name: this.props.device.name,
          });
          this.props.onChange();
        } catch {
          window.alert('api request failed');
        }
      }
    };

    renameDevice = async () => {
      const device = this.props.device;
      const newName = await prompt('Rename "' + device.name + '" to:', device.name);
      if (newName === null || newName === device.name) {
        return;
      }

      try {
        // The key and the address stay as they are, so the client
        // configuration the user already has keeps working.
        await grpc.devices.renameDevice({ name: device.name, newName });
        toast({ text: 'Device renamed to "' + newName + '"', intent: 'success' });
        this.props.onChange();
      } catch (error) {
        toast({ text: 'Failed to rename device: ' + errorMessage(error), intent: 'error' });
      }
    };

    render() {
      const device = this.props.device;
      const metadata = AppState.info?.metadataEnabled;
      return (
        <DeviceCard
          title={<Typography style={{ wordBreak: 'break-word' }}>{device.name}</Typography>}
          subheader={'Last seen: ' + lastSeen(device.lastHandshakeTime)}
          avatar={
            <Avatar style={{ backgroundColor: device.connected ? '#76de8a' : '#bdbdbd' }}>
              {device.connected ? <WifiIcon /> : <WifiOffIcon />}
            </Avatar>
          }
          action={
            <>
              <IconButton onClick={this.renameDevice} title="Rename device">
                <EditIcon />
              </IconButton>
              <IconButton sx={{ '&:hover': { color: 'red' } }} onClick={this.removeDevice} title="Delete device">
                <DeleteIcon />
              </IconButton>
            </>
          }
          rows={[
            ...(metadata && device.connected
              ? [
                  ['Endpoint', device.endpoint] as Row,
                  ['Download', numeral(device.transmitBytes).format('0b')] as Row,
                  ['Upload', numeral(device.receiveBytes).format('0b')] as Row,
                ]
              : []),
            ...(metadata && !device.connected ? [['Disconnected'] as Row] : []),
            ['Public key', <PopoverDisplay label="Show">{device.publicKey}</PopoverDisplay>] as Row,
            [
              'Pre-shared key',
              device.presharedKey ? <PopoverDisplay label="Show">{device.presharedKey}</PopoverDisplay> : 'None',
            ] as Row,
          ]}
        />
      );
    }
  },
);

// Row is a line of the card's table: a label, and the value beside it. A row
// without a value spans the whole width, as "Disconnected" does.
type Row = [React.ReactNode] | [React.ReactNode, React.ReactNode];

interface CardProps {
  title: React.ReactNode;
  subheader: React.ReactNode;
  avatar: React.ReactNode;
  action: React.ReactNode;
  rows: Row[];
}

// DeviceCard is the layout of a device, drawn for a real one as well as for
// the placeholder below, so that the two cannot drift apart.
function DeviceCard(props: CardProps) {
  return (
    <Card>
      <CardHeader title={props.title} subheader={props.subheader} avatar={props.avatar} action={props.action} />
      <CardContent>
        <table cellPadding="5">
          <tbody>
            {props.rows.map(([label, value], i) => (
              <tr key={i}>
                <td>{label}</td>
                {value !== undefined && <td>{value}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

// DeviceListItemSkeleton stands in for a device while the list is loading.
export function DeviceListItemSkeleton() {
  const line = <Skeleton variant="text" width={100} />;
  return (
    <DeviceCard
      title={<Skeleton variant="text" width={100} />}
      subheader={<Skeleton variant="text" width={50} />}
      avatar={<Skeleton variant="circular" width={40} height={40} />}
      action={<Skeleton variant="text" width={50} />}
      rows={[
        ['Endpoint', line],
        ['Download', line],
        ['Upload', line],
        ['Public key', line],
        ['Pre-shared key', line],
      ]}
    />
  );
}
