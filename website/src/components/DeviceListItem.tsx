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
import { IconButton, Typography } from '@mui/material';

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
      return (
        <Card>
          <CardHeader
            title={<Typography style={{ wordBreak: 'break-word' }}>{device.name}</Typography>}
            subheader={'Last seen: ' + lastSeen(device.lastHandshakeTime)}
            avatar={
              <Avatar style={{ backgroundColor: device.connected ? '#76de8a' : '#bdbdbd' }}>
                {/* <DonutSmallIcon /> */}
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
          />
          <CardContent>
            <table cellPadding="5">
              <tbody>
                {AppState.info?.metadataEnabled && device.connected && (
                  <>
                    <tr>
                      <td>Endpoint</td>
                      <td>{device.endpoint}</td>
                    </tr>
                    <tr>
                      <td>Download</td>
                      <td>{numeral(device.transmitBytes).format('0b')}</td>
                    </tr>
                    <tr>
                      <td>Upload</td>
                      <td>{numeral(device.receiveBytes).format('0b')}</td>
                    </tr>
                  </>
                )}
                {AppState.info?.metadataEnabled && !device.connected && (
                  <tr>
                    <td>Disconnected</td>
                  </tr>
                )}
                <tr>
                  <td>Public key</td>
                  <td>
                    <PopoverDisplay label="show">{device.publicKey}</PopoverDisplay>
                  </td>
                </tr>
                <tr>
                  <td>Pre-shared key</td>
                  <td>
                    {device.presharedKey ? <PopoverDisplay label="show">{device.presharedKey}</PopoverDisplay> : 'None'}
                  </td>
                </tr>
              </tbody>
            </table>
          </CardContent>
        </Card>
      );
    }
  },
);
