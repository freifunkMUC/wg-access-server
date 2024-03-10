import React from 'react';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Avatar from '@mui/material/Avatar';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import DeleteIcon from '@mui/icons-material/Delete';
import numeral from 'numeral';
import { lastSeen } from '../Util';
import { AppState } from '../AppState';
import { PopoverDisplay } from './PopoverDisplay';
import { Device } from '../sdk/devices_pb';
import { grpc } from '../Api';
import { observer } from 'mobx-react';
import { confirm } from './Present';
import { IconButton } from '@mui/material';

interface Props {
  device: Device.AsObject;
  onRemove: () => void;
}

export const DeviceListItem = observer(
  class DeviceListItem extends React.Component<Props> {
    removeDevice = async () => {
      if (await confirm('Are you sure you want to delete ' + this.props.device.name + '?')) {
        try {
          await grpc.devices.deleteDevice({
            name: this.props.device.name,
          });
          this.props.onRemove();
        } catch {
          window.alert('api request failed');
        }
      }

    };

    render() {
      const device = this.props.device;
      return (
        <Card>
          <CardHeader
            title={device.name}
            subheader={"Last seen: " + lastSeen(device.lastHandshakeTime)}
            avatar={
              <Avatar style={{ backgroundColor: device.connected ? '#76de8a' : '#bdbdbd' }}>
                {/* <DonutSmallIcon /> */}
                {device.connected ? <WifiIcon /> : <WifiOffIcon />}
              </Avatar>
            }
            action={
              <IconButton sx={{ "&:hover": { color: "red" } }} onClick={this.removeDevice}>
                <DeleteIcon />
              </IconButton>       
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
