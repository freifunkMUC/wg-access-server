import React from 'react';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Avatar from '@mui/material/Avatar';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import KeyIcon from '@mui/icons-material/Key';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import { box_keyPair, randomBytes } from 'tweetnacl-ts';
import numeral from 'numeral';
import { deviceAccess, lastSeen } from '../Util';
import { AppState } from '../AppState';
import { PopoverDisplay } from './PopoverDisplay';
import { Device } from '../sdk/devices_pb';
import { grpc, toDate } from '../Api';
import { observer } from 'mobx-react';
import { confirm, prompt } from './Present';
import { toast } from './Toast';
import { errorMessage } from '../Util';
import { Chip, IconButton, Skeleton, Stack, Typography } from '@mui/material';
import { clientConfig } from './AddDevice';
import { GetConnected } from './GetConnected';

interface Props {
  device: Device.AsObject;
  // called whenever the device changed, so the list can reload
  onChange: () => void;
}

// base64 of what the browser generated: the private half never leaves it.
function encode(bytes: Uint8Array): string {
  return window.btoa(String.fromCharCode(...Array.from(bytes)));
}

export const DeviceListItem = observer(function DeviceListItem({ device, onChange }: Props) {
  const [newConfig, setNewConfig] = React.useState<string>();

  // rotateKey gives the device a new key pair and hands back the
  // configuration that goes with it. The device keeps its name, its address
  // and everything else - only the key that reaches the VPN is a different
  // one, which is what makes this the answer to a private key somebody else
  // may have.
  const rotateKey = async () => {
    if (
      !(await confirm(
        `Give "${device.name}" a new key? It stops connecting until you install the new configuration ` +
          'on it - and the one it uses now stops working at once, wherever it is.',
      ))
    ) {
      return;
    }

    const keypair = box_keyPair();
    const publicKey = encode(new Uint8Array(keypair.publicKey));
    const privateKey = encode(new Uint8Array(keypair.secretKey));
    // a device that had a pre-shared key gets a new one; one that had none
    // does not suddenly need one
    const presharedKey = device.presharedKey ? encode(randomBytes(32)) : '';

    try {
      const rotated = await grpc.devices.rotateDeviceKey({ name: device.name, publicKey, presharedKey });
      setNewConfig(
        clientConfig({
          info: AppState.info!,
          privateKey,
          address: rotated.address,
          presharedKey,
          persistentKeepalive: AppState.info?.clientConfigPersistentKeepalive || 0,
        }),
      );
      toast({ text: `"${device.name}" has a new key`, intent: 'success' });
      onChange();
    } catch (error) {
      toast({ text: 'Failed to change the key: ' + errorMessage(error), intent: 'error' });
    }
  };

  const removeDevice = async () => {
    if (await confirm('Are you sure you want to delete ' + device.name + '?')) {
      try {
        await grpc.devices.deleteDevice({ name: device.name });
        onChange();
      } catch {
        window.alert('api request failed');
      }
    }
  };

  const renameDevice = async () => {
    const newName = await prompt('Rename "' + device.name + '" to:', device.name);
    if (newName === null || newName === device.name) {
      return;
    }

    try {
      // The key and the address stay as they are, so the client
      // configuration the user already has keeps working.
      await grpc.devices.renameDevice({ name: device.name, newName });
      toast({ text: 'Device renamed to "' + newName + '"', intent: 'success' });
      onChange();
    } catch (error) {
      toast({ text: 'Failed to rename device: ' + errorMessage(error), intent: 'error' });
    }
  };

  const metadata = AppState.info?.metadataEnabled;
  // Why the tunnel is dead, if it is: without this the user would only see a
  // device that never connects, and nothing saying that an admin blocked it or
  // that its access ran out.
  const access = deviceAccess(device);
  return (
    <DeviceCard
      title={
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
          <Typography style={{ wordBreak: 'break-word' }}>{device.name}</Typography>
          {access && <Chip size="small" color={access.blocked ? 'error' : 'warning'} label={access.label} />}
        </Stack>
      }
      subheader={'Last seen: ' + lastSeen(device.lastHandshakeTime)}
      avatar={
        <Avatar style={{ backgroundColor: device.connected ? '#76de8a' : '#bdbdbd' }}>
          {device.connected ? <WifiIcon /> : <WifiOffIcon />}
        </Avatar>
      }
      action={
        <>
          <IconButton onClick={renameDevice} title="Rename device">
            <EditIcon />
          </IconButton>
          <IconButton onClick={rotateKey} title="Give the device a new key">
            <KeyIcon />
          </IconButton>
          <IconButton sx={{ '&:hover': { color: 'red' } }} onClick={removeDevice} title="Delete device">
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
        ...(device.expiresAt ? [['Access ends', toDate(device.expiresAt).toLocaleString()] as Row] : []),
        ...(device.routes?.length ? [['Carries traffic for', device.routes.join(', ')] as Row] : []),
        ['Public key', <PopoverDisplay label="Show">{device.publicKey}</PopoverDisplay>] as Row,
        [
          'Pre-shared key',
          device.presharedKey ? <PopoverDisplay label="Show">{device.presharedKey}</PopoverDisplay> : 'None',
        ] as Row,
      ]}
      dialog={
        newConfig && (
          <Dialog maxWidth="xl" open onClose={() => setNewConfig(undefined)}>
            <DialogTitle>The new configuration for &quot;{device.name}&quot;</DialogTitle>
            <DialogContent>
              <Typography component="p" style={{ paddingBottom: 8 }}>
                Install this on the device. Its old configuration no longer connects, and this one is not stored here -
                if you lose it, give the device another key.
              </Typography>
              <GetConnected configFile={newConfig} showMobile={true} />
            </DialogContent>
            <DialogActions>
              <Button color="secondary" variant="outlined" onClick={() => setNewConfig(undefined)}>
                Done
              </Button>
            </DialogActions>
          </Dialog>
        )
      }
    />
  );
});

// Row is a line of the card's table: a label, and the value beside it. A row
// without a value spans the whole width, as "Disconnected" does.
type Row = [React.ReactNode] | [React.ReactNode, React.ReactNode];

interface CardProps {
  title: React.ReactNode;
  subheader: React.ReactNode;
  avatar: React.ReactNode;
  action: React.ReactNode;
  rows: Row[];
  // shown beside the card, for what a device's actions have to open
  dialog?: React.ReactNode;
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
      {props.dialog}
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
