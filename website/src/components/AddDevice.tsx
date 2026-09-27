import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CardHeader from '@mui/material/CardHeader';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormHelperText from '@mui/material/FormHelperText';
import Input from '@mui/material/Input';
import InputLabel from '@mui/material/InputLabel';
import Typography from '@mui/material/Typography';
import AddIcon from '@mui/icons-material/Add';
import { codeBlock } from 'common-tags';
import { observer } from 'mobx-react';
import React from 'react';
import { box_keyPair, randomBytes } from 'tweetnacl-ts';
import { grpc } from '../Api';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';
import { GetConnected } from './GetConnected';
import { Info } from './Info';

import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Box from '@mui/material/Box';
import { Warning } from '@mui/icons-material';
import { ImportExportDelete } from './ImportExportDelete';
import { errorMessage } from '../Util';

interface Props {
  onAdd: () => void;
  onRefresh: () => void;
}

export const AddDevice = observer(function AddDevice({ onAdd, onRefresh }: Props) {
  const keepaliveDefault = AppState.info?.clientConfigPersistentKeepalive || 0;
  const [deviceName, setDeviceName] = React.useState('');
  const [devicePublicKey, setDevicePublicKey] = React.useState('');
  const [usePresharedKey, setUsePresharedKey] = React.useState(false);
  const [persistentKeepalive, setPersistentKeepalive] = React.useState(keepaliveDefault);
  const [manualIPAssignment, setManualIPAssignment] = React.useState(false);
  const [manualIPv4Address, setManualIPv4Address] = React.useState('');
  const [manualIPv6Address, setManualIPv6Address] = React.useState('');
  const [error, setError] = React.useState('');
  const [configFile, setConfigFile] = React.useState<string | undefined>(undefined);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [showMobile, setShowMobile] = React.useState(true);

  const reset = () => {
    setDeviceName('');
    setDevicePublicKey('');
    setUsePresharedKey(false);
    setPersistentKeepalive(keepaliveDefault);
    setError('');
    setManualIPAssignment(false);
    setManualIPv4Address('');
    setManualIPv6Address('');
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();

    const keypair = box_keyPair();
    let publicKey: string;
    let privateKey: string;
    if (devicePublicKey) {
      // someone brought their own key, so there is no private key to hand out
      // and nothing for the phone to scan
      publicKey = devicePublicKey;
      privateKey = 'pleaseReplaceThisPrivatekey';
      setShowMobile(false);
    } else {
      publicKey = window.btoa(String.fromCharCode(...Array.from(new Uint8Array(keypair.publicKey))));
      privateKey = window.btoa(String.fromCharCode(...Array.from(new Uint8Array(keypair.secretKey))));
      setShowMobile(true);
    }

    const presharedKey = usePresharedKey ? window.btoa(String.fromCharCode(...Array.from(randomBytes(32)))) : '';

    try {
      const device = await grpc.devices.addDevice({
        name: deviceName,
        publicKey,
        presharedKey,
        manualIpAssignment: manualIPAssignment,
        manualIpv4Address: manualIPv4Address,
        manualIpv6Address: manualIPv6Address,
      });
      onAdd();

      setConfigFile(
        clientConfig({
          info: AppState.info!,
          privateKey,
          address: device.address,
          presharedKey,
          persistentKeepalive,
        }),
      );
      setDialogOpen(true);
      reset();
    } catch (error) {
      console.log(error);
      setError('Failed to add device: ' + errorMessage(error));
    }
  };

  const handleClose = (event: unknown, reason: string) => {
    if (reason === 'backdropClick') {
      return false;
    }

    if (reason === 'escapeKeyDown') {
      return false;
    }

    return true;
  };

  return (
    <>
      <Card>
        <CardHeader title="Add a device" action={<ImportExportDelete onRefresh={() => onRefresh()} />} />
        <CardContent>
          <form onSubmit={submit}>
            <FormControl fullWidth>
              <InputLabel htmlFor="device-name">Device name</InputLabel>
              <Input
                id="device-name"
                value={deviceName}
                onChange={(event) => setDeviceName(event.currentTarget.value)}
                aria-describedby="device-name-text"
              />
            </FormControl>
            <Box sx={{ mt: 2, mb: 2 }}>
              <Accordion>
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  aria-controls="advanced-options-content"
                  id="advanced-options-header"
                >
                  <Typography>Advanced</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <FormControl fullWidth>
                    <InputLabel htmlFor="device-publickey">Device public key (optional)</InputLabel>
                    <Input
                      id="device-publickey"
                      value={devicePublicKey}
                      onChange={(event) => setDevicePublicKey(event.currentTarget.value)}
                      aria-describedby="device-publickey-text"
                    />
                    <FormHelperText id="device-publickey-text">
                      Put your public key to a pre-generated private key here. Replace the private key in the config
                      file after downloading it.
                    </FormHelperText>
                  </FormControl>
                  <FormControlLabel
                    control={
                      <Checkbox
                        id="device-presharedkey"
                        checked={usePresharedKey}
                        onChange={(event) => setUsePresharedKey(event.currentTarget.checked)}
                      />
                    }
                    label="Use pre-shared key"
                  />
                  <FormControl fullWidth>
                    <InputLabel htmlFor="persistent-keepalive">Persistent keepalive (optional)</InputLabel>
                    <Input
                      id="persistent-keepalive"
                      type="number"
                      placeholder="25"
                      value={persistentKeepalive || ''}
                      onChange={(event) => setPersistentKeepalive(parseInt(event.currentTarget.value) || 0)}
                      aria-describedby="persistent-keepalive-text"
                    />
                    <FormHelperText id="persistent-keepalive-text">
                      Interval in seconds between keepalive packets (empty to disable)
                    </FormHelperText>
                  </FormControl>
                  <FormControlLabel
                    control={
                      <Checkbox
                        id="manual-ip-assignment"
                        checked={manualIPAssignment}
                        onChange={(event) => {
                          setManualIPAssignment(event.currentTarget.checked);
                          if (!event.currentTarget.checked) {
                            setManualIPv4Address('');
                            setManualIPv6Address('');
                          }
                        }}
                      />
                    }
                    label="Manually assign IP address"
                  />
                  {manualIPAssignment && (
                    <>
                      <FormControl fullWidth>
                        <InputLabel htmlFor="manual-ipv4-address">IPv4 address</InputLabel>
                        <Input
                          id="manual-ipv4-address"
                          value={manualIPv4Address}
                          onChange={(event) => setManualIPv4Address(event.currentTarget.value)}
                          aria-describedby="manual-ipv4-address-text"
                          placeholder="e.g. 10.0.0.123"
                        />
                        <FormHelperText id="manual-ipv4-address-text">
                          Enter a valid IPv4 address for this device.
                        </FormHelperText>
                      </FormControl>
                      <FormControl fullWidth>
                        <InputLabel htmlFor="manual-ipv6-address">IPv6 address</InputLabel>
                        <Input
                          id="manual-ipv6-address"
                          value={manualIPv6Address}
                          onChange={(event) => setManualIPv6Address(event.currentTarget.value)}
                          aria-describedby="manual-ipv6-address-text"
                          placeholder="e.g. fd00::123"
                        />
                        <FormHelperText id="manual-ipv6-address-text">
                          Enter a valid IPv6 address for this device.
                        </FormHelperText>
                      </FormControl>
                    </>
                  )}
                </AccordionDetails>
              </Accordion>
            </Box>
            {error && (
              <FormHelperText id="device-error-text" error={true}>
                <Warning />
                <span>{error}</span>
              </FormHelperText>
            )}
            <Typography component="div" align="right">
              <Button color="secondary" type="button" onClick={reset}>
                Cancel
              </Button>
              <Button color="primary" variant="contained" endIcon={<AddIcon />} type="submit">
                Add
              </Button>
            </Typography>
          </form>
        </CardContent>
      </Card>
      <Dialog maxWidth="xl" open={dialogOpen} onClose={handleClose}>
        <DialogTitle>
          Get connected
          <Info>
            <Typography component="p" style={{ paddingBottom: 8 }}>
              Your VPN connection file is not stored by this portal.
            </Typography>
            <Typography component="p" style={{ paddingBottom: 8 }}>
              If you lose this file you can simply create a new device on this portal to generate a new connection file.
            </Typography>
            <Typography component="p">
              The connection file contains your WireGuard Private Key (i.e. password) and should <strong>never</strong>{' '}
              be shared.
            </Typography>
          </Info>
        </DialogTitle>
        <DialogContent>
          <GetConnected configFile={configFile!} showMobile={showMobile} />
        </DialogContent>
        <DialogActions>
          <Button color="secondary" variant="outlined" onClick={() => setDialogOpen(false)}>
            Done
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
});

// clientConfig is the WireGuard configuration file a new device is handed,
// either as a download or as the QR code a phone scans.
export function clientConfig(opts: {
  info: InfoRes.AsObject;
  privateKey: string;
  address: string;
  presharedKey: string;
  persistentKeepalive: number;
}): string {
  const info = opts.info;

  const dnsInfo = [];
  if (info.clientConfigDnsServers) {
    // If custom DNS entries are specified via client config, prefer them over the calculated ones.
    dnsInfo.push(info.clientConfigDnsServers);
  } else if (info.dnsEnabled) {
    // Otherwise, and if DNS is enabled, use the ones from the server.
    dnsInfo.push(info.dnsAddress);
  }

  if (info.clientConfigDnsSearchDomain) {
    // In any case, if there is a custom search domain configured in the client config, append it to the list of DNS servers.
    dnsInfo.push(info.clientConfigDnsSearchDomain);
  }

  return codeBlock`
        [Interface]
        PrivateKey = ${opts.privateKey}
        Address = ${opts.address}
        ${0 < dnsInfo.length && `DNS = ${dnsInfo.join(', ')}`}
        ${info.clientConfigMtu != 0 && `MTU = ${info.clientConfigMtu}`}

        [Peer]
        PublicKey = ${info.publicKey}
        AllowedIPs = ${info.allowedIps}
        Endpoint = ${`${info.host?.value || window.location.hostname}:${info.port || '51820'}`}
        ${opts.presharedKey ? `PresharedKey = ${opts.presharedKey}` : ``}
        ${opts.persistentKeepalive > 0 ? `PersistentKeepalive = ${opts.persistentKeepalive}` : ``}
      `;
}
