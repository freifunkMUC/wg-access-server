import React from 'react';
import { IconMenu } from './IconMenu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import FileUploadIcon from '@mui/icons-material/FileUpload';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import { grpc } from '../Api';
import { toast } from './Toast';

export function ImportExport() {
  const handleExport = async () => {
    try {
      const response = await grpc.devices.list({});
      const devices = response.getDevicesList();
      const jsonStr = JSON.stringify(devices, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'vpn-devices.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ text: 'Devices exported successfully', intent: 'success' });
    } catch (error) {
      toast({ text: 'Failed to export devices', intent: 'error' });
    }
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const devices = JSON.parse(text);
      
      // Validate the imported data
      if (!Array.isArray(devices)) {
        throw new Error('Invalid format: expected an array of devices');
      }

      // Import each device
      for (const device of devices) {
        await grpc.devices.add({
          name: device.name,
          publicKey: device.publicKey,
          address: device.address,
        });
      }

      toast({ text: 'Devices imported successfully', intent: 'success' });
    } catch (error) {
      toast({ text: 'Failed to import devices: ' + (error as Error).message, intent: 'error' });
    }
  };

  return (
    <IconMenu>
      <MenuItem onClick={handleExport}>
        <ListItemIcon>
          <FileDownloadIcon fontSize="small" />
        </ListItemIcon>
        <ListItemText>Export Devices</ListItemText>
      </MenuItem>
      <MenuItem component="label">
        <ListItemIcon>
          <FileUploadIcon fontSize="small" />
        </ListItemIcon>
        <ListItemText>Import Devices</ListItemText>
        <input
          type="file"
          hidden
          accept=".json"
          onChange={handleImport}
        />
      </MenuItem>
    </IconMenu>
  );
} 