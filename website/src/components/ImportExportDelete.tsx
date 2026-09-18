import React from 'react';
import { IconMenu } from './IconMenu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import FileUploadIcon from '@mui/icons-material/FileUpload';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import DeleteIcon from '@mui/icons-material/Delete';
import { grpc } from '../Api';
import { toast } from './Toast';
import { confirm } from './Present';
import { errorMessage } from '../Util';
import { ExportedDevice, parseExportedAddresses } from './ImportDevices';


export function ImportExportDelete({ onRefresh }: { onRefresh?: () => void }) {
  const handleExport = async () => {
    try {
      const response = await grpc.devices.listDevices({});
      const devices = response.items;
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
    } catch {
      toast({ text: 'Failed to export devices', intent: 'error' });
    }
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const parsed: unknown = JSON.parse(text);

      // Validate the imported data
      if (!Array.isArray(parsed)) {
        throw new Error('Invalid format: expected an array of devices');
      }
      const devices = parsed as ExportedDevice[];

      // Import each device, continue on errors and collect failures
      const failed: string[] = [];
      const reassigned: string[] = [];
      let imported = 0;
      for (const device of devices) {
        const label = device.name || device.publicKey || 'unnamed device';
        const exported = parseExportedAddresses(device.address);
        const wantedIpv4 = device.manualIpv4Address || exported.ipv4;
        const wantedIpv6 = device.manualIpv6Address || exported.ipv6;
        const base = {
          name: device.name ?? '',
          publicKey: device.publicKey ?? '',
          presharedKey: device.presharedKey || '',
        };

        // Keep the address the device had, so an imported configuration file
        // still matches the device on the server.
        let added = false;
        let manualFailed = false;
        if (wantedIpv4 || wantedIpv6) {
          try {
            await grpc.devices.addDevice({
              ...base,
              manualIpAssignment: true,
              manualIpv4Address: wantedIpv4,
              manualIpv6Address: wantedIpv6,
            });
            added = true;
            imported++;
          } catch {
            // The address may be taken or outside of the server's subnet now.
            manualFailed = true;
          }
        }

        if (!added) {
          try {
            await grpc.devices.addDevice({
              ...base,
              manualIpAssignment: false,
              manualIpv4Address: '',
              manualIpv6Address: '',
            });
            imported++;
            if (manualFailed) {
              reassigned.push(label);
            }
          } catch (err) {
            failed.push(`${label}: ${errorMessage(err)}`);
          }
        }
      }

      const reassignedNote = reassigned.length > 0 ? `, ${reassigned.length} got a new address (${reassigned.join(', ')})` : '';
      if (failed.length > 0) {
        toast({
          text: `Imported ${imported} devices${reassignedNote}, failed ${failed.length}: ${failed.join('; ')}`,
          intent: 'warning',
        });
      } else if (reassigned.length > 0) {
        toast({ text: `Imported ${imported} devices${reassignedNote}`, intent: 'warning' });
      } else {
        toast({ text: 'Devices imported successfully', intent: 'success' });
      }

      if (onRefresh) {
        onRefresh();
      } else {
        window.dispatchEvent(new CustomEvent('wg.devices.refresh'));
      }
    } catch (error) {
      toast({ text: 'Failed to import devices: ' + (error as Error).message, intent: 'error' });
    }
  };

  const handleDeleteAll = async () => {
    if (await confirm('Are you sure you want to delete ALL your devices? This action cannot be undone!')) {
      try {
        const response = await grpc.devices.listDevices({});
        const devices = response.items;
        
        for (const device of devices) {
          await grpc.devices.deleteDevice({
            name: device.name,
          });
        }
  
  toast({ text: 'All devices deleted successfully', intent: 'success' });
  if (onRefresh) {
    onRefresh();
  } else {
    window.dispatchEvent(new CustomEvent('wg.devices.refresh'));
  }
      } catch (error) {
        toast({ text: 'Failed to delete devices: ' + (error as Error).message, intent: 'error' });
      }
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
      <MenuItem onClick={handleDeleteAll}>
        <ListItemIcon>
          <DeleteIcon fontSize="small" />
        </ListItemIcon>
        <ListItemText>Delete All Devices</ListItemText>
      </MenuItem>
    </IconMenu>
  );
} 
