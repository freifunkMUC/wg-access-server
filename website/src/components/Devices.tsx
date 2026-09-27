import React from 'react';
import { Box } from '@mui/material';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { errorMessage } from '../Util';
import { usePolling } from '../hooks';
import { DeviceListItem, DeviceListItemSkeleton } from './DeviceListItem';
import { Device } from '../sdk/devices_pb';
import { AddDevice } from './AddDevice';
import { AppState } from '../AppState';
import { Error } from './Error';

export const Devices = observer(function Devices() {
  const devices = usePolling(30, async () => {
    try {
      const res = await grpc.devices.listDevices({});
      // a refresh that works again ends an earlier failure
      AppState.clearLoadingError();
      return res.items;
    } catch (error) {
      console.log('An error occurred:', error);
      AppState.setLoadingError(errorMessage(error));
      return null;
    }
  });

  if (AppState.loadingError) {
    return <Error message={AppState.loadingError} />;
  }

  const cards = (children: React.ReactNode) => (
    <Box sx={{ display: 'grid', gap: 3, justifyContent: 'center' }}>
      <Box sx={{ gridColumn: 'span 12' }}>
        <Box
          sx={{
            display: 'grid',
            gap: 3,
            gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(3, 1fr)', lg: 'repeat(4, 1fr)' },
          }}
        >
          {children}
        </Box>
      </Box>
      <Box sx={{ gridColumn: { xs: 'span 12', sm: 'span 10', md: 'span 10', lg: 'span 6' } }}>
        {/* the form needs no devices, so it works while they load */}
        <AddDevice onAdd={() => devices.refresh()} onRefresh={() => devices.refresh()} />
      </Box>
    </Box>
  );

  if (!devices.current) {
    return cards(
      Array.from({ length: 4 }).map((_, i) => (
        <Box key={i}>
          <DeviceListItemSkeleton />
        </Box>
      )),
    );
  }

  return cards(
    sortByName(devices.current).map((device: Device.AsObject) => (
      <Box key={device.name}>
        <DeviceListItem device={device} onChange={() => devices.refresh()} />
      </Box>
    )),
  );
});

// The storage hands devices out in whatever order it keeps them - SQL puts
// "Tablet" before "iPhone". People expect them alphabetically.
export function sortByName(devices: Device.AsObject[]): Device.AsObject[] {
  return [...devices].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
}
