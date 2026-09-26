import React from 'react';
import { Box } from '@mui/material';
import { observable, makeObservable, runInAction } from 'mobx';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { autorefresh, errorMessage } from '../Util';
import { DeviceListItem, DeviceListItemSkeleton } from './DeviceListItem';
import { Device } from '../sdk/devices_pb';
import { AddDevice } from './AddDevice';
import { AppState } from '../AppState';
import { Error } from './Error';

type DeviceResource = ReturnType<typeof autorefresh<Device.AsObject[] | null>>;

export const Devices = observer(
  class Devices extends React.Component {
    devices: DeviceResource | null = null;

    constructor(props: object) {
      super(props);

      makeObservable(this, {
        devices: observable,
      });
    }

    setDevices(devices: DeviceResource) {
      runInAction(() => {
        this.devices = devices;
      });
    }

    componentDidMount() {
      this.setDevices(
        autorefresh(30, async () => {
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
        }),
      );
    }

    componentWillUnmount() {
      this.devices?.dispose();
    }

    render() {
      // bind once: the field stays null until componentDidMount has run, and
      // narrowing on `this.devices` would not carry into the callbacks below
      const devices = this.devices;

      if (AppState.loadingError) {
        return <Error message={AppState.loadingError} />;
      }
      if (!devices || !devices.current) {
        return (
          <Box sx={{ display: 'grid', gap: 3, justifyContent: 'center' }}>
            <Box sx={{ gridColumn: 'span 12' }}>
              <Box
                sx={{
                  display: 'grid',
                  gap: 3,
                  gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(3, 1fr)', lg: 'repeat(4, 1fr)' },
                }}
              >
                {Array.from({ length: 4 }).map((_, i) => (
                  <Box key={i}>
                    <DeviceListItemSkeleton />
                  </Box>
                ))}
              </Box>
            </Box>
            <Box sx={{ gridColumn: { xs: 'span 12', sm: 'span 10', md: 'span 10', lg: 'span 6' } }}>
              {/* the form needs no devices, so it works while they load */}
              <AddDevice onAdd={() => this.devices?.refresh()} onRefresh={() => this.devices?.refresh()} />
            </Box>
          </Box>
        );
      }
      return (
        <Box sx={{ display: 'grid', gap: 3, justifyContent: 'center' }}>
          <Box sx={{ gridColumn: 'span 12' }}>
            <Box
              sx={{
                display: 'grid',
                gap: 3,
                gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(3, 1fr)', lg: 'repeat(4, 1fr)' },
              }}
            >
              {sortByName(devices.current).map((device: Device.AsObject) => (
                <Box key={device.name}>
                  <DeviceListItem device={device} onChange={() => devices.refresh()} />
                </Box>
              ))}
            </Box>
          </Box>
          <Box sx={{ gridColumn: { xs: 'span 12', sm: 'span 10', md: 'span 10', lg: 'span 6' } }}>
            <AddDevice onAdd={() => devices.refresh()} onRefresh={() => devices.refresh()} />
          </Box>
        </Box>
      );
    }
  },
);

// The storage hands devices out in whatever order it keeps them - SQL puts
// "Tablet" before "iPhone". People expect them alphabetically.
export function sortByName(devices: Device.AsObject[]): Device.AsObject[] {
  return [...devices].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
}
