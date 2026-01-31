import React from 'react';
import { Box } from '@mui/material';
import { observable, makeObservable, runInAction } from 'mobx';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { autorefresh } from '../Util';
import { DeviceListItem } from './DeviceListItem';
import { Device } from '../sdk/devices_pb';
import { AddDevice } from './AddDevice';
import { Loading } from './Loading';
import { AppState } from '../AppState';
import { Error } from './Error';
import { Card, CardContent, CardHeader, Skeleton } from '@mui/material';
import { DeviceListItemSkeleton } from './DeviceListItemSkeleton';
import { AddDeviceSkeleton } from './AddDeviceSkeleton';

export const Devices = observer(
  class Devices extends React.Component {
    devices: any = null;
    refreshHandler?: EventListener;

    constructor(props: {}) {
      super(props);

      makeObservable(this, {
        devices: observable,
      });   
    }

    setDevices(devices: any) {
      runInAction(() => {
        this.devices = devices;
      })
    }

    componentDidMount() {
      this.setDevices(autorefresh(30, async () => {
        try {
          const res = await grpc.devices.listDevices({});
          return res.items;
        } catch (error: any) {
          console.log('An error occurred:', error);
          AppState.loadingError = error.message;
          return null;
        }
      }));

      // listen for global refresh events (e.g. import/delete from other UI locations)
      this.refreshHandler = async () => {
        try {
          if (this.devices) await this.devices.refresh();
        } catch (err) {
          console.error('Failed to refresh devices from global event', err);
        }
      };
      window.addEventListener('wg.devices.refresh', this.refreshHandler as EventListener);
    }

    componentWillUnmount() {
        if (this.refreshHandler) {
          window.removeEventListener('wg.devices.refresh', this.refreshHandler as EventListener);
        }
        this.devices.dispose();
      }

    render() {
      if (AppState.loadingError) {
        return <Error message={AppState.loadingError} />;
      }
      if (!this.devices || !this.devices.current) {
        return (
          <Box sx={{ display: 'grid', gap: 3, justifyContent: 'center' }}>
            <Box sx={{ gridColumn: 'span 12' }}>
              <Box sx={{ display: 'grid', gap: 3, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(3, 1fr)', lg: 'repeat(4, 1fr)' } }}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <Box key={i}>
                    <DeviceListItemSkeleton />
                  </Box>
                ))}
              </Box>
            </Box>
            <Box sx={{ gridColumn: { xs: 'span 12', sm: 'span 10', md: 'span 10', lg: 'span 6' } }}>
              <AddDeviceSkeleton />
            </Box>
          </Box>
        );
      }
      return (
        <Box sx={{ display: 'grid', gap: 3, justifyContent: 'center' }}>
          <Box sx={{ gridColumn: 'span 12' }}>
            <Box sx={{ display: 'grid', gap: 3, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(3, 1fr)', lg: 'repeat(4, 1fr)' } }}>
              {this.devices.current.map((device: Device.AsObject, i: React.Key) => (
                <Box key={i}>
                  <DeviceListItem device={device} onRemove={() => this.devices.refresh()} />
                </Box>
              ))}
            </Box>
          </Box>
          <Box sx={{ gridColumn: { xs: 'span 12', sm: 'span 10', md: 'span 10', lg: 'span 6' } }}>
            <AddDevice onAdd={() => this.devices.refresh()} />
          </Box>
        </Box>
      );
    }
  },
);
