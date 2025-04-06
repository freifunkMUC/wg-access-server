import React from 'react';
import Grid from '@mui/material/Grid';
import { observable, makeObservable } from 'mobx';
import { observer } from 'mobx-react';
import { grpc } from '../Api';
import { autorefresh } from '../Util';
import { DeviceListItem } from './DeviceListItem';
import { AddDevice } from './AddDevice';
import { Loading } from './Loading';
import { AppState } from '../AppState';
import { Error } from './Error';
import { Card, CardContent, CardHeader, Skeleton } from '@mui/material';
import { DeviceListItemSkeleton } from './DeviceListItemSkeleton';
import { AddDeviceSkeleton } from './AddDeviceSkeleton';

export const Devices = observer(
  class Devices extends React.Component {
    devices = autorefresh(30, async () => {
      try {
        const res = await grpc.devices.listDevices({});
        return res.items;
      } catch (error: any) {
        console.log('An error occurred:', error);
        AppState.loadingError = error.message;
        return null;
      }
    });

    constructor(props: {}) {
      super(props);

      makeObservable(this, {
        devices: observable,
      });
    }

    componentDidMount() {
      // Register the refresh function with the AppState
      AppState.setRefreshDevices(() => this.devices.refresh());
    }

    componentWillUnmount() {
      this.devices.dispose();
    }

    render() {
      if (AppState.loadingError) {
        return <Error message={AppState.loadingError} />;
      }
      if (!this.devices.current) {
        return (
          <Grid container spacing={3} justifyContent="center">
            <Grid item xs={12}>
              <Grid container spacing={3}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <Grid key={i} item xs={12} sm={6} md={4} lg={3}>
                    <DeviceListItemSkeleton />
                  </Grid>
                ))}
              </Grid>
            </Grid>
            <Grid item xs={12} sm={10} md={10} lg={6}>
              <AddDeviceSkeleton />
            </Grid>
          </Grid>
        );
      }
      return (
        <Grid container spacing={3} justifyContent="center">
          <Grid item xs={12}>
            <Grid container spacing={3}>
              {this.devices.current.map((device, i) => (
                <Grid key={i} item xs={12} sm={6} md={4} lg={3}>
                  <DeviceListItem device={device} onRemove={() => this.devices.refresh()} />
                </Grid>
              ))}
            </Grid>
          </Grid>
          <Grid item xs={12} sm={10} md={10} lg={6}>
            <AddDevice onAdd={() => this.devices.refresh()} />
          </Grid>
        </Grid>
      );
    }
  },
);
