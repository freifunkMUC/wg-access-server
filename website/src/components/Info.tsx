import React from 'react';
import { observable, makeObservable, runInAction } from 'mobx';
import { observer } from 'mobx-react';
import Popover from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import InfoIcon from '@mui/icons-material/Info';

interface Props {
  children: React.ReactNode;
}

export const Info = observer(
  class Info extends React.Component<Props> {
    anchor?: HTMLElement;

    constructor(props: Props) {
      super(props);

      makeObservable(this, {
        anchor: observable,
      });
    }


    setAnchor(anchor?: HTMLElement){
      runInAction(() => {
        this.anchor = anchor;
      });
    }

    render() {
      return (
        <>
          <IconButton onClick={(event) => (this.setAnchor(event.currentTarget))} size="large">
            <InfoIcon />
          </IconButton>
          <Popover
            open={!!this.anchor}
            anchorEl={this.anchor}
            onClose={() => (this.setAnchor(undefined))}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'center',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'center',
            }}
          >
            <div style={{ padding: 16 }}>{this.props.children}</div>
          </Popover>
        </>
      );
    }
  },
);
