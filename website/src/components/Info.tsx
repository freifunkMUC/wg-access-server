import React from 'react';
import Popover from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import InfoIcon from '@mui/icons-material/Info';

interface Props {
  children: React.ReactNode;
}

export function Info(props: Props) {
  const [anchor, setAnchor] = React.useState<HTMLElement | undefined>(undefined);

  return (
    <>
      <IconButton onClick={(event) => setAnchor(event.currentTarget)} size="large">
        <InfoIcon />
      </IconButton>
      <Popover
        open={!!anchor}
        anchorEl={anchor}
        onClose={() => setAnchor(undefined)}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
      >
        <div style={{ padding: 16 }}>{props.children}</div>
      </Popover>
    </>
  );
}
