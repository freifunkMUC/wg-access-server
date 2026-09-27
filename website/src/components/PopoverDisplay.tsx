import React from 'react';
import Button from '@mui/material/Button';
import Popover from '@mui/material/Popover';

interface Props {
  label: string;
  children: React.ReactNode;
}

export function PopoverDisplay(props: Props) {
  const [anchorEl, setAnchorEl] = React.useState<HTMLElement | undefined>(undefined);

  return (
    <>
      <Button
        size="small"
        variant="outlined"
        color="secondary"
        style={{ padding: 0 }}
        onClick={(event) => setAnchorEl(event.currentTarget)}
      >
        {props.label}
      </Button>
      <Popover
        open={Boolean(anchorEl)}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(undefined)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        transformOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <div style={{ padding: '2rem' }}>{props.children}</div>
      </Popover>
    </>
  );
}
