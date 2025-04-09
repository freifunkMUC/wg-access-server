import React from 'react';
import qrcode from 'qrcode';
import { lazy } from '../Util';
import { Paper, CircularProgress, Box } from '@mui/material';

interface Props {
  content: string;
}

export class QRCode extends React.Component<Props> {
  uri = lazy(async () => {
    return await qrcode.toDataURL(this.props.content);
  });

  render() {
    if (!this.uri.current) {
      return <CircularProgress color="secondary" />;
    }
    return (
      <Box
        component={Paper}
        elevation={2}
        sx={{
          p: 0.5,
          background: '#ffffff',
          borderRadius: 3,
          transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
          '&:hover': {
            transform: 'scale(1.02)',
            boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
          },
        }}
      >
        <img
          alt="WireGuard QR code"
          src={this.uri.current}
          style={{
            display: 'block',
            width: '250px',
            height: '250px',
          }}
        />
      </Box>
    );
  }
}
