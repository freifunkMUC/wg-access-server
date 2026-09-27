import React from 'react';
import qrcode from 'qrcode';
import { Paper, CircularProgress, Box } from '@mui/material';

interface Props {
  content: string;
}

export function QRCode(props: Props) {
  const [uri, setUri] = React.useState<string | undefined>(undefined);

  React.useEffect(() => {
    let current = true;
    void qrcode.toDataURL(props.content).then((dataURL) => {
      // the content may have changed while the code was being drawn
      if (current) {
        setUri(dataURL);
      }
    });
    return () => {
      current = false;
    };
  }, [props.content]);

  if (!uri) {
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
        src={uri}
        style={{
          display: 'block',
          width: '250px',
          height: '250px',
        }}
      />
    </Box>
  );
}
