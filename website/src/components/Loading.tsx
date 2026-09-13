import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';

export function Loading() {
  return (
    <Box
      component="div"
      sx={{
        m: 4,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '50vh',
      }}
    >
      <Box sx={{ mb: 5 }}>Loading...</Box>
      <CircularProgress color="primary" />
    </Box>
  );
}
