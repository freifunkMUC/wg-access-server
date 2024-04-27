import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';

export function Loading() {
  return (
    <Box
      component="div"
      m={4}
      display="flex"
      flexDirection="column"
      justifyContent="center"
      alignItems="center"
      minHeight="50vh"
    >
      <Box mb={5}>Loading...</Box>
      <CircularProgress color="primary" />
    </Box>
  );
}
