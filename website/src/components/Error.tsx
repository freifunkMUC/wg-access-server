import { Alert, AlertTitle, Box } from '@mui/material';

interface ErrorProps {
  message: String;
}

export function Error({ message }: ErrorProps) {
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
      <Alert variant="filled" severity="error" sx={{ m: 5, p: 3, minWidth: 500 }}>
        <AlertTitle>Error loading the page</AlertTitle>
        An error has occurred!
        <Box mt={2} mb={2}>
          {message}
        </Box>
        Please try again later or contact support.
      </Alert>
    </Box>
  );
}
