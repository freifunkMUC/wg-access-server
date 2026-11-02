import React from 'react';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Navigation from './components/Navigation';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { observer } from 'mobx-react';
import { grpc } from './Api';
import { AppState } from './AppState';
import { YourDevices } from './pages/YourDevices';
import { AllDevices } from './pages/admin/AllDevices';
import { Account } from './pages/Account';
import { ThemeProvider } from '@mui/material/styles';
import { appTheme } from './Theme';
import { Loading } from './components/Loading';
import { Error } from './components/Error';
import { errorMessage } from './Util';

// AppRoutes are the pages once the server info has loaded; on their own so
// that a test can render the real ones.
export const AppRoutes = observer(function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<YourDevices />} />
      {AppState.info?.isAdmin && <Route path="/admin/all-devices" element={<AllDevices />} />}
      <Route path="/account/*" element={<Account />} />
      {/* the pages moved into the tabs of /account; bookmarks and links in the docs still work */}
      <Route path="/password" element={<Navigate to="/account/password" replace />} />
      <Route path="/sessions" element={<Navigate to="/account/sessions" replace />} />
      <Route path="/tokens" element={<Navigate to="/account/tokens" replace />} />
    </Routes>
  );
});

export const App = observer(function App() {
  React.useEffect(() => {
    void (async () => {
      try {
        AppState.setInfo(await grpc.server.info({}));
      } catch (error) {
        AppState.setLoadingError(errorMessage(error));
        console.error('An error occurred:', error);
      }
    })();
  }, []);

  const pageContent = () => {
    if (AppState.loadingError) {
      return <Error message={AppState.loadingError} />;
    }
    if (!AppState.info) {
      return <Loading />;
    }
    return <AppRoutes />;
  };

  return (
    <Router>
      <ThemeProvider theme={appTheme(AppState.darkMode)}>
        <CssBaseline />
        <Navigation />
        <Box component="div" sx={{ m: 2 }}>
          {pageContent()}
        </Box>
      </ThemeProvider>
    </Router>
  );
});
