import React from 'react';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Navigation from './components/Navigation';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { observer } from 'mobx-react';
import { grpc } from './Api';
import { AppState } from './AppState';
import { YourDevices } from './pages/YourDevices';
import { AllDevices } from './pages/admin/AllDevices';
import { ApiTokens } from './pages/ApiTokens';
import { Sessions } from './pages/Sessions';
import { ThemeProvider } from '@mui/material/styles';
import { appTheme } from './Theme';
import { Loading } from './components/Loading';
import { Error } from './components/Error';
import { errorMessage } from './Util';

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
    return (
      <Routes>
        <Route path="/" element={<YourDevices />} />
        {AppState.info.isAdmin && <Route path="/admin/all-devices" element={<AllDevices />} />}
        <Route path="/sessions" element={<Sessions />} />
        {AppState.info.apiTokensEnabled && <Route path="/tokens" element={<ApiTokens />} />}
      </Routes>
    );
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
