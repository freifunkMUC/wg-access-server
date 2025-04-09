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
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { Loading } from './components/Loading';
import { Error } from './components/Error';

export const App = observer(
  class App extends React.Component {
    async componentDidMount() {
      try {
        AppState.setInfo(await grpc.server.info({}));
      } catch (error: any) {

        AppState.setLoadingError(error.message);
        console.error('An error occurred:', error);
      }
    }

    pageContent() {
      if (AppState.loadingError) {
        return <Error message={AppState.loadingError} />;
      } else if (!AppState.info) {
        return <Loading />;
      } else {
        return (
          <Routes>
            <Route path="/" element={<YourDevices />} />
            {AppState.info.isAdmin && <Route path="/admin/all-devices" element={<AllDevices />} />}
          </Routes>
        );
      }
    }

    render() {
      const darkLightTheme = createTheme({
        palette: {
          mode: AppState.darkMode ? 'dark' : 'light',
        },
      });

      return (
        <Router>
          <ThemeProvider theme={darkLightTheme}>
            <CssBaseline />
            <Navigation />
            <Box component="div" m={2}>
              {this.pageContent()}
            </Box>
          </ThemeProvider>
        </Router>
      );
    }
  },
);
