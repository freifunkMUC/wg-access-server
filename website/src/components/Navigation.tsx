import React, { useEffect } from 'react';
import styled from '@emotion/styled';
import { getCookie } from '../Cookies';
import { AppState } from '../AppState';
import { NavLink } from 'react-router-dom';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';
import Chip from '@mui/material/Chip';
import VpnKey from '@mui/icons-material/VpnKey';
import IconButton from '@mui/material/IconButton';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import LogoutIcon from '@mui/icons-material/Logout';
import LoginIcon from '@mui/icons-material/Login';
import DevicesIcon from '@mui/icons-material/Devices';
import { useMediaQuery } from '@mui/material';

// Stile mit `styled` definieren
const Title = styled(Typography)`
  flex-grow: 1;
`;

export default function Navigation() {
  const hasAuthCookie = !!getCookie('auth-session');

  return (
    <AppBar position="static">
      <Toolbar>
        <Title variant="h6">
          <Link to="/" color="inherit" component={NavLink}>
            <VpnKey /> wg-access-server
          </Link>
          {AppState.info?.isAdmin && (
            <Chip
              label="admin"
              color="secondary"
              variant="outlined"
              size="small"
              style={{
                marginLeft: 20,
                background: AppState.darkMode ? 'transparent' : 'white',
              }}
            />
          )}
        </Title>

        <DarkModeToggle />

        {AppState.info?.isAdmin && (
          <Link to="/admin/all-devices" color="inherit" component={NavLink}>
            <IconButton sx={{ ml: 1 }} color="inherit" title="All Devices">
              <DevicesIcon />
            </IconButton>
          </Link>
        )}

        {hasAuthCookie ? (
          <Link href="/signout" color="inherit">
            <IconButton sx={{ ml: 1 }} color="inherit" title="Logout">
              <LogoutIcon />
            </IconButton>
          </Link>
        ) : (
          <Link href="/signin" color="inherit">
            <IconButton sx={{ ml: 1 }} color="inherit" title="Login">
              <LoginIcon />
            </IconButton>
          </Link>
        )}
      </Toolbar>
    </AppBar>
  );
}

function DarkModeToggle() {
  const CUSTOM_DARK_MODE_KEY = 'customDarkMode';
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)');

  useEffect(() => {
    let customDarkMode = localStorage.getItem(CUSTOM_DARK_MODE_KEY);
    if (customDarkMode) {
      AppState.setDarkMode(JSON.parse(customDarkMode));
    } else {
      AppState.setDarkMode(prefersDarkMode);
    }
  }, [prefersDarkMode]);

  function toggleDarkMode() {
    AppState.setDarkMode(!AppState.darkMode);

    // We only persist the preference in the local storage if it is different to the OS setting.
    if (prefersDarkMode !== AppState.darkMode) {
      localStorage.setItem(CUSTOM_DARK_MODE_KEY, JSON.stringify(AppState.darkMode));
    } else {
      localStorage.removeItem(CUSTOM_DARK_MODE_KEY);
    }
  }

  return (
    <IconButton sx={{ ml: 1 }} onClick={toggleDarkMode} color="inherit" title={'Light / Dark'}>
      {AppState.darkMode ? <Brightness7Icon /> : <Brightness4Icon />}
    </IconButton>
  );
}
