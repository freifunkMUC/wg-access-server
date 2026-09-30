import React, { useEffect } from 'react';
import styled from '@emotion/styled';
import { AppState } from '../AppState';
import { NavLink } from 'react-router-dom';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';
import Chip from '@mui/material/Chip';
import VpnKey from '@mui/icons-material/VpnKey';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Divider from '@mui/material/Divider';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import LogoutIcon from '@mui/icons-material/Logout';
import LoginIcon from '@mui/icons-material/Login';
import DevicesIcon from '@mui/icons-material/Devices';
import KeyIcon from '@mui/icons-material/Key';
import ShieldIcon from '@mui/icons-material/Shield';
import PasswordIcon from '@mui/icons-material/Password';
import { useMediaQuery } from '@mui/material';

// Stile mit `styled` definieren
const Title = styled(Typography)`
  flex-grow: 1;
`;

export default function Navigation() {
  // The web UI is only served to signed in users, and the server info only
  // loads with a session - the session cookie itself is HttpOnly and not
  // visible from here.
  const signedIn = !!AppState.info;

  return (
    <AppBar position="static">
      <Toolbar>
        <Title variant="h6">
          <Link to="/" color="inherit" underline="none" component={NavLink}>
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

        {/* The admin pages are a place in the app, not a setting of your own
            account, so they keep their own button. */}
        {AppState.info?.isAdmin && (
          <Link to="/admin/all-devices" color="inherit" component={NavLink}>
            <IconButton sx={{ ml: 1 }} color="inherit" title="All devices">
              <DevicesIcon />
            </IconButton>
          </Link>
        )}

        {signedIn ? <AccountMenu /> : <SignInButton />}
      </Toolbar>
    </AppBar>
  );
}

// AccountMenu collects everything that is about your own account behind one
// button. As icons in the bar they were a row of shapes you had to hover one
// by one to find out what each of them does; a menu says it in words.
function AccountMenu() {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const close = () => setAnchorEl(null);

  return (
    <>
      <IconButton
        sx={{ ml: 1 }}
        color="inherit"
        title="Your account"
        aria-label="Your account"
        aria-haspopup="true"
        aria-controls={open ? 'account-menu' : undefined}
        aria-expanded={open ? 'true' : undefined}
        onClick={(event) => setAnchorEl(event.currentTarget)}
      >
        <AccountCircleIcon />
      </IconButton>
      <Menu
        id="account-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={close}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {AppState.info?.passwordChangeEnabled && (
          <MenuItem component={NavLink} to="/password" onClick={close}>
            <ListItemIcon>
              <PasswordIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Password and two-factor</ListItemText>
          </MenuItem>
        )}

        <MenuItem component={NavLink} to="/sessions" onClick={close}>
          <ListItemIcon>
            <ShieldIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Where you are signed in</ListItemText>
        </MenuItem>

        {AppState.info?.apiTokensEnabled && (
          <MenuItem component={NavLink} to="/tokens" onClick={close}>
            <ListItemIcon>
              <KeyIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>API tokens</ListItemText>
          </MenuItem>
        )}

        <Divider />

        <DarkModeItem onSwitched={close} />

        <Divider />

        {/* a form, not a link: signing out takes a POST, which another site
            cannot make the browser send (see CrossOriginProtection) */}
        <form method="post" action="/signout">
          <MenuItem component="button" type="submit" title="Sign out" sx={{ width: '100%' }}>
            <ListItemIcon>
              <LogoutIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Sign out</ListItemText>
          </MenuItem>
        </form>
      </Menu>
    </>
  );
}

function SignInButton() {
  return (
    <Link href="/signin" color="inherit">
      <IconButton sx={{ ml: 1 }} color="inherit" title="Sign in">
        <LoginIcon />
      </IconButton>
    </Link>
  );
}

const CUSTOM_DARK_MODE_KEY = 'customDarkMode';

function DarkModeItem(props: { onSwitched: () => void }) {
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)');

  useEffect(() => {
    const customDarkMode = localStorage.getItem(CUSTOM_DARK_MODE_KEY);
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

    props.onSwitched();
  }

  return (
    <MenuItem onClick={toggleDarkMode}>
      <ListItemIcon>
        {AppState.darkMode ? <Brightness7Icon fontSize="small" /> : <Brightness4Icon fontSize="small" />}
      </ListItemIcon>
      <ListItemText>{AppState.darkMode ? 'Switch to light mode' : 'Switch to dark mode'}</ListItemText>
    </MenuItem>
  );
}
