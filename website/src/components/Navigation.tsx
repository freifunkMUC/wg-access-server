import React, { useEffect } from 'react';
import styled from '@emotion/styled';
import { observer } from 'mobx-react';
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
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import Divider from '@mui/material/Divider';
import Tooltip from '@mui/material/Tooltip';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import LogoutIcon from '@mui/icons-material/Logout';
import LoginIcon from '@mui/icons-material/Login';
import DevicesIcon from '@mui/icons-material/Devices';
import SettingsIcon from '@mui/icons-material/Settings';
import { useMediaQuery } from '@mui/material';

// Stile mit `styled` definieren
const Title = styled(Typography)`
  flex-grow: 1;
  min-width: 0;
`;

export default observer(function Navigation() {
  // The web UI is only served to signed in users, and the server info only
  // loads with a session - the session cookie itself is HttpOnly and not
  // visible from here.
  const signedIn = !!AppState.info;

  return (
    <AppBar position="static">
      <Toolbar>
        <Title variant="h6" noWrap>
          <Link to="/" color="inherit" underline="none" component={NavLink}>
            <VpnKey /> wg-access-server
          </Link>
          {AppState.info?.isAdmin && (
            <Chip
              label="admin"
              color="secondary"
              variant="outlined"
              size="small"
              // the account menu says it as well; the bar has no room for it on a phone
              sx={{
                ml: 2.5,
                display: { xs: 'none', sm: 'inline-flex' },
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

        <ThemeButton />

        {signedIn ? <AccountMenu /> : <SignInButton />}
      </Toolbar>
    </AppBar>
  );
});

// initialsOf is what the avatar shows: the first letters of the first and the
// last word of the name, or the first two letters of a single word. Names
// and subjects are free text, so it works on code points, not bytes.
export function initialsOf(name: string): string {
  const words = name.split(/[\s._@-]+/).filter(Boolean);
  if (words.length === 0) {
    return '?';
  }
  const letters = (word: string) => Array.from(word);
  const picked =
    words.length === 1 ? letters(words[0]).slice(0, 2) : [letters(words[0])[0], letters(words[words.length - 1])[0]];
  return picked.join('').toUpperCase();
}

// AccountMenu collects everything that is about your own account behind one
// button: who you are signed in as, the settings, and signing out.
function AccountMenu() {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const close = () => setAnchorEl(null);
  const info = AppState.info;
  const name = info?.userDisplayName || info?.subject || '';

  return (
    <>
      <IconButton
        sx={{ ml: 1, p: 0.5 }}
        color="inherit"
        title="Your account"
        aria-label="Your account"
        aria-haspopup="true"
        aria-controls={open ? 'account-menu' : undefined}
        aria-expanded={open ? 'true' : undefined}
        onClick={(event) => setAnchorEl(event.currentTarget)}
      >
        <Avatar
          aria-hidden="true"
          sx={{ width: 32, height: 32, fontSize: 14, bgcolor: 'secondary.main', color: 'secondary.contrastText' }}
        >
          {initialsOf(name)}
        </Avatar>
      </IconButton>
      <Menu
        id="account-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={close}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {/* not an item: there is nothing to click, it only says whose account this is */}
        <Box sx={{ px: 2, py: 1, maxWidth: 280 }} data-testid="account-header">
          <Typography variant="subtitle1" noWrap>
            {name}
          </Typography>
          {info?.userProvider && (
            <Typography variant="body2" color="text.secondary" noWrap>
              Signed in with {info.userProvider}
            </Typography>
          )}
          {info?.isAdmin && <Chip label="Admin" color="secondary" size="small" sx={{ mt: 0.5 }} />}
        </Box>

        <Divider />

        <MenuItem component={NavLink} to="/account" onClick={close}>
          <ListItemIcon>
            <SettingsIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Account settings</ListItemText>
        </MenuItem>

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

const ThemeButton = observer(function ThemeButton() {
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
  }

  const label = AppState.darkMode ? 'Switch to light mode' : 'Switch to dark mode';

  return (
    <Tooltip title={label}>
      <IconButton sx={{ ml: 1 }} color="inherit" aria-label={label} onClick={toggleDarkMode}>
        {AppState.darkMode ? <Brightness7Icon /> : <Brightness4Icon />}
      </IconButton>
    </Tooltip>
  );
});
