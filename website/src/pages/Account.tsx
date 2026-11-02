import React from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { observer } from 'mobx-react';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppState } from '../AppState';
import { ApiTokens } from './ApiTokens';
import { Password } from './Password';
import { Sessions } from './Sessions';

interface AccountTab {
  // the last segment of the route, /account/<path>
  path: string;
  label: string;
  element: React.ReactElement;
}

// The tabs this server offers: the password page only where it keeps
// passwords, the tokens only where they are turned on. Sessions are always
// there, so the list is never empty.
export function accountTabs(info: { passwordChangeEnabled?: boolean; apiTokensEnabled?: boolean } | undefined) {
  const tabs: AccountTab[] = [];
  if (info?.passwordChangeEnabled) {
    tabs.push({ path: 'password', label: 'Password and two-factor', element: <Password /> });
  }
  tabs.push({ path: 'sessions', label: 'Sessions', element: <Sessions /> });
  if (info?.apiTokensEnabled) {
    tabs.push({ path: 'tokens', label: 'API tokens', element: <ApiTokens /> });
  }
  return tabs;
}

// Account is everything about your own account, one tab per page. The tabs
// are routes, so a tab can be linked to and the back button leaves it.
export const Account = observer(function Account() {
  const tabs = accountTabs(AppState.info);
  const { pathname } = useLocation();
  const current = tabs.find((tab) => pathname === `/account/${tab.path}`);

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <Tabs
        value={current?.path ?? false}
        variant="scrollable"
        scrollButtons="auto"
        allowScrollButtonsMobile
        aria-label="Account settings"
        sx={{ mb: 3, borderBottom: 1, borderColor: 'divider' }}
      >
        {tabs.map((tab) => (
          <Tab key={tab.path} value={tab.path} label={tab.label} component={Link} to={`/account/${tab.path}`} />
        ))}
      </Tabs>

      <Routes>
        {tabs.map((tab) => (
          <Route key={tab.path} path={tab.path} element={tab.element} />
        ))}
        {/* /account itself, and a tab this server does not offer */}
        <Route path="*" element={<Navigate to={`/account/${tabs[0].path}`} replace />} />
      </Routes>
    </Box>
  );
});
