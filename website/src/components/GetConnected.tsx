import { ButtonGroup, Box } from '@mui/material';
import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { GetApp } from '@mui/icons-material';
import Laptop from '@mui/icons-material/Laptop';
import PhoneIphone from '@mui/icons-material/PhoneIphone';
import React, { PropsWithChildren } from 'react';
import { AppState } from '../AppState';
import { isMobile } from '../Platform';
import { download } from '../Util';
import { LinuxIcon } from './Icons';
import AppleIcon from '@mui/icons-material/Apple';
import MicrosoftIcon from '@mui/icons-material/Microsoft';
import { QRCode } from './QRCode';
import { TabPanel } from './TabPanel';

interface Props {
  configFile: string;
  showMobile: boolean;
}

export function GetConnected({ configFile, showMobile }: PropsWithChildren<Props>) {
  const [currentTab, setCurrentTab] = React.useState(isMobile() && showMobile ? 'mobile' : 'desktop');

  const go = (href: string) => {
    window.open(href, '__blank', 'noopener noreferrer');
  };

  const downloadConfigFile = () => {
    const info = AppState.info!;
    download({
      filename: info.filename.length > 0 ? info.filename + '.conf' : 'WireGuard.conf',
      content: configFile,
    });
  };

  return (
    <React.Fragment>
      <Paper>
        <Tabs
          value={currentTab}
          onChange={(_, currentTab) => setCurrentTab(currentTab)}
          indicatorColor="primary"
          textColor="primary"
          variant="fullWidth"
        >
          <Tab icon={<Laptop />} value="desktop" />
          {showMobile && <Tab icon={<PhoneIphone />} value="mobile" />}
        </Tabs>
      </Paper>

      <TabPanel for="desktop" value={currentTab}>
        <Box sx={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
          <List>
            <ListItem>
              <ListItemText style={{ width: 300 }} primary="1. Install the WireGuard app" />
              <ButtonGroup size="large" color="primary" aria-label="Download the WireGuard app">
                <Button onClick={() => go('https://www.WireGuard.com/install/')}>
                  <LinuxIcon />
                </Button>
                <Button onClick={() => go('https://www.wireguard.com/install/')}>
                  <MicrosoftIcon />
                </Button>
                <Button onClick={() => go('https://www.wireguard.com/install/#macos-app-store')}>
                  <AppleIcon />
                </Button>
              </ButtonGroup>
            </ListItem>
            <ListItem>
              <ListItemText style={{ width: 300 }} primary="2. Download your connection file" />
              <Button variant="outlined" color="primary" onClick={downloadConfigFile}>
                <GetApp /> Connection file
              </Button>
            </ListItem>
            <ListItem>
              <ListItemText style={{ width: 300 }} primary="3. Import your connection file in the app" />
            </ListItem>
          </List>
        </Box>
      </TabPanel>

      {showMobile && (
        <TabPanel for="mobile" value={currentTab}>
          <Box sx={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
            <Box>
              <List>
                <ListItem>
                  <ListItemText primary="1. Install the WireGuard app" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="2. Add a tunnel" />
                </ListItem>
                <ListItem>
                  <ListItemText primary="3. Create from QR code" />
                </ListItem>
              </List>
            </Box>
            <Box>
              <QRCode content={configFile} />
            </Box>
          </Box>
        </TabPanel>
      )}
    </React.Fragment>
  );
}
