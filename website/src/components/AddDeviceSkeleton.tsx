import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  FormControl,
  FormControlLabel,
  FormHelperText,
  Input,
  InputLabel,
  Skeleton,
  Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import AddIcon from '@mui/icons-material/Add';

export function AddDeviceSkeleton() {
  return (
    <Card>
      <CardHeader title="Add A Device" />
      <CardContent>
        <FormControl fullWidth>
          <InputLabel htmlFor="device-name">
            <Skeleton variant="text" width={100} />
          </InputLabel>
          <Input id="device-name" aria-describedby="device-name-text" />
        </FormControl>
        <Box mt={2} mb={2}>
          <Accordion>
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              aria-controls="advanced-options-content"
              id="advanced-options-header"
            >
              <Typography>
                <Skeleton variant="text" width={80} />
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <FormControl fullWidth>
                <InputLabel htmlFor="device-publickey">
                  <Skeleton variant="text" width={180} />
                </InputLabel>
                <Input id="device-publickey" aria-describedby="device-publickey-text" />
                <FormHelperText id="device-publickey-text">
                  <Skeleton variant="text" width="80%" />
                </FormHelperText>
              </FormControl>
              <FormControlLabel
                control={<Checkbox id="device-presharedkey" value={<Skeleton variant="text" width={20} />} />}
                label={<Skeleton variant="text" width={100} />}
              />
              <FormControlLabel
                control={<Checkbox id="manual-ip-assignment" value={<Skeleton variant="text" width={20} />} />}
                label={<Skeleton variant="text" width={180} />}
              />
              <FormControl fullWidth>
                <InputLabel htmlFor="manual-ipv4-address">
                  <Skeleton variant="text" width={120} />
                </InputLabel>
                <Input id="manual-ipv4-address" aria-describedby="manual-ipv4-address-text" />
                <FormHelperText id="manual-ipv4-address-text">
                  <Skeleton variant="text" width={100} />
                </FormHelperText>
              </FormControl>
              <FormControl fullWidth>
                <InputLabel htmlFor="manual-ipv6-address">
                  <Skeleton variant="text" width={120} />
                </InputLabel>
                <Input id="manual-ipv6-address" aria-describedby="manual-ipv6-address-text" />
                <FormHelperText id="manual-ipv6-address-text">
                  <Skeleton variant="text" width={100} />
                </FormHelperText>
              </FormControl>
            </AccordionDetails>
          </Accordion>
        </Box>
        <Typography component="div" align="right">
          <Button color="secondary" type="button">
            Cancel
          </Button>
          <Button color="primary" variant="contained" endIcon={<AddIcon />} type="submit">
            Add
          </Button>
        </Typography>
      </CardContent>
    </Card>
  );
}
