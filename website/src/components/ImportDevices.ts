export interface ExportedDevice {
  name?: string;
  publicKey?: string;
  presharedKey?: string;
  // as written by the export: "10.44.0.2/32, fd48:4c4:7aa9::2/128"
  address?: string;
  manualIpv4Address?: string;
  manualIpv6Address?: string;
}

/**
 * Splits the address of an exported device into a bare IPv4 and IPv6 address,
 * which is the form the server expects for a manual assignment.
 */
export function parseExportedAddresses(address?: string): { ipv4: string; ipv6: string } {
  const addresses = { ipv4: '', ipv6: '' };
  for (const part of (address ?? '').split(',')) {
    const value = part.trim().split('/')[0];
    if (!value) {
      continue;
    }
    if (value.includes(':')) {
      addresses.ipv6 ||= value;
    } else {
      addresses.ipv4 ||= value;
    }
  }
  return addresses;
}
