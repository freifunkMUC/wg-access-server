import { describe, expect, it } from 'vitest';
import { parseExportedAddresses } from './ImportDevices';

describe('parseExportedAddresses', () => {
  it('splits a dual stack address', () => {
    expect(parseExportedAddresses('10.44.0.2/32, fd48:4c4:7aa9::2/128')).toEqual({
      ipv4: '10.44.0.2',
      ipv6: 'fd48:4c4:7aa9::2',
    });
  });

  it('handles a single address family', () => {
    expect(parseExportedAddresses('10.44.0.2/32')).toEqual({ ipv4: '10.44.0.2', ipv6: '' });
    expect(parseExportedAddresses('fd48:4c4:7aa9::2/128')).toEqual({ ipv4: '', ipv6: 'fd48:4c4:7aa9::2' });
  });

  // rows written by an older version or by hand may have no prefix length
  it('accepts an address without a prefix', () => {
    expect(parseExportedAddresses('10.44.0.2')).toEqual({ ipv4: '10.44.0.2', ipv6: '' });
  });

  it('ignores surrounding whitespace', () => {
    expect(parseExportedAddresses('  10.44.0.9/32 ,  fd48::9/128 ')).toEqual({
      ipv4: '10.44.0.9',
      ipv6: 'fd48::9',
    });
  });

  it('returns empty strings for nothing usable', () => {
    expect(parseExportedAddresses('')).toEqual({ ipv4: '', ipv6: '' });
    expect(parseExportedAddresses(undefined)).toEqual({ ipv4: '', ipv6: '' });
  });
});
