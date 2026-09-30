import { describe, expect, it } from 'vitest';
import { decodeCreationOptions, encodeCredential, fromBase64url, toBase64url } from './webauthn';

const bytes = (...values: number[]) => new Uint8Array(values).buffer;

describe('base64url', () => {
  // the server speaks base64url without padding; getting either half of this
  // wrong produces credentials that almost work
  it('round-trips bytes', () => {
    for (const value of [bytes(), bytes(0), bytes(1, 2, 3), bytes(251, 252, 253, 254, 255)]) {
      const encoded = toBase64url(value);
      expect(new Uint8Array(fromBase64url(encoded))).toEqual(new Uint8Array(value));
    }
  });

  it('writes the url alphabet and no padding', () => {
    // 0xfb 0xff 0xfe is "+//+" in standard base64
    const encoded = toBase64url(bytes(251, 255, 254));
    expect(encoded).not.toMatch(/[+/=]/);
    expect(encoded).toBe('-__-');
  });

  it('reads what the server writes, padding or not', () => {
    expect(new Uint8Array(fromBase64url('AQID'))).toEqual(new Uint8Array([1, 2, 3]));
  });
});

describe('decodeCreationOptions', () => {
  it('turns the ids the server sent into buffers, and leaves the rest alone', () => {
    const options = decodeCreationOptions({
      publicKey: {
        challenge: 'AQID',
        rp: { id: 'vpn.example.com', name: 'wg-access-server' },
        user: { id: 'BAUG', name: 'alice', displayName: 'Alice' },
        excludeCredentials: [{ id: 'BwgJ', type: 'public-key', transports: ['usb'] }],
        timeout: 60000,
      },
    });

    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(new Uint8Array([4, 5, 6]));
    expect(new Uint8Array(options.excludeCredentials![0].id as ArrayBuffer)).toEqual(new Uint8Array([7, 8, 9]));
    // what the browser needs unchanged
    expect(options.user.name).toBe('alice');
    expect(options.timeout).toBe(60000);
    expect(options.excludeCredentials![0].transports).toEqual(['usb']);
  });

  it('copes with no credentials to exclude', () => {
    const options = decodeCreationOptions({
      publicKey: { challenge: 'AQID', rp: {}, user: { id: 'BAUG', name: 'a', displayName: 'a' } },
    });
    expect(options.excludeCredentials).toBeUndefined();
  });
});

describe('encodeCredential', () => {
  it('writes what the server reads', () => {
    const credential = {
      id: 'the-id',
      rawId: bytes(1, 2, 3),
      type: 'public-key',
      response: { clientDataJSON: bytes(4, 5, 6), attestationObject: bytes(7, 8, 9) },
    } as unknown as PublicKeyCredential;

    const sent = JSON.parse(encodeCredential(credential));

    expect(sent).toEqual({
      id: 'the-id',
      rawId: 'AQID',
      type: 'public-key',
      response: { clientDataJSON: 'BAUG', attestationObject: 'BwgJ' },
    });
  });
});
