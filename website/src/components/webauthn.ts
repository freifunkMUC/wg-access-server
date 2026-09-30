// The browser's WebAuthn API speaks ArrayBuffers; the server speaks base64url
// JSON. These are the two translations in between, kept in one place because
// getting them subtly wrong produces credentials that almost work.

export function fromBase64url(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes.buffer;
}

export function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let raw = '';
  for (let i = 0; i < bytes.length; i++) {
    raw += String.fromCharCode(bytes[i]);
  }
  return window.btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// what the server sends for a registration, before the buffers are decoded
interface CreationOptions {
  publicKey: {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    excludeCredentials?: { id: string; type: string; transports?: string[] }[];
    [key: string]: unknown;
  };
}

// decodeCreationOptions turns what the server sent into what the browser
// takes: the same object with its ids as buffers.
export function decodeCreationOptions(options: CreationOptions): PublicKeyCredentialCreationOptions {
  const publicKey = { ...options.publicKey } as unknown as PublicKeyCredentialCreationOptions;
  publicKey.challenge = fromBase64url(options.publicKey.challenge);
  publicKey.user = {
    ...options.publicKey.user,
    id: fromBase64url(options.publicKey.user.id),
  } as PublicKeyCredentialUserEntity;
  if (options.publicKey.excludeCredentials) {
    publicKey.excludeCredentials = options.publicKey.excludeCredentials.map((credential) => ({
      ...credential,
      id: fromBase64url(credential.id),
      type: credential.type as 'public-key',
      transports: credential.transports as AuthenticatorTransport[] | undefined,
    }));
  }
  return publicKey;
}

// encodeCredential turns what the browser made into what the server reads.
export function encodeCredential(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      attestationObject: toBase64url(response.attestationObject),
    },
  });
}

// supported says whether this browser can make a passkey at all. A page
// served over plain HTTP cannot, whatever the browser: WebAuthn needs a
// secure context, and saying so beats a failure nobody can explain.
export function passkeysSupported(): boolean {
  return typeof window.PublicKeyCredential !== 'undefined' && window.isSecureContext;
}
