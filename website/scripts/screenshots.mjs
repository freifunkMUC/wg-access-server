// Takes the screenshots in the README: npm run screenshots
//
// It builds the web UI and the server, fills a fresh database with a few
// devices, starts the server without WireGuard and photographs the pages in
// light and dark mode. A second server with more sign-in providers shows the
// sign-in page; a tiny stand-in answers for its identity providers. Nothing
// is left running, and nothing but the files in screenshots/ changes.
//
// Needs Go, and Chromium for Playwright: npx playwright install chromium

import { chromium } from 'playwright';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const website = path.resolve(import.meta.dirname, '..');
const repo = path.resolve(website, '..');
const out = path.join(repo, 'screenshots');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-screenshots-'));
const size = { width: 1600, height: 800 };
const password = 'screenshots';

const cleanups = [];
async function cleanup() {
  for (const fn of cleanups.reverse()) {
    await fn();
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

function run(cmd, args, cwd) {
  console.log(`> ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });
}

// Starts the server and waits until it answers.
async function serve(name, port, args) {
  const log = fs.openSync(path.join(tmp, `${name}.log`), 'w');
  // from the repository: the server serves ./website/build
  const server = spawn(path.join(tmp, 'wg-access-server'), ['serve', '--port', String(port), ...args], {
    cwd: repo,
    stdio: ['ignore', log, log],
  });
  cleanups.push(
    () =>
      new Promise((resolve) => {
        if (server.exitCode !== null) return resolve();
        server.once('exit', resolve);
        server.kill();
      }),
  );
  const base = `http://localhost:${port}`;
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) break;
    try {
      if ((await fetch(`${base}/health`)).ok) return base;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`${name} did not start:\n${fs.readFileSync(path.join(tmp, `${name}.log`), 'utf8')}`);
}

// Answers the OIDC discovery of the sign-in page's providers. Signing in is
// never attempted, the providers only have to be found at start-up.
async function identityProviders(port) {
  const server = http.createServer((req, res) => {
    const issuer = `http://localhost:${port}${req.url.replace('/.well-known/openid-configuration', '')}`;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/auth`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/certs`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      }),
    );
  });
  await new Promise((resolve) => server.listen(port, resolve));
  cleanups.push(() => new Promise((resolve) => server.close(resolve)));
  return `http://localhost:${port}`;
}

// Chromium compresses its PNG files for speed. Packing the image data again at
// the highest level keeps every pixel and saves up to 40% - the sign-in page's
// gradient compresses badly.
function recompress(file) {
  const png = fs.readFileSync(file);
  const chunks = [];
  const idat = [];
  for (let pos = 8; pos < png.length; ) {
    const length = png.readUInt32BE(pos);
    const type = png.toString('latin1', pos + 4, pos + 8);
    const data = png.subarray(pos + 8, pos + 8 + length);
    if (type === 'IDAT') {
      if (idat.length === 0) chunks.push({ type });
      idat.push(data);
    } else {
      chunks.push({ type, data });
    }
    pos += 12 + length;
  }
  const packed = zlib.deflateSync(zlib.inflateSync(Buffer.concat(idat)), { level: 9, memLevel: 9 });
  const parts = [png.subarray(0, 8)];
  for (const chunk of chunks) {
    const data = chunk.type === 'IDAT' ? packed : chunk.data;
    const header = Buffer.alloc(8);
    header.writeUInt32BE(data.length);
    header.write(chunk.type, 4, 'latin1');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(Buffer.concat([header.subarray(4), data])));
    parts.push(header, data, crc);
  }
  fs.writeFileSync(file, Buffer.concat(parts));
}

async function shoot(page, name) {
  // no hover effect on whatever is under the pointer
  await page.mouse.move(0, size.height - 1);
  await page.waitForTimeout(500);
  const file = path.join(out, `${name}.png`);
  await page.screenshot({ path: file });
  recompress(file);
  console.log(`  ${path.relative(repo, file)} (${Math.round(fs.statSync(file).size / 1024)} KB)`);
}

async function appScreenshots(browser, base) {
  for (const scheme of ['light', 'dark']) {
    const suffix = scheme === 'dark' ? '-dark' : '';
    const context = await browser.newContext({ viewport: size, colorScheme: scheme });
    const page = await context.newPage();
    await page.goto(`${base}/signin`);
    await page.fill('#username', 'admin');
    await page.fill('#password', password);
    await page.click('#submit');
    await page.getByText('iPhone').waitFor();
    await shoot(page, `devices${suffix}`);

    // the dialog shows up after adding a device
    await page.fill('#device-name', 'Tablet');
    await page.getByRole('button', { name: /^add/i }).click();
    const dialog = page.getByRole('dialog');
    await dialog.waitFor();
    await shoot(page, `connect-desktop${suffix}`);
    await dialog.getByRole('tab').nth(1).click();
    await shoot(page, `connect-mobile${suffix}`);

    // so that the dark screenshots show the same devices
    const res = await context.request.post(`${base}/api/proto.Devices/DeleteDevice`, {
      headers: { 'Content-Type': 'application/json' },
      data: { name: 'Tablet' },
    });
    if (!res.ok()) throw new Error(`deleting the device failed: ${res.status()}`);
    await context.close();
  }
}

async function signinScreenshots(browser, base) {
  for (const scheme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: size, colorScheme: scheme });
    const page = await context.newPage();
    await page.goto(`${base}/signin`);
    await shoot(page, `signin${scheme === 'dark' ? '-dark' : ''}`);
    await context.close();
  }
}

try {
  run('npm', ['run', 'build'], website);
  run('go', ['build', '-o', path.join(tmp, 'wg-access-server'), '.'], repo);

  const db = `sqlite3://${path.join(tmp, 'screenshots.db')}`;
  run('go', ['run', './scripts/screenshots/seed', '-storage', db], repo);

  const browser = await chromium.launch();
  cleanups.push(() => browser.close());

  console.log('the web UI:');
  const app = await serve('app', 18101, [
    '--no-wireguard-enabled',
    '--no-dns-enabled',
    '--no-https-enabled',
    '--storage',
    db,
    '--admin-password',
    password,
    '--wireguard-private-key',
    randomBytes(32).toString('base64'),
    '--external-host',
    'vpn.example.com',
  ]);
  await appScreenshots(browser, app);

  console.log('the sign-in page:');
  const idp = await identityProviders(18102);
  const config = path.join(tmp, 'config.yaml');
  fs.writeFileSync(
    config,
    `adminPassword: ${password}
storage: memory://
wireguard:
  enabled: false
dns:
  enabled: false
https:
  enabled: false
auth:
  oidc:
    name: Keycloak
    issuer: ${idp}/realms/demo
    clientID: wg-access-server
    clientSecret: secret
    redirectURL: http://localhost:18103/callback
  gitlab:
    name: GitLab
    baseURL: ${idp}/gitlab
    clientID: wg-access-server
    clientSecret: secret
    redirectURL: http://localhost:18103/callback/gitlab
`,
    { mode: 0o600 },
  );
  const signin = await serve('signin', 18103, ['--config', config]);
  await signinScreenshots(browser, signin);
} finally {
  await cleanup();
}
