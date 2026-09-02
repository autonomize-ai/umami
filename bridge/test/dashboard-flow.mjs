// End-to-end verification of the gated Umami dashboard, in a REAL browser.
//
// Why this exists rather than a curl script: three separate bugs shipped past
// curl-level testing on this feature, because each hop answered correctly on
// its own and the SEQUENCE did not. Two of them lived in client-side
// JavaScript that curl never executes at all --
//
//   * the bridge called /api/auth/login instead of /umami/api/auth/login, so
//     every sign-in 404'd (the proxy path was tested; the entry path was not)
//   * the hand-off redirected to "/", which with basePath IS the entry path,
//     so it minted a token and redirected forever
//   * openid-connect overwrote the Authorization header that Umami's own
//     client needs, so the dashboard signed in and then 401'd on every call
//
// This drives Keycloak's login, follows the hand-off, and fails on ANY 4xx/5xx,
// ANY console error, or a navigation count that suggests a loop. All three
// bugs above would have been caught by it.
//
// Usage:
//   TEST_USER=... TEST_PASS=... EXPECT=allow|deny [CHROMIUM_PATH=...] \
//     node bridge/test/dashboard-flow.mjs
//
// EXPECT=allow  -> must reach the dashboard cleanly
// EXPECT=deny   -> must be refused before reaching Umami

import { chromium } from 'playwright';

const BASE = 'http://genesis.localhost';
const USER = process.env.TEST_USER;
const PASS = process.env.TEST_PASS;
const EXPECT_ALLOWED = process.env.EXPECT === 'allow';

const failures = [];
const netErrors = [];
const consoleErrors = [];

// Use the Chromium already on this machine rather than downloading one --
// the installed build (1208) does not match what this playwright version
// expects, and the binary is perfectly usable.
const EXEC = process.env.CHROMIUM_PATH;
const browser = await chromium.launch(EXEC ? { executablePath: EXEC } : {});
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();

page.on('response', r => {
  const u = r.url();
  if (r.status() >= 400 && !/favicon|site\.webmanifest|\.png$|\.ico$/.test(u)) {
    netErrors.push(`${r.status()} ${r.request().method()} ${u.replace(BASE, '')}`);
  }
});
page.on('console', m => {
  if (m.type() === 'error' && !/favicon|webmanifest|Manifest/i.test(m.text())) {
    consoleErrors.push(m.text().slice(0, 160));
  }
});

const redirects = [];
page.on('framenavigated', f => { if (f === page.mainFrame()) redirects.push(f.url().replace(BASE, '')); });

try {
  await page.goto(`${BASE}/umami`, { waitUntil: 'domcontentloaded', timeout: 45000 });

  // Keycloak login form, if we are not already signed in.
  // This realm uses a TWO-STEP login: username, then password on the next
  // screen. Handle both shapes so the test does not depend on that staying so.
  if (page.url().includes('/auth/realms/')) {
    await page.fill('#username', USER);

    const pwdVisible = await page.locator('#password').count();
    if (!pwdVisible) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 45000 }).catch(() => {}),
        page.click('#kc-login, button[type=submit], input[type=submit]'),
      ]);
      await page.waitForSelector('#password', { timeout: 30000 });
    }

    await page.fill('#password', PASS);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 45000 }).catch(() => {}),
      page.click('#kc-login, button[type=submit], input[type=submit]'),
    ]);
  }

  // Let the SSO hand-off + client-side redirects settle.
  await page.waitForLoadState('networkidle', { timeout: 45000 }).catch(() => {});
  await page.waitForTimeout(3000);

  const finalUrl = page.url().replace(BASE, '');
  const bodyText = (await page.textContent('body').catch(() => '')) || '';
  const title = await page.title().catch(() => '');

  console.log(`  final url : ${finalUrl}`);
  console.log(`  title     : ${title}`);
  console.log(`  redirects : ${redirects.length} (${redirects.slice(0, 6).join(' -> ')}${redirects.length > 6 ? ' ...' : ''})`);

  if (EXPECT_ALLOWED) {
    if (redirects.length > 12) failures.push(`redirect loop suspected: ${redirects.length} navigations`);
    if (!/\/umami\//.test(finalUrl)) failures.push(`did not land inside /umami/ (at ${finalUrl})`);
    if (/Could not sign in/i.test(bodyText)) failures.push('bridge could not sign in');
    if (/No authorization pattern/i.test(bodyText)) failures.push('genesis-authz DEFAULT-DENY');
    if (!/Umami/i.test(title)) failures.push(`unexpected title: ${title}`);
    // The dashboard must actually render, not spin.
    const hasNav = await page.locator('a[href*="/websites"], nav, header').count().catch(() => 0);
    if (!hasNav) failures.push('no dashboard chrome rendered (still loading?)');
  } else {
    const denied = /Forbidden|Insufficient role|403/i.test(bodyText) || netErrors.some(e => e.startsWith('403'));
    if (!denied) failures.push(`non-admin was NOT denied (landed at ${finalUrl})`);
  }
} catch (e) {
  failures.push(`exception: ${e.message.split('\n')[0]}`);
}

if (netErrors.length) console.log(`  net errors: ${netErrors.slice(0, 8).join(' | ')}`);
if (consoleErrors.length) console.log(`  console   : ${consoleErrors.slice(0, 5).join(' | ')}`);

await browser.close();

if (EXPECT_ALLOWED && netErrors.length) failures.push(`${netErrors.length} failed request(s)`);
if (EXPECT_ALLOWED && consoleErrors.length) failures.push(`${consoleErrors.length} console error(s)`);

console.log(failures.length ? `  RESULT: FAIL\n${failures.map(f => '    - ' + f).join('\n')}` : '  RESULT: PASS');
process.exit(failures.length ? 1 : 0);
