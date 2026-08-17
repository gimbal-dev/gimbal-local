// browser-cdp-drive.mjs -- V11.3 (#332): drive a browser that is inside a VM.
//
// The agent's whole view of the sandbox is the CDP endpoint this connects to.
// There is no shell into the guest and no shared filesystem, which is the
// point of the browser sandbox: if this script can do it, an agent can, and
// if it cannot, an agent cannot either.
//
// Usage:
//   node browser-cdp-drive.mjs <host-port> <allowed-url> [denied-url]
//
// Output is KEY=value lines so the calling script can assert on them rather
// than a human reading prose. Any failure exits non-zero.
//
// The denied URL is optional and is expected to FAIL: it is the egress-policy
// half of the acceptance. A navigation that succeeds there is a policy escape,
// so this script treats that as an error, not as a passing page load.

// NODE_PATH is a CommonJS-only mechanism, so an ESM `import` of a bare
// specifier ignores it entirely. playwright-core is itself CommonJS, and its
// `chromium` lives on module.exports rather than as a detected named export --
// so require it outright rather than importing the path require resolves.
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright-core');

const [portArg, allowedUrl, deniedUrl] = process.argv.slice(2);

if (!portArg || !allowedUrl) {
  console.error('usage: browser-cdp-drive.mjs <host-port> <allowed-url> [denied-url]');
  process.exit(2);
}

// A hard ceiling on the whole run. Without it a wedged guest hangs the gate
// forever, and a gate whose failure mode is "the suite never finishes" is not
// a gate (the lesson from the #309 livelock guard).
const DEADLINE_MS = 90_000;
const deadline = setTimeout(() => {
  console.log('VERDICT=timeout');
  console.error(`browser-cdp-drive: no verdict within ${DEADLINE_MS} ms`);
  process.exit(1);
}, DEADLINE_MS);

let browser;
try {
  const t0 = Date.now();
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${portArg}`);
  console.log(`CONNECT_MS=${Date.now() - t0}`);
  console.log(`VERSION=${browser.version()}`);

  const context = browser.contexts()[0] ?? (await browser.newContext());
  const page = await context.newPage();

  // 1. A page rendered entirely inside the guest, with no network at all.
  //    This separates "the browser works" from "the network works", so a
  //    later egress failure cannot be misread as a broken browser.
  await page.setContent('<h1 id="local">rendered inside a Hypervisor.framework VM</h1>');
  console.log(`LOCAL_DOM=${await page.locator('#local').innerText()}`);
  console.log(`EVAL=${await page.evaluate(() => 2 ** 10)}`);

  const shot = await page.screenshot();
  // A PNG signature, not just a non-zero length: a truncated or error-page
  // buffer also has a length.
  const isPng = shot.length > 8 && shot[0] === 0x89 && shot.toString('latin1', 1, 4) === 'PNG';
  console.log(`SHOT_BYTES=${shot.length}`);
  console.log(`SHOT_IS_PNG=${isPng ? 'yes' : 'no'}`);
  if (!isPng) throw new Error('screenshot is not a PNG');

  // 2. The allowed destination, over the real internet, through the NAT.
  //    One page load is on the order of tens of parallel connections, which
  //    is the first honest load the NAT sees.
  const t1 = Date.now();
  await page.goto(allowedUrl, { waitUntil: 'load' });
  console.log(`ALLOWED_MS=${Date.now() - t1}`);
  console.log(`ALLOWED_URL=${page.url()}`);
  console.log(`ALLOWED_TITLE=${await page.title()}`);
  const bodyLen = (await page.evaluate(() => document.body.innerText)).length;
  console.log(`ALLOWED_BODY_CHARS=${bodyLen}`);
  if (bodyLen === 0) throw new Error(`${allowedUrl} rendered an empty body`);

  // 3. The denied destination. Fail-closed egress must refuse it, and the
  //    refusal must arrive as a navigation error rather than a blank page
  //    that an agent would mistake for a slow site.
  if (deniedUrl) {
    let refusal = null;
    try {
      await page.goto(deniedUrl, { waitUntil: 'load', timeout: 20_000 });
    } catch (err) {
      refusal = err.message.split('\n')[0];
    }
    if (refusal === null) {
      console.log('DENIED_RESULT=loaded');
      throw new Error(`${deniedUrl} loaded, but the egress policy does not permit it`);
    }
    console.log(`DENIED_RESULT=refused`);
    console.log(`DENIED_ERROR=${refusal}`);
  }

  console.log('VERDICT=ok');
  clearTimeout(deadline);
  await browser.close();
  process.exit(0);
} catch (err) {
  console.log('VERDICT=failed');
  console.error(`browser-cdp-drive: ${err.message}`);
  clearTimeout(deadline);
  try {
    await browser?.close();
  } catch {
    // The connection is already gone; the verdict above is what matters.
  }
  process.exit(1);
}
