/* The browser: client-side storage and CSRF
   Concepts adapted from Pilcrow's Auth book: https://auth.pilcrowonpaper.com */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block, book } = AIM;

  // ================================================================ 09 · Browser storage
  AIM.chapters.push({
    id: 'browser-storage',
    num: '09',
    group: 'The browser',
    short: 'Cookies vs. Web Storage',
    title: 'Keeping the token in the browser',
    flowName: 'Cookies, localStorage and an XSS attack',
    lede: 'A browser can keep a session token in a cookie or in Web Storage. Neither is encrypted, and an XSS bug can abuse either one. The cookie flags you choose decide most of the remaining risk.',
    sources: [book('browser-client-side-storage', 'Browser client-side storage')],
    glance: [
      ['HttpOnly', 'scripts can’t read the token'],
      ['Secure', 'sent over HTTPS only'],
      ['SameSite=Lax', 'default for session cookies'],
      ['CSP', 'the real defence against XSS'],
    ],
    analogy: {
      title: 'Your membership card',
      intro: 'A cookie is a membership card the browser shows automatically at the right club. localStorage is a note in a desk drawer that your own scripts read and copy onto each request.',
      map: [
        ['Cookie', 'A card the browser shows by itself'],
        ['localStorage', 'A note in a drawer your scripts open'],
        ['HttpOnly', 'The card stays in a sealed sleeve: shown, never photocopied'],
        ['Secure', 'Only shown at a club with locked doors (HTTPS)'],
        ['SameSite', 'Only shown when you walked in yourself'],
        ['XSS', 'A pickpocket working inside your own browser tab'],
      ],
    },
    actors: ['browser', 'api', 'attacker'],
    steps: [
      send('api', 'browser', 'token', 'Set-Cookie: session=…; HttpOnly; Secure; SameSite=Lax; Path=/', 'The server sets a session cookie',
        `<p>The flags are the important part. <code>HttpOnly</code> hides the cookie from JavaScript, <code>Secure</code> restricts it to HTTPS, and <code>SameSite=Lax</code> keeps it off most cross-site requests.</p>`,
        `You’re handed your membership card in a sealed sleeve.`),
      send('browser', 'api', 'token', 'Cookie: session=… (automatic)', 'Cookies travel on their own',
        `<p>The browser attaches the cookie to every matching request. That makes server-rendered pages and simple SPAs easy. It’s also exactly why CSRF exists (chapter 10).</p>`,
        `At the club door, the card is shown without you reaching for it.`),
      proc('browser', 'token', 'localStorage.setItem("token", …)', 'The alternative: Web Storage',
        `<p>Your code stores the token and adds it to requests as a header. It’s easy to use, but browsers clear Web Storage more aggressively, and every script on the page can read it.</p>`,
        `A note in the drawer: your own hands copy it onto every request.`),
      block('attacker', 'browser', '<script>steal(document.cookie, localStorage)</script>', 'HttpOnly: nothing to read', 'XSS tries to steal the token',
        `<p>An injected script, or a compromised npm package, tries to read the token and send it away. An HttpOnly cookie isn’t visible to scripts at all. A token in localStorage would be gone.</p>`,
        `The pickpocket can’t photocopy a card that stays sealed in its sleeve.`),
      send('attacker', 'api', 'attack', 'XSS: fetch("/api/account", { method: "DELETE" })', 'But XSS can still act as the user',
        `<p>HttpOnly isn’t an XSS fix. Injected script runs on your page, so it can send requests that carry the cookie and do anything the user can, while the tab is open.</p>`,
        `The pickpocket can’t copy the card, but can walk you up to the counter.`),
      proc('browser', 'ok', 'Content-Security-Policy · escaping · sanitising', 'The real defence: prevent XSS',
        `<p>A strict Content Security Policy blocks injected scripts from running. React escapes text by default. Sanitise any HTML you must render, and review third-party scripts.</p>`,
        `Keep pickpockets out of the building in the first place.`),
      block('attacker', 'api', 'sniff http:// traffic on café Wi-Fi', 'Secure: cookie only sent over HTTPS', 'Secure keeps the cookie off plain HTTP',
        `<p>Always set <code>Secure</code>. Chrome treats <code>http://localhost</code> as secure during development; Safari strictly requires HTTPS.</p>`,
        `The card is only ever shown inside clubs with locked doors.`),
      proc('browser', 'data', 'no personal data client-side', 'Neither option is encrypted',
        `<p>Cookies and Web Storage are plain text on the user’s device. Keep only the random session token there, and look everything else up on the server.</p>`,
        `The card carries a membership number, not your home address.`),
    ],
    concept: `
<h3>Cookies vs. Web Storage</h3>
<div class="table-wrap"><table>
  <thead><tr><th></th><th>Cookie (HttpOnly)</th><th>localStorage / sessionStorage</th></tr></thead>
  <tbody>
    <tr><td>Sent automatically</td><td>Yes, so CSRF needs handling</td><td>No; your code adds a header</td></tr>
    <tr><td>Readable by scripts</td><td><span class="good">No</span></td><td><span class="bad">Yes</span>, including injected ones</td></tr>
    <tr><td>Works with server rendering</td><td>Yes</td><td>No (the server never sees it on page loads)</td></tr>
    <tr><td>Cleared by the browser</td><td>On expiry</td><td>More aggressively</td></tr>
    <tr><td>Encrypted</td><td>No</td><td>No</td></tr>
  </tbody>
</table></div>
<p>The book’s verdict: the two are broadly similar, with cookies slightly ahead thanks to HttpOnly. Whichever you choose, defending against XSS is what really matters.</p>
<h3>Cookie flags</h3>
<dl>
  <dt><code>HttpOnly</code></dt><dd>Invisible to JavaScript. Stops token theft by XSS and by malicious packages that read cookies.</dd>
  <dt><code>Secure</code></dt><dd>Only sent over HTTPS. Always include it.</dd>
  <dt><code>SameSite=Lax</code></dt><dd>Not sent on cross-site requests except top-level GET navigations. The book’s default (chapter 10).</dd>
  <dt><code>Path=/</code></dt><dd>Sent to the whole app.</dd>
  <dt><code>Expires</code></dt><dd>Match the session’s server-side expiry.</dd>
</dl>`,
    threats: [
      { name: 'Token theft by XSS', risk: 'Injected scripts or compromised packages read the token and use it elsewhere.', fix: 'HttpOnly cookies; never put tokens where scripts can read them.' },
      { name: 'XSS acting as the user', risk: 'Even without the token, injected script sends requests from the page.', fix: 'Content Security Policy, React escaping, HTML sanitising, careful third-party scripts.' },
      { name: 'Network sniffing', risk: 'A cookie sent over plain HTTP is visible on shared networks.', fix: '<code>Secure</code> on every cookie, plus HTTPS and HSTS.' },
      { name: 'Sensitive data on the device', risk: 'Anything stored client-side can be read by anyone with the device.', fix: 'Store only the random token.' },
    ],
    code: [
      {
        file: 'server/src/lib/cookies.js',
        code: code`
// One set of flags for every auth cookie
const BASE = {
  httpOnly: true,     // invisible to JavaScript
  secure: true,       // HTTPS only. Chrome allows http://localhost; Safari needs HTTPS even locally.
  sameSite: 'lax',    // the book's default (see chapter 10)
  path: '/',
};

export const setCookie = (res, name, value, expiresAt) => res.cookie(name, value, { ...BASE, expires: expiresAt });
export const clearCookie = (res, name) => res.clearCookie(name, BASE);   // same flags, or it won't clear

export const setSessionCookie = (res, token, expiresAt) => setCookie(res, 'session', token, expiresAt);
export const clearSessionCookie = (res) => clearCookie(res, 'session');`,
      },
      {
        file: 'server/src/middleware/securityHeaders.js',
        note: 'If Express also serves the built React app, a strict CSP is your main XSS safety net.',
        code: code`
import helmet from 'helmet';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],                     // no inline scripts, no third-party scripts
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],                // no framing (clickjacking)
      formAction: ["'self'"],
    },
  },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
});`,
      },
      {
        file: 'client/src/api.js',
        note: 'With an HttpOnly cookie, the React app never touches the token at all.',
        code: code`
// The browser attaches the session cookie by itself. No token in JS, no localStorage.
export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(\`/api\${path}\`, {
    method,
    credentials: 'same-origin',                                   // send cookies to our own origin
    headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),   // always JSON (chapter 10)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error ?? 'Request failed'), { status: res.status });
  return data;
}

// const { user } = await api('/me');
// await api('/account/logout', { method: 'POST' });`,
      },
    ],
    checklist: [
      'Session tokens live in HttpOnly cookies, not localStorage',
      'Every auth cookie has <code>Secure</code> and <code>SameSite=Lax</code>',
      'Cookies are cleared with the same flags they were set with',
      'The app ships a strict Content Security Policy',
      'Nothing but the random token is stored on the client',
    ],
  });

  // ================================================================ 10 · CSRF
  AIM.chapters.push({
    id: 'csrf',
    num: '10',
    group: 'The browser',
    short: 'Cross-site request forgery',
    title: 'Cross-site request forgery (CSRF)',
    flowName: 'Another site sends a request as your user',
    lede: 'CSRF is another website making your user’s browser send a request to your app, cookies included. The defence is simple: know where each state-changing request really came from.',
    sources: [book('csrf', 'Cross-site request forgery')],
    glance: [
      ['No GET', 'for anything that changes data'],
      ['SameSite=Lax', 'default cookie mode'],
      ['Sec-Fetch-Site', 'must be same-origin'],
      ['Content-Type', 'parsed properly, never string-matched'],
    ],
    analogy: {
      title: 'The forged letter',
      intro: 'Your office stamps every outgoing letter from your desk with the company seal, automatically. A stranger slips their own letter into your outbox. The receiving office has to check which building the letter really came from.',
      map: [
        ['Your cookies', 'The company seal stamped on everything from your desk'],
        ['evil.example', 'A stranger who slips letters into your outbox'],
        ['Simple request', 'A postcard the post office never inspects'],
        ['SameSite=Lax', 'The mailroom won’t stamp letters handed in by strangers'],
        ['Sec-Fetch-Site', 'The postmark saying which building sent it'],
        ['Origin allowlist', 'The list of buildings the office accepts mail from'],
      ],
    },
    actors: ['browser', 'api', 'db', 'site'],
    steps: [
      send('browser', 'site', 'data', 'user opens evil.example', 'The user visits another website',
        `<p>They’re still signed in to your app in another tab, so the browser holds your session cookie.</p>`,
        `You pop into a café; your office’s outbox sits unattended.`),
      send('site', 'browser', 'attack', 'hidden <form action="https://app.example.com/api/transfer">', 'The page plants a hidden form',
        `<p>The form posts to your app and submits itself with JavaScript. The user sees nothing.</p>`,
        `A stranger slips a letter into your outbox.`,
        `<form action="https://app.example.com/api/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="500">
</form>
<script>document.forms[0].submit()</script>`),
      send('browser', 'api', 'attack', 'POST /api/transfer · Cookie: session=…', 'Without defences, the browser sends it with cookies',
        `<p>Form posts are “simple requests”: there’s no CORS preflight. The same-origin policy stops evil.example from <i>reading</i> the response, but the transfer has already happened.</p>`,
        `Without a check, the letter goes out with your company seal on it.`),
      block('browser', 'api', 'POST from evil.example (cross-site)', 'SameSite=Lax: cookie not attached', 'Layer 1: SameSite=Lax',
        `<p>With <code>SameSite=Lax</code> the browser doesn’t attach the cookie to cross-site POSTs. <code>Strict</code> would also drop it when users follow a link to your site from elsewhere, so they’d appear signed out. Lax is the better default.</p>`,
        `The mailroom won’t seal letters a stranger dropped in.`),
      block('browser', 'api', 'GET /api/delete-account (link on evil.example)', 'GET never changes state', 'Lax still sends cookies on GET navigations',
        `<p>Clicking a link is a top-level GET navigation, so Lax attaches the cookie. That’s fine only if GET requests never change anything. Use POST, PATCH or DELETE for actions.</p>`,
        `Postcards are only ever used to ask questions, never to give orders.`),
      block('browser', 'api', 'POST · Sec-Fetch-Site: cross-site', '403 · not same-origin', 'Layer 2: check where it came from',
        `<p>Browsers add <code>Sec-Fetch-Site</code> to every request, and pages can’t forge it. Reject non-GET requests unless it says <code>same-origin</code>. It has been supported everywhere since 2023. For older browsers, fall back to an exact <code>Origin</code> allowlist.</p>`,
        `The office checks the postmark: wrong building, letter rejected.`),
      block('browser', 'api', 'Content-Type: text/plain; application/json', '415 · that’s text/plain', 'Layer 3: parse Content-Type properly',
        `<p>A JSON-only API might think it’s safe from forms. But <code>text/plain</code> is a simple type that forms can send, and naive string matching on “application/json” is fooled by this header. Parse the MIME type properly (Express’s <code>req.is()</code> does).</p>`,
        `The office reads the envelope type properly, not just whether the word “official” appears somewhere on it.`),
      send('browser', 'api', 'token', 'POST /api/transfer · Sec-Fetch-Site: same-origin', 'Your own app’s request',
        `<p>A <code>fetch</code> from your React app is same-origin, sends JSON, and carries the cookie.</p>`,
        `A real letter from your own desk, correctly postmarked.`),
      send('api', 'db', 'data', 'transfer saved', 'It passes every check',
        `<p>Method ✓, origin ✓, content type ✓, session ✓.</p>`,
        `The office accepts it.`),
      send('api', 'browser', 'ok', '200 OK', 'Done',
        `<p>Legitimate users notice nothing.</p>`,
        `Your reply arrives.`),
      proc('api', 'data', 'same-site ≠ same-origin', 'SameSite’s blind spot: your other subdomains',
        `<p><code>blog.example.com</code> and <code>app.example.com</code> are the <b>same site</b>, so SameSite allows requests between them. An XSS bug or takeover of any subdomain could then forge requests. Checking <code>Sec-Fetch-Site: same-origin</code> closes that gap. (Sites are defined by the Public Suffix List, so <code>foo.github.io</code> and <code>bar.github.io</code> are different sites.)</p>`,
        `A letter from the warehouse next door has your company’s address too. Check the exact building, not just the company.`),
    ],
    concept: `
<h3>Origin vs. site</h3>
<div class="table-wrap"><table>
  <thead><tr><th>From → to <code>https://app.example.com</code></th><th>Same origin?</th><th>Same site?</th></tr></thead>
  <tbody>
    <tr><td><code>https://app.example.com</code></td><td><span class="good">Yes</span></td><td><span class="good">Yes</span></td></tr>
    <tr><td><code>https://blog.example.com</code></td><td>No</td><td><span class="good">Yes</span></td></tr>
    <tr><td><code>https://evil.example</code></td><td>No</td><td>No</td></tr>
  </tbody>
</table></div>
<h3>The checklist, in order of importance</h3>
<ol>
  <li><b>Never change state on GET.</b></li>
  <li><b>SameSite=Lax</b> on session cookies.</li>
  <li><b>Check <code>Sec-Fetch-Site</code></b> on every non-GET request and accept only <code>same-origin</code>. Fall back to an exact <code>Origin</code> allowlist if you need older browsers or trusted subdomains.</li>
  <li><b>Parse <code>Content-Type</code></b> properly and reject anything that isn’t what you expect.</li>
  <li><b>Anti-CSRF tokens</b> if you must support very old browsers (see OWASP’s CSRF cheat sheet).</li>
</ol>
<h3>Simple requests</h3>
<p>A “simple” request skips the CORS preflight: GET, HEAD, or POST whose <code>Content-Type</code> is missing, <code>application/x-www-form-urlencoded</code>, <code>multipart/form-data</code> or <code>text/plain</code>. Any site can make the browser send these.</p>
<p class="callout"><b>Not CSRF:</b> someone sending requests with curl. They don’t have the victim’s cookies; that’s ordinary authentication.</p>`,
    threats: [
      { name: 'Forged form posts', risk: 'A hidden form on another site performs actions with the user’s cookies.', fix: 'SameSite=Lax plus a <code>Sec-Fetch-Site</code> check.' },
      { name: 'State-changing GET', risk: 'Links and image tags trigger actions, even with Lax cookies.', fix: 'Only non-GET methods change data.' },
      { name: 'Content-Type tricks', risk: '<code>text/plain; application/json</code> passes naive string checks.', fix: 'Parse the MIME type with <code>req.is()</code>; reject missing or unexpected types.' },
      { name: 'Subdomain attacks', risk: 'Same-site subdomains bypass SameSite.', fix: 'Require <code>Sec-Fetch-Site: same-origin</code>, or an exact Origin allowlist.' },
      { name: 'Legacy browsers', risk: 'Browsers without SameSite or Sec-Fetch-Site support.', fix: 'Reject requests missing the headers, or add anti-CSRF tokens.' },
    ],
    code: [
      {
        file: 'server/src/middleware/csrf.js',
        code: code`
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const TRUSTED_ORIGINS = new Set([process.env.APP_ORIGIN]);   // e.g. https://app.example.com

// 1. Where did this request come from?
export function csrfProtection(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite) {
    // Set by the browser, can't be forged by a page
    if (fetchSite === 'same-origin') return next();
    return res.status(403).json({ error: 'Cross-site request blocked' });
  }

  // Older browsers don't send Sec-Fetch-Site: fall back to an exact Origin allowlist
  const origin = req.get('origin');
  if (origin && TRUSTED_ORIGINS.has(origin)) return next();
  return res.status(403).json({ error: 'Cross-site request blocked' });
}

// 2. Is it really JSON?
export function requireJson(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  // req.is() parses the MIME type: "text/plain; application/json" is text/plain, so it fails here
  if (!req.is('application/json')) {
    return res.status(415).json({ error: 'Send JSON with Content-Type: application/json' });
  }
  next();
}`,
      },
      {
        file: 'server/src/app.js',
        code: code`
import express from 'express';
import cookieParser from 'cookie-parser';
import { securityHeaders } from './middleware/securityHeaders.js';
import { csrfProtection, requireJson } from './middleware/csrf.js';
import { loadSession } from './middleware/session.js';
import { authRouter } from './routes/auth.routes.js';
import { accountRouter } from './routes/account.routes.js';

export const app = express();
app.set('trust proxy', 1);

app.use(securityHeaders);
app.use(csrfProtection);          // before any route can change state
app.use(requireJson);
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(loadSession);             // req.session (chapter 03)

app.use('/api/auth', authRouter);
app.use('/api/account', accountRouter);

// Never do this: a state change on GET
// app.get('/api/account/delete', deleteAccount);`,
      },
    ],
    checklist: [
      'No GET route changes state',
      'Session cookies use <code>SameSite=Lax</code>',
      'Non-GET requests require <code>Sec-Fetch-Site: same-origin</code> (or an allowlisted Origin)',
      'Content-Type is parsed with <code>req.is()</code>, never string-matched',
      'My React app always sends JSON with the right Content-Type',
    ],
  });
})();
