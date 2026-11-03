/* Chapters 08–10: recovery, second factor, social login */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block } = AIM;

  // ================================================================ 08 · Password recovery
  AIM.chapters.push({
    id: 'recovery',
    num: '08',
    group: 'Recovery & extra factors',
    short: 'Password recovery',
    title: 'Password recovery',
    flowName: 'Forgot password → emailed link → new password',
    lede: 'A password reset link is a temporary password delivered by email. If it is guessable, reusable, long-lived or leaks into logs, it becomes the easiest way into any account.',
    actors: ['browser', 'api', 'db', 'redis', 'mail', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /api/auth/forgot-password', 'The user asks for a reset',
        `<p>Just an email address. The form doesn't hint whether the address is registered.</p>`,
        `POST /api/auth/forgot-password
{ "email": "ana@example.com" }`),
      send('api', 'redis', 'data', 'rate limit · queue.add("forgot-password", { email })', 'Throttle, then hand everything to a worker',
        `<p>Limits: 5 per IP per 15 min and 3 per email per hour, which stops attackers from bombing someone's inbox.</p><p>The request handler doesn't even look the user up. It queues a job with the email, so the response time is identical whether or not the account exists.</p>`),
      send('api', 'browser', 'ok', '200 · "If an account exists, we sent a link"', 'Always the same answer',
        `<p>Same status, same body, same speed. The page also tells people to check spam and that the link expires in 30 minutes.</p>`,
        `HTTP/1.1 200 OK
{ "message": "If an account exists for that email, we sent a link to reset the password." }`),
      send('redis', 'db', 'data', 'worker: findOne({ email })', 'The worker looks up the account',
        `<p>No account, or a disabled one? The job ends quietly. Nobody is told anything.</p>`),
      proc('redis', 'cred', 'raw = randomBytes(32) · 30 min · single use', 'Mint a reset token',
        `<p>Same recipe as email verification, with a much shorter life: 30 minutes. Older reset tokens for this user are deleted, so only the newest link works.</p>`),
      send('redis', 'db', 'data', 'tokens.insertOne({ sha256(raw), purpose: "reset_password" })', 'Store only the hash',
        `<p>A database leak exposes hashes of reset tokens, which can't be turned back into working links.</p>`),
      send('redis', 'mail', 'mail', 'sendMail(resetPassword({ link }))', 'Send the link',
        `<p>The link is built from <code>APP_URL</code> in config. Never from the incoming request's <code>Host</code> header.</p>`),
      send('mail', 'browser', 'mail', 'app.example.com/reset-password?token=…', 'The user opens the link',
        `<p>The React page reads the token, immediately removes it from the address bar with <code>history.replaceState</code>, and sets <code>Referrer-Policy: no-referrer</code> so it can't leak to analytics or third-party scripts.</p>`),
      send('browser', 'api', 'cred', 'POST /api/auth/reset-password { token, password }', 'Submit the new password',
        `<p>The page uses <code>autocomplete="new-password"</code> so the password manager offers to generate one and updates its saved entry.</p>`),
      proc('api', 'cred', 'zod · HIBP · then findOneAndDelete(hash)', 'Validate first, then consume the token',
        `<p>Check the new password before spending the token, so a "password too weak" error doesn't burn the link. Then find-and-delete the token atomically, filtered to unexpired ones.</p>`),
      send('api', 'db', 'data', 'new hash · tokenVersion++ · revoke all sessions', 'Reset means: everyone out',
        `<p>If an attacker was in the account, they're out now. Every refresh family is revoked, every access token fails the <code>tokenVersion</code> check, and other pending reset tokens are deleted.</p><p>The email is also marked verified, because the user just proved they can read that inbox.</p>`),
      send('api', 'mail', 'mail', '"Your password was changed"', 'Notify the owner',
        `<p>If the owner didn't do this, the notice tells them their email account itself may be compromised.</p>`),
      send('api', 'browser', 'ok', '200 · sign in with your new password', 'No automatic login',
        `<p>The user signs in normally, which means <b>2FA still applies</b>. A reset flow that logs people straight in would let anyone who controls the inbox skip the second factor.</p>`),
      block('attacker', 'api', 'POST /forgot-password · Host: evil.example', 'link built from APP_URL', 'Host header poisoning',
        `<p>The attacker requests a reset for the victim with a forged <code>Host</code> header, hoping the email links to their domain so the victim's click delivers the token to them. Building links from configuration makes the header irrelevant.</p>`),
      block('attacker', 'api', 'POST /reset-password × 1,000,000 guesses', '2²⁵⁶ possibilities + 429', 'Guessing a token',
        `<p>A 256-bit token has more possible values than there are atoms in the observable universe, and the endpoint is rate-limited anyway. The 30-minute expiry closes the window further.</p>`),
    ],
    concept: `
<h3>The rules for a safe reset</h3>
<ol>
  <li>Same response for known and unknown emails, with the lookup off the request path.</li>
  <li>A random 256-bit token, stored as a SHA-256 hash, valid 30 minutes, single use.</li>
  <li>Only the newest token works; issuing one deletes the others.</li>
  <li>Validate the new password before consuming the token.</li>
  <li>After the reset, revoke every session and bump <code>tokenVersion</code>.</li>
  <li>Send a "password changed" notice.</li>
  <li>Don't log the user in; 2FA still applies at the next login.</li>
</ol>
<h3>Keeping the token out of places it shouldn't be</h3>
<ul>
  <li><b>Server logs:</b> the link opens the React app, and the token goes to the API in a POST body. The API logger also strips query strings.</li>
  <li><b>Browser history:</b> <code>history.replaceState</code> removes it as soon as the page loads.</li>
  <li><b>Referer header:</b> set <code>&lt;meta name="referrer" content="no-referrer"&gt;</code> on the reset page, and don't load third-party scripts there.</li>
  <li><b>Optional:</b> put the token in the URL fragment (<code>#token=…</code>). Browsers never send fragments to any server.</li>
</ul>
<h3>What about users who also lost their 2FA device?</h3>
<p>Password reset recovers the <i>password</i>. A lost authenticator is recovered with <b>backup codes</b> (chapter 09). If someone has lost both, fall back to a deliberate support process: identity checks, a waiting period (for example 72 hours with notices to every address on file), and an audit trail. Never let a single email link remove 2FA.</p>
<h3>Things not to build</h3>
<ul>
  <li><b>Security questions.</b> Mother's maiden name is public on social media.</li>
  <li><b>Emailing a new password.</b> It sits in the inbox forever.</li>
  <li><b>Showing the email on the reset form</b> ("Resetting password for ana@…") before the token is validated.</li>
  <li><b>SMS-only recovery.</b> SIM-swap attacks move a number to an attacker's phone.</li>
</ul>`,
    threats: [
      { name: 'Enumeration through the reset form', risk: '"No account with that email" confirms who is a customer.', fix: 'Identical message and timing; all lookups happen in the background worker.' },
      { name: 'Host header injection', risk: 'Links built from <code>req.headers.host</code> can point at an attacker\'s domain.', fix: 'Build every emailed link from <code>env.APP_URL</code>.' },
      { name: 'Token leakage', risk: 'Tokens in API URLs land in access logs, proxies, browser history and Referer headers.', fix: 'Frontend link, POST body, <code>replaceState</code>, <code>no-referrer</code>, query strings stripped from logs.' },
      { name: 'Long-lived or reusable links', risk: 'A week-old link in an inbox, or one that works twice, is a standing backdoor.', fix: '30-minute expiry, <code>findOneAndDelete</code>, delete older tokens on issue and after use.' },
      { name: 'Sessions survive the reset', risk: 'The attacker who triggered the incident stays logged in after the owner resets.', fix: 'Revoke all refresh families, bump <code>tokenVersion</code>, clear the auth cache.' },
      { name: 'Reset bypasses 2FA', risk: 'Auto-login after reset lets anyone with inbox access skip the authenticator.', fix: 'Require a normal login after reset; 2FA can only be removed with a backup code or a support process.' },
      { name: 'Inbox bombing', risk: 'Scripts trigger thousands of reset emails at one victim and damage your sender reputation.', fix: 'Per-email and per-IP limits in Redis; CAPTCHA on the form for public apps.' },
    ],
    code: [
      {
        file: 'server/src/controllers/recovery.controller.js',
        code: code`
import { z } from 'zod';
import { env } from '../config/env.js';
import { User } from '../models/User.js';
import { Token } from '../models/Token.js';
import { mailQueue } from '../jobs/mail.queue.js';
import { sendMail } from '../services/mail.js';
import * as templates from '../services/mail.templates.js';
import { hashPassword, isBreached } from '../services/password.js';
import { revokeAllSessions } from '../services/token.service.js';
import { invalidateAuthUser } from '../services/authUser.js';
import { randomToken, sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';
import { email as emailField, resetSchema } from '../validation/auth.schemas.js';

const RESET_TTL = 30 * 60 * 1000;
const invalidLink = () =>
  new HttpError(400, 'This reset link is invalid or has expired. Request a new one.', 'RESET_TOKEN_INVALID');

export async function forgotPassword(req, res) {
  const { email } = z.object({ email: emailField }).parse(req.body);
  // Nothing here depends on whether the account exists: same work, same timing
  await mailQueue.add('forgot-password', { email });
  audit(req, 'password.reset_requested', { email });
  res.json({ message: 'If an account exists for that email, we sent a link to reset the password.' });
}

// Runs inside the mail worker, off the request path
export async function handleForgotPassword(email) {
  const user = await User.findOne({ email });
  if (!user || user.disabled) return;

  const raw = randomToken();
  await Token.deleteMany({ userId: user._id, purpose: 'reset_password' });
  await Token.create({
    userId: user._id,
    purpose: 'reset_password',
    tokenHash: sha256(raw),
    expiresAt: new Date(Date.now() + RESET_TTL),
  });
  // Send directly so the raw token never sits in a queue
  await sendMail(user.email, templates.resetPassword({ link: \`\${env.APP_URL}/reset-password?token=\${raw}\` }));
}

export async function resetPassword(req, res) {
  const { token, password } = resetSchema.parse(req.body);

  // Validate before consuming, so a weak password doesn't burn the link
  if (await isBreached(password)) {
    throw new HttpError(400, 'This password appeared in a data breach. Choose a different one.', 'PASSWORD_BREACHED');
  }

  const record = await Token.findOneAndDelete({
    tokenHash: sha256(token),
    purpose: 'reset_password',
    expiresAt: { $gt: new Date() },
  });
  if (!record) throw invalidLink();

  const user = await User.findById(record.userId);
  if (!user || user.disabled) throw invalidLink();

  user.passwordHash = await hashPassword(password);
  user.passwordChangedAt = new Date();
  user.emailVerified = true;      // they just proved they read this inbox
  user.tokenVersion += 1;         // every access token is now invalid
  await user.save();

  await Promise.all([
    revokeAllSessions(user._id, 'password_reset'),
    Token.deleteMany({ userId: user._id, purpose: 'reset_password' }),
    invalidateAuthUser(user.id),
  ]);

  await mailQueue.add('password-changed', { to: user.email, when: new Date().toUTCString() });
  audit(req, 'password.reset', { userId: user.id });

  // No auto-login: the next sign-in still goes through 2FA
  res.json({ message: 'Your password was reset. Sign in with your new password.' });
}`,
      },
      {
        file: 'client/src/pages/ForgotPassword.jsx',
        lang: 'jsx',
        code: code`
import { useState } from 'react';
import { api } from '../api/client';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [state, setState] = useState({ status: 'idle', message: '' });

  async function onSubmit(e) {
    e.preventDefault();
    setState({ status: 'working', message: '' });
    try {
      const { data } = await api.post('/auth/forgot-password', { email });
      setState({ status: 'sent', message: data.message });
    } catch (err) {
      const message = err.response?.status === 429
        ? 'Too many requests. Wait a few minutes and try again.'
        : 'Could not reach the server. Try again.';
      setState({ status: 'error', message });
    }
  }

  if (state.status === 'sent') {
    return <p>{state.message} The link expires in 30 minutes. Check your spam folder if it doesn't arrive.</p>;
  }

  return (
    <form onSubmit={onSubmit}>
      <label htmlFor="email">Email</label>
      <input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      <button disabled={state.status === 'working'}>Send reset link</button>
      {state.status === 'error' && <p role="alert">{state.message}</p>}
    </form>
  );
}`,
      },
      {
        file: 'client/src/pages/ResetPassword.jsx',
        lang: 'jsx',
        code: code`
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const [token] = useState(() => params.get('token'));
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [state, setState] = useState({ status: 'idle', message: '' });

  useEffect(() => {
    if (token) window.history.replaceState(null, '', '/reset-password');   // out of the address bar
    const meta = document.createElement('meta');                           // and out of Referer headers
    meta.name = 'referrer';
    meta.content = 'no-referrer';
    document.head.appendChild(meta);
    return () => meta.remove();
  }, [token]);

  async function onSubmit(e) {
    e.preventDefault();
    if (password !== confirm) return setState({ status: 'error', message: 'The two passwords don\'t match.' });
    setState({ status: 'working', message: '' });
    try {
      const { data } = await api.post('/auth/reset-password', { token, password });
      setState({ status: 'done', message: data.message });
    } catch (err) {
      setState({ status: 'error', message: err.response?.data?.error ?? 'Could not reach the server. Try again.' });
    }
  }

  if (!token) return <p>This link is missing its token. <Link to="/forgot-password">Request a new link</Link>.</p>;
  if (state.status === 'done') return <p>{state.message} <Link to="/login">Sign in</Link></p>;

  return (
    <form onSubmit={onSubmit}>
      {/* Hidden username field helps password managers update the right entry */}
      <input type="text" name="username" autoComplete="username" hidden readOnly />
      <label htmlFor="new-password">New password (at least 12 characters)</label>
      <input id="new-password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required
        value={password} onChange={(e) => setPassword(e.target.value)} />
      <label htmlFor="confirm-password">Repeat it</label>
      <input id="confirm-password" type="password" autoComplete="new-password" required
        value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      <button disabled={state.status === 'working'}>Set new password</button>
      {state.status === 'error' && <p role="alert">{state.message}</p>}
    </form>
  );
}`,
      },
    ],
    checklist: [
      'Forgot-password returns the same response and timing for every email',
      'Reset tokens are 256-bit, hashed, single-use and expire in 30 minutes',
      'Issuing a new reset token deletes the older ones',
      'Links are built from <code>APP_URL</code>, never from the Host header',
      'The reset page strips the token from the URL and sends no Referer',
      'A successful reset revokes all sessions and bumps <code>tokenVersion</code>',
      'Users get a "password changed" email',
      'Reset never logs the user in or removes 2FA',
    ],
  });

  // ================================================================ 09 · Two-factor (TOTP)
  AIM.chapters.push({
    id: 'two-factor',
    num: '09',
    group: 'Recovery & extra factors',
    short: 'Two-factor auth (TOTP)',
    title: 'Two-factor authentication',
    flowName: 'Enrol an authenticator, then log in with it',
    lede: 'A second factor means a stolen or reused password is no longer enough. Authenticator-app codes (TOTP) are free, work offline, and can be built with one library and about 150 lines of code.',
    actors: ['browser', 'api', 'db', 'redis', 'phone', 'attacker'],
    steps: [
      send('browser', 'api', 'token', 'POST /api/mfa/setup · Bearer', 'Enrolment starts from a signed-in session',
        `<p>The user opens Security settings and chooses "Turn on two-factor authentication".</p>`),
      proc('api', 'cred', 'secret = 20 random bytes (base32)', 'Generate a shared secret',
        `<p>The server creates a 160-bit secret. From now on, the server and the phone will both hold it, and each will compute the same 6-digit code from it every 30 seconds.</p>`,
        `secret (base32):  JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
otpauth URI:      otpauth://totp/YourApp:ana%40example.com?secret=JBSW…&issuer=YourApp&algorithm=SHA1&digits=6&period=30`),
      send('api', 'db', 'data', 'mfa.pendingSecretEnc = AES-256-GCM(secret)', 'Store it encrypted, and only as pending',
        `<p>Unlike a password, the TOTP secret must be <b>recoverable</b> (the server needs it to compute codes), so it is encrypted, not hashed. The key lives in an environment variable or KMS, not in the database.</p><p>It stays "pending" until the user proves their app works, so a half-finished setup can't lock anyone out.</p>`),
      send('api', 'browser', 'cred', '{ qrDataUrl, manualKey }', 'Show a QR code',
        `<p>The QR code encodes the <code>otpauth://</code> URI. The manual key is for people who can't scan. This is the only time the secret is shown.</p>`),
      send('browser', 'phone', 'cred', 'camera scans QR', 'The secret moves once, by camera',
        `<p>Google Authenticator, 1Password, Authy, Microsoft Authenticator, Bitwarden: any RFC 6238 app works.</p>`),
      proc('phone', 'token', 'HMAC-SHA1(secret, ⌊now / 30⌋) → 482 913', 'The phone computes codes offline',
        `<p>Code = HMAC of the current 30-second time step, truncated to 6 digits. No network needed: the shared secret and a correct clock are enough.</p>`),
      send('browser', 'api', 'token', 'POST /api/mfa/enable { code: "482913" }', 'Prove the app works',
        `<p>The user types the current code. If the server computes the same one from the pending secret, the phone is set up correctly.</p>`),
      proc('api', 'token', 'verify ±1 step · enable · 10 backup codes', 'Turn it on and issue backup codes',
        `<p>The pending secret becomes the active one. Ten single-use backup codes are generated, <b>hashed</b> for storage, and shown to the user exactly once. Every other session is signed out, and an email confirms the change.</p>`,
        `{ "backupCodes": ["7F3A9-C21D0", "B84E1-90A6F", "…8 more"] }`),
      send('browser', 'api', 'cred', 'POST /api/auth/login (password correct)', 'Later: a normal login',
        `<p>Email and password are checked exactly as in chapter 04.</p>`),
      send('api', 'browser', 'token', '{ mfaRequired: true, mfaToken }', 'Password OK, but no session yet',
        `<p>Instead of tokens, the API returns an <code>mfaToken</code>: a JWT signed with a <b>different secret</b>, audience <code>mfa</code>, valid 5 minutes. It proves "this person passed step one" and nothing else; <code>requireAuth</code> would reject it.</p>`,
        `{ "mfaRequired": true, "mfaToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NmYx…InB1cnBvc2UiOiJtZmEi…" }`),
      send('phone', 'browser', 'token', 'user reads 731 004', 'The user types the current code',
        `<p>The input uses <code>inputMode="numeric"</code> and <code>autoComplete="one-time-code"</code> for a good mobile keyboard.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/mfa/verify { mfaToken, code }', 'Submit the second factor',
        `<p>If the phone is lost, the same endpoint accepts <code>backupCode</code> instead of <code>code</code>.</p>`),
      send('api', 'redis', 'data', 'INCR rl:mfa-user:66f1… (max 5)', 'Limit guesses per user',
        `<p>Six digits is only a million combinations, and with ±1 step drift three codes are valid at any moment. Five tries per 15 minutes per user makes guessing hopeless.</p>`),
      proc('api', 'token', 'step > lastUsedStep → save step', 'Reject replays',
        `<p>Each code is valid for about 90 seconds. Storing the last used time step and accepting only newer ones means a code seen over someone's shoulder, or captured by a phishing page, can't be used a second time.</p>`),
      send('api', 'browser', 'ok', '200 { accessToken } + Set-Cookie: rt', 'Now the session starts',
        `<p>Exactly the same <code>issueSession</code> as a password-only login.</p>`),
      block('attacker', 'api', 'mfa/verify: 000000, 000001, 000002…', '429 after 5 tries', 'Brute-forcing the code',
        `<p>With a stolen password, the attacker reaches the code prompt and starts guessing. The per-user limit stops them long before they have a meaningful chance, and the burst of failures goes to the audit log.</p>`),
    ],
    concept: `
<h3>Factors, ranked</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Second factor</th><th>Phishing-resistant?</th><th>Cost</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>Passkeys / WebAuthn (Touch ID, Windows Hello, YubiKey)</td><td><span class="good">Yes</span></td><td>Free</td><td>The browser binds the credential to your domain. The best option; <code>@simplewebauthn/server</code> makes it practical.</td></tr>
    <tr><td>TOTP authenticator app (this chapter)</td><td>No, but strong</td><td>Free</td><td>A real-time phishing proxy can relay a code. Still stops password reuse and stuffing.</td></tr>
    <tr><td>Email code</td><td>No</td><td>Cheap</td><td>Only as strong as the inbox, which is also the reset channel.</td></tr>
    <tr><td>SMS code</td><td>No</td><td>Costs per message</td><td>SIM swaps and SS7 interception. Better than nothing, worst of the list.</td></tr>
  </tbody>
</table></div>
<h3>How TOTP works (RFC 6238)</h3>
<ol>
  <li>Server and app share a random secret.</li>
  <li>Both compute <code>T = floor(unixTime / 30)</code>.</li>
  <li>Both compute <code>HMAC-SHA1(secret, T)</code>, take 31 bits from an offset the hash itself chooses, and keep the last 6 decimal digits.</li>
  <li>The server accepts T−1, T and T+1 to tolerate clock drift.</li>
</ol>
<h3>Design decisions in this guide</h3>
<ul>
  <li><b>Pending then active.</b> The secret becomes active only after the user proves a working code.</li>
  <li><b>Encrypted at rest</b> with AES-256-GCM, key outside the database.</li>
  <li><b>Replay guard</b> with <code>lastUsedStep</code>, updated atomically.</li>
  <li><b>MFA ticket</b> signed with its own secret and audience, valid 5 minutes, limited to 5 attempts.</li>
  <li><b>Backup codes</b>: 10 × 50-bit random codes, argon2-hashed, single use, regenerable.</li>
  <li><b>Turning 2FA off</b> requires the password and a current code, revokes other sessions and emails the user.</li>
</ul>
<h3>Optional: "Trust this device for 30 days"</h3>
<p>After a successful code, set a separate signed, HttpOnly cookie with a random device id stored server-side. At the next login from that browser, skip the code. Revoke all trusted devices when the password changes or 2FA is reset.</p>
<p class="callout"><b>Next step up.</b> Once TOTP works, add passkeys as an option. They remove phishing entirely, and many users find Touch ID faster than typing codes.</p>`,
    threats: [
      { name: 'Brute-forcing 6 digits', risk: 'A million combinations with three valid at any time; an unthrottled endpoint falls in hours.', fix: '5 attempts per user per 15 minutes in Redis, plus a short-lived MFA ticket.' },
      { name: 'Code replay', risk: 'A code shoulder-surfed or captured by a phishing page stays valid for ~90 seconds.', fix: 'Store <code>lastUsedStep</code>; accept only newer steps with an atomic update.' },
      { name: 'Secret theft from the database', risk: 'Plaintext TOTP secrets in a leaked dump let attackers generate codes for everyone.', fix: 'AES-256-GCM with the key in KMS or an env var, never in MongoDB. <code>select: false</code> on the field.' },
      { name: 'MFA ticket used as a session', risk: 'If the "password OK" token were an ordinary access token, attackers could skip the code step.', fix: 'Different secret, <code>aud: \'mfa\'</code>, <code>purpose</code> claim, 5-minute expiry. <code>requireAuth</code> rejects it.' },
      { name: 'Real-time phishing', risk: 'A fake login page relays the password and the code to your real site within seconds.', fix: 'TOTP can\'t prevent this. Passkeys can, because the browser refuses to use them on the wrong domain.' },
      { name: 'Silent 2FA removal', risk: 'An attacker with a hijacked session turns 2FA off and changes the password.', fix: 'Password + current code to disable, revoke other sessions, email the owner.' },
    ],
    code: [
      {
        file: 'server/src/services/mfa.service.js',
        note: 'Uses otplib v12 (npm i otplib@12). Version 13 changed its API.',
        code: code`
import crypto from 'node:crypto';
import argon2 from 'argon2';
import { authenticator } from 'otplib';
import { env } from '../config/env.js';
import { User } from '../models/User.js';

authenticator.options = { step: 30, window: 1 };   // accept the previous and next code for clock drift
const KEY = Buffer.from(env.MFA_ENC_KEY, 'hex');   // 32 bytes, kept outside the database

// ---------- encryption at rest (AES-256-GCM: confidentiality + tamper detection)
export function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString('base64')).join('.');
}

export function decrypt(payload) {
  const [iv, tag, data] = payload.split('.').map((part) => Buffer.from(part, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

// ---------- TOTP
export function newTotpSecret(accountName) {
  const secret = authenticator.generateSecret(20);   // 20 bytes = 160 bits
  return { secret, otpauthUrl: authenticator.keyuri(accountName, 'YourApp', secret) };
}

/** The 30-second time step this code belongs to, or null if it doesn't match. */
export function matchStep(secret, code) {
  const delta = authenticator.checkDelta(code, secret);   // -1, 0, 1 or null
  if (delta === null) return null;
  return Math.floor(Date.now() / 30_000) + delta;
}

/** Verify and consume a code: each time step can be used once. */
export async function verifyTotpForUser(user, code) {
  const step = matchStep(decrypt(user.mfa.secretEnc), code);
  if (step === null) return false;
  const result = await User.updateOne(
    {
      _id: user._id,
      $or: [{ 'mfa.lastUsedStep': { $lt: step } }, { 'mfa.lastUsedStep': null }],
    },
    { $set: { 'mfa.lastUsedStep': step } },
  );
  return result.modifiedCount === 1;   // 0 means this step (or a later one) was already used
}

// ---------- backup codes: XXXXX-XXXXX, 50 bits each
export function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const hex = crypto.randomBytes(5).toString('hex').toUpperCase();
    return \`\${hex.slice(0, 5)}-\${hex.slice(5)}\`;
  });
}

const normalizeCode = (value) => value.replace(/[\s-]/g, '').toUpperCase();

export const hashBackupCodes = (codes) => Promise.all(codes.map((c) => argon2.hash(normalizeCode(c))));

export async function useBackupCode(user, input) {
  const candidate = normalizeCode(input);
  const hashes = user.mfa.backupCodes ?? [];
  for (const hash of hashes) {
    if (await argon2.verify(hash, candidate)) {
      // $pull is atomic: the same code can't be spent twice in parallel
      const result = await User.updateOne({ _id: user._id, 'mfa.backupCodes': hash }, { $pull: { 'mfa.backupCodes': hash } });
      return result.modifiedCount === 1;
    }
  }
  return false;
}`,
      },
      {
        file: 'server/src/controllers/mfa.controller.js',
        code: code`
import { z } from 'zod';
import QRCode from 'qrcode';
import { User } from '../models/User.js';
import { mailQueue } from '../jobs/mail.queue.js';
import {
  encrypt, decrypt, newTotpSecret, matchStep, verifyTotpForUser,
  generateBackupCodes, hashBackupCodes, useBackupCode,
} from '../services/mfa.service.js';
import { verifyPassword } from '../services/password.js';
import {
  issueSession, signAccessToken, verifyMfaToken, revokeAllSessions,
} from '../services/token.service.js';
import { invalidateAuthUser } from '../services/authUser.js';
import { hit } from '../middleware/rateLimit.js';
import { totpCode } from '../validation/auth.schemas.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';

// ---------- enrolment (signed in)
export async function setup(req, res) {
  const user = await User.findById(req.user.id);
  if (user.mfa?.enabled) throw new HttpError(409, 'Two-factor authentication is already on', 'MFA_ALREADY_ENABLED');

  const { secret, otpauthUrl } = newTotpSecret(user.email);
  user.mfa.pendingSecretEnc = encrypt(secret);
  await user.save();

  res.json({ qrDataUrl: await QRCode.toDataURL(otpauthUrl), manualKey: secret });
}

export async function enable(req, res) {
  const { code } = z.object({ code: totpCode }).parse(req.body);
  const user = await User.findById(req.user.id).select('+mfa.pendingSecretEnc');
  if (!user.mfa?.pendingSecretEnc) throw new HttpError(400, 'Start setup again', 'MFA_NOT_PENDING');

  const step = matchStep(decrypt(user.mfa.pendingSecretEnc), code);
  if (step === null) {
    throw new HttpError(400, 'That code didn\'t match. Check that your phone\'s clock is set automatically.', 'MFA_INVALID');
  }

  const backupCodes = generateBackupCodes();
  user.mfa = {
    enabled: true,
    secretEnc: user.mfa.pendingSecretEnc,
    lastUsedStep: step,
    backupCodes: await hashBackupCodes(backupCodes),
  };
  user.tokenVersion += 1;                       // sign out every other device
  await user.save();
  await revokeAllSessions(user._id, 'mfa_enabled');
  await invalidateAuthUser(user.id);
  await issueSession(req, res, user);           // this device continues

  await mailQueue.add('mfa-changed', { to: user.email, enabled: true });
  audit(req, 'mfa.enabled', { userId: user.id });
  res.json({ backupCodes, accessToken: signAccessToken(user) });   // shown once, never again
}

export async function disable(req, res) {
  const { password, code } = z.object({ password: z.string().max(128).optional(), code: totpCode }).parse(req.body);
  const user = await User.findById(req.user.id).select('+passwordHash +mfa.secretEnc');
  if (!user.mfa?.enabled) throw new HttpError(400, 'Two-factor authentication is not on', 'MFA_NOT_ENABLED');

  // Step-up: password (if the account has one) and a current code
  const passwordOk = user.passwordHash ? await verifyPassword(user.passwordHash, password ?? '') : true;
  if (!passwordOk || !(await verifyTotpForUser(user, code))) {
    throw new HttpError(400, 'Password or code is incorrect', 'REAUTH_FAILED');
  }

  user.mfa = { enabled: false };
  user.tokenVersion += 1;
  await user.save();
  await revokeAllSessions(user._id, 'mfa_disabled');
  await invalidateAuthUser(user.id);
  await issueSession(req, res, user);

  await mailQueue.add('mfa-changed', { to: user.email, enabled: false });
  audit(req, 'mfa.disabled', { userId: user.id });
  res.json({ accessToken: signAccessToken(user) });
}

export async function regenerateBackupCodes(req, res) {
  const { code } = z.object({ code: totpCode }).parse(req.body);
  const user = await User.findById(req.user.id).select('+mfa.secretEnc');
  if (!user.mfa?.enabled || !(await verifyTotpForUser(user, code))) {
    throw new HttpError(400, 'Code is incorrect', 'MFA_INVALID');
  }
  const backupCodes = generateBackupCodes();
  await User.updateOne({ _id: user._id }, { $set: { 'mfa.backupCodes': await hashBackupCodes(backupCodes) } });
  audit(req, 'mfa.backup_codes_regenerated', { userId: user.id });
  res.json({ backupCodes });
}

// ---------- second step of login (public route, uses the MFA ticket)
const verifySchema = z.object({
  mfaToken: z.string().min(1).max(2000),
  code: totpCode.optional(),
  backupCode: z.string().min(10).max(20).optional(),
}).refine((b) => b.code || b.backupCode, 'Enter a code');

export async function verifyMfaLogin(req, res) {
  const { mfaToken, code, backupCode } = verifySchema.parse(req.body);

  let claims;
  try {
    claims = verifyMfaToken(mfaToken);
  } catch {
    throw new HttpError(401, 'This sign-in attempt expired. Start again.', 'MFA_TOKEN_INVALID');
  }

  await hit(\`rl:mfa-user:\${claims.sub}\`, 5, 15 * 60);   // 5 guesses per user per 15 minutes

  const user = await User.findById(claims.sub).select('+mfa.secretEnc +mfa.backupCodes');
  if (!user || user.disabled || !user.mfa?.enabled) {
    throw new HttpError(401, 'This sign-in attempt expired. Start again.', 'MFA_TOKEN_INVALID');
  }

  const ok = code ? await verifyTotpForUser(user, code) : await useBackupCode(user, backupCode);
  if (!ok) {
    audit(req, 'mfa.failed', { userId: user.id });
    throw new HttpError(401, 'That code is incorrect', 'MFA_INVALID');
  }

  if (backupCode) audit(req, 'mfa.backup_code_used', { userId: user.id });
  await issueSession(req, res, user);
  audit(req, 'login.success', { userId: user.id, mfa: true });
  res.json({ accessToken: signAccessToken(user), user: user.toPublic() });
}`,
      },
      {
        file: 'server/src/routes/mfa.routes.js',
        code: code`
import { Router } from 'express';
import { rateLimit, byUser } from '../middleware/rateLimit.js';
import { setup, enable, disable, regenerateBackupCodes } from '../controllers/mfa.controller.js';

// Mounted in app.js as: app.use('/api/mfa', requireAuth, mfaRouter)
export const mfaRouter = Router();
mfaRouter.use(rateLimit({ name: 'mfa-manage', limit: 10, windowSec: 15 * 60, key: byUser }));

mfaRouter.post('/setup', setup);
mfaRouter.post('/enable', enable);
mfaRouter.post('/disable', disable);
mfaRouter.post('/backup-codes', regenerateBackupCodes);`,
      },
      {
        file: 'client/src/pages/TwoFactorSetup.jsx',
        lang: 'jsx',
        code: code`
import { useState } from 'react';
import { api, setAccessToken } from '../api/client';

export default function TwoFactorSetup() {
  const [setup, setSetup] = useState(null);           // { qrDataUrl, manualKey }
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState(null);
  const [error, setError] = useState('');

  async function start() {
    setError('');
    const { data } = await api.post('/mfa/setup');
    setSetup(data);
  }

  async function confirm(e) {
    e.preventDefault();
    setError('');
    try {
      const { data } = await api.post('/mfa/enable', { code });
      setAccessToken(data.accessToken);                // other sessions were signed out; this one continues
      setBackupCodes(data.backupCodes);
    } catch (err) {
      setError(err.response?.data?.error ?? 'Could not reach the server. Try again.');
    }
  }

  if (backupCodes) {
    return (
      <section>
        <h2>Save your backup codes</h2>
        <p>Each code works once if you lose your phone. We won't show them again.</p>
        <pre>{backupCodes.join('\n')}</pre>
        <button onClick={() => navigator.clipboard?.writeText(backupCodes.join('\n'))}>Copy codes</button>
      </section>
    );
  }

  if (!setup) return <button onClick={start}>Turn on two-factor authentication</button>;

  return (
    <form onSubmit={confirm}>
      <p>Scan this with your authenticator app:</p>
      <img src={setup.qrDataUrl} alt="QR code for your authenticator app" width={200} height={200} />
      <p>Can't scan? Enter this key: <code>{setup.manualKey}</code></p>
      <label htmlFor="totp">6-digit code from the app</label>
      <input id="totp" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required
        value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
      <button>Turn on</button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}`,
      },
    ],
    checklist: [
      'TOTP secrets are encrypted with AES-256-GCM, key outside the database',
      'A secret becomes active only after the user enters a working code',
      'Codes are accepted for ±1 time step, and each step only once',
      'The MFA ticket has its own secret and audience and expires in 5 minutes',
      'Code attempts are limited to 5 per user per 15 minutes',
      'Backup codes are hashed, single-use and shown once',
      'Turning 2FA off requires password + code, revokes sessions and sends an email',
      'Passkeys are on the roadmap as the phishing-resistant upgrade',
    ],
  });

  // ================================================================ 10 · Google sign-in
  AIM.chapters.push({
    id: 'oauth',
    num: '10',
    group: 'Recovery & extra factors',
    short: 'Sign in with Google',
    title: 'Sign in with Google (OAuth 2.0 + OpenID Connect)',
    flowName: 'Authorization code flow with PKCE',
    lede: '"Continue with Google" lets Google prove who the user is, so you never see their Google password. The protocol has a few moving parts, and each one exists to stop a specific attack.',
    actors: ['browser', 'api', 'google', 'db'],
    steps: [
      send('browser', 'api', 'data', 'GET /api/auth/google (full-page navigation)', 'The user clicks "Continue with Google"',
        `<p>It's a plain link, not an XHR call. The whole page navigates, because the user is about to visit Google's own site.</p>`),
      proc('api', 'cred', 'state · nonce · PKCE verifier', 'Generate three one-time secrets',
        `<ul><li><b>state</b> ties the callback to this browser, defeating login CSRF.</li><li><b>nonce</b> is embedded in Google's ID token, defeating token replay.</li><li><b>code_verifier</b> (PKCE) proves that whoever exchanges the code is whoever started the flow.</li></ul>`),
      send('api', 'browser', 'cred', '302 → accounts.google.com · Set-Cookie: g_oauth', 'Remember them in a signed cookie, redirect to Google',
        `<p>The three values go into a signed, HttpOnly cookie that lives 10 minutes and is sent only to <code>/api/auth/google</code>. It uses <code>SameSite=Lax</code> because the browser must send it when Google redirects back, which is a cross-site navigation.</p>`,
        `HTTP/1.1 302 Found
Set-Cookie: g_oauth=s%3A{"state":"x9…","nonce":"Lq…","codeVerifier":"dBjf…"}.sig; Path=/api/auth/google; Max-Age=600; HttpOnly; Secure; SameSite=Lax
Location: https://accounts.google.com/o/oauth2/v2/auth
  ?client_id=1234.apps.googleusercontent.com
  &redirect_uri=https://api.example.com/api/auth/google/callback
  &response_type=code
  &scope=openid email profile
  &state=x9…&nonce=Lq…
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`),
      send('browser', 'google', 'cred', 'user signs in to Google + consents', 'Google authenticates the user',
        `<p>On Google's domain, with Google's 2FA, passkeys and risk checks. Your app never sees the password.</p>`),
      send('google', 'browser', 'token', '302 → /callback?code=4/0Ad…&state=x9…', 'Google sends back a one-time code',
        `<p>The authorization code is short-lived (minutes) and single-use. It is worthless without your client secret and the PKCE verifier.</p>`),
      send('browser', 'api', 'token', 'GET /api/auth/google/callback?code&state · Cookie: g_oauth', 'The browser delivers the code to your API',
        `<p>The flow cookie rides along because this is a top-level navigation and the cookie is <code>SameSite=Lax</code>.</p>`),
      proc('api', 'token', 'query.state === cookie.state ?', 'Check state first',
        `<p>If an attacker tricked the victim's browser into opening a callback URL carrying the <i>attacker's</i> code, the victim would be logged into the attacker's account (and might then add a card or upload files there). The state check fails for any callback this browser didn't start.</p>`),
      send('api', 'google', 'cred', 'POST oauth2.googleapis.com/token { code, code_verifier, client_secret }', 'Exchange the code server-to-server',
        `<p>This is the back channel: your server talks to Google directly over TLS. The client secret never touches the browser.</p>`),
      send('google', 'api', 'token', '{ id_token, access_token }', 'Google returns an ID token',
        `<p>The <code>id_token</code> is a JWT signed by Google that states who the user is.</p>`,
        `// id_token payload
{
  "iss": "https://accounts.google.com",
  "aud": "1234.apps.googleusercontent.com",
  "sub": "110248495921238986420",
  "email": "ana@example.com",
  "email_verified": true,
  "name": "Ana Silva",
  "nonce": "Lq…",
  "exp": 1762127100
}`),
      proc('api', 'token', 'verify sig · iss · aud · exp · nonce · email_verified', 'Verify the ID token',
        `<p><code>verifyIdToken</code> checks Google's signature against its published keys, the issuer, your client id as audience, and expiry. Then you check the nonce matches the cookie and that Google says the email is verified.</p>`),
      send('api', 'db', 'data', 'find googleId → else link verified email → else create', 'Find, link or create the user',
        `<p>Identify by <code>sub</code> (Google's stable user id), never by email alone, since emails can change hands. If a local account has the same email, link only when it's safe (see the threats below).</p>`),
      send('api', 'browser', 'token', '302 → app.example.com/auth/callback · Set-Cookie: rt', 'Start your own session',
        `<p>From here on it's your session, not Google's. The same <code>issueSession</code> sets the refresh cookie, and the browser is redirected to a fixed path in your React app.</p><p>If the user has your 2FA turned on, redirect to the code prompt with an MFA ticket instead.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/refresh → { accessToken }', 'The React app picks up the session',
        `<p>The callback page calls <code>/refresh</code> exactly like the app does on start-up, and the user lands on their dashboard.</p>`),
    ],
    concept: `
<h3>OAuth 2.0 versus OpenID Connect</h3>
<p><b>OAuth 2.0</b> is about <i>authorization</i>: letting your app act on the user's behalf at Google (read their calendar, say). <b>OpenID Connect</b> adds <i>authentication</i> on top: a signed <code>id_token</code> that says who the user is. "Sign in with Google" is OIDC, which is why the scope includes <code>openid</code>.</p>
<h3>Why the backend runs the flow</h3>
<ul>
  <li>The <b>client secret</b> stays on the server.</li>
  <li>You end up with <b>your own session</b> (refresh cookie + access token), so the rest of your app doesn't care how the user signed in.</li>
  <li>You don't need Google's access token at all unless you call Google APIs. Throw it away if you don't.</li>
</ul>
<h3>Account linking rules</h3>
<div class="table-wrap"><table>
  <thead><tr><th>What you find</th><th>What to do</th></tr></thead>
  <tbody>
    <tr><td>A user with this <code>googleId</code></td><td>Sign them in.</td></tr>
    <tr><td>A user with this email, <b>verified</b></td><td>Link: set <code>googleId</code>, sign in. Google's <code>email_verified</code> and your own verification both prove ownership.</td></tr>
    <tr><td>A user with this email, <b>unverified</b></td><td>The account may belong to someone squatting on the address. Remove its password, revoke its sessions, then link and mark verified.</td></tr>
    <tr><td>Nobody</td><td>Create a user with <code>googleId</code>, <code>emailVerified: true</code> and no password.</td></tr>
  </tbody>
</table></div>
<h3>Setting it up in Google Cloud Console</h3>
<ol>
  <li>APIs &amp; Services → OAuth consent screen: app name, support email, scopes <code>openid email profile</code>.</li>
  <li>Credentials → Create OAuth client ID → Web application.</li>
  <li>Authorized redirect URI: <code>https://api.example.com/api/auth/google/callback</code> (plus <code>http://localhost:4000/…</code> for development).</li>
  <li>Put the client id and secret in <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code>.</li>
</ol>
<p class="callout"><b>Prefer a library?</b> Passport.js with <code>passport-google-oauth20</code> handles the redirect dance, and <code>openid-client</code> supports any OIDC provider (Microsoft, Apple, GitHub through OAuth). The code here shows every step so you can see what those libraries do for you.</p>`,
    threats: [
      { name: 'Login CSRF on the callback', risk: 'An attacker makes the victim\'s browser complete a flow with the attacker\'s code, silently logging the victim into the attacker\'s account.', fix: 'A random <code>state</code> stored in a signed cookie and compared in constant time on the callback.' },
      { name: 'Authorization code interception', risk: 'A leaked code (logs, a malicious browser extension, a misconfigured redirect) is exchanged by someone else.', fix: 'PKCE: only the holder of the original <code>code_verifier</code> can redeem the code.' },
      { name: 'Unverified ID token', risk: 'Decoding the <code>id_token</code> without verifying lets anyone forge "I am ana@example.com".', fix: '<code>verifyIdToken</code> with your client id as audience, then check <code>nonce</code> and <code>email_verified</code>.' },
      { name: 'Pre-account takeover', risk: 'An attacker registers the victim\'s email with a password but never verifies it. When the victim later signs in with Google and the accounts link, the attacker\'s password still works.', fix: 'When linking to an unverified local account, delete its password and revoke its sessions first.' },
      { name: 'Identity by email', risk: 'Email addresses get recycled and changed; matching on email alone can attach a new person to an old account.', fix: 'Store and match on Google\'s <code>sub</code>. Use email only for the one-time linking decision.' },
      { name: 'Open redirect after login', risk: 'A <code>?returnTo=https://evil.example</code> parameter sends freshly signed-in users to a phishing page.', fix: 'Redirect to a fixed path, or accept only relative paths that start with a single <code>/</code>.' },
    ],
    code: [
      {
        file: 'server/src/controllers/google.controller.js',
        code: code`
import { OAuth2Client } from 'google-auth-library';
import { env, isProd } from '../config/env.js';
import { User } from '../models/User.js';
import { issueSession, signMfaToken, revokeAllSessions } from '../services/token.service.js';
import { randomToken, safeEqual } from '../utils/crypto.js';
import { audit } from '../utils/audit.js';

const google = new OAuth2Client({
  clientId: env.GOOGLE_CLIENT_ID,
  clientSecret: env.GOOGLE_CLIENT_SECRET,
  redirectUri: \`\${env.API_URL}/api/auth/google/callback\`,
});

const FLOW_COOKIE = 'g_oauth';
const flowCookie = {
  httpOnly: true,
  secure: isProd,
  sameSite: 'lax',              // must survive the cross-site redirect back from Google
  signed: true,
  path: '/api/auth/google',
};

export async function googleStart(req, res) {
  const state = randomToken(16);
  const nonce = randomToken(16);
  const { codeVerifier, codeChallenge } = await google.generateCodeVerifierAsync();

  res.cookie(FLOW_COOKIE, JSON.stringify({ state, nonce, codeVerifier }), { ...flowCookie, maxAge: 10 * 60 * 1000 });
  res.redirect(google.generateAuthUrl({
    scope: ['openid', 'email', 'profile'],
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  }));
}

export async function googleCallback(req, res) {
  const fail = (reason) => {
    audit(req, 'login.google_failed', { reason });
    res.redirect(\`\${env.APP_URL}/login?error=google\`);
  };

  const rawFlow = req.signedCookies[FLOW_COOKIE];
  res.clearCookie(FLOW_COOKIE, flowCookie);   // one attempt per cookie
  if (!rawFlow) return fail('missing_flow_cookie');

  const { state, nonce, codeVerifier } = JSON.parse(rawFlow);
  const { code, state: returnedState } = req.query;
  if (typeof returnedState !== 'string' || !safeEqual(returnedState, state)) return fail('state_mismatch');
  if (typeof code !== 'string') return fail('no_code');   // e.g. the user pressed Cancel

  let profile;
  try {
    const { tokens } = await google.getToken({ code, codeVerifier });
    const ticket = await google.verifyIdToken({ idToken: tokens.id_token, audience: env.GOOGLE_CLIENT_ID });
    profile = ticket.getPayload();   // signature, iss, aud and exp already verified
  } catch {
    return fail('token_exchange');
  }
  if (profile.nonce !== nonce || !profile.email_verified) return fail('bad_id_token');

  const user = await findOrLinkGoogleUser(profile);
  if (user.disabled) return fail('disabled');

  if (user.mfa?.enabled) {
    // Google proved the first factor; your 2FA still applies. Fragments never reach any server.
    return res.redirect(\`\${env.APP_URL}/login/mfa#ticket=\${signMfaToken(user)}\`);
  }

  await issueSession(req, res, user);
  audit(req, 'login.success', { userId: user.id, method: 'google' });
  res.redirect(\`\${env.APP_URL}/auth/callback\`);   // fixed path: no open redirect
}

async function findOrLinkGoogleUser(profile) {
  const byGoogle = await User.findOne({ googleId: profile.sub });
  if (byGoogle) return byGoogle;

  const email = profile.email.toLowerCase();
  const byEmail = await User.findOne({ email });
  if (byEmail) {
    if (!byEmail.emailVerified) {
      // Someone registered this address without proving it. Google just proved it belongs
      // to this person, so remove anything the squatter could still use.
      byEmail.passwordHash = undefined;
      byEmail.tokenVersion += 1;
      await revokeAllSessions(byEmail._id, 'google_link_unverified');
    }
    byEmail.googleId = profile.sub;
    byEmail.emailVerified = true;
    await byEmail.save();
    return byEmail;
  }

  return User.create({ email, name: profile.name, googleId: profile.sub, emailVerified: true });
}`,
      },
      {
        file: 'client/src/pages/OAuthCallback.jsx',
        lang: 'jsx',
        code: code`
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthProvider';

// Google → API → here. The refresh cookie is already set; fetch an access token with it.
export default function OAuthCallback() {
  const { completeExternalLogin } = useAuth();
  const navigate = useNavigate();
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;   // StrictMode runs effects twice in development
    started.current = true;
    completeExternalLogin()
      .then(() => navigate('/dashboard', { replace: true }))
      .catch(() => navigate('/login?error=google', { replace: true }));
  }, [completeExternalLogin, navigate]);

  return <p>Signing you in…</p>;
}

// The button is a plain link: the whole page goes to Google and back.
export function GoogleButton() {
  return <a className="btn" href={\`\${import.meta.env.VITE_API_URL ?? '/api'}/auth/google\`}>Continue with Google</a>;
}`,
      },
    ],
    checklist: [
      'The flow uses the authorization code grant with PKCE (S256), never the implicit flow',
      '<code>state</code> and <code>nonce</code> are random, stored in a signed short-lived cookie and verified',
      'The ID token is verified with the client id as audience; <code>email_verified</code> is required',
      'Users are matched by Google <code>sub</code>, not email',
      'Linking to an unverified local account removes its password and sessions',
      'After login the API redirects to a fixed path in the React app',
      'Users with 2FA enabled still have to enter a code',
      'The client secret lives only on the server',
    ],
  });
})();
