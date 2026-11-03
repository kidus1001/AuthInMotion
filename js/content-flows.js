/* Chapters 03–07: core flows */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block } = AIM;

  // ================================================================ 03 · Sign-up + email verification
  AIM.chapters.push({
    id: 'signup',
    num: '03',
    group: 'Core flows',
    short: 'Sign-up & email verification',
    title: 'Sign-up and email verification',
    flowName: 'Register, then prove the inbox',
    lede: 'Creating an account is easy. Creating one without leaking who already has an account, without letting bots flood you, and with proof the person owns the email address takes a few deliberate steps.',
    actors: ['browser', 'api', 'db', 'redis', 'mail'],
    steps: [
      send('browser', 'api', 'cred', 'POST /api/auth/register', 'The form is submitted',
        `<p>Name, email and password go to the API. The React form uses <code>autocomplete="email"</code> and <code>autocomplete="new-password"</code> so password managers offer to generate and save a strong password.</p>`,
        `POST /api/auth/register
{ "name": "Ana", "email": "Ana@Example.com ", "password": "correct horse battery staple" }`),
      send('api', 'redis', 'data', 'INCR rl:register-ip:203.0.113.9', 'Throttle sign-ups per IP',
        `<p>Five sign-ups per IP per hour is plenty for humans. Bots hit the limit fast. For public apps, add an invisible CAPTCHA (Cloudflare Turnstile, hCaptcha) on this route too.</p>`),
      proc('api', 'cred', 'zod · HIBP · argon2id', 'Normalize, validate, hash',
        `<p>The email is trimmed and lower-cased so <code>Ana@Example.com</code> and <code>ana@example.com</code> are one account. The password is checked for length and breaches, then hashed.</p><p>The hash is computed <b>before</b> checking if the email exists, so both paths spend the same ~100 ms.</p>`),
      send('api', 'db', 'data', 'users.insertOne({ emailVerified: false })', 'Insert, and let the unique index decide',
        `<p>Don't run <code>findOne</code> then <code>insert</code>: two parallel requests could both pass the check. Insert directly and catch MongoDB's duplicate-key error <code>11000</code> from the unique index on <code>email</code>.</p>`),
      proc('api', 'cred', 'raw = randomBytes(32) · store sha256(raw)', 'Mint a verification token',
        `<p>32 random bytes (256 bits) from Node's cryptographic RNG. The raw value goes in the email; only its SHA-256 goes in the database, with a 24-hour expiry.</p><p>A fast hash is fine here because the token is random and unguessable, unlike a password. If the database leaks, the hashes can't be turned back into working links.</p>`,
        `raw token  (emailed):   q0V3pN2kZ7…mE  (43 chars, base64url)
tokenHash  (stored):    5f2b9c…e81a     (64 hex chars)
expiresAt:              2026-11-03T22:41:00Z`),
      send('api', 'db', 'data', 'tokens.insertOne({ tokenHash, expiresAt })', 'Store the hash with a TTL index',
        `<p>A TTL index on <code>expiresAt</code> makes MongoDB delete expired tokens on its own. No cron job.</p>`),
      send('api', 'redis', 'mail', 'queue.add("verify-email", …)', 'Queue the email instead of sending it inline',
        `<p>Talking to an SMTP server takes 200–2000 ms. If you send inline, a new account responds slowly and an existing one responds fast, which leaks who is registered. A BullMQ job on Redis returns in a millisecond either way, and retries if the provider hiccups.</p>`),
      send('api', 'browser', 'ok', '201 · Check your inbox', 'The same answer for new and existing emails',
        `<p>If the email was already registered, the API queues a different email to the <b>owner of that address</b>: "Someone tried to create an account with your email. If it was you, sign in or reset your password." The person at the form learns nothing.</p>`,
        `HTTP/1.1 201 Created
{ "message": "Check your inbox for a link to confirm your email." }`),
      send('redis', 'mail', 'mail', 'worker → SMTP', 'A background worker delivers it',
        `<p>The worker (same codebase, its own process in production) renders the template and hands it to your provider. SPF, DKIM and DMARC records on your sending domain keep it out of spam.</p>`),
      send('mail', 'browser', 'mail', 'app.example.com/verify-email?token=q0V3…', 'The link opens the React app, not the API',
        `<p>Corporate email scanners and link previewers <b>open every link</b> in an email. If the link were <code>GET /api/verify?token=</code>, the scanner would verify the account before the human ever clicked.</p><p>So the link opens a React page with a "Confirm my email" button, and the page strips the token from the address bar.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/verify-email { token }', 'The user clicks Confirm',
        `<p>A POST from your page can't be triggered by a scanner, and the token stays out of server access logs (which record URLs, not bodies).</p>`),
      send('api', 'db', 'data', 'tokens.findOneAndDelete({ sha256(token) })', 'Find and consume in one atomic step',
        `<p>Hash the submitted token, then find <i>and delete</i> it in one operation, filtered to unexpired ones. Atomic delete means a link works exactly once, even if clicked twice at the same moment.</p>`),
      send('api', 'db', 'data', 'users.updateOne({ emailVerified: true })', 'Mark the email as verified',
        `<p>Now the account can log in. Unverified accounts get a <code>403 EMAIL_NOT_VERIFIED</code> at login, and the UI offers "Resend link".</p>`),
      send('api', 'browser', 'ok', '200 · Email confirmed', 'Done',
        `<p>Send them to the login page. Logging them in automatically from an email link is convenient, but it turns every leaked link into a session, so a separate login is the safer default.</p>`),
    ],
    concept: `
<h3>What verification buys you</h3>
<ul>
  <li>Password reset emails go to someone who really owns the address.</li>
  <li>Nobody can squat on another person's email to block their sign-up or impersonate them.</li>
  <li>Your email sender reputation stays healthy because you stop mailing typo'd and fake addresses.</li>
</ul>
<h3>Random token or JWT for email links?</h3>
<p>Use a <b>random token stored hashed in MongoDB</b>. A JWT link can't be used only once and can't be revoked without extra state, and its payload is readable. A database row gives you single use, revocation and expiry for free.</p>
<h3>Token rules for every emailed link</h3>
<ul>
  <li>At least 128 bits of randomness from <code>crypto.randomBytes</code>. Never <code>Math.random</code>, never a UUID v1 or a timestamp.</li>
  <li>Store only <code>sha256(token)</code>. Look it up by that hash.</li>
  <li>Set an expiry: 24 hours for verification, 30 minutes for password reset.</li>
  <li>Delete on use, and delete older tokens of the same purpose when you issue a new one.</li>
  <li>Build links from <code>APP_URL</code> in config, never from the request's <code>Host</code> header.</li>
</ul>
<h3>Changing an email address later</h3>
<p>Treat it like a sign-up: send a verification link to the <b>new</b> address and switch only when it's confirmed. Also email the <b>old</b> address ("Your email was changed to a••@…. If this wasn't you, contact support") and require the current password for the change.</p>
<h3>Email delivery basics</h3>
<dl>
  <dt>Provider</dt><dd>Amazon SES, Resend, Postmark, SendGrid or Mailgun. Use a subdomain like <code>mail.example.com</code> for sending.</dd>
  <dt>SPF</dt><dd>A DNS record listing which servers may send for your domain.</dd>
  <dt>DKIM</dt><dd>Your provider signs each message; receivers check the signature against a DNS key.</dd>
  <dt>DMARC</dt><dd>Tells receivers what to do when SPF or DKIM fails. Start with <code>p=none</code> and reports, then move to <code>quarantine</code>.</dd>
</dl>`,
    threats: [
      { name: 'User enumeration', risk: '"Email already registered" or a faster response for existing accounts lets anyone check whether a person uses your app, and builds target lists for phishing.', fix: 'Identical status, body and timing. Hash before the insert, queue all emails, and notify the real owner instead of the requester.' },
      { name: 'Link scanners consuming tokens', risk: 'Outlook Safe Links and similar services fetch every URL, so a GET that verifies would be "clicked" by a robot.', fix: 'Link to a frontend page; verification happens on a POST from a button click.' },
      { name: 'Token leakage', risk: 'Tokens in API URLs end up in access logs, proxies and the <code>Referer</code> header sent to third-party scripts on the next page.', fix: 'POST the token in the body, strip it from the address bar with <code>history.replaceState</code>, send <code>Referrer-Policy: no-referrer</code>.' },
      { name: 'Host header poisoning', risk: 'If the link is built from <code>req.headers.host</code>, an attacker can trigger an email whose link points to their domain and capture the token.', fix: 'Always build links from <code>env.APP_URL</code>.' },
      { name: 'Bot sign-ups and email bombing', risk: 'Scripts create thousands of accounts or hammer "resend link" to flood a victim\'s inbox and hurt your sender reputation.', fix: 'Per-IP and per-email limits in Redis, a resend cooldown, and Turnstile or hCaptcha on public forms.' },
      { name: 'Race on duplicate email', risk: 'Two parallel sign-ups both pass a <code>findOne</code> check and create duplicate accounts.', fix: 'A unique index on <code>email</code>; insert directly and handle error code <code>11000</code>.' },
    ],
    code: [
      {
        file: 'server/src/models/Token.js',
        note: 'One collection for every emailed one-time token: email verification and password reset.',
        code: code`
import mongoose from 'mongoose';

const tokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    purpose: { type: String, enum: ['verify_email', 'reset_password'], required: true },
    tokenHash: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);

// MongoDB's TTL monitor deletes a document once expiresAt has passed (it runs about once a minute,
// so still check expiresAt in queries).
tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const Token = mongoose.model('Token', tokenSchema);`,
      },
      {
        file: 'server/src/utils/crypto.js',
        code: code`
import crypto from 'node:crypto';

// 32 bytes = 256 bits of entropy, URL-safe, 43 characters
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// Fast hash is fine for random tokens: there is nothing to brute-force
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// Constant-time comparison for secrets you compare directly (e.g. OAuth state)
export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}`,
      },
      {
        file: 'server/src/controllers/signup.controller.js',
        code: code`
import { z } from 'zod';
import { env } from '../config/env.js';
import { User } from '../models/User.js';
import { Token } from '../models/Token.js';
import { mailQueue } from '../jobs/mail.queue.js';
import { hashPassword, isBreached } from '../services/password.js';
import { randomToken, sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';
import { registerSchema, tokenSchema, email as emailField } from '../validation/auth.schemas.js';

const DAY = 24 * 60 * 60 * 1000;

async function sendVerification(user) {
  const raw = randomToken();
  await Token.deleteMany({ userId: user._id, purpose: 'verify_email' });   // only the newest link works
  await Token.create({
    userId: user._id,
    purpose: 'verify_email',
    tokenHash: sha256(raw),
    expiresAt: new Date(Date.now() + DAY),
  });
  // Points at the React app, which POSTs the token back. Built from config, never from req.host.
  await mailQueue.add('verify-email', {
    to: user.email,
    name: user.name,
    link: \`\${env.APP_URL}/verify-email?token=\${raw}\`,
  });
}

export async function register(req, res) {
  const { name, email, password } = registerSchema.parse(req.body);

  if (await isBreached(password)) {
    throw new HttpError(400, 'This password appeared in a data breach. Choose a different one.', 'PASSWORD_BREACHED');
  }
  // Hash first so "new email" and "taken email" cost the same time
  const passwordHash = await hashPassword(password);

  try {
    const user = await User.create({ name, email, passwordHash });
    await sendVerification(user);
    audit(req, 'user.registered', { userId: user.id });
  } catch (err) {
    if (err.code !== 11000) throw err;   // 11000 = duplicate key on the unique email index
    await mailQueue.add('account-exists', { to: email, link: \`\${env.APP_URL}/forgot-password\` });
  }

  res.status(201).json({ message: 'Check your inbox for a link to confirm your email.' });
}

export async function verifyEmail(req, res) {
  const { token } = tokenSchema.parse(req.body);
  const record = await Token.findOneAndDelete({
    tokenHash: sha256(token),
    purpose: 'verify_email',
    expiresAt: { $gt: new Date() },
  });
  if (!record) {
    throw new HttpError(400, 'This link is invalid or has expired. Request a new one from the sign-in page.', 'VERIFY_TOKEN_INVALID');
  }
  await User.updateOne({ _id: record.userId }, { $set: { emailVerified: true } });
  audit(req, 'user.email_verified', { userId: String(record.userId) });
  res.json({ message: 'Email confirmed. You can sign in now.' });
}

export async function resendVerification(req, res) {
  const { email } = z.object({ email: emailField }).parse(req.body);
  const user = await User.findOne({ email });
  if (user && !user.emailVerified && !user.disabled) await sendVerification(user);
  res.json({ message: 'If that account still needs confirming, we sent a new link.' });
}`,
      },
      {
        file: 'server/src/jobs/mail.queue.js',
        code: code`
import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import { env } from '../config/env.js';

// BullMQ needs maxRetriesPerRequest: null on its connections
const connection = new IORedis(env.REDIS_URL, { maxRetriesPerRequest: null });

export const mailQueue = new Queue('mail', {
  connection,
  defaultJobOptions: {
    attempts: 5,
    backoff: { type: 'exponential', delay: 10_000 },
    removeOnComplete: true,   // job data contains one-time links: don't keep it around
    removeOnFail: 200,
  },
});`,
      },
      {
        file: 'server/src/jobs/mail.worker.js',
        note: 'Import it from server.js for a single process, or run it as its own process in production.',
        code: code`
import { Worker } from 'bullmq';
import IORedis from 'ioredis';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { sendMail } from '../services/mail.js';
import * as templates from '../services/mail.templates.js';
import { handleForgotPassword } from '../controllers/recovery.controller.js';

const connection = new IORedis(env.REDIS_URL, { maxRetriesPerRequest: null });

const worker = new Worker(
  'mail',
  async (job) => {
    switch (job.name) {
      case 'verify-email':     return sendMail(job.data.to, templates.verifyEmail(job.data));
      case 'account-exists':   return sendMail(job.data.to, templates.accountExists(job.data));
      case 'forgot-password':  return handleForgotPassword(job.data.email);   // lookup happens here, off the request
      case 'reset-password':   return sendMail(job.data.to, templates.resetPassword(job.data));
      case 'password-changed': return sendMail(job.data.to, templates.passwordChanged(job.data));
      case 'mfa-changed':      return sendMail(job.data.to, templates.mfaChanged(job.data));
      default: throw new Error(\`Unknown mail job: \${job.name}\`);
    }
  },
  { connection, concurrency: 5 },
);

worker.on('failed', (job, err) => logger.error({ err, job: job?.name }, 'mail job failed'));`,
      },
      {
        file: 'server/src/services/mail.js',
        code: code`
import nodemailer from 'nodemailer';
import { env } from '../config/env.js';

const transport = nodemailer.createTransport(env.SMTP_URL);

export async function sendMail(to, { subject, text, html }) {
  await transport.sendMail({ from: env.MAIL_FROM, to, subject, text, html });
}`,
      },
      {
        file: 'server/src/services/mail.templates.js',
        note: 'Always send a plain-text part too. Escape anything user-supplied that goes into HTML.',
        code: code`
const esc = (s = '') =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const layout = (body) => \`<!doctype html><html><body style="font-family:system-ui,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1f2c">
\${body}
<p style="color:#667085;font-size:13px">If you didn't ask for this, you can ignore this email.</p>
</body></html>\`;

const button = (href, label) =>
  \`<p><a href="\${esc(href)}" style="display:inline-block;background:#1a1f2c;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">\${esc(label)}</a></p>\`;

export const verifyEmail = ({ name, link }) => ({
  subject: 'Confirm your email',
  text: \`Hi \${name},\n\nConfirm your email address:\n\${link}\n\nThe link expires in 24 hours.\`,
  html: layout(\`<p>Hi \${esc(name)},</p>\${button(link, 'Confirm my email')}<p>The link expires in 24 hours.</p>\`),
});

export const accountExists = ({ link }) => ({
  subject: 'Someone tried to sign up with your email',
  text: \`Someone tried to create an account with this email. You already have one.\nForgot your password? \${link}\`,
  html: layout(\`<p>Someone tried to create an account with this email. You already have one.</p>\${button(link, 'Reset my password')}\`),
});

export const resetPassword = ({ link }) => ({
  subject: 'Reset your password',
  text: \`Reset your password:\n\${link}\n\nThe link works once and expires in 30 minutes.\`,
  html: layout(\`\${button(link, 'Choose a new password')}<p>The link works once and expires in 30 minutes.</p>\`),
});

export const passwordChanged = ({ when }) => ({
  subject: 'Your password was changed',
  text: \`Your password was changed on \${when}. All other devices were signed out.\nIf this wasn't you, reset your password now and contact support.\`,
  html: layout(\`<p>Your password was changed on \${esc(when)}. All other devices were signed out.</p><p><b>If this wasn't you</b>, reset your password now and contact support.</p>\`),
});

export const mfaChanged = ({ enabled }) => ({
  subject: enabled ? 'Two-factor authentication is on' : 'Two-factor authentication was turned off',
  text: enabled ? 'Two-factor authentication is now on for your account.' : 'Two-factor authentication was turned off. If this wasn\'t you, reset your password now.',
  html: layout(\`<p>\${enabled ? 'Two-factor authentication is now on for your account.' : '<b>Two-factor authentication was turned off.</b> If this wasn\'t you, reset your password now.'}</p>\`),
});`,
      },
      {
        file: 'client/src/pages/VerifyEmail.jsx',
        lang: 'jsx',
        code: code`
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const [token] = useState(() => params.get('token'));
  const [state, setState] = useState({ status: 'idle', message: '' });

  // Remove the token from the address bar and browser history
  useEffect(() => {
    if (token) window.history.replaceState(null, '', '/verify-email');
  }, [token]);

  async function confirm() {
    setState({ status: 'working', message: '' });
    try {
      const { data } = await api.post('/auth/verify-email', { token });
      setState({ status: 'done', message: data.message });
    } catch (err) {
      setState({ status: 'error', message: err.response?.data?.error ?? 'Could not reach the server. Try again.' });
    }
  }

  if (!token) return <p>This link is missing its token. Open the latest email we sent you.</p>;
  if (state.status === 'done') return <p>{state.message} <Link to="/login">Sign in</Link></p>;

  return (
    <main>
      <h1>Confirm your email</h1>
      {/* A button, not an auto-submit: email scanners open links but don't click buttons */}
      <button onClick={confirm} disabled={state.status === 'working'}>
        {state.status === 'working' ? 'Confirming…' : 'Confirm my email'}
      </button>
      {state.status === 'error' && <p role="alert">{state.message}</p>}
    </main>
  );
}`,
      },
    ],
    checklist: [
      'Email is trimmed and lower-cased before every lookup and insert',
      'A unique index on <code>email</code> handles duplicate sign-ups',
      'Sign-up returns the same response whether or not the email exists',
      'Verification tokens are 256-bit random, stored as SHA-256, expire in 24h, and work once',
      'Emails are sent from a queue, never inline in the request',
      'Links point at the React app and are built from <code>APP_URL</code>',
      'SPF, DKIM and DMARC are set up for the sending domain',
      'Sign-up and resend are rate-limited per IP and per email',
    ],
  });

  // ================================================================ 04 · Login
  AIM.chapters.push({
    id: 'login',
    num: '04',
    group: 'Core flows',
    short: 'Login & tokens',
    title: 'Login and issuing tokens',
    flowName: 'Email + password → two tokens',
    lede: 'Login is the most attacked endpoint you own. It needs to be throttled, give nothing away to guessers, and hand the browser tokens in places where scripts can\'t steal them.',
    actors: ['browser', 'api', 'db', 'redis'],
    steps: [
      send('browser', 'api', 'cred', 'POST /api/auth/login', 'Credentials arrive',
        `<p>The login form posts email and password as JSON. The axios client always sends <code>withCredentials: true</code> so the browser accepts the cookie in the response.</p>`,
        `POST /api/auth/login
Content-Type: application/json
X-Requested-With: fetch

{ "email": "ana@example.com", "password": "correct horse battery staple" }`),
      send('api', 'redis', 'data', 'INCR login-ip · INCR login-email', 'Two counters: per IP and per account',
        `<p><b>Per IP</b> (20 per 15 min) slows one machine guessing many accounts. <b>Per email</b> (8 per 15 min) slows a botnet guessing one account from many IPs.</p><p>The email key is hashed, so raw addresses never sit in Redis.</p>`,
        `MULTI
SET  rl:login-email:7c1e9a…  0 EX 900 NX
INCR rl:login-email:7c1e9a…        → 3
TTL  rl:login-email:7c1e9a…        → 612
EXEC`),
      send('redis', 'api', 'data', 'count 3 of 8 · ttl 612s', 'Under the limit, continue',
        `<p>Over the limit, the API answers <code>429</code> with a <code>Retry-After</code> header and never reaches the database or the hash function.</p>`),
      send('api', 'db', 'data', 'findOne({ email }).select("+passwordHash")', 'Load the user and the hidden hash',
        `<p>Because <code>passwordHash</code> is <code>select: false</code>, you must ask for it explicitly. Every other query in the app can never leak it by accident.</p>`),
      send('db', 'api', 'data', 'user | null', 'The user might not exist',
        `<p>The next step must behave identically either way.</p>`),
      proc('api', 'cred', 'user ? argon2.verify() : fakeVerify()', 'Same work, same message, either way',
        `<p>If there's no user, verify against a dummy hash anyway so the response takes the same ~100 ms. Then reply with one message for every failure: <i>Invalid email or password</i>.</p><p>On success, clear the per-email counter and re-hash if the stored hash uses old parameters.</p>`,
        `HTTP/1.1 401 Unauthorized
{ "error": "Invalid email or password", "code": "INVALID_CREDENTIALS" }`),
      proc('api', 'token', 'emailVerified? · mfa.enabled?', 'Gates after the password',
        `<p>These checks happen <b>after</b> the password is proven, so they don't reveal anything to guessers.</p><ul><li>Email not verified → <code>403 EMAIL_NOT_VERIFIED</code>; the UI offers to resend.</li><li>2FA on → no tokens yet. Return a 5-minute <code>mfaToken</code> and ask for a code (chapter 09).</li></ul>`),
      proc('api', 'token', 'jwt.sign() · randomBytes(32)', 'Mint an access token and a refresh token',
        `<p>The <b>access token</b> is a JWT signed with HS256 that lives 15 minutes. It carries just enough to authorize requests: user id, role and token version.</p><p>The <b>refresh token</b> is 32 random bytes. It means nothing on its own; the database row behind it is the session.</p>`,
        `// JWT payload (base64url-decoded). Readable by anyone: no secrets in here.
{
  "sub": "66f1c2a9e4b0d1f7a3c2b8e1",
  "role": "user",
  "ver": 3,
  "iat": 1762123200,
  "exp": 1762124100,
  "iss": "api.example.com",
  "aud": "api"
}`),
      send('api', 'db', 'data', 'refreshtokens.insertOne({ tokenHash, familyId })', 'Store the session server-side',
        `<p>A new <code>familyId</code> represents this device's session. The row holds the SHA-256 of the refresh token, its expiry, an absolute session cap of 60 days, the user agent and the IP, which later power the "Your devices" screen.</p>`),
      send('api', 'browser', 'token', '200 { accessToken } + Set-Cookie: rt', 'Tokens go back in two different places',
        `<p>The access token rides in the JSON body. The refresh token rides in a cookie the browser stores and JavaScript can't read.</p>`,
        `HTTP/1.1 200 OK
Set-Cookie: rt=q0V3pN2kZ7…; Path=/api/auth; Expires=Tue, 17 Nov 2026 22:40:00 GMT; HttpOnly; Secure; SameSite=Strict

{ "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi…", "user": { "id": "66f1…", "role": "user", "mfaEnabled": false } }`),
      proc('browser', 'token', 'accessToken → memory · rt → cookie jar', 'Where the browser keeps them',
        `<p>The access token lives in a JavaScript variable inside the API client module. It disappears on reload, and the app gets a fresh one from the refresh cookie on start-up.</p><p>The cookie is <code>HttpOnly</code> (no JS access), <code>Secure</code> (HTTPS only), <code>SameSite=Strict</code> (never sent on cross-site requests) and <code>Path=/api/auth</code> (only sent to the auth routes, never to <code>/api/projects</code>).</p>`),
    ],
    concept: `
<h3>Anatomy of a JWT</h3>
<p>Three base64url parts joined by dots: <code>header.payload.signature</code>. The signature is an HMAC of the first two parts with your secret. Change one character of the payload and verification fails. But the payload is only <b>encoded</b>, not encrypted. Paste any JWT into jwt.io and read it, so never put emails, permissions lists or anything secret inside.</p>
<dl>
  <dt><code>sub</code></dt><dd>Subject: the user id.</dd>
  <dt><code>exp</code> / <code>iat</code></dt><dd>Expiry and issued-at, in Unix seconds. Keep access tokens at 5–15 minutes.</dd>
  <dt><code>iss</code> / <code>aud</code></dt><dd>Who issued it and who it's for. Verify both, so a token minted for one purpose can't be replayed for another.</dd>
  <dt><code>ver</code></dt><dd>Your own claim: the user's <code>tokenVersion</code>. Bump it in the database to invalidate every outstanding access token.</dd>
</dl>
<h3>HS256 or RS256?</h3>
<p><b>HS256</b> (one shared secret) is right when one API both signs and verifies. Choose <b>RS256 or EdDSA</b> (private key signs, public key verifies) once several services need to verify tokens but shouldn't be able to mint them.</p>
<h3>Where to keep tokens in the browser</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Storage</th><th>XSS can steal it?</th><th>Sent automatically?</th><th>Verdict</th></tr></thead>
  <tbody>
    <tr><td><code>localStorage</code> / <code>sessionStorage</code></td><td><span class="bad">Yes</span>, any script can read it</td><td>No</td><td>Avoid for anything long-lived</td></tr>
    <tr><td>Memory (a JS variable)</td><td>Only while the page is open</td><td>No</td><td><span class="good">Access token</span></td></tr>
    <tr><td>HttpOnly, Secure, SameSite cookie</td><td><span class="good">No</span>, scripts can't read it</td><td>Yes, so CSRF must be considered</td><td><span class="good">Refresh token</span></td></tr>
  </tbody>
</table></div>
<p>XSS can still <i>use</i> a session while the page is open, whatever you do. The goal is that it can't <i>walk away</i> with a token that works for weeks.</p>
<h3>Lockout versus throttling</h3>
<p>Hard lockouts ("account locked after 5 attempts") let anyone lock your users out on purpose. Prefer throttling: per-account and per-IP windows, a CAPTCHA after a few failures, and an email to the user if their account sees a burst of failures. Pair it with 2FA for real protection.</p>
<h3>"Remember me"</h3>
<p>Without it, set the refresh cookie as a session cookie (no <code>Expires</code>) so it goes away when the browser closes, and keep the server-side row short. With it, use the 14-day rolling token and 60-day absolute cap shown here.</p>`,
    threats: [
      { name: 'Credential stuffing and brute force', risk: 'Automated guessing using leaked password lists, from one IP or a botnet of thousands.', fix: 'Redis counters per IP and per hashed email, <code>429</code> with <code>Retry-After</code>, a CAPTCHA after repeated failures, breach checks, 2FA.' },
      { name: 'Enumeration by message or timing', risk: '"No account with that email" or a 5 ms reply for unknown users versus 100 ms for real ones reveals who is registered.', fix: 'One error message; <code>fakeVerify</code> against a dummy hash; check <code>emailVerified</code> only after the password succeeds.' },
      { name: 'JWT algorithm confusion', risk: 'Libraries that trust the token\'s own <code>alg</code> header can be tricked with <code>alg: none</code> or by using a public key as an HMAC secret.', fix: 'Always pass <code>algorithms: [\'HS256\']</code> to <code>jwt.verify</code>, plus <code>issuer</code> and <code>audience</code>.' },
      { name: 'Weak signing secret', risk: 'A short or default secret like <code>"secret"</code> can be brute-forced offline from any token, letting attackers mint admin tokens.', fix: '32+ random bytes from a secret manager, validated at boot, different per environment, rotated if exposed.' },
      { name: 'Session fixation', risk: 'An attacker plants a known session id in a victim\'s browser before they log in, then shares the session.', fix: 'Always issue a brand-new refresh token and family on login. Never reuse an id that existed before authentication.' },
      { name: 'Secrets inside the JWT', risk: 'Payloads are readable by anyone holding the token: browser extensions, logs, error trackers.', fix: 'Only ids, role and version. Look everything else up on the server.' },
    ],
    code: [
      {
        file: 'server/src/models/RefreshToken.js',
        code: code`
import mongoose from 'mongoose';

// One document per refresh token. Tokens issued by rotation share a familyId:
// one family = one signed-in device.
const refreshTokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    familyId: { type: String, required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },          // this token
    sessionExpiresAt: { type: Date, required: true },   // the whole family, no matter how often it rotates
    usedAt: Date,                                       // set when rotated
    revokedAt: Date,
    revokeReason: String,
    userAgent: String,
    ip: String,
  },
  { timestamps: true },
);

// Keep rows 7 days past expiry so a replayed old token is still recognised as reuse, then delete
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 24 * 60 * 60 });

export const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);`,
      },
      {
        file: 'server/src/services/token.service.js',
        code: code`
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env, isProd } from '../config/env.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { randomToken, sha256 } from '../utils/crypto.js';

const DAY = 24 * 60 * 60 * 1000;
const ACCESS_TTL = '15m';
const REFRESH_TTL = 14 * DAY;   // one token's life; every refresh issues a new one
const SESSION_MAX = 60 * DAY;   // absolute cap: sign in again after 60 days

export const REFRESH_COOKIE = 'rt';
const cookieBase = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/api/auth' };

// ---------- access token
export function signAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id ?? user._id), role: user.role, ver: user.tokenVersion },
    env.JWT_ACCESS_SECRET,
    { algorithm: 'HS256', expiresIn: ACCESS_TTL, issuer: env.JWT_ISSUER, audience: 'api' },
  );
}

export function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_ACCESS_SECRET, {
    algorithms: ['HS256'],   // never let the token choose its own algorithm
    issuer: env.JWT_ISSUER,
    audience: 'api',
    clockTolerance: 5,
  });
}

// ---------- MFA ticket: "password was right, now prove the second factor"
export function signMfaToken(user) {
  return jwt.sign({ sub: user.id, purpose: 'mfa' }, env.JWT_MFA_SECRET, {
    algorithm: 'HS256', expiresIn: '5m', issuer: env.JWT_ISSUER, audience: 'mfa',
  });
}

export function verifyMfaToken(token) {
  const claims = jwt.verify(token, env.JWT_MFA_SECRET, { algorithms: ['HS256'], issuer: env.JWT_ISSUER, audience: 'mfa' });
  if (claims.purpose !== 'mfa') throw new Error('Wrong token purpose');
  return claims;
}

// ---------- refresh token (the session)
export async function issueSession(req, res, user, opts = {}) {
  const familyId = opts.familyId ?? crypto.randomUUID();
  const sessionExpiresAt = opts.sessionExpiresAt ?? new Date(Date.now() + SESSION_MAX);
  const expiresAt = new Date(Math.min(Date.now() + REFRESH_TTL, sessionExpiresAt.getTime()));
  const raw = randomToken();

  await RefreshToken.create({
    userId: user._id,
    familyId,
    tokenHash: sha256(raw),
    expiresAt,
    sessionExpiresAt,
    userAgent: req.get('user-agent')?.slice(0, 200),
    ip: req.ip,
  });
  res.cookie(REFRESH_COOKIE, raw, { ...cookieBase, expires: expiresAt });
}

// Must use the same path/flags as when it was set, or the browser keeps the old cookie
export const clearRefreshCookie = (res) => res.clearCookie(REFRESH_COOKIE, cookieBase);

export const revokeFamily = (familyId, reason, extraFilter = {}) =>
  RefreshToken.updateMany(
    { familyId, revokedAt: null, ...extraFilter },
    { $set: { revokedAt: new Date(), revokeReason: reason } },
  );

export const revokeAllSessions = (userId, reason) =>
  RefreshToken.updateMany(
    { userId, revokedAt: null },
    { $set: { revokedAt: new Date(), revokeReason: reason } },
  );`,
      },
      {
        file: 'server/src/controllers/login.controller.js',
        code: code`
import { User } from '../models/User.js';
import { loginSchema } from '../validation/auth.schemas.js';
import { verifyPassword, fakeVerify, needsRehash, hashPassword } from '../services/password.js';
import { issueSession, signAccessToken, signMfaToken } from '../services/token.service.js';
import { clearLimit, emailKey } from '../middleware/rateLimit.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';

export async function login(req, res) {
  const { email, password } = loginSchema.parse(req.body);
  const user = await User.findOne({ email }).select('+passwordHash');

  // Do the same expensive work whether or not the user exists
  const valid = user?.passwordHash
    ? await verifyPassword(user.passwordHash, password)
    : await fakeVerify(password);

  if (!user || !valid || user.disabled) {
    audit(req, 'login.failed', { email });
    throw new HttpError(401, 'Invalid email or password', 'INVALID_CREDENTIALS');
  }

  await clearLimit('login-email', emailKey(email));

  if (needsRehash(user.passwordHash)) {
    user.passwordHash = await hashPassword(password);
    await user.save();
  }

  if (!user.emailVerified) {
    throw new HttpError(403, 'Confirm your email to continue. Check your inbox or request a new link.', 'EMAIL_NOT_VERIFIED');
  }

  if (user.mfa?.enabled) {
    // No session yet: the client must come back with a code within 5 minutes
    return res.json({ mfaRequired: true, mfaToken: signMfaToken(user) });
  }

  await issueSession(req, res, user);
  audit(req, 'login.success', { userId: user.id });
  res.json({ accessToken: signAccessToken(user), user: user.toPublic() });
}

export async function me(req, res) {
  const user = await User.findById(req.user.id);
  res.json({ user: user.toPublic() });
}`,
      },
      {
        file: 'server/src/middleware/rateLimit.js',
        note: 'A fixed-window limiter in about 30 lines. It is shared by every API instance because the counters live in Redis.',
        code: code`
import { redis } from '../lib/redis.js';
import { sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/http.js';

export async function hit(key, limit, windowSec) {
  const results = await redis
    .multi()
    .set(key, 0, 'EX', windowSec, 'NX')   // start the window if it doesn't exist
    .incr(key)
    .ttl(key)
    .exec();
  const count = results[1][1];
  const ttl = results[2][1];
  if (count > limit) {
    const err = new HttpError(429, 'Too many attempts. Wait a few minutes and try again.', 'RATE_LIMITED');
    err.retryAfter = ttl > 0 ? ttl : windowSec;
    throw err;
  }
  return count;
}

export function rateLimit({ name, limit, windowSec, key = (req) => req.ip }) {
  return async (req, res, next) => {
    const id = key(req);
    if (!id) return next();
    try {
      await hit(\`rl:\${name}:\${id}\`, limit, windowSec);
    } catch (err) {
      if (err.retryAfter) res.set('Retry-After', String(err.retryAfter));
      throw err;
    }
    next();
  };
}

// Hash emails so raw addresses never sit in Redis keys
export const emailKey = (email) => sha256(String(email).trim().toLowerCase()).slice(0, 32);
export const byEmail = (req) => (req.body?.email ? emailKey(req.body.email) : null);
export const byUser = (req) => req.user?.id ?? null;

export const clearLimit = (name, id) => redis.del(\`rl:\${name}:\${id}\`);`,
      },
      {
        file: 'server/src/lib/redis.js',
        code: code`
import IORedis from 'ioredis';
import { env } from '../config/env.js';
import { logger } from './logger.js';

export const redis = new IORedis(env.REDIS_URL, { enableAutoPipelining: true });

redis.on('error', (err) => logger.error({ err }, 'redis error'));`,
      },
      {
        file: 'server/src/routes/auth.routes.js',
        note: 'Every auth endpoint in this guide, with its rate limits. Routes that rely on the refresh cookie get the same-origin check (chapter 11).',
        code: code`
import { Router } from 'express';
import { rateLimit, byEmail, byUser } from '../middleware/rateLimit.js';
import { requireAuth } from '../middleware/auth.js';
import { requireSameOrigin } from '../middleware/security.js';
import { register, verifyEmail, resendVerification } from '../controllers/signup.controller.js';
import { login, me } from '../controllers/login.controller.js';
import { refresh } from '../controllers/refresh.controller.js';
import { listSessions, revokeSession, logout, logoutAll, changePassword } from '../controllers/sessions.controller.js';
import { forgotPassword, resetPassword } from '../controllers/recovery.controller.js';
import { verifyMfaLogin } from '../controllers/mfa.controller.js';
import { googleStart, googleCallback } from '../controllers/google.controller.js';

const MIN = 60;
export const authRouter = Router();

// sign-up
authRouter.post('/register', rateLimit({ name: 'register-ip', limit: 5, windowSec: 60 * MIN }), register);
authRouter.post('/verify-email', rateLimit({ name: 'verify-ip', limit: 20, windowSec: 15 * MIN }), verifyEmail);
authRouter.post('/resend-verification',
  rateLimit({ name: 'resend-ip', limit: 5, windowSec: 60 * MIN }),
  rateLimit({ name: 'resend-email', limit: 3, windowSec: 60 * MIN, key: byEmail }),
  resendVerification);

// login + second factor
authRouter.post('/login',
  rateLimit({ name: 'login-ip', limit: 20, windowSec: 15 * MIN }),
  rateLimit({ name: 'login-email', limit: 8, windowSec: 15 * MIN, key: byEmail }),
  login);
authRouter.post('/mfa/verify', rateLimit({ name: 'mfa-ip', limit: 20, windowSec: 15 * MIN }), verifyMfaLogin);

// cookie-based session routes
authRouter.post('/refresh', requireSameOrigin, rateLimit({ name: 'refresh-ip', limit: 60, windowSec: 5 * MIN }), refresh);
authRouter.post('/logout', requireSameOrigin, logout);

// recovery
authRouter.post('/forgot-password',
  rateLimit({ name: 'forgot-ip', limit: 5, windowSec: 15 * MIN }),
  rateLimit({ name: 'forgot-email', limit: 3, windowSec: 60 * MIN, key: byEmail }),
  forgotPassword);
authRouter.post('/reset-password', rateLimit({ name: 'reset-ip', limit: 10, windowSec: 15 * MIN }), resetPassword);

// Google
authRouter.get('/google', rateLimit({ name: 'google-ip', limit: 30, windowSec: 15 * MIN }), googleStart);
authRouter.get('/google/callback', googleCallback);

// signed-in account management
authRouter.get('/me', requireAuth, me);
authRouter.get('/sessions', requireAuth, listSessions);
authRouter.delete('/sessions/:familyId', requireAuth, revokeSession);
authRouter.post('/logout-all', requireAuth, logoutAll);
authRouter.post('/change-password', requireAuth,
  rateLimit({ name: 'change-pw', limit: 5, windowSec: 15 * MIN, key: byUser }),
  changePassword);`,
      },
    ],
    checklist: [
      'Login is rate-limited per IP and per (hashed) email in Redis',
      'Unknown emails go through <code>fakeVerify</code> and get the same error as wrong passwords',
      '<code>jwt.verify</code> pins <code>algorithms</code>, <code>issuer</code> and <code>audience</code>',
      'Access tokens live 15 minutes or less and contain no personal data',
      'The refresh cookie is <code>HttpOnly</code>, <code>Secure</code>, <code>SameSite=Strict</code>, <code>Path=/api/auth</code>',
      'Refresh tokens are stored as SHA-256 hashes with an absolute session cap',
      'Every login issues a brand-new session family',
      'Successful and failed logins are written to the audit log',
    ],
  });

  // ================================================================ 05 · Refresh + rotation
  AIM.chapters.push({
    id: 'tokens',
    num: '05',
    group: 'Core flows',
    short: 'Token refresh & rotation',
    title: 'Refresh token rotation',
    flowName: 'Silent refresh, and catching a stolen token',
    lede: 'A 15-minute access token keeps damage small, but nobody wants to log in every 15 minutes. Refresh tokens bridge the gap, and rotation turns a stolen refresh token into an alarm instead of a skeleton key.',
    actors: ['browser', 'api', 'db', 'attacker'],
    steps: [
      send('browser', 'api', 'token', 'GET /api/projects · Bearer (expired)', 'An access token quietly expires',
        `<p>Fifteen minutes after login, the user clicks something. The request carries an access token whose <code>exp</code> is in the past.</p>`),
      send('api', 'browser', 'token', '401 { code: "TOKEN_EXPIRED" }', 'The API says exactly why',
        `<p>A stable <code>code</code> lets the client tell "expired, go refresh" apart from "invalid" or "forbidden", which should not trigger a refresh.</p>`,
        `HTTP/1.1 401 Unauthorized
{ "error": "Session expired", "code": "TOKEN_EXPIRED" }`),
      proc('browser', 'token', 'interceptor: pause · single-flight refresh', 'The axios interceptor takes over',
        `<p>The response interceptor catches the 401 and starts <b>one</b> refresh. If five requests fail at once, they all wait on the same promise rather than firing five refreshes, which would trip reuse detection.</p><p>Across browser tabs, the Web Locks API makes tabs take turns.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/refresh · Cookie: rt=A', 'The cookie goes along automatically',
        `<p>JavaScript never touches the refresh token. The browser attaches it because the request goes to <code>/api/auth/*</code> on the same site.</p>`,
        `POST /api/auth/refresh
Cookie: rt=A_q0V3pN2kZ7…
X-Requested-With: fetch
Origin: https://app.example.com`),
      send('api', 'db', 'data', 'findOneAndUpdate({ hash(A), usedAt: null } → usedAt: now)', 'Claim the token atomically',
        `<p>One database operation both checks that token A is unused, unrevoked and unexpired, and marks it used. If two requests race, only one can win.</p>`),
      proc('api', 'token', 'A → B · same familyId', 'Rotate: the old token dies, a new one is born',
        `<p>The API issues refresh token <b>B</b> in the same family, keeping the family's absolute expiry. A is now permanently spent, and a fresh access token is signed.</p>`),
      send('api', 'db', 'data', 'insertOne({ hash(B), familyId })', 'Store B',
        `<p>The chain now reads A (used) → B (active). Only the newest token in a family is ever valid.</p>`),
      send('api', 'browser', 'token', '200 { accessToken } + Set-Cookie: rt=B', 'The browser gets both new tokens',
        `<p>The interceptor stores the new access token in memory and replays every queued request. The user never noticed.</p>`),
      send('browser', 'api', 'ok', 'retry GET /api/projects → 200', 'The original request succeeds',
        `<p>From the user's point of view, the click just worked.</p>`),
      send('attacker', 'api', 'attack', 'POST /refresh · Cookie: rt=A (stolen copy)', 'Old token A shows up again',
        `<p>Suppose malware or a compromised proxy copied token A earlier. The attacker now tries to use it.</p>`),
      proc('api', 'attack', 'A.usedAt is set → REUSE', 'Reuse detected',
        `<p>A rotated token should never come back. If it does, someone has a copy. The server can't tell whether the attacker or the real user is holding B, so it does the only safe thing: <b>revoke the whole family</b>.</p>`),
      send('api', 'db', 'data', 'updateMany({ familyId }, { revokedAt })', 'Kill the device session and log it',
        `<p>Both A and B are dead. A <code>session.reuse_detected</code> audit event fires, and that event should alert you.</p>`),
      send('api', 'attacker', 'attack', '401 SESSION_INVALID', 'The attacker gets nothing',
        `<p>The real user's next refresh with B also fails, so they're asked to sign in again. That's a small cost for cutting off a thief.</p>`),
    ],
    concept: `
<h3>Why two tokens?</h3>
<p>The access token is checked on every request, so it must be cheap to verify (a signature check, no database). That also makes it hard to revoke, so it must be <b>short-lived</b>. The refresh token is used rarely, so it can be checked against the database each time, which makes it <b>revocable</b> and safe to keep for weeks.</p>
<h3>Rotation and families</h3>
<ul>
  <li>Every refresh spends the presented token and issues a new one. A stolen token is useful only until the real client refreshes.</li>
  <li>All tokens descended from one login share a <code>familyId</code>. Revoking a family signs out exactly one device.</li>
  <li>The family has an <b>absolute expiry</b> (60 days here). Rotation can't extend a session forever.</li>
  <li>Used tokens stay in the database until a week after expiry, so a replay is recognised as reuse rather than as "unknown token".</li>
</ul>
<h3>The multi-tab trap</h3>
<p>Two tabs that refresh at the same moment both send token A. One wins; the other looks exactly like reuse and logs the user out. Fix it on the client: a single-flight promise inside a tab and <code>navigator.locks</code> across tabs, so the second tab waits and then sends the cookie B that the first tab received. Some teams also accept a reused token within a 10–30 second grace window; that's a trade-off you can add later.</p>
<h3>When the app loads</h3>
<p>The access token is gone after a reload because it lived in memory. On start-up the app calls <code>/api/auth/refresh</code> once. Success means "signed in"; a 401 means "show the login page". Chapter 12 builds that into the React <code>AuthProvider</code>.</p>
<p class="callout"><b>Clock skew.</b> Servers' clocks drift. Allow a few seconds of <code>clockTolerance</code> when verifying, and let the client refresh on a 401 rather than trying to predict expiry exactly.</p>`,
    threats: [
      { name: 'Stolen refresh token', risk: 'A long-lived token copied from a device grants access for weeks.', fix: 'HttpOnly cookie, rotation on every use, reuse detection that revokes the family, and an absolute session cap.' },
      { name: 'Race between parallel refreshes', risk: 'Two requests read "unused" before either writes "used", so both mint new tokens and the chain forks.', fix: 'A single <code>findOneAndUpdate</code> with <code>usedAt: null</code> in the filter: an atomic compare-and-set.' },
      { name: 'False reuse from multiple tabs', risk: 'Legitimate tabs refreshing together trip reuse detection and log people out randomly.', fix: 'Single-flight promise per tab and <code>navigator.locks.request(\'auth-refresh\')</code> across tabs.' },
      { name: 'Endless sessions', risk: 'Rolling expiry means an active (or stolen) session never has to re-authenticate.', fix: '<code>sessionExpiresAt</code> copied unchanged to every rotated token.' },
      { name: 'CSRF on the refresh route', risk: 'A malicious site makes the browser POST to <code>/refresh</code> with the cookie attached.', fix: '<code>SameSite=Strict</code>, a required <code>X-Requested-With</code> header and an <code>Origin</code> allowlist. The response is unreadable cross-origin anyway thanks to CORS.' },
    ],
    code: [
      {
        file: 'server/src/controllers/refresh.controller.js',
        code: code`
import { User } from '../models/User.js';
import { RefreshToken } from '../models/RefreshToken.js';
import {
  REFRESH_COOKIE, issueSession, signAccessToken, clearRefreshCookie, revokeFamily,
} from '../services/token.service.js';
import { sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';

const sessionEnded = () => new HttpError(401, 'Your session ended. Sign in again.', 'SESSION_INVALID');

export async function refresh(req, res) {
  const raw = req.cookies[REFRESH_COOKIE];
  if (!raw) throw new HttpError(401, 'Not signed in', 'NO_SESSION');

  const tokenHash = sha256(raw);
  const now = new Date();

  // Atomic compare-and-set: only one request can ever spend this token
  const claimed = await RefreshToken.findOneAndUpdate(
    { tokenHash, usedAt: null, revokedAt: null, expiresAt: { $gt: now } },
    { $set: { usedAt: now } },
  );

  if (!claimed) {
    const known = await RefreshToken.findOne({ tokenHash });
    if (known?.usedAt && !known.revokedAt) {
      // A token that was already rotated came back: someone holds a copy
      await revokeFamily(known.familyId, 'reuse_detected');
      audit(req, 'session.reuse_detected', { userId: String(known.userId), familyId: known.familyId });
    }
    clearRefreshCookie(res);
    throw sessionEnded();
  }

  const user = await User.findById(claimed.userId);
  if (!user || user.disabled) {
    await revokeFamily(claimed.familyId, 'user_unavailable');
    clearRefreshCookie(res);
    throw sessionEnded();
  }

  await issueSession(req, res, user, {
    familyId: claimed.familyId,
    sessionExpiresAt: claimed.sessionExpiresAt,   // rotation never extends the absolute cap
  });

  res.json({ accessToken: signAccessToken(user), user: user.toPublic() });
}`,
      },
      {
        file: 'client/src/api/client.js',
        note: 'The single axios instance the whole React app uses. The access token never leaves this module\'s memory.',
        code: code`
import axios from 'axios';

let accessToken = null;
export const setAccessToken = (token) => { accessToken = token; };

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '/api',
  withCredentials: true,                            // send and accept the refresh cookie
  headers: { 'X-Requested-With': 'fetch' },        // required by the API's CSRF check
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = \`Bearer \${accessToken}\`;
  return config;
});

// ---------- one refresh at a time, in this tab and across tabs
let refreshing = null;

function doRefresh() {
  return api.post('/auth/refresh', null, { skipAuthRefresh: true }).then(({ data }) => {
    setAccessToken(data.accessToken);
    return data;
  });
}

export function refreshSession() {
  refreshing ??= (navigator.locks
    ? navigator.locks.request('auth-refresh', doRefresh)   // other tabs wait their turn
    : doRefresh()
  ).finally(() => { refreshing = null; });
  return refreshing;
}

// ---------- retry once after a refresh when the access token has expired
const REFRESHABLE = new Set(['TOKEN_EXPIRED', 'TOKEN_REVOKED']);

api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error;
  if (!config || config.skipAuthRefresh || config._retried) throw error;
  if (response?.status !== 401 || !REFRESHABLE.has(response.data?.code)) throw error;

  config._retried = true;
  try {
    await refreshSession();
  } catch {
    setAccessToken(null);
    window.dispatchEvent(new Event('auth:session-lost'));   // AuthProvider listens and shows login
    throw error;
  }
  return api(config);
});`,
      },
    ],
    checklist: [
      'Refresh tokens rotate on every use',
      'Spending a token is a single atomic <code>findOneAndUpdate</code>',
      'A replayed rotated token revokes its whole family and raises an alert',
      'Each family has an absolute expiry that rotation can\'t extend',
      'The client refreshes single-flight, with <code>navigator.locks</code> across tabs',
      'Only <code>TOKEN_EXPIRED</code>/<code>TOKEN_REVOKED</code> 401s trigger a refresh, and only once per request',
      'The refresh route requires the custom header and an allowed Origin',
    ],
  });

  // ================================================================ 06 · Authorization
  AIM.chapters.push({
    id: 'authorization',
    num: '06',
    group: 'Core flows',
    short: 'Authorization (roles & ownership)',
    title: 'Authorization: roles and ownership',
    flowName: 'Who may touch this record?',
    lede: 'Broken access control is the most common serious flaw in web apps. Logging people in correctly means nothing if any logged-in user can read, edit or delete anyone else\'s data by changing an id.',
    actors: ['browser', 'api', 'db', 'redis', 'attacker'],
    steps: [
      send('browser', 'api', 'token', 'PATCH /api/projects/66a1… · Bearer', 'A user edits their own project',
        `<p>The request names a resource by id and carries the access token.</p>`,
        `PATCH /api/projects/66a1f0c3b2e4d5a6f7b8c9d0
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9…
{ "name": "Q4 launch plan" }`),
      proc('api', 'token', 'requireAuth: verify sig · exp · iss · aud', 'Authenticate the request',
        `<p>The router mounts <code>requireAuth</code> in front of the whole <code>/api/projects</code> tree, so a new route can't be added without it. The token's claims give us <code>sub</code> and <code>ver</code>.</p>`),
      send('api', 'redis', 'data', 'GET authuser:66f1… (60s cache)', 'Is this user still allowed in at all?',
        `<p>A JWT can outlive a change: a disabled account, a demoted admin, a "sign out everywhere". A 60-second Redis cache of <code>{ role, tokenVersion, disabled }</code> lets every request check that cheaply. On a miss, it falls back to MongoDB.</p><p>If <code>ver</code> in the token doesn't match <code>tokenVersion</code>, the token is rejected immediately.</p>`),
      proc('api', 'token', "can(user, 'project:update', project)", 'Check the permission against the record',
        `<p>The role grants <code>project:update:own</code>. The rule compares <code>project.ownerId</code> with <code>user.id</code>. Admins hold <code>project:update:any</code> and skip the ownership check.</p>`),
      send('api', 'db', 'data', 'save({ name }) · ownerId untouched', 'Write only whitelisted fields',
        `<p>The body is parsed with a <code>.strict()</code> zod schema that accepts <code>name</code> and <code>description</code> only. <code>ownerId</code> comes from the token, never from the request.</p>`),
      send('api', 'browser', 'ok', '200 { project }', 'Allowed',
        `<p>The happy path. Now watch what the same checks stop.</p>`),
      block('attacker', 'api', 'PATCH /api/projects/<someone else\'s id>', '404 Not found', 'IDOR: swapping the id',
        `<p>The attacker is a real, logged-in user. They copy an id from a shared link or guess one, and send it with their own valid token. Authentication passes; this is purely an authorization question.</p><p>The ownership check fails, and the API answers <b>404</b> rather than 403 so it doesn't confirm the project exists.</p>`),
      block('attacker', 'api', 'PATCH /api/users/me { "role": "admin" }', '400 unrecognized key "role"', 'Mass assignment',
        `<p>If a handler does <code>Object.assign(user, req.body)</code> or <code>User.updateOne({ _id }, req.body)</code>, any field in the schema becomes writable, including <code>role</code>, <code>emailVerified</code> and <code>tokenVersion</code>.</p><p>A strict schema per endpoint rejects unknown keys.</p>`),
      block('attacker', 'api', 'GET /api/admin/users', '403 Forbidden', 'Vertical privilege escalation',
        `<p>The admin router is mounted behind <code>requireRole('admin')</code>. Hiding the admin link in React is a UX choice; this check is the security.</p>`),
    ],
    concept: `
<h3>Three questions on every request</h3>
<ol>
  <li><b>Who is calling?</b> <code>requireAuth</code> answers with <code>req.user</code>.</li>
  <li><b>May this kind of user do this kind of action?</b> Roles and permissions: "users can update their own projects; admins can update any".</li>
  <li><b>May this user do it to this record?</b> Ownership, team membership, or tenant. Checked against the loaded document, or baked into the query filter.</li>
</ol>
<h3>Models, from simple to rich</h3>
<dl>
  <dt>RBAC</dt><dd>Role-based. Roles map to permission strings. Enough for most medium apps: <code>user</code>, <code>admin</code>, maybe <code>support</code>.</dd>
  <dt>Ownership</dt><dd>The <code>:own</code> vs <code>:any</code> suffix in this guide. Covers "my stuff" apps.</dd>
  <dt>Multi-tenant</dt><dd>Every document carries an <code>orgId</code>, and every query filters by the caller's org. Roles live on the membership (<code>{ userId, orgId, role }</code>), not on the user.</dd>
  <dt>ABAC / ReBAC</dt><dd>Attribute or relationship based ("editors of the parent folder"). Reach for CASL, Oso, OpenFGA or Cerbos when your rules outgrow a lookup table.</dd>
</dl>
<h3>Rules that prevent most bugs</h3>
<ul>
  <li><b>Deny by default.</b> Mount <code>requireAuth</code> at the router level and explicitly list public routes.</li>
  <li><b>Scope queries, don't filter results.</b> <code>find({ ownerId: user.id })</code>, never <code>find()</code> then <code>.filter()</code> in JavaScript.</li>
  <li><b>404 for "not yours".</b> Don't confirm that other people's ids exist.</li>
  <li><b>Take identity from the token.</b> <code>ownerId</code>, <code>userId</code>, <code>orgId</code> come from <code>req.user</code>, never from the body or query.</li>
  <li><b>Allowlist writable fields</b> with a strict schema per endpoint.</li>
  <li><b>Project outputs.</b> Return <code>toPublic()</code> or a <code>.select()</code>; don't serialize whole documents.</li>
  <li><b>When roles change</b>, bump <code>tokenVersion</code> and clear the user cache. The client transparently refreshes and gets a token with the new role.</li>
</ul>
<h3>Status codes</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Situation</th><th>Status</th><th>Example code</th></tr></thead>
  <tbody>
    <tr><td>No token, expired, or invalid</td><td><code>401</code></td><td><code>NO_TOKEN</code>, <code>TOKEN_EXPIRED</code></td></tr>
    <tr><td>Signed in, but the role lacks this action</td><td><code>403</code></td><td><code>FORBIDDEN</code></td></tr>
    <tr><td>Signed in, the record exists, but it's someone else's</td><td><code>404</code></td><td><code>NOT_FOUND</code></td></tr>
    <tr><td>Signed in, but needs a fresh password or 2FA code for this action</td><td><code>403</code></td><td><code>REAUTH_REQUIRED</code></td></tr>
  </tbody>
</table></div>`,
    threats: [
      { name: 'IDOR / BOLA', risk: 'Insecure direct object reference: <code>/api/invoices/1043</code> returns any invoice to any logged-in user who changes the number.', fix: 'Ownership in the query or a <code>can()</code> check against the loaded record, on every read, write and delete. 404 on mismatch.' },
      { name: 'Mass assignment', risk: 'Passing <code>req.body</code> straight to Mongoose lets users set <code>role</code>, <code>ownerId</code> or <code>emailVerified</code>.', fix: 'A <code>.strict()</code> zod schema per endpoint; set ownership fields from <code>req.user</code>.' },
      { name: 'Stale privileges', risk: 'A demoted admin keeps admin power until their JWT expires; a banned user keeps using the app.', fix: 'Check <code>tokenVersion</code> and <code>disabled</code> through a short Redis cache; bump the version on role changes.' },
      { name: 'Missing check on a new route', risk: 'Someone adds <code>router.get(\'/export\')</code> and forgets the middleware.', fix: 'Mount <code>requireAuth</code> on the router, not on each route. Add a test that hits every route without a token and expects 401.' },
      { name: 'Client-side only checks', risk: 'Hiding a button in React doesn\'t stop anyone from calling the endpoint with curl.', fix: 'Treat UI checks as convenience. The API enforces every rule.' },
      { name: 'Over-sharing responses', risk: 'Returning a full user document leaks hashes, emails or internal flags to other users.', fix: '<code>toPublic()</code>, explicit <code>.select()</code> and <code>select: false</code> on sensitive fields.' },
    ],
    code: [
      {
        file: 'server/src/middleware/auth.js',
        code: code`
import { verifyAccessToken } from '../services/token.service.js';
import { getAuthUser } from '../services/authUser.js';
import { can } from '../auth/permissions.js';
import { HttpError } from '../utils/http.js';

export async function requireAuth(req, res, next) {
  const [scheme, token] = (req.get('authorization') ?? '').split(' ');
  if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Sign in to continue', 'NO_TOKEN');

  let claims;
  try {
    claims = verifyAccessToken(token);
  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    throw new HttpError(401, expired ? 'Session expired' : 'Invalid token', expired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN');
  }

  const user = await getAuthUser(claims.sub);
  if (!user || user.disabled || user.tokenVersion !== claims.ver) {
    throw new HttpError(401, 'Session revoked', 'TOKEN_REVOKED');
  }

  req.user = user;   // { id, role, tokenVersion, emailVerified, disabled }
  next();
}

export const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) throw new HttpError(403, 'You do not have access to this', 'FORBIDDEN');
  next();
};

// For global permissions that don't depend on a specific record
export const requirePermission = (action) => (req, res, next) => {
  if (!can(req.user, action)) throw new HttpError(403, 'You do not have access to this', 'FORBIDDEN');
  next();
};`,
      },
      {
        file: 'server/src/services/authUser.js',
        code: code`
import { redis } from '../lib/redis.js';
import { User } from '../models/User.js';

const TTL_SECONDS = 60;
const key = (id) => \`authuser:\${id}\`;

// The minimum needed to authorize a request, cached briefly so it costs ~0.3 ms
export async function getAuthUser(id) {
  const cached = await redis.get(key(id));
  if (cached) return JSON.parse(cached);

  const doc = await User.findById(id).select('role tokenVersion disabled emailVerified').lean();
  if (!doc) return null;

  const user = {
    id: String(doc._id),
    role: doc.role,
    tokenVersion: doc.tokenVersion,
    disabled: Boolean(doc.disabled),
    emailVerified: doc.emailVerified,
  };
  await redis.set(key(id), JSON.stringify(user), 'EX', TTL_SECONDS);
  return user;
}

// Call after changing role, disabled or tokenVersion
export const invalidateAuthUser = (id) => redis.del(key(String(id)));`,
      },
      {
        file: 'server/src/auth/permissions.js',
        code: code`
// Every action the app knows about. Anything not granted here is denied.
const GRANTS = {
  user: [
    'project:create',
    'project:read:own', 'project:update:own', 'project:delete:own',
  ],
  admin: [
    'project:create',
    'project:read:any', 'project:update:any', 'project:delete:any',
    'user:read:any', 'user:disable:any',
  ],
};

const granted = Object.fromEntries(Object.entries(GRANTS).map(([role, list]) => [role, new Set(list)]));

/** May this user perform this action (optionally on this record)? */
export function can(user, action, resource) {
  const perms = granted[user?.role];
  if (!perms) return false;
  if (perms.has(action) || perms.has(\`\${action}:any\`)) return true;
  if (perms.has(\`\${action}:own\`) && resource) return String(resource.ownerId) === String(user.id);
  return false;
}

/** A Mongo filter restricting a list query to what this user may see, or null for nothing. */
export function scopeFor(user, action) {
  const perms = granted[user?.role];
  if (!perms) return null;
  if (perms.has(\`\${action}:any\`)) return {};
  if (perms.has(\`\${action}:own\`)) return { ownerId: user.id };
  return null;
}`,
      },
      {
        file: 'server/src/controllers/projects.controller.js',
        code: code`
import mongoose from 'mongoose';
import { z } from 'zod';
import { Project } from '../models/Project.js';
import { can, scopeFor } from '../auth/permissions.js';
import { HttpError } from '../utils/http.js';

// .strict() rejects unknown keys such as ownerId instead of silently passing them through
const projectInput = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(2000).optional(),
}).strict();

const notFound = () => new HttpError(404, 'Project not found', 'NOT_FOUND');

async function loadProject(req, action) {
  if (!mongoose.isValidObjectId(req.params.id)) throw notFound();
  const project = await Project.findById(req.params.id);
  // Same answer for "doesn't exist" and "not yours"
  if (!project || !can(req.user, action, project)) throw notFound();
  return project;
}

export async function listProjects(req, res) {
  const filter = scopeFor(req.user, 'project:read');
  if (!filter) throw new HttpError(403, 'You do not have access to this', 'FORBIDDEN');
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const projects = await Project.find(filter).sort({ updatedAt: -1 }).skip((page - 1) * 20).limit(20).lean();
  res.json(projects);
}

export async function getProject(req, res) {
  res.json(await loadProject(req, 'project:read'));
}

export async function createProject(req, res) {
  if (!can(req.user, 'project:create')) throw new HttpError(403, 'You do not have access to this', 'FORBIDDEN');
  const data = projectInput.parse(req.body);
  const project = await Project.create({ ...data, ownerId: req.user.id });   // owner from the token
  res.status(201).json(project);
}

export async function updateProject(req, res) {
  const project = await loadProject(req, 'project:update');
  Object.assign(project, projectInput.partial().parse(req.body));
  await project.save();
  res.json(project);
}

export async function deleteProject(req, res) {
  const project = await loadProject(req, 'project:delete');
  await project.deleteOne();
  res.status(204).end();
}`,
      },
      {
        file: 'server/src/routes/projects.routes.js',
        code: code`
import { Router } from 'express';
import { requireRole } from '../middleware/auth.js';
import {
  listProjects, getProject, createProject, updateProject, deleteProject,
} from '../controllers/projects.controller.js';
import { listUsers, disableUser } from '../controllers/admin.controller.js';

// Mounted in app.js as: app.use('/api/projects', requireAuth, projectsRouter)
export const projectsRouter = Router();
projectsRouter.get('/', listProjects);
projectsRouter.post('/', createProject);
projectsRouter.get('/:id', getProject);
projectsRouter.patch('/:id', updateProject);
projectsRouter.delete('/:id', deleteProject);

// Mounted as: app.use('/api/admin', requireAuth, adminRouter)
export const adminRouter = Router();
adminRouter.use(requireRole('admin'));          // every admin route, including future ones
adminRouter.get('/users', listUsers);
adminRouter.post('/users/:id/disable', disableUser);`,
      },
      {
        file: 'server/src/controllers/admin.controller.js',
        code: code`
import mongoose from 'mongoose';
import { User } from '../models/User.js';
import { revokeAllSessions } from '../services/token.service.js';
import { invalidateAuthUser } from '../services/authUser.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';

export async function listUsers(req, res) {
  const users = await User.find().select('email name role disabled emailVerified createdAt').limit(100).lean();
  res.json(users);
}

export async function disableUser(req, res) {
  if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, 'User not found', 'NOT_FOUND');
  if (req.params.id === req.user.id) throw new HttpError(400, 'You cannot disable your own account', 'SELF_DISABLE');

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { $set: { disabled: true }, $inc: { tokenVersion: 1 } },   // kills their access tokens
    { new: true },
  );
  if (!user) throw new HttpError(404, 'User not found', 'NOT_FOUND');

  await revokeAllSessions(user._id, 'disabled_by_admin');       // kills their refresh tokens
  await invalidateAuthUser(user.id);
  audit(req, 'admin.user_disabled', { userId: user.id, by: req.user.id });
  res.status(204).end();
}`,
      },
      {
        file: 'client/src/auth/RoleGate.jsx',
        lang: 'jsx',
        code: code`
import { useAuth } from './AuthProvider';

// UI convenience only: hides controls the user can't use.
// The API enforces the real rule on every request.
export function RoleGate({ roles, children, fallback = null }) {
  const { user } = useAuth();
  return user && roles.includes(user.role) ? children : fallback;
}

// Usage:
// <RoleGate roles={['admin']}><Link to="/admin">Admin</Link></RoleGate>`,
      },
    ],
    checklist: [
      '<code>requireAuth</code> is mounted per router, not remembered per route',
      'Every read, update and delete checks ownership or scopes the query',
      '"Not yours" returns 404, not 403',
      'Ownership fields come from <code>req.user</code>, never the request body',
      'Every write endpoint uses a <code>.strict()</code> schema',
      'Role changes bump <code>tokenVersion</code> and clear the auth cache',
      'A test calls every route without a token and expects 401',
      'Admin routes sit behind <code>requireRole(\'admin\')</code> at the router level',
    ],
  });

  // ================================================================ 07 · Sessions + logout
  AIM.chapters.push({
    id: 'sessions',
    num: '07',
    group: 'Core flows',
    short: 'Sessions & logout',
    title: 'Sessions, logout and revocation',
    flowName: 'Signing out one device, or all of them',
    lede: 'A logout that only clears React state leaves a working session on the server. Real logout revokes server-side state, and a password change should end every other session immediately.',
    actors: ['browser', 'api', 'db', 'redis', 'mail'],
    steps: [
      send('browser', 'api', 'token', 'GET /api/auth/sessions', 'Open "Your devices"',
        `<p>Because this route lives under <code>/api/auth</code>, the browser also sends the refresh cookie, which lets the API mark which row is <i>this</i> device.</p>`),
      send('api', 'db', 'data', 'find({ userId, usedAt: null, revokedAt: null })', 'Each family has exactly one live token',
        `<p>The unused, unrevoked token of each family represents one signed-in device.</p>`),
      send('api', 'browser', 'data', '[ MacBook · Chrome (this device), iPhone · Safari ]', 'Show the list',
        `<p>User agent, approximate location from IP, last active time. Users spot "I don't own a Windows laptop" faster than any anomaly detector.</p>`,
        `[
  { "id": "1b7e…", "userAgent": "Mozilla/5.0 (Macintosh…) Chrome/131", "ip": "203.0.113.9", "lastActiveAt": "2026-11-02T21:58:00Z", "current": true },
  { "id": "9c40…", "userAgent": "Mozilla/5.0 (iPhone…) Safari/604.1", "ip": "198.51.100.23", "lastActiveAt": "2026-10-29T08:12:00Z", "current": false }
]`),
      send('browser', 'api', 'token', 'DELETE /api/auth/sessions/9c40…', 'Sign out the lost phone',
        `<p>The request names a family id. That id is an object reference like any other, so the API must check it belongs to the caller.</p>`),
      send('api', 'db', 'data', 'updateMany({ familyId, userId }, { revokedAt })', 'Revoke, scoped to the caller',
        `<p>Including <code>userId: req.user.id</code> in the filter means a guessed family id from another account matches nothing. The phone's next refresh fails and it lands on the login page within 15 minutes.</p>`),
      send('browser', 'api', 'token', 'POST /api/auth/logout · Cookie: rt', 'Log out this device',
        `<p>Logout needs the cookie, not the access token, so it still works when the access token has already expired.</p>`),
      send('api', 'db', 'data', 'revoke family of hash(rt)', 'Kill this session server-side',
        `<p>Even if someone copied the refresh cookie a minute ago, it's now useless.</p>`),
      send('api', 'browser', 'ok', '204 · Set-Cookie: rt=; Expires=1970', 'Clear the cookie with matching flags',
        `<p>A cookie is deleted only if the clearing <code>Set-Cookie</code> uses the same <code>Path</code> and <code>Domain</code>. Use the same options object for setting and clearing.</p>`,
        `HTTP/1.1 204 No Content
Set-Cookie: rt=; Path=/api/auth; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`),
      proc('browser', 'token', "token = null · BroadcastChannel('auth')", 'Every open tab logs out',
        `<p>The client drops its in-memory access token, clears cached user data (React Query cache too) and broadcasts <code>logout</code> so other tabs follow.</p>`),
      send('browser', 'api', 'cred', 'POST /api/auth/change-password', 'Change password: everything else must go',
        `<p>Requires the current password, even though the user is signed in. A borrowed laptop or a stolen session shouldn't be able to lock the owner out.</p>`),
      send('api', 'db', 'data', 'new hash · tokenVersion++ · revoke all families', 'Invalidate every token at once',
        `<p>Revoking all refresh families stops future refreshes. Incrementing <code>tokenVersion</code> kills every outstanding <b>access</b> token too, because <code>requireAuth</code> compares it on each request.</p>`),
      send('api', 'redis', 'data', 'DEL authuser:66f1…', 'Clear the cached user',
        `<p>Without this, the old <code>tokenVersion</code> could be served from cache for up to 60 seconds.</p>`),
      send('api', 'mail', 'mail', '"Your password was changed"', 'Tell the owner',
        `<p>If an attacker changed it, this email is how the real owner finds out. Include the time and a link to reset.</p>`),
      send('api', 'browser', 'token', '200 { accessToken } + new rt', 'This device stays signed in',
        `<p>The current device gets a brand-new session family, so the person who just changed their password isn't punished for it.</p>`),
    ],
    concept: `
<h3>Revocation options for stateless access tokens</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Approach</th><th>How fast</th><th>Cost</th></tr></thead>
  <tbody>
    <tr><td>Short expiry only</td><td>Up to 15 minutes</td><td>Free</td></tr>
    <tr><td><code>tokenVersion</code> check through a 60 s Redis cache (this guide)</td><td>Instant if you clear the cache, ≤60 s otherwise</td><td>One Redis GET per request</td></tr>
    <tr><td>Denylist of <code>jti</code> ids in Redis with TTL = remaining lifetime</td><td>Instant, per token</td><td>One Redis lookup per request, and you need a <code>jti</code> claim</td></tr>
  </tbody>
</table></div>
<h3>Events that should end sessions</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Event</th><th>This device</th><th>Other devices</th><th>Email the user</th></tr></thead>
  <tbody>
    <tr><td>Logout</td><td>Revoke</td><td>Keep</td><td>No</td></tr>
    <tr><td>"Sign out everywhere"</td><td>Revoke</td><td>Revoke</td><td>Optional</td></tr>
    <tr><td>Password changed</td><td>New session</td><td>Revoke</td><td><span class="good">Yes</span></td></tr>
    <tr><td>Password reset by email</td><td>Revoke (sign in again)</td><td>Revoke</td><td><span class="good">Yes</span></td></tr>
    <tr><td>2FA enabled or disabled</td><td>New session</td><td>Revoke</td><td><span class="good">Yes</span></td></tr>
    <tr><td>Account disabled by an admin</td><td>Revoke</td><td>Revoke</td><td>Depends</td></tr>
    <tr><td>Refresh-token reuse detected</td><td colspan="2">Revoke that family</td><td>Consider it</td></tr>
  </tbody>
</table></div>
<h3>Idle and absolute timeouts</h3>
<p>The <b>idle timeout</b> is the refresh token's own lifetime (14 days here): a device unused for two weeks has to sign in again. The <b>absolute timeout</b> is the family's <code>sessionExpiresAt</code> (60 days). Banking-style apps use minutes and hours instead; pick numbers that match your risk.</p>
<h3>Step-up authentication</h3>
<p>Some actions deserve fresh proof even inside a valid session: changing email or password, disabling 2FA, deleting the account, viewing API keys. Ask for the password or a 2FA code right there. A common pattern is a short-lived <code>reauthAt</code> timestamp you check on sensitive routes.</p>
<h3>Deleting an account</h3>
<p>Require step-up auth, revoke all sessions, then delete or anonymize personal data and the user's tokens. Data-protection laws like GDPR give users the right to erasure, and an explicit flow makes it a button instead of a support ticket.</p>`,
    threats: [
      { name: 'Client-only logout', risk: 'React clears its state but the refresh token keeps working for anyone who copied it.', fix: 'Revoke the family on the server and clear the cookie.' },
      { name: 'Sessions survive a password change', risk: 'The attacker who knew the old password stays logged in after the victim changes it.', fix: 'Revoke all families, bump <code>tokenVersion</code>, clear the auth cache, email the user.' },
      { name: 'IDOR on session ids', risk: '<code>DELETE /sessions/:id</code> without a user filter lets anyone sign out anyone.', fix: 'Include <code>userId: req.user.id</code> in the revoke filter.' },
      { name: 'Cookie not actually cleared', risk: '<code>clearCookie</code> with a different <code>path</code> or <code>domain</code> creates a second cookie and leaves the real one in place.', fix: 'One shared options object for <code>cookie</code> and <code>clearCookie</code>.' },
      { name: 'Hijacking a signed-in device', risk: 'Someone at an unlocked laptop changes the email and password and takes over the account.', fix: 'Step-up auth (current password or 2FA code) for email, password and 2FA changes; notify the old email.' },
    ],
    code: [
      {
        file: 'server/src/controllers/sessions.controller.js',
        code: code`
import { User } from '../models/User.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { mailQueue } from '../jobs/mail.queue.js';
import {
  REFRESH_COOKIE, clearRefreshCookie, revokeFamily, revokeAllSessions, issueSession, signAccessToken,
} from '../services/token.service.js';
import { invalidateAuthUser } from '../services/authUser.js';
import { verifyPassword, hashPassword, isBreached } from '../services/password.js';
import { changePasswordSchema } from '../validation/auth.schemas.js';
import { sha256 } from '../utils/crypto.js';
import { HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';

export async function listSessions(req, res) {
  const raw = req.cookies[REFRESH_COOKIE];
  const currentHash = raw ? sha256(raw) : null;
  const active = await RefreshToken.find({
    userId: req.user.id, usedAt: null, revokedAt: null, expiresAt: { $gt: new Date() },
  }).sort({ createdAt: -1 }).lean();

  res.json(active.map((t) => ({
    id: t.familyId,
    userAgent: t.userAgent,
    ip: t.ip,
    lastActiveAt: t.createdAt,   // a token is created on every refresh
    current: t.tokenHash === currentHash,
  })));
}

export async function revokeSession(req, res) {
  // userId in the filter: you can only revoke your own sessions
  await revokeFamily(req.params.familyId, 'user_revoked', { userId: req.user.id });
  audit(req, 'session.revoked', { userId: req.user.id, familyId: req.params.familyId });
  res.status(204).end();
}

export async function logout(req, res) {
  const raw = req.cookies[REFRESH_COOKIE];
  if (raw) {
    const token = await RefreshToken.findOne({ tokenHash: sha256(raw) }).lean();
    if (token) {
      await revokeFamily(token.familyId, 'logout');
      audit(req, 'logout', { userId: String(token.userId) });
    }
  }
  clearRefreshCookie(res);
  res.status(204).end();
}

export async function logoutAll(req, res) {
  await User.updateOne({ _id: req.user.id }, { $inc: { tokenVersion: 1 } });
  await revokeAllSessions(req.user.id, 'logout_all');
  await invalidateAuthUser(req.user.id);
  clearRefreshCookie(res);
  audit(req, 'logout.all', { userId: req.user.id });
  res.status(204).end();
}

export async function changePassword(req, res) {
  const { currentPassword, newPassword } = changePasswordSchema.parse(req.body);
  const user = await User.findById(req.user.id).select('+passwordHash');

  if (!user.passwordHash || !(await verifyPassword(user.passwordHash, currentPassword))) {
    throw new HttpError(400, 'Your current password is incorrect', 'INVALID_PASSWORD');
  }
  if (await isBreached(newPassword)) {
    throw new HttpError(400, 'This password appeared in a data breach. Choose a different one.', 'PASSWORD_BREACHED');
  }

  user.passwordHash = await hashPassword(newPassword);
  user.passwordChangedAt = new Date();
  user.tokenVersion += 1;                       // every access token everywhere is now invalid
  await user.save();

  await revokeAllSessions(user._id, 'password_changed');
  await invalidateAuthUser(user.id);
  await issueSession(req, res, user);           // keep this device signed in with a fresh family

  await mailQueue.add('password-changed', { to: user.email, when: new Date().toUTCString() });
  audit(req, 'password.changed', { userId: user.id });
  res.json({ accessToken: signAccessToken(user) });
}`,
      },
      {
        file: 'client/src/pages/Sessions.jsx',
        lang: 'jsx',
        code: code`
import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../auth/AuthProvider';

function describe(ua = '') {
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return \`\${browser} on \${os}\`;
}

export default function Sessions() {
  const { logoutEverywhere } = useAuth();
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState('');

  const load = () =>
    api.get('/auth/sessions')
      .then(({ data }) => setSessions(data))
      .catch(() => setError('Could not load your devices. Refresh to try again.'));

  useEffect(() => { load(); }, []);

  async function revoke(id) {
    await api.delete(\`/auth/sessions/\${id}\`);
    load();
  }

  if (error) return <p role="alert">{error}</p>;
  if (!sessions) return <p>Loading your devices…</p>;

  return (
    <section>
      <h2>Where you're signed in</h2>
      <ul>
        {sessions.map((s) => (
          <li key={s.id}>
            <strong>{describe(s.userAgent)}</strong> · {s.ip} · active {new Date(s.lastActiveAt).toLocaleString()}
            {s.current ? <em> (this device)</em> : <button onClick={() => revoke(s.id)}>Sign out</button>}
          </li>
        ))}
      </ul>
      <button onClick={logoutEverywhere}>Sign out of all devices</button>
    </section>
  );
}`,
      },
    ],
    checklist: [
      'Logout revokes the refresh family on the server and clears the cookie with identical options',
      'Users can see and revoke their active sessions',
      'Session revocation filters by <code>userId</code>',
      'Password change requires the current password and revokes every other session',
      '<code>tokenVersion</code> bumps also clear the Redis auth cache',
      'Users get an email when their password or 2FA settings change',
      'Logout is broadcast to other tabs and clears client-side caches',
      'Sensitive actions require step-up authentication',
    ],
  });
})();
