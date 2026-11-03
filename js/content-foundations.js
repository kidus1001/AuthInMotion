/* Shared helpers + chapters 01–02 */
(function () {
  'use strict';
  const AIM = (window.AIM = { chapters: [] });

  // Tagged template for code samples: keeps backslashes as written.
  // Inside samples, write \` for a backtick and \${ for a template placeholder.
  AIM.code = (strings) => strings.raw.join('').replace(/\\([`$])/g, '$1').replace(/^\n/, '').replace(/\s+$/, '');
  AIM.send = (from, to, kind, label, title, text, payload) => ({ type: 'send', from, to, kind, label, title, text, payload });
  AIM.proc = (at, kind, label, title, text, payload) => ({ type: 'process', at, kind, label, title, text, payload });
  AIM.block = (from, to, label, result, title, text, payload) => ({ type: 'blocked', from, to, kind: 'attack', label, result, title, text, payload });

  const { code, send, proc, block } = AIM;

  // ================================================================ 01 · Big picture
  AIM.chapters.push({
    id: 'overview',
    num: '01',
    group: 'Foundations',
    short: 'The big picture',
    title: 'The big picture',
    flowName: 'One authenticated request',
    lede: 'Authentication proves who someone is. Authorization decides what they may do. Every request in your app passes through both, in that order, and this chapter follows one of them from login to data.',
    actors: ['browser', 'api', 'db', 'redis'],
    steps: [
      send('browser', 'api', 'cred', 'POST /api/auth/login', 'The user proves who they are',
        `<p>The React app sends an email and password over HTTPS. This is <b>authentication</b>: proving identity with something the user <i>knows</i> (a password), <i>has</i> (a phone, a security key) or <i>is</i> (a fingerprint, through a passkey).</p>`,
        `POST /api/auth/login HTTP/1.1
Host: api.example.com
Content-Type: application/json
X-Requested-With: fetch

{ "email": "ana@example.com", "password": "correct horse battery staple" }`),
      send('api', 'redis', 'data', 'INCR rl:login-ip:203.0.113.9', 'Throttle before doing expensive work',
        `<p>Before touching the database or hashing anything, the API bumps a counter in Redis for this IP and for this email. Too many attempts in 15 minutes means a <code>429 Too Many Requests</code> right here.</p><p>Redis is shared by every API instance, so the limit holds even when you run several servers.</p>`),
      send('api', 'db', 'data', 'users.findOne({ email })', 'Look up the account',
        `<p>The API fetches the user, including the <code>passwordHash</code> field that is hidden from every other query by default (<code>select: false</code>).</p>`),
      send('db', 'api', 'data', '{ _id, passwordHash, role, mfa }', 'The database returns a hash, never a password',
        `<p>MongoDB never had the real password. It stores an <b>argon2id</b> hash: a one-way, slow, salted fingerprint of it.</p>`,
        `{
  "_id": "66f1c2…",
  "email": "ana@example.com",
  "passwordHash": "$argon2id$v=19$m=19456,t=2,p=1$Zk9x…$9dJ…",
  "role": "user",
  "emailVerified": true,
  "tokenVersion": 3
}`),
      proc('api', 'cred', 'argon2.verify(hash, password)', 'Compare the proof',
        `<p>The API hashes the submitted password with the same salt and parameters and compares the result in constant time. A match means the user is <b>authenticated</b>.</p>`),
      send('api', 'browser', 'token', '200 { accessToken } + Set-Cookie: rt', 'Hand back two tokens',
        `<p>An <b>access token</b> (a signed JWT that expires in 15 minutes) goes back in the JSON body. A <b>refresh token</b> (random, long-lived) goes in an <code>HttpOnly</code> cookie that JavaScript cannot read.</p>`,
        `HTTP/1.1 200 OK
Set-Cookie: rt=q0V3…; Path=/api/auth; HttpOnly; Secure; SameSite=Strict; Expires=…
Content-Type: application/json

{ "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NmYxYzIi…", "user": { "id": "66f1c2…", "role": "user" } }`),
      send('browser', 'api', 'token', 'GET /api/projects · Bearer eyJ…', 'Every later request carries the access token',
        `<p>The app keeps the access token in memory and attaches it as a header. The server can check it without a database lookup because it is <b>signed</b>: any change to it breaks the signature.</p>`,
        `GET /api/projects HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NmYxYzIi…`),
      proc('api', 'token', 'requireAuth → can(user, action)', 'Authenticate, then authorize',
        `<p><code>requireAuth</code> verifies the signature, expiry, issuer and audience, then attaches <code>req.user</code>. <b>Authorization</b> comes next: is this user allowed to do <i>this</i> to <i>this</i> resource?</p><p>Missing or bad token → <code>401 Unauthorized</code>. Valid token, but not allowed → <code>403 Forbidden</code> (or <code>404</code> to hide that the thing exists).</p>`),
      send('api', 'db', 'data', 'projects.find({ ownerId: user.id })', 'Scope every query to the caller',
        `<p>The query itself is filtered by the authenticated user's id. Even if the UI had a bug, the database can only return this user's rows.</p>`),
      send('api', 'browser', 'ok', '200 [ …3 projects ]', 'Data returns to the right person',
        `<p>That is the whole loop. The rest of this guide zooms into each step: how to store passwords, mint and rotate tokens, verify email, recover accounts, add a second factor, sign in with Google and defend all of it.</p>`),
    ],
    concept: `
<h3>Two questions, asked in order</h3>
<dl>
  <dt>Authentication (AuthN)</dt><dd>Who are you? Proven with a password, a code from a phone, a passkey or a Google sign-in. Failure is <code>401 Unauthorized</code> (the name is a historical accident: it means <i>unauthenticated</i>).</dd>
  <dt>Authorization (AuthZ)</dt><dd>What may you do? Decided by roles, ownership and rules on every request. Failure is <code>403 Forbidden</code>, or <code>404 Not Found</code> when you don't want to confirm the resource exists.</dd>
</dl>
<h3>The system you will build</h3>
<ul>
  <li><b>React app</b> keeps the short-lived access token in memory, never in <code>localStorage</code>.</li>
  <li><b>Express API</b> owns all auth logic: hashing, tokens, rate limits, email links, 2FA, Google sign-in.</li>
  <li><b>MongoDB</b> stores users, hashed refresh tokens, hashed one-time tokens and an audit log.</li>
  <li><b>Redis</b> holds rate-limit counters, a 60-second user cache and the background email queue.</li>
  <li><b>An email provider</b> (Amazon SES, Resend, Postmark, any SMTP) delivers verification and reset links.</li>
</ul>
<h3>Sessions or JWTs?</h3>
<p>Both are production-grade. The question is where the truth about a login lives.</p>
<div class="table-wrap"><table>
  <thead><tr><th></th><th>Server sessions (express-session + Redis)</th><th>Access JWT + rotating refresh token (this guide)</th></tr></thead>
  <tbody>
    <tr><td>What the browser holds</td><td>An opaque session id in an HttpOnly cookie</td><td>A 15-min JWT in memory + a refresh token in an HttpOnly cookie</td></tr>
    <tr><td>Per-request cost</td><td>One store lookup</td><td>A signature check (plus an optional cached user check)</td></tr>
    <tr><td>Instant logout</td><td><span class="good">Yes</span>, delete the session</td><td>Within 15 min, or instantly with a <code>tokenVersion</code> check</td></tr>
    <tr><td>Mobile apps and other APIs</td><td>Awkward (cookies)</td><td><span class="good">Natural</span> (Bearer header)</td></tr>
    <tr><td>CSRF exposure</td><td>Every route uses the cookie, so every route needs CSRF protection</td><td>Only the refresh and logout routes use the cookie</td></tr>
  </tbody>
</table></div>
<p class="callout"><b>Recommendation.</b> For a MERN app that might later get a mobile client, use the hybrid shown here. If you will only ever have one web app on one domain, plain server sessions are simpler and equally safe. Don't let anyone tell you sessions are outdated.</p>
<h3>Vocabulary you will see everywhere</h3>
<dl>
  <dt>Hash</dt><dd>A one-way fingerprint. You can check a guess against it but not reverse it.</dd>
  <dt>Salt</dt><dd>Random bytes mixed into each password hash so identical passwords get different hashes.</dd>
  <dt>JWT</dt><dd>JSON Web Token: <code>header.payload.signature</code>, base64url encoded. Signed, <b>not encrypted</b>: anyone can read the payload.</dd>
  <dt>Claim</dt><dd>A field inside a JWT: <code>sub</code> (user id), <code>exp</code> (expiry), <code>iss</code>, <code>aud</code>, <code>role</code>.</dd>
  <dt>Refresh token</dt><dd>A long-lived random secret, exchanged for new access tokens. Stored hashed on the server.</dd>
  <dt>TOTP</dt><dd>Time-based one-time password: the 6-digit code an authenticator app shows every 30 seconds.</dd>
  <dt>OAuth 2.0 / OIDC</dt><dd>The protocols behind "Sign in with Google". OIDC adds a signed <code>id_token</code> that says who the user is.</dd>
</dl>`,
    threats: [
      { name: 'Broken access control', risk: 'The number one web risk on the OWASP Top 10. An endpoint checks that you are logged in but not that the record is yours, so changing an id in the URL returns someone else\'s data.', fix: 'Authorize on the server on every request, scope queries by <code>ownerId</code>, deny by default. Chapter 06.' },
      { name: 'Credential stuffing', risk: 'Attackers replay millions of email/password pairs leaked from other sites. People reuse passwords, so a few percent succeed.', fix: 'Rate limits per IP and per account in Redis, breached-password checks at signup, and 2FA. Chapters 02, 04, 09.' },
      { name: 'Token theft through XSS', risk: 'Tokens kept in <code>localStorage</code> can be read by any script that runs on your page, including injected ones.', fix: 'Access token in memory only, refresh token in an HttpOnly cookie, a strict Content Security Policy. Chapters 04, 11.' },
      { name: 'Weak account recovery', risk: 'A guessable or long-lived reset link is a password anyone can use.', fix: '256-bit random single-use tokens, stored hashed, valid 30 minutes, and every session revoked after a reset. Chapter 08.' },
      { name: 'User enumeration', risk: 'Different messages or response times for "no such user" and "wrong password" let attackers build a list of your customers.', fix: 'One generic message, a dummy hash check for unknown emails, and email sending off the request path. Chapters 03, 04.' },
    ],
    code: [
      {
        file: 'server/src/app.js',
        note: 'Wires every piece in this guide together. Each import is built in a later chapter.',
        code: code`
import express from 'express';
import cookieParser from 'cookie-parser';
import { env } from './config/env.js';
import { httpLogger } from './lib/logger.js';
import { securityHeaders, corsPolicy } from './middleware/security.js';
import { requireAuth } from './middleware/auth.js';
import { errorHandler, notFound } from './utils/http.js';
import { authRouter } from './routes/auth.routes.js';
import { mfaRouter } from './routes/mfa.routes.js';
import { projectsRouter } from './routes/projects.routes.js';

export const app = express();

// Behind exactly one proxy or load balancer (Render, Railway, Nginx, an AWS ALB).
// Without this, req.ip is the proxy's address and every user shares one rate limit.
app.set('trust proxy', 1);

app.use(securityHeaders);
app.use(corsPolicy);
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser(env.COOKIE_SECRET));
app.use(httpLogger);

app.get('/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRouter);                    // public + cookie routes
app.use('/api/mfa', requireAuth, mfaRouter);          // signed-in only
app.use('/api/projects', requireAuth, projectsRouter);

app.use(notFound);
app.use(errorHandler);`,
      },
      {
        file: 'server/src/server.js',
        code: code`
import mongoose from 'mongoose';
import { app } from './app.js';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';
import './jobs/mail.worker.js';   // starts the background email worker (or run it as its own process)

// Ignore filter fields that aren't in the schema. Operator injection ({ "$ne": null }) is
// stopped earlier by zod: every input field is validated as a string (chapter 11).
mongoose.set('strictQuery', true);

await mongoose.connect(env.MONGO_URI);
await mongoose.syncIndexes();   // creates the unique and TTL indexes declared in the models

const server = app.listen(env.PORT, () => logger.info(\`API listening on :\${env.PORT}\`));

// Finish in-flight requests on deploys instead of cutting them off
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    server.close(async () => {
      await mongoose.disconnect();
      process.exit(0);
    });
  });
}`,
      },
      {
        file: 'server/src/config/env.js',
        note: 'Crash at boot if a secret is missing or too short, instead of failing at 3am on the first login.',
        code: code`
import 'dotenv/config';
import { z } from 'zod';

const secret = z.string().min(32, 'Use at least 32 random characters');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),
  MONGO_URI: z.string().min(1),
  REDIS_URL: z.string().min(1),
  APP_URL: z.string().url(),          // the React app, e.g. https://app.example.com
  API_URL: z.string().url(),          // this API,     e.g. https://api.example.com
  JWT_ACCESS_SECRET: secret,
  JWT_MFA_SECRET: secret,             // a different key, so an MFA ticket can never pass as an access token
  JWT_ISSUER: z.string().default('api.example.com'),
  COOKIE_SECRET: secret,
  MFA_ENC_KEY: z.string().regex(/^[0-9a-f]{64}$/, '32 bytes as hex'),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  SMTP_URL: z.string().min(1),        // smtps://user:pass@email-smtp.eu-west-1.amazonaws.com:465
  MAIL_FROM: z.string().min(1),       // "YourApp <no-reply@mail.example.com>"
});

export const env = schema.parse(process.env);
export const isProd = env.NODE_ENV === 'production';

// Generate secrets with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
      },
      {
        file: 'server/src/utils/http.js',
        code: code`
import { ZodError } from 'zod';
import { logger } from '../lib/logger.js';

export class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;   // stable string the React app can switch on
  }
}

export function notFound(req, res) {
  res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' });
}

// Express 5 forwards rejected promises from async handlers here automatically.
// On Express 4, wrap handlers with express-async-handler.
export function errorHandler(err, req, res, _next) {
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'Some fields are invalid',
      code: 'VALIDATION',
      fields: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message, code: err.code });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large', code: 'TOO_LARGE' });
  }
  logger.error({ err, path: req.path }, 'unhandled error');
  // Never send stack traces or driver errors to the client
  res.status(500).json({ error: 'Something went wrong. Try again.', code: 'INTERNAL' });
}`,
      },
      {
        file: 'server/package.json',
        lang: 'javascript',
        code: code`
{
  "name": "api",
  "type": "module",
  "scripts": {
    "dev": "node --watch src/server.js",
    "start": "node src/server.js",
    "test": "vitest run"
  },
  "dependencies": {
    "argon2": "^0.41.1",
    "bullmq": "^5.12.0",
    "cookie-parser": "^1.4.7",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^5.1.0",
    "google-auth-library": "^9.14.0",
    "helmet": "^8.0.0",
    "ioredis": "^5.4.1",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.8.0",
    "nodemailer": "^6.9.15",
    "otplib": "^12.0.1",
    "pino": "^9.5.0",
    "pino-http": "^10.3.0",
    "qrcode": "^1.5.4",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "mongodb-memory-server": "^10.1.2",
    "supertest": "^7.0.0",
    "vitest": "^2.1.4"
  }
}`,
      },
    ],
    checklist: [
      'Every route is behind <code>requireAuth</code> unless it is deliberately public',
      'I can explain the difference between a 401 and a 403 in my own API',
      'Secrets are loaded from the environment and validated at boot',
      'The API runs only on HTTPS in production',
      '<code>trust proxy</code> matches my real proxy setup',
      'Errors never leak stack traces or database messages',
      'I picked sessions or JWT + refresh deliberately, and wrote down why',
    ],
  });

  // ================================================================ 02 · Passwords
  AIM.chapters.push({
    id: 'passwords',
    num: '02',
    group: 'Foundations',
    short: 'Storing passwords',
    title: 'Storing passwords',
    flowName: 'Hashing at signup, and a stolen database',
    lede: 'You will be breached one day, through a leaked backup, a bad IP allowlist or a bug. How you hash passwords decides whether that day is an incident or a catastrophe for your users.',
    actors: ['browser', 'api', 'db', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /api/auth/register', 'The password travels once, inside TLS',
        `<p>It is plaintext inside the HTTPS tunnel, and that is normal: TLS protects it in transit.</p><p>Don't hash on the client as a substitute. The client-side hash would simply become the password, and anyone who steals it can log in with it.</p>`,
        `POST /api/auth/register
Content-Type: application/json

{ "name": "Ana", "email": "ana@example.com", "password": "correct horse battery staple" }`),
      proc('api', 'cred', 'zod: 12–128 chars · HIBP check', 'Validate before hashing',
        `<p>Require <b>length, not complexity</b>: at least 12 characters (NIST now asks for 15 when the password is the only factor), at most 128 so nobody can send a 1 MB password to burn your CPU.</p><p>Then check it against the 900+ million leaked passwords in Have I Been Pwned. Only the first 5 characters of its SHA-1 hash leave your server (k-anonymity).</p>`,
        `GET https://api.pwnedpasswords.com/range/A94A8
→ 0018A45C4D1DEF81644B54AB7F969B88D65:3
  …
  FE5CCB19BA61C4C0873D391E987982FBBD3:41208   ← our suffix: seen 41,208 times → reject`),
      proc('api', 'cred', 'argon2id(password, randomSalt)', 'Hash with a slow, salted, memory-hard function',
        `<p><b>argon2id</b> generates a random 16-byte salt and uses 19 MiB of memory per hash. Memory is what makes it expensive on GPUs, which have thousands of cores but little memory per core.</p><p>The output string carries the algorithm, parameters, salt and hash together, so you store just one field.</p>`,
        `$argon2id$v=19$m=19456,t=2,p=1$Zk9xS3pRa1h2bWJtR2RqUQ$9dJ3l0u4mRk2nBqN8m1T0q3Q6m5rK4b1sY0bR3dZ2aQ
 └ algo    └ ver └ memory KiB, passes, lanes └ salt (base64)          └ hash`),
      send('api', 'db', 'data', 'users.insertOne({ passwordHash })', 'Only the hash is stored',
        `<p>No plaintext copy anywhere: not in the database, not in logs, not in error reports. The logger redacts any field named <code>password</code>.</p>`),
      send('attacker', 'db', 'attack', 'mongodump → users.bson', 'Assume the database leaks',
        `<p>A backup bucket left public, an Atlas cluster open to <code>0.0.0.0/0</code>, an injection bug. Plan for the dump being on a forum tomorrow.</p>`),
      proc('attacker', 'attack', 'hashcat: guess → hash → compare', 'The attacker tries to crack hashes offline',
        `<p>Against unsalted MD5 or SHA-256 a single modern GPU tests <b>tens of billions</b> of guesses per second, and precomputed rainbow tables make common passwords instant. No rate limit applies offline.</p>`),
      block('attacker', 'db', 'crack argon2id hashes', 'slow + unique salt per user', 'Memory-hard hashing makes cracking uneconomic',
        `<p>With argon2id at these settings, the same GPU manages only a few thousand guesses per second. Unique salts mean every user must be attacked separately, and rainbow tables are useless.</p><p>Long, unbreached passwords stay safe. Weak ones still fall eventually, which is why the breach check and 2FA matter.</p>`),
      proc('api', 'cred', 'argon2.verify() · needsRehash()', 'At login, verify and upgrade',
        `<p><code>argon2.verify</code> recomputes the hash using the salt and parameters stored in the string and compares in constant time.</p><p>If you raised the cost since this hash was created, <code>needsRehash</code> returns true and you re-hash right then, while you briefly hold the plaintext. Old hashes upgrade silently as people log in.</p>`),
    ],
    concept: `
<h3>Hash, don't encrypt</h3>
<p>Encryption is reversible with a key; if the key leaks with the database, every password leaks. A hash is one-way. You never need the original password back, only to check a guess, so hashing is the right tool.</p>
<h3>Why fast hashes are wrong</h3>
<p>SHA-256 is designed to be fast, which is exactly what an attacker wants. Password hashes are deliberately slow and, in argon2's case, memory-hungry, so each guess costs real hardware.</p>
<div class="table-wrap"><table>
  <thead><tr><th>Algorithm</th><th>Use it?</th><th>Settings</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>argon2id</td><td><span class="good">First choice</span></td><td>m=19 MiB, t=2, p=1 (OWASP minimum)</td><td>Memory-hard. <code>npm i argon2</code> ships prebuilt binaries.</td></tr>
    <tr><td>scrypt</td><td><span class="good">Good</span></td><td>N=2<sup>17</sup>, r=8, p=1</td><td>Built into Node (<code>crypto.scrypt</code>), no native dependency.</td></tr>
    <tr><td>bcrypt</td><td>Acceptable</td><td>cost 12 or higher</td><td>Silently ignores bytes after 72. Fine for existing systems.</td></tr>
    <tr><td>PBKDF2-SHA256</td><td>Only if FIPS requires it</td><td>600,000 iterations</td><td>Not memory-hard, so GPUs are efficient against it.</td></tr>
    <tr><td>MD5, SHA-1, SHA-256 alone</td><td><span class="bad">Never</span></td><td></td><td>Billions of guesses per second.</td></tr>
  </tbody>
</table></div>
<h3>A password policy that helps people</h3>
<ul>
  <li><b>Minimum length 12–15</b>, maximum at least 64 (cap at 128 to protect the CPU).</li>
  <li><b>No composition rules</b> ("one symbol, one capital"). They produce <code>Password1!</code> and frustrate password managers.</li>
  <li><b>No forced rotation.</b> Change passwords only when there is evidence of compromise.</li>
  <li><b>Block breached and obvious passwords</b> (HIBP, your app's name, the user's email).</li>
  <li><b>Allow paste</b> and add a show-password toggle. Password managers are your friends.</li>
  <li>Use <code>autocomplete="new-password"</code> at signup and <code>"current-password"</code> at login so managers fill the right thing.</li>
</ul>
<h3>Optional: a pepper</h3>
<p>A pepper is a server-side secret mixed into every hash (for example, HMAC the password with a key from your secret manager before argon2). If only the database leaks, hashes can't be cracked without the key. It adds key-management work, so treat it as a later upgrade, not a launch requirement.</p>
<p class="callout"><b>Rule of thumb.</b> Hashing one password should take roughly 50–250 ms on your production server. Measure it, then tune <code>memoryCost</code> and <code>timeCost</code>.</p>`,
    threats: [
      { name: 'Offline cracking', risk: 'A leaked table of fast hashes is cracked within hours; most users\' passwords become public and reusable on other sites.', fix: 'argon2id with OWASP parameters. Store the full encoded string. Rehash on login when parameters change.' },
      { name: 'Rainbow tables', risk: 'Precomputed hash → password tables reverse unsalted hashes instantly.', fix: 'A unique random salt per hash. argon2 and bcrypt generate it for you; never reuse or hard-code one.' },
      { name: 'Long-password DoS', risk: 'An attacker posts megabyte-long passwords to the login route; each one costs a full hash.', fix: 'Body limit of 100 kb, password <code>max(128)</code> in validation, and rate limits before hashing.' },
      { name: 'Passwords in logs', risk: 'Request logging or an error tracker records the login body, so plaintext passwords end up in a third-party dashboard.', fix: 'pino <code>redact</code> for <code>password</code>, <code>newPassword</code>, <code>token</code>, <code>authorization</code> and <code>cookie</code>. Scrub the same fields in Sentry.' },
      { name: 'Password reuse', risk: 'A user\'s password leaked from another site is valid on yours. Your hashing can\'t help.', fix: 'Reject breached passwords, rate-limit logins, offer 2FA, alert on logins from new devices.' },
      { name: 'bcrypt truncation', risk: 'bcrypt ignores everything after 72 bytes, so two long passwords sharing a prefix both match.', fix: 'Use argon2id. If you must keep bcrypt, cap passwords at 72 bytes and say so in the UI.' },
    ],
    code: [
      {
        file: 'server/src/models/User.js',
        code: code`
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    name: { type: String, trim: true, maxlength: 80 },
    passwordHash: { type: String, select: false },      // absent for Google-only accounts
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    emailVerified: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    tokenVersion: { type: Number, default: 0 },          // bump to invalidate every access token
    googleId: { type: String, unique: true, sparse: true },
    passwordChangedAt: Date,
    mfa: {
      enabled: { type: Boolean, default: false },
      secretEnc: { type: String, select: false },          // AES-256-GCM encrypted TOTP secret
      pendingSecretEnc: { type: String, select: false },   // during setup, before the first code is confirmed
      lastUsedStep: { type: Number, select: false },       // replay guard
      backupCodes: { type: [String], select: false },      // argon2 hashes
    },
  },
  { timestamps: true },
);

// The only shape that ever leaves the API
userSchema.methods.toPublic = function () {
  return {
    id: this.id,
    email: this.email,
    name: this.name,
    role: this.role,
    emailVerified: this.emailVerified,
    mfaEnabled: this.mfa?.enabled ?? false,
    hasPassword: Boolean(this.passwordHash),
  };
};

export const User = mongoose.model('User', userSchema);`,
      },
      {
        file: 'server/src/services/password.js',
        code: code`
import argon2 from 'argon2';
import crypto from 'node:crypto';

// OWASP Password Storage Cheat Sheet baseline for argon2id
const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const hashPassword = (plain) => argon2.hash(plain.normalize('NFKC'), OPTIONS);

export async function verifyPassword(hash, plain) {
  try {
    return await argon2.verify(hash, plain.normalize('NFKC'));
  } catch {
    return false;   // malformed hash: treat as a mismatch, never as a crash
  }
}

export const needsRehash = (hash) => argon2.needsRehash(hash, OPTIONS);

// Called when the email doesn't exist, so "unknown user" takes as long as "wrong password"
let dummyHash;
export async function fakeVerify(plain) {
  dummyHash ??= await argon2.hash('dummy-password-for-timing', OPTIONS);
  await verifyPassword(dummyHash, plain);
  return false;
}

// Have I Been Pwned range API: only 5 hex chars of the SHA-1 leave the server
export async function isBreached(password) {
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const res = await fetch(\`https://api.pwnedpasswords.com/range/\${prefix}\`, {
      headers: { 'Add-Padding': 'true' },
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return false;   // fail open: an outage shouldn't block signups
    const body = await res.text();
    return body.split('\n').some((line) => {
      const [hashSuffix, count] = line.trim().split(':');
      return hashSuffix === suffix && Number(count) > 0;   // padding rows have count 0
    });
  } catch {
    return false;
  }
}`,
      },
      {
        file: 'server/src/validation/auth.schemas.js',
        note: 'One place for every auth input shape. Strict types here are also your NoSQL-injection defense.',
        code: code`
import { z } from 'zod';

export const email = z.string().trim().toLowerCase().email().max(254);

export const password = z
  .string()
  .min(12, 'Use at least 12 characters')
  .max(128, 'Use at most 128 characters');

export const registerSchema = z.object({
  name: z.string().trim().min(1).max(80),
  email,
  password,
});

export const loginSchema = z.object({
  email,
  password: z.string().min(1).max(128),   // don't apply new rules to old passwords at login
});

export const tokenSchema = z.object({ token: z.string().min(20).max(200) });

export const resetSchema = z.object({ token: z.string().min(20).max(200), password });

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: password,
});

export const totpCode = z.string().regex(/^\d{6}$/, 'Enter the 6-digit code');`,
      },
      {
        file: 'server/src/lib/logger.js',
        code: code`
import pino from 'pino';
import pinoHttp from 'pino-http';
import crypto from 'node:crypto';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      '*.password', '*.newPassword', '*.currentPassword',
      '*.token', '*.accessToken', '*.refreshToken', '*.mfaToken', '*.code', '*.backupCode',
    ],
    censor: '[redacted]',
  },
});

export const httpLogger = pinoHttp({
  logger,
  genReqId: (req) => req.headers['x-request-id'] ?? crypto.randomUUID(),
  // keep URLs with one-time tokens out of logs
  serializers: { req: (req) => ({ id: req.id, method: req.method, url: req.url.split('?')[0] }) },
});`,
      },
    ],
    checklist: [
      'Passwords are hashed with argon2id (or bcrypt cost 12+), never encrypted or fast-hashed',
      'Hashing one password takes 50–250 ms on production hardware',
      'Minimum length 12+, maximum 128, no composition rules',
      'New passwords are checked against Have I Been Pwned',
      '<code>passwordHash</code> has <code>select: false</code> and never appears in API responses',
      'Logs and error trackers redact password and token fields',
      'Login re-hashes old hashes when parameters change',
    ],
  });
})();
