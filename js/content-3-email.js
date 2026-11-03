/* Email: addresses, verification codes, email-code sign-in and password reset
   Concepts adapted from Pilcrow's Auth book: https://auth.pilcrowonpaper.com */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block, book } = AIM;

  // ================================================================ 07 · Email verification
  AIM.chapters.push({
    id: 'email-verification',
    num: '07',
    group: 'Email',
    short: 'Email addresses & verification',
    title: 'Email addresses and verification codes',
    flowName: 'Sign up, then prove the inbox is yours',
    lede: 'An email address makes a good account identifier: it’s unique and people remember it. Proving the user owns it takes a short code, tied to one sign-up session and one address.',
    sources: [book('email-addresses', 'Email addresses'), book('email-address-verification-codes', 'Email address verification codes')],
    glance: [
      ['≤ 100', 'characters in an address'],
      ['8 digits', 'verification code'],
      ['≤ 1 hour', 'code lifetime'],
      ['1 / min', 'tries per email address'],
    ],
    analogy: {
      title: 'The parcel locker PIN',
      intro: 'To prove an address is yours, the courier drops a PIN in that mailbox. Only someone who can open the mailbox can read it back, and the PIN only opens the locker you’re standing at.',
      map: [
        ['Email address', 'The delivery address'],
        ['Validation rules', 'The courier refusing a malformed label'],
        ['Verification code', 'The PIN dropped in the mailbox'],
        ['Sign-up session', 'The locker you’re standing at'],
        ['Binding to one address', 'This PIN is printed for this address only'],
        ['Rate limit', 'The keypad accepts one try a minute'],
      ],
    },
    actors: ['browser', 'api', 'db', 'redis', 'mail', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /signup { email: "ana@example.com", … }', 'The user signs up with an email address',
        `<p>The address becomes the account’s identifier, which also makes it visible to anyone who can probe your sign-up form. Avoid email identifiers if users must stay anonymous.</p>`,
        `You write your address on the delivery form.`),
      proc('api', 'data', '≤100 · one @ · allowed chars · domain has a dot', 'Validate strictly, but never rewrite',
        `<p>Fully validating an email address against the RFC isn’t worth it. For account identifiers the book suggests six strict rules (shown below). Reject anything else with a clear message, and don’t lowercase or strip <code>+tags</code>: some mail servers treat those as different inboxes.</p>`,
        `The courier refuses a label with two @ signs, and never rewrites your address for you.`),
      proc('api', 'cred', 'code = 8 random digits', 'Generate an 8-digit code',
        `<p>Use a cryptographically secure, unbiased generator. In Node, <code>crypto.randomInt(100_000_000)</code> padded to 8 digits does it.</p>`,
        `The courier prints a fresh PIN.`,
        `crypto.randomInt(100_000_000).toString().padStart(8, '0')   →  "04051287"`),
      send('api', 'db', 'data', 'insert sign-up { email, code, expiresAt: +30 min }', 'Bind it to this session and this address',
        `<p>A unique code for each attempt, stored with the sign-up session and the exact address it was sent to. At these limits the book says the code doesn’t need hashing, and failed tries don’t need counting.</p>`,
        `The PIN is printed for this address and this locker only.`),
      send('api', 'browser', 'token', 'Set-Cookie: signup_session=…', 'The browser holds the sign-up session',
        `<p>The code only works together with this cookie, so it has to be entered on the device that started sign-up.</p>`,
        `You’re standing at locker 14.`),
      send('api', 'mail', 'mail', '“Your code is 04 051 287”', 'Send the code',
        `<p>The book prefers codes to links. Links get opened by email scanners, and open in whatever browser the mail app picks, not the one that started sign-up.</p>`,
        `The PIN goes into your mailbox.`),
      send('mail', 'browser', 'mail', 'user reads 04 051 287', 'Only the inbox owner can read it',
        `<p>Reading the code back proves the user can read mail at that address.</p>`,
        `You open your mailbox and read the PIN.`),
      send('browser', 'api', 'token', 'POST /signup/verify { code } + cookie', 'The user types the code',
        `<p>Use <code>inputMode="numeric"</code> and <code>autoComplete="one-time-code"</code> on the input.</p>`,
        `You type the PIN on locker 14’s keypad.`),
      send('api', 'redis', 'data', 'takeToken("verify:ana@example.com")', 'One try a minute per address',
        `<p>The bucket is keyed by the <b>email address</b>, so opening more sessions or accounts doesn’t buy more guesses.</p>`,
        `The keypad for this address accepts one try a minute, whichever locker you use.`),
      proc('api', 'token', 'session ✓ · address ✓ · not expired · code ✓', 'Check everything the code is bound to',
        `<p>The code must belong to this session, for this address, within its lifetime (at most an hour, shorter is better). Compare in constant time.</p>`,
        `Right PIN, right address, right locker, still in time: the door opens.`),
      send('api', 'db', 'data', 'create user (emailVerified) · delete sign-up', 'Create the account, consume the code',
        `<p>The sign-up session is deleted so the code can’t be used again, and a normal auth session starts.</p>`,
        `The parcel is collected and the PIN is wiped.`),
      block('attacker', 'api', 'verify “me@attacker.com” with ana’s code', 'code bound to one address and session', 'Why binding matters',
        `<p>Without binding, someone could request a code to an inbox they control and use it to “verify” a different address. The goal isn’t to make misuse impossible, just impractical.</p>`,
        `A PIN printed for 12 Oak Street doesn’t open the locker for 9 Elm Street.`),
    ],
    concept: `
<h3>The book’s strict rules for account email addresses</h3>
<ol>
  <li>At most 100 characters.</li>
  <li>Exactly one <code>@</code>.</li>
  <li>At least one character before and after the <code>@</code>.</li>
  <li>Before the <code>@</code>: lowercase letters, digits, <code>.</code> <code>+</code> <code>_</code> <code>-</code> only.</li>
  <li>The domain contains at least one <code>.</code>.</li>
  <li>The domain: lowercase letters, digits, <code>-</code> and <code>.</code> only.</li>
</ol>
<p>If you only need an address to send mail to (not as an identifier), checking for an <code>@</code> is enough.</p>
<h3>Why codes beat links</h3>
<ul>
  <li><b>Scanners</b> in corporate mail open every link, which can “click” a verification link before the person does.</li>
  <li><b>Wrong browser:</b> a link opens wherever the mail app decides; a code keeps the flow on the device that started it.</li>
  <li><b>Binding:</b> a code entered next to its session cookie is naturally tied to one device.</li>
</ul>
<h3>The numbers</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Setting</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Code</td><td>8 random digits (about 26.6 bits)</td></tr>
    <tr><td>Lifetime</td><td>Up to 1 hour, preferably shorter</td></tr>
    <tr><td>Rate limit</td><td>Token bucket per email address: 5 capacity, 1 per minute</td></tr>
    <tr><td>Storage</td><td>Plain is acceptable at these limits; hash with Argon2 and use a longer code if there are strong incentives to cheat</td></tr>
  </tbody>
</table></div>`,
    threats: [
      { name: 'Verifying someone else’s address', risk: 'Squatting on an address, or claiming a company domain, by verifying an inbox you don’t own.', fix: 'A fresh code per attempt, bound to one session and one address.' },
      { name: 'Guessing the code', risk: '8 digits is 100 million options.', fix: 'Per-address bucket (5, +1/min) and a short lifetime: about 65 tries before the code expires.' },
      { name: 'Link scanners', risk: 'Automated link-openers complete verification without the user.', fix: 'Use codes instead of links.' },
      { name: 'Quietly changed addresses', risk: 'Lowercasing or stripping <code>+tags</code> can merge or misroute different inboxes.', fix: 'Validate strictly and reject; never modify.' },
    ],
    code: [
      {
        file: 'server/src/validation/email.js',
        code: code`
/** The book's strict rules for email addresses used as account identifiers.
 *  Returns an error message or null. Never modifies the input. */
export function validateEmail(email) {
  if (typeof email !== 'string' || email.length === 0) return 'Enter your email address';
  if (email.length > 100) return 'Use an email address of 100 characters or fewer';

  const parts = email.split('@');
  if (parts.length !== 2) return 'An email address has exactly one @';
  const [local, domain] = parts;
  if (!local || !domain) return 'Something is missing before or after the @';

  if (!/^[a-z0-9.+_-]+$/.test(local)) return 'Before the @, use lowercase letters, numbers and . + _ - only';
  if (!/^[a-z0-9.-]+$/.test(domain)) return 'After the @, use lowercase letters, numbers, dots and hyphens only';
  if (!domain.includes('.')) return 'The domain needs a dot, like example.com';
  return null;
}`,
      },
      {
        file: 'server/src/lib/sessionToken.js',
        note: 'The id.secret pattern from chapter 02, reusable for any session type: sign-up, email sign-in, reset.',
        code: code`
import crypto from 'node:crypto';

const ID_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
const hash = (secret) => crypto.createHash('sha256').update(secret).digest();

export function newSessionToken() {
  let id = '';
  for (const byte of crypto.randomBytes(24)) id += ID_ALPHABET[byte >> 3];
  const secret = crypto.randomBytes(32).toString('base64url');
  return { id, secretHash: hash(secret), token: \`\${id}.\${secret}\` };
}

/** Finds the record with Model.findById and checks the secret. Returns the record or null. */
export async function checkSessionToken(Model, token) {
  if (typeof token !== 'string') return null;
  const [id, secret, extra] = token.split('.');
  if (!id || !secret || extra !== undefined) return null;
  const record = await Model.findById(id);
  if (!record || record.expiresAt <= new Date()) return null;
  return crypto.timingSafeEqual(hash(secret), record.secretHash) ? record : null;
}`,
      },
      {
        file: 'server/src/controllers/signup.controller.js',
        code: code`
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { User } from '../models/User.js';
import { validateEmail } from '../validation/email.js';
import { validatePassword, isBreached, hashPassword } from '../services/password.js';
import { newSessionToken, checkSessionToken } from '../lib/sessionToken.js';
import { createSession } from '../services/session.js';
import { takeToken } from '../lib/tokenBucket.js';
import { setSessionCookie, setCookie, clearCookie } from '../lib/cookies.js';
import { sendMail } from '../services/mail.js';

const Signup = mongoose.model('Signup', new mongoose.Schema({
  _id: String,
  secretHash: { type: Buffer, required: true },
  email: { type: String, required: true },
  passwordHash: String,
  code: { type: String, required: true },          // plain is acceptable at these limits
  expiresAt: { type: Date, required: true, expires: 0 },
}));

// POST /signup { email, password }
export async function startSignup(req, res) {
  const { email, password } = req.body;
  const emailError = validateEmail(email);
  if (emailError) return res.status(400).json({ error: emailError });
  if (await User.exists({ email })) {
    return res.status(409).json({ error: 'An account already uses this email address. Sign in instead.' });
  }
  const passwordError = validatePassword(password);
  if (passwordError) return res.status(400).json({ error: passwordError });
  if (await isBreached(password)) return res.status(400).json({ error: 'This password has appeared in a data breach. Choose another one.' });

  const { id, secretHash, token } = newSessionToken();
  const code = crypto.randomInt(100_000_000).toString().padStart(8, '0');   // unbiased 8 digits
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);                    // 30 minutes
  await Signup.create({ _id: id, secretHash, email, passwordHash: await hashPassword(password), code, expiresAt });

  setCookie(res, 'signup_session', token, expiresAt);
  await sendMail(email, { subject: 'Your verification code', text: \`Your code is \${code}. It expires in 30 minutes.\` });
  res.status(201).json({ message: \`We sent an 8-digit code to \${email}\` });
}

// POST /signup/verify { code }
export async function verifySignup(req, res) {
  const signup = await checkSessionToken(Signup, req.cookies.signup_session);
  if (!signup) return res.status(400).json({ error: 'Your sign-up expired. Please start again.' });

  // Keyed by the address: more sessions don't mean more guesses
  const bucket = await takeToken(\`verify:\${signup.email}\`);
  if (!bucket.allowed) return res.status(429).json({ error: \`Too many attempts. Try again in \${bucket.retryAfterSec} seconds.\` });

  const input = String(req.body.code ?? '');
  const ok = input.length === 8 && crypto.timingSafeEqual(Buffer.from(input), Buffer.from(signup.code));
  if (!ok) return res.status(400).json({ error: 'That code is incorrect' });

  await Signup.deleteOne({ _id: signup._id });   // single use
  const user = await User.create({ email: signup.email, passwordHash: signup.passwordHash, emailVerified: true });

  clearCookie(res, 'signup_session');
  const session = await createSession(user._id, req);
  setSessionCookie(res, session.token, session.expiresAt);
  res.status(201).json({ user: user.toPublic() });
}`,
      },
    ],
    checklist: [
      'Account emails follow strict rules and are never silently changed',
      'Verification uses codes, not links',
      'Each code is unique per attempt and bound to one session and one address',
      'Codes expire within an hour (ideally less) and are deleted after use',
      'Attempts are rate-limited per email address',
    ],
  });

  // ================================================================ 08 · Email code sign-in + reset
  AIM.chapters.push({
    id: 'email-codes',
    num: '08',
    group: 'Email',
    short: 'Email-code sign-in & password reset',
    title: 'Signing in and resetting passwords with email codes',
    flowName: 'A one-time code instead of a password',
    lede: 'Email sign-in replaces the password with a code the server invents every time. The server controls its strength, so it’s often safer than a password, and the same flow powers password reset.',
    sources: [book('email-code-authentication', 'Email code authentication'), book('authentication-methods', 'Authentication methods')],
    glance: [
      ['40 bits', 'minimum code strength'],
      ['8 characters', 'from a 32-character alphabet'],
      ['Argon2id', 'the code is hashed'],
      ['≤ 1 hour', 'then it’s gone'],
    ],
    analogy: {
      title: 'The bank’s one-time combination',
      intro: 'Instead of a permanent safe combination, the bank posts you a fresh one for each visit. It works once, only with the queue ticket you were given, and the bank keeps only a scrambled copy.',
      map: [
        ['Email code', 'A one-time safe combination'],
        ['Sign-in attempt session', 'Your queue ticket at the counter'],
        ['32-character alphabet', 'Characters you can’t mix up (no I, O, 0, 1)'],
        ['Argon2 hash of the code', 'The bank’s scrambled copy'],
        ['Single use', 'The combination self-destructs after one turn'],
        ['Second factor during reset', 'Also showing your ID card for a new permanent combination'],
      ],
    },
    actors: ['browser', 'api', 'db', 'redis', 'mail', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /login/email { email }', 'The user asks for a code',
        `<p>No password field at all, just the email address.</p>`,
        `You ask the bank for today’s combination.`),
      proc('api', 'cred', 'new attempt session · 8-char code', 'A fresh attempt and a fresh code',
        `<p>Each attempt gets its own session and its own code. Don’t cap how many attempts can be open for one account; an attacker could use the cap to block the real user.</p>`,
        `You get a queue ticket and a new combination is printed for it.`,
        `alphabet: ABCDEFGHJKLMNPQRSTUVWXYZ23456789   (32 chars → 5 bits each)
code:     7KXMQ2PD                             (8 chars → 40 bits ≈ 1.1 trillion options)`),
      proc('api', 'cred', 'codeHash = argon2id(code)', 'Hash the code with a slow hash',
        `<p>40 bits is small enough that a stolen SHA-256 of the code could be brute-forced quickly. A password hash (a lighter Argon2 setting is fine) makes a stolen hash useless before the code expires.</p>`,
        `The bank keeps only a scrambled copy that takes ages to unscramble.`),
      send('api', 'db', 'data', 'insert attempt { userId, codeHash, expiresAt: +15 min }', 'Store the attempt',
        `<p>At most an hour; 10–15 minutes is kinder to security.</p>`,
        `The scrambled copy is filed with your queue ticket.`),
      send('api', 'browser', 'token', 'Set-Cookie: login_attempt=…', 'Bind the code to this browser',
        `<p>The code only works together with this attempt’s session.</p>`,
        `You keep your queue ticket.`),
      send('api', 'mail', 'mail', '“Your sign-in code: 7KXM Q2PD”', 'Email the code',
        `<p>Mention the expiry, and that the user can ignore the email if it wasn’t them.</p>`,
        `The combination is posted to you.`),
      send('mail', 'browser', 'mail', 'user copies 7KXM Q2PD', 'The user reads the code',
        `<p>An unambiguous alphabet means no confusing O with 0 or I with 1.</p>`,
        `You read the combination off the letter.`),
      send('browser', 'api', 'token', 'POST /login/email/verify { code } + cookie', 'The user enters the code',
        `<p>Accepting lowercase and ignoring spaces is fine for codes; it’s a convenience, not a security choice.</p>`,
        `You hand over your ticket and dial the combination.`),
      send('api', 'redis', 'data', 'takeToken("email-code:66f1")', 'Rate-limit per user',
        `<p>Token bucket: 5 capacity, 1 per minute. Failed attempts don’t need separate counting.</p>`,
        `The safe allows one try a minute.`),
      proc('api', 'token', 'argon2.verify(codeHash, code)', 'Check the code',
        `<p>Hash the input and compare it against the stored hash.</p>`,
        `The scrambled copy matches.`),
      send('api', 'db', 'data', 'delete attempt · create auth session', 'Single use, then a real session',
        `<p>The code is invalidated immediately after use. Codes are also invalidated when the user changes their email address.</p>`,
        `The combination self-destructs and you’re let into the vault.`),
      send('api', 'browser', 'ok', 'Set-Cookie: session=…', 'Signed in',
        `<p>A brand-new auth session, exactly as in chapter 03.</p>`,
        `You’re in.`),
      proc('api', 'cred', 'reset: code ✓ → 2nd factor ✓ → new password', 'Password reset reuses this flow',
        `<p>An email code proves the user controls the inbox. If the account has a second factor, ask for it too. Email can’t count as the second factor when it’s also how resets work. Then set the new password, and ask whether to sign out other devices.</p>`,
        `For a new permanent combination, the bank also wants your ID card, not just the posted code.`),
      block('attacker', 'api', 'guess codes for the full hour', '≈ 65 tries vs 1.1 trillion codes', 'Why guessing fails',
        `<p>With 5 instant tries and 1 per minute after that, an attacker gets about 65 guesses before a code expires, out of roughly 1.1 trillion possibilities.</p>`,
        `Sixty-five spins of a dial with a trillion positions.`),
    ],
    concept: `
<h3>Code design, step by step</h3>
<ol>
  <li>Generate 8 random bytes from a secure generator.</li>
  <li>Keep 5 bits of each byte (a number from 0 to 31) and pick that character from a 32-character alphabet without I, O, 0 or 1.</li>
  <li>That gives 8 characters × 5 bits = 40 bits.</li>
  <li>Hash it with Argon2id (16 MiB, 3 iterations, parallelism 1 is the book’s example) before storing.</li>
  <li>Expire it within an hour; delete it on use or when the email address changes.</li>
</ol>
<h3>Codes for sign-in and for reset</h3>
<div class="table-wrap"><table>
  <thead><tr><th></th><th>Email sign-in</th><th>Password reset</th></tr></thead>
  <tbody>
    <tr><td>Proves</td><td>Control of the inbox</td><td>Control of the inbox</td></tr>
    <tr><td>Then asks for</td><td>Nothing more (or a passkey if required)</td><td>The second factor, if the account has one</td></tr>
    <tr><td>Result</td><td>A new auth session</td><td>A new password; optionally sign out other devices</td></tr>
  </tbody>
</table></div>
<p class="callout"><b>Why hash a short code with Argon2?</b> A 40-bit space is about a trillion options. GPUs test billions of SHA-256 hashes a second, so a leaked SHA-256 would fall in minutes. With Argon2id the book estimates thousands of top GPUs would be needed to crack one within the hour.</p>`,
    threats: [
      { name: 'Brute-forcing the code', risk: 'Guessing 8 characters online.', fix: '40 bits of entropy, a per-user bucket, and a short lifetime.' },
      { name: 'Leaked code hashes', risk: 'A fast hash of a 40-bit code can be reversed offline in minutes.', fix: 'Hash codes with Argon2id or bcrypt, never SHA-256.' },
      { name: 'Blocking the real user', risk: 'Limiting the number of open attempts lets an attacker fill the limit.', fix: 'Don’t cap concurrent attempts or codes per account.' },
      { name: 'Reset bypasses 2FA', risk: 'Anyone with inbox access resets the password and walks in.', fix: 'Require the existing second factor during reset.' },
      { name: 'Stale codes', risk: 'A code still valid after use or after an email change.', fix: 'Delete on use and on email change.' },
    ],
    code: [
      {
        file: 'server/src/services/emailCode.js',
        code: code`
import crypto from 'node:crypto';
import argon2 from 'argon2';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // 32 characters: no I, O, 0 or 1

/** 8 characters × 5 bits = 40 bits of entropy. */
export function generateEmailCode() {
  let code = '';
  for (const byte of crypto.randomBytes(8)) code += ALPHABET[byte & 31];   // keep 5 of the 8 bits: no bias
  return code;
}

// A lighter setting than for passwords is acceptable; this is the book's example
const CODE_HASH = { type: argon2.argon2id, memoryCost: 16384, timeCost: 3, parallelism: 1 };

export const hashEmailCode = (code) => argon2.hash(code, CODE_HASH);

// Accept "7kxm q2pd" or "7KXM-Q2PD" as a convenience
export const normalizeCode = (input) => String(input ?? '').replace(/[\s-]/g, '').toUpperCase();

export const verifyEmailCode = (hash, input) => argon2.verify(hash, normalizeCode(input)).catch(() => false);`,
      },
      {
        file: 'server/src/controllers/emailSignIn.controller.js',
        code: code`
import mongoose from 'mongoose';
import { User } from '../models/User.js';
import { generateEmailCode, hashEmailCode, verifyEmailCode } from '../services/emailCode.js';
import { newSessionToken, checkSessionToken } from '../lib/sessionToken.js';
import { createSession } from '../services/session.js';
import { setPassword } from './password.controller.js';
import { verifyTotp } from '../services/totp.js';            // your second-factor check
import { takeToken } from '../lib/tokenBucket.js';
import { setSessionCookie, setCookie, clearCookie } from '../lib/cookies.js';
import { sendMail } from '../services/mail.js';
import { Session } from '../models/Session.js';

const Attempt = mongoose.model('EmailCodeAttempt', new mongoose.Schema({
  _id: String,
  secretHash: { type: Buffer, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  purpose: { type: String, enum: ['sign-in', 'reset'], required: true },
  codeHash: { type: String, required: true },
  codeVerified: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true, expires: 0 },
}));

// POST /login/email { email, purpose }
export async function startEmailCode(req, res) {
  const purpose = req.body.purpose === 'reset' ? 'reset' : 'sign-in';
  const user = await User.findOne({ email: String(req.body.email ?? '') });
  if (!user) return res.status(404).json({ error: 'No account uses this email address' });

  const code = generateEmailCode();
  const { id, secretHash, token } = newSessionToken();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  await Attempt.create({ _id: id, secretHash, userId: user._id, purpose, codeHash: await hashEmailCode(code), expiresAt });

  setCookie(res, 'code_attempt', token, expiresAt);
  await sendMail(user.email, {
    subject: purpose === 'reset' ? 'Reset your password' : 'Your sign-in code',
    text: \`Your code is \${code.slice(0, 4)} \${code.slice(4)}. It expires in 15 minutes. If this wasn't you, ignore this email.\`,
  });
  res.json({ message: 'Check your inbox for an 8-character code' });
}

// POST /login/email/verify { code }
export async function verifyEmailCodeStep(req, res) {
  const attempt = await checkSessionToken(Attempt, req.cookies.code_attempt);
  if (!attempt) return res.status(400).json({ error: 'This code request expired. Ask for a new code.' });

  const bucket = await takeToken(\`email-code:\${attempt.userId}\`);
  if (!bucket.allowed) return res.status(429).json({ error: \`Too many attempts. Try again in \${bucket.retryAfterSec} seconds.\` });

  if (!(await verifyEmailCode(attempt.codeHash, req.body.code))) {
    return res.status(400).json({ error: 'That code is incorrect' });
  }

  if (attempt.purpose === 'reset') {
    attempt.codeVerified = true;   // the attempt now authorises exactly one password reset
    await attempt.save();
    const user = await User.findById(attempt.userId).select('+totpKeyEnc');
    return res.json({ next: 'new-password', secondFactorRequired: Boolean(user.totpKeyEnc) });
  }

  await Attempt.deleteOne({ _id: attempt._id });   // single use
  clearCookie(res, 'code_attempt');
  const session = await createSession(attempt.userId, req);
  setSessionCookie(res, session.token, session.expiresAt);
  res.json({ ok: true });
}

// POST /reset/password { password, totp?, signOutOthers }
export async function resetPassword(req, res) {
  const attempt = await checkSessionToken(Attempt, req.cookies.code_attempt);
  if (!attempt || attempt.purpose !== 'reset' || !attempt.codeVerified) {
    return res.status(400).json({ error: 'Start the reset again' });
  }
  const user = await User.findById(attempt.userId).select('+totpKeyEnc');
  // Email can't be the second factor when it's also how resets work
  if (user.totpKeyEnc && !(await verifyTotp(user, req.body.totp))) {
    return res.status(400).json({ error: 'Enter the code from your authenticator app' });
  }

  const problem = await setPassword(user._id, req.body.password);
  if (problem) return res.status(400).json({ error: problem });

  await Attempt.deleteOne({ _id: attempt._id });
  clearCookie(res, 'code_attempt');
  if (req.body.signOutOthers) await Session.deleteMany({ userId: user._id });   // the user's choice
  res.json({ message: 'Password updated. Sign in with your new password.' });
}`,
      },
    ],
    checklist: [
      'Email codes have at least 40 bits (8 characters from a 32-character alphabet)',
      'Codes are hashed with Argon2id or bcrypt, never SHA-256',
      'Each attempt has its own session and code; open attempts aren’t capped',
      'Codes expire within an hour and are deleted on use or email change',
      'Code checks are rate-limited per user',
      'Password reset asks for the second factor when one exists',
    ],
  });
})();
