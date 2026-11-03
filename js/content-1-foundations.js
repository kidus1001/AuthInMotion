/* Shared helpers + Foundations: methods, sessions, auth sessions
   Concepts adapted from Pilcrow's Auth book: https://auth.pilcrowonpaper.com */
(function () {
  'use strict';
  const AIM = (window.AIM = { chapters: [] });

  // Tagged template for code samples: keeps backslashes as written.
  // Inside samples, write \` for a backtick and \${ for a template placeholder.
  AIM.code = (strings) => strings.raw.join('').replace(/\\([`$])/g, '$1').replace(/^\n/, '').replace(/\s+$/, '');
  AIM.send = (from, to, kind, label, title, text, analogy, payload) => ({ type: 'send', from, to, kind, label, title, text, analogy, payload });
  AIM.proc = (at, kind, label, title, text, analogy, payload) => ({ type: 'process', at, kind, label, title, text, analogy, payload });
  AIM.block = (from, to, label, result, title, text, analogy, payload) => ({ type: 'blocked', from, to, kind: 'attack', label, result, title, text, analogy, payload });
  AIM.book = (slug, title) => ({ title, url: 'https://auth.pilcrowonpaper.com/' + slug });

  const { code, send, proc, block, book } = AIM;

  // ================================================================ 01 · Choosing a method
  AIM.chapters.push({
    id: 'methods',
    num: '01',
    group: 'Foundations',
    short: 'Choosing a sign-in method',
    title: 'Choosing a sign-in method',
    flowName: 'Four ways to prove “it’s me”',
    lede: 'Every sign-in method answers one question, “is this really you?”, with a different level of confidence. Pick a method you’re sure is strong enough for what an account is worth.',
    sources: [book('authentication-methods', 'Authentication methods')],
    glance: [
      ['Password', 'fine for low-stakes apps'],
      ['+ second factor', 'slows an attacker down'],
      ['Email code', 'the server sets the strength'],
      ['Passkey', 'nothing to guess, steal or phish'],
    ],
    analogy: {
      title: 'Getting into an office building',
      intro: 'Each sign-in method is a different way to convince the front desk you belong in the building.',
      map: [
        ['Password', 'A door code you memorised'],
        ['Second factor', 'A code from your phone as well'],
        ['Email code', 'A one-time code left in your mailbox'],
        ['Passkey', 'Your fingerprint on a scanner that only works at this building'],
        ['Attacker', 'Someone who saw your door code at the gym'],
      ],
    },
    actors: ['browser', 'api', 'db', 'mail', 'phone', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /login { email, password }', 'Method 1: a password',
        `<p>The user proves who they are with something they know. It’s familiar and works everywhere.</p>`,
        `You type your door code on the keypad and the door opens.`),
      send('attacker', 'api', 'attack', 'same password, leaked from another site', 'The weakness: passwords get reused and leaked',
        `<p>People reuse passwords, type them into phishing pages, and other sites’ databases leak. Whoever holds the password <i>is</i> the user as far as your server can tell.</p>`,
        `Someone saw you use the same code at your gym. They try it here, and it works.`),
      proc('api', 'token', 'password ✓ → ask for a second factor', 'Method 2: add a second factor',
        `<p>After the password, ask for a code from an authenticator app (or an SMS). The book calls these factors <b>relatively weak on their own</b>, but together with a password they slow an attacker down a lot.</p>`,
        `The desk also asks for the code your phone shows right now.`),
      block('attacker', 'api', 'password ✓ · code ?', 'second factor missing', 'A stolen password alone stops working',
        `<p>The attacker has the password but not the user’s phone, so the sign-in stops halfway.</p>`,
        `The gym snoop knows your door code but doesn’t have your phone.`),
      send('api', 'mail', 'mail', 'one-time sign-in code', 'Method 3: email codes, no password at all',
        `<p>The server emails a fresh random code for each sign-in. Because the <b>server</b> chooses the code, it can’t be weak or reused. The book calls this often more secure than passwords.</p>`,
        `The desk leaves a fresh one-time code in your mailbox each morning.`),
      send('mail', 'browser', 'mail', 'code: 7KXM Q2PD', 'The risk moves to the inbox',
        `<p>Email sign-in is exactly as safe as the user’s email account and device. That’s the trade-off.</p>`,
        `Anyone who can open your mailbox can get into the building.`),
      send('api', 'phone', 'cred', 'random challenge', 'Method 4: passkeys',
        `<p>The server sends a random challenge. The user’s device signs it with a private key it never reveals, after a fingerprint, face scan or PIN.</p>`,
        `The scanner asks for your fingerprint and checks it against this building only.`),
      send('phone', 'api', 'ok', 'signature ✓', 'Nothing reusable crosses the network',
        `<p>The server checks the signature with the public key it stored at registration. There’s no shared secret to leak, and each signature works for one challenge only.</p>`,
        `The scanner says yes. There’s no code anyone could copy for tomorrow.`),
      block('attacker', 'phone', 'phishing page: “use your passkey”', 'passkey bound to the real domain', 'Phishing doesn’t work on passkeys',
        `<p>A passkey belongs to one domain. On a look-alike site the device simply has no passkey to offer.</p>`,
        `A fake building down the street can’t use your fingerprint at the real one.`),
      proc('api', 'ok', 'offer email sign-in + passkeys', 'What the book recommends',
        `<p>For a new app: support <b>email-based sign-in and passkeys</b> and let users choose, with an option to require passkeys only. Passwords alone are enough for low-stakes apps like a casual forum or game.</p><p>If you reset passwords by email, don’t also use email as the second factor. Ask for the real second factor during the reset.</p>`,
        `Give tenants the mailbox code or the fingerprint scanner, and let cautious tenants ask for scanner-only.`),
    ],
    concept: `
<h3>Match the method to what an account is worth</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Method</th><th>Strength</th><th>Main risk</th><th>Good fit</th></tr></thead>
  <tbody>
    <tr><td>Password</td><td>Depends entirely on the user</td><td>Reuse, phishing, leaked databases</td><td>Casual forums, games</td></tr>
    <tr><td>Password + authenticator app or SMS</td><td>Better: two things to steal</td><td>Phishing can relay both; SMS can be hijacked</td><td>Everyday apps with real accounts</td></tr>
    <tr><td>Email code (passwordless)</td><td>Server-chosen, random, single use</td><td>The user’s email account and device</td><td>Everyday apps; a great default</td></tr>
    <tr><td>Passkey</td><td><span class="good">Highest</span>: unguessable, domain-bound, no shared secret</td><td>Device loss (solved by multiple passkeys)</td><td>Anything high-value; offer it everywhere</td></tr>
  </tbody>
</table></div>
<h3>Rules from the book worth memorising</h3>
<ul>
  <li><b>Don’t use a method you aren’t confident is strong enough</b> for the account it protects.</li>
  <li><b>Email isn’t a second factor</b> if email is also how passwords get reset. Ask for the real second factor during a reset.</li>
  <li><b>Security keys as a second factor add little</b> when they already check a PIN or biometric. At that point they’re a passkey.</li>
  <li><b>A sensible default:</b> email sign-in plus passkeys, the user’s choice, and a setting to require passkeys only.</li>
</ul>`,
    threats: [
      { name: 'Password reuse', risk: 'A password leaked from another site works on yours.', fix: 'Check new passwords against breach lists, rate-limit sign-in, and offer passkeys or email sign-in.' },
      { name: 'Phishing', risk: 'A look-alike page collects passwords and even one-time codes, then replays them.', fix: 'Passkeys: the device won’t use a credential on the wrong domain.' },
      { name: 'Leaked password database', risk: 'Hashes get cracked, and the passwords get tried on other sites.', fix: 'Argon2id hashing (chapter 05), or no passwords at all.' },
      { name: 'Compromised inbox', risk: 'Email sign-in and resets fall to whoever controls the inbox.', fix: 'Offer passkeys; require the second factor during password resets.' },
    ],
    code: [
      {
        file: 'server/src/models/User.js',
        note: 'One user record that can support every method in this guide: passwords, email codes and passkeys.',
        code: code`
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, maxlength: 100 },
    emailVerified: { type: Boolean, default: false },
    passwordHash: { type: String, select: false },   // absent for email-code or passkey-only users
    requirePasskey: { type: Boolean, default: false },  // "passkeys only" for cautious users
    totpKeyEnc: { type: String, select: false },      // optional second factor, encrypted
  },
  { timestamps: true },
);

userSchema.methods.toPublic = function () {
  return {
    id: this.id,
    email: this.email,
    emailVerified: this.emailVerified,
    hasPassword: Boolean(this.passwordHash),
    requirePasskey: this.requirePasskey,
  };
};

export const User = mongoose.model('User', userSchema);`,
      },
    ],
    checklist: [
      'I know which accounts in my app are worth attacking and why',
      'My app offers email sign-in and/or passkeys, not only passwords',
      'Password reset asks for the second factor when one is set up',
      'Users can choose to require passkeys only',
    ],
  });

  // ================================================================ 02 · Sessions
  AIM.chapters.push({
    id: 'sessions',
    num: '02',
    group: 'Foundations',
    short: 'Sessions & session tokens',
    title: 'Sessions and session tokens',
    flowName: 'Issuing and checking a session token',
    lede: 'HTTP forgets you between requests. A session is the server’s memory of one client, and the session token is the claim ticket that proves which memory is yours.',
    sources: [book('sessions', 'Sessions')],
    glance: [
      ['32 bytes', 'random secret per session'],
      ['SHA-256', 'all the database keeps'],
      ['id.secret', 'token format'],
      ['Constant-time', 'how hashes are compared'],
    ],
    analogy: {
      title: 'The coat check',
      intro: 'You hand over your coat and get a ticket with a printed number and a hidden scratch-off code. The attendant files your coat under the number and keeps only a fingerprint of the code.',
      map: [
        ['Session', 'Your coat, hanging on the rack'],
        ['Session ID', 'The number printed on the ticket'],
        ['Session secret', 'The hidden scratch-off code'],
        ['SHA-256 hash', 'A fingerprint of the code: recognisable, not reversible'],
        ['Session token', 'The whole ticket: number + code'],
        ['Constant-time compare', 'Checking every digit, every time'],
      ],
    },
    actors: ['browser', 'api', 'db', 'attacker'],
    steps: [
      send('browser', 'api', 'data', 'GET /dashboard', 'HTTP has no memory',
        `<p>Every request arrives as if from a stranger. Without help, the server can’t tell that two requests came from the same browser.</p>`,
        `The attendant sees a crowd and has no idea who owns which coat.`),
      block('attacker', 'api', 'Cookie: userId=66f1c2', 'client-only data is never trusted', 'Don’t just believe the client',
        `<p>Putting the user ID in a cookie and trusting it would be, in the book’s words, a complete breakdown in security. Anyone can edit their own cookies.</p>`,
        `Shouting “the blue coat is mine” doesn’t get you the blue coat.`),
      proc('api', 'cred', 'id = random · secret = randomBytes(32)', 'Create a session: an ID and a separate secret',
        `<p>The <b>ID</b> finds the record; the <b>secret</b> proves the client owns it. Never use the ID as the secret. Both come from a cryptographically secure generator (<code>crypto.randomBytes</code>, never <code>Math.random</code>).</p>`,
        `The attendant prints a ticket number and a separate scratch-off code.`),
      proc('api', 'cred', 'secretHash = sha256(secret)', 'Store a hash of the secret, not the secret',
        `<p>32 random bytes can’t be guessed, so a fast hash like SHA-256 is enough. This isn’t a password: there’s nothing to brute-force.</p>`,
        `The attendant keeps a fingerprint of the code and throws the original away.`,
        `{
  _id:        "u9qerabnmqwfjrig",          // session ID
  secretHash: <32 bytes of SHA-256>,      // never the secret itself
  userId:     "66f1c2a9e4b0d1f7a3c2b8e1",
  createdAt:  "2026-11-03T07:40:00Z"
}`),
      send('api', 'db', 'data', 'sessions.insertOne(…)', 'Save the session record',
        `<p>One row per session. Deleting the row ends the session immediately, which is something a self-contained token can’t do.</p>`,
        `Your coat goes on the rack under ticket number u9qe…`),
      send('api', 'browser', 'token', 'Set-Cookie: session=u9qe….oIGZ…', 'Give the client the full token',
        `<p>Token = ID + <code>.</code> + secret, with the secret encoded as hex, base64 or base64url. The client gets the only copy of the secret.</p>`,
        `You get the full ticket, number and scratch-off code.`,
        `u9qerabnmqwfjrig.oIGZG+9w+flpwCIb5azPgXLdmmS+86KYkQbIag/wXB8=
└── session ID ──┘ └────────────── secret (32 bytes, base64) ──────────────┘`),
      send('browser', 'api', 'token', 'Cookie: session=u9qe….oIGZ…', 'Every request shows the ticket',
        `<p>The browser attaches the cookie automatically. Chapter 09 covers where and how to store the token.</p>`,
        `Each time you come back, you hand over your ticket.`),
      send('api', 'db', 'data', 'findById("u9qerabnmqwfjrig")', 'Look the session up by ID',
        `<p>Split the token at the period and fetch the row by ID. No row means no session.</p>`,
        `The attendant walks to rack spot u9qe…`),
      proc('api', 'token', 'timingSafeEqual(sha256(secret), secretHash)', 'Compare hashes in constant time',
        `<p>Hash the presented secret and compare with the stored hash using a constant-time comparison, so response timing reveals nothing about how close a guess was.</p>`,
        `The attendant checks every digit of the fingerprint, every time, even after a mismatch.`),
      block('attacker', 'api', 'leaked DB row: secretHash', 'a hash can’t be turned back into a token', 'A database leak doesn’t leak sessions',
        `<p>The database only has hashes. Rebuilding a working token from SHA-256 of 32 random bytes isn’t feasible.</p>`,
        `A fingerprint of the code doesn’t give you a ticket you can hand over.`),
      block('attacker', 'api', 'stolen token, weeks later', 'expired · replaced after sign-in', 'Limiting hijacked sessions',
        `<p>Give sessions an expiry and issue a new session after authentication events. Binding sessions to an IP breaks for mobile and VPN users; binding to a country or region is a practical middle ground.</p>`,
        `Tickets expire at closing time, and you get a new ticket whenever you show ID.`),
    ],
    concept: `
<h3>Why the server needs a session</h3>
<p>HTTP is stateless, and anything stored only on the client can be edited by the client. A session is a server-side record of a client’s activity; the session token is how the client points at its record. An <b>auth session</b> (chapter 03) is a session that holds a signed-in user’s ID. Apps often have other sessions too, like a sign-up session that remembers the email being verified.</p>
<h3>Token anatomy</h3>
<div class="anatomy"><span class="seg a">u9qerabnmqwfjrig</span><span class="dot">.</span><span class="seg b">oIGZG+9w+flpwCIb5azPgXLdmmS+86KYkQbIag/wXB8=</span></div>
<dl>
  <dt>ID</dt><dd>Finds the record. Doesn’t have to be secret.</dd>
  <dt>Secret</dt><dd>32 bytes from a cryptographically secure generator. A longer secret adds nothing, because the SHA-256 output is 32 bytes anyway.</dd>
  <dt>Stored</dt><dd><code>SHA-256(secret)</code>, compared in constant time.</dd>
</dl>
<h3>Why a fast hash is fine here</h3>
<p>Passwords need slow hashes because humans pick guessable ones. A 256-bit random secret has no guessable values, so SHA-256 is safe and keeps every request fast.</p>
<p class="callout"><b>What about JWTs?</b> The book uses database-backed sessions. Unlike a JWT, deleting a row ends a session instantly, which makes logout, “sign out everywhere” and account suspension simple and reliable.</p>`,
    threats: [
      { name: 'Trusting client data', risk: 'A cookie holding <code>userId</code> lets anyone become anyone by editing it.', fix: 'Store identity server-side; the client only holds a random token.' },
      { name: 'Predictable tokens', risk: '<code>Math.random</code> and timestamps can be predicted, so tokens can be guessed.', fix: '<code>crypto.randomBytes(32)</code> for the secret.' },
      { name: 'Database leak', risk: 'Raw tokens in the database let anyone with a backup impersonate every user.', fix: 'Store only <code>SHA-256(secret)</code>.' },
      { name: 'Timing attacks', risk: 'An early-exit comparison leaks how many bytes matched.', fix: '<code>crypto.timingSafeEqual</code> on the hashes.' },
      { name: 'Session hijacking', risk: 'A stolen token works until the session ends.', fix: 'Expiry, new sessions after sign-in, optional country/region binding.' },
    ],
    code: [
      {
        file: 'server/src/models/Session.js',
        code: code`
import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
  _id: { type: String },                                   // the session ID
  secretHash: { type: Buffer, required: true },             // SHA-256 of the secret
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  createdAt: { type: Date, required: true },
  lastUsedAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
  userAgent: String,
});

// MongoDB deletes expired sessions on its own (checked about once a minute)
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const Session = mongoose.model('Session', sessionSchema);`,
      },
      {
        file: 'server/src/services/session.js',
        code: code`
import crypto from 'node:crypto';
import { Session } from '../models/Session.js';

const DAY = 24 * 60 * 60 * 1000;
export const SESSION_TTL = 30 * DAY;           // signed out after 30 days without use

// 24 chars from a 32-letter alphabet = 120 random bits. b >> 3 keeps 5 bits: no bias.
const ID_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
function generateId() {
  let id = '';
  for (const byte of crypto.randomBytes(24)) id += ID_ALPHABET[byte >> 3];
  return id;
}

const hashSecret = (secret) => crypto.createHash('sha256').update(secret).digest();

export async function createSession(userId, req) {
  const id = generateId();
  const secret = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  await Session.create({
    _id: id,
    secretHash: hashSecret(secret),
    userId,
    createdAt: now,
    lastUsedAt: now,
    expiresAt: new Date(now.getTime() + SESSION_TTL),
    userAgent: req.get('user-agent')?.slice(0, 200),
  });
  return { token: \`\${id}.\${secret}\`, expiresAt: new Date(now.getTime() + SESSION_TTL) };
}

/** Returns the session for a valid token, or null. */
export async function validateSessionToken(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [id, secret] = parts;

  const session = await Session.findById(id);
  if (!session) return null;

  const valid = crypto.timingSafeEqual(hashSecret(secret), session.secretHash);
  if (!valid) return null;

  if (session.expiresAt <= new Date()) {
    await Session.deleteOne({ _id: id });
    return null;
  }
  return session;
}

export const invalidateSession = (id) => Session.deleteOne({ _id: id });
export const invalidateAllSessions = (userId) => Session.deleteMany({ userId });`,
      },
    ],
    checklist: [
      'Session tokens are an ID plus a separate 32-byte random secret',
      'Only <code>SHA-256(secret)</code> is stored',
      'Secrets are compared with <code>crypto.timingSafeEqual</code>',
      'No identity data is trusted from cookies or headers alone',
      'Sessions expire and are deleted server-side',
    ],
  });

  // ================================================================ 03 · Auth sessions
  AIM.chapters.push({
    id: 'auth-sessions',
    num: '03',
    group: 'Foundations',
    short: 'Auth sessions & sign-out',
    title: 'Auth sessions: lifetime, sign-out and re-verification',
    flowName: 'A session from sign-in to sign-out',
    lede: 'An auth session is a session that remembers who signed in. When it starts, how it stretches, how it ends, and when it isn’t enough on its own decide how safe your users’ accounts are.',
    sources: [book('auth-sessions', 'Auth sessions')],
    glance: [
      ['New session', 'on every sign-in'],
      ['Sliding expiry', 'active users stay signed in'],
      ['Refresh hourly', 'not on every request'],
      ['Single-use', 're-verification for risky actions'],
    ],
    analogy: {
      title: 'The hotel key card',
      intro: 'Check-in programs a brand-new card for your room. It keeps working while you’re around, the desk can switch it off, and for the room safe you still need to show ID.',
      map: [
        ['Sign-in', 'Checking in at the front desk'],
        ['Auth session', 'Your programmed key card'],
        ['Sliding expiry', 'Your stay is extended while you keep coming back'],
        ['Sign out', 'Handing the card back so it’s switched off'],
        ['Sign out everywhere', 'Switching off every card for your room'],
        ['Action-specific session', 'Showing ID to open the safe, once'],
      ],
    },
    actors: ['browser', 'api', 'db', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /login (identity proven)', 'Sign-in succeeds',
        `<p>Password, email code or passkey: the user has just proved who they are.</p>`,
        `You show ID at the front desk.`),
      proc('api', 'token', 'createSession(userId) — always new', 'A brand-new session for every sign-in',
        `<p>One auth session belongs to one successful sign-in. Never upgrade a session that existed before. If you did, an attacker could plant a session in the victim’s browser, wait for them to sign in, and then share it.</p>`,
        `The desk programs a new card. It never activates a card you walked in with.`),
      send('api', 'db', 'data', 'insert { userId, lastUsedAt, expiresAt: +30d }', 'Store it with an expiry',
        `<p>How long depends on the app: an hour for banking, until midnight, or weeks for most consumer apps.</p>`,
        `Your stay is booked for 30 days.`),
      send('api', 'browser', 'token', 'Set-Cookie: session=…; HttpOnly; Secure; SameSite=Lax', 'The browser stores the token',
        `<p>Cookie flags are covered in chapter 09.</p>`,
        `You get the card.`),
      send('browser', 'api', 'token', 'Cookie: session=… (2 hours later)', 'The user comes back',
        `<p>The session is still valid; the question is whether to extend it.</p>`,
        `You tap your card at the lift.`),
      proc('api', 'token', 'lastUsedAt > 1 h ago → extend expiry', 'Extend on use, but not on every request',
        `<p>Extending the expiry whenever the session is used signs out only inactive users, the best experience when maximum security isn’t needed. Only update it once an hour (or once a day) so you don’t write to the database on every request.</p>`,
        `The desk extends your stay when they see you, but only writes it down once a day.`,
        `if (now - session.lastUsedAt > 1 hour) {
  session.lastUsedAt = now
  session.expiresAt  = now + 30 days     // sliding window
  save + refresh cookie expiry
}`),
      block('attacker', 'api', 'stolen token, unused for 31 days', 'session expired', 'Idle sessions die on their own',
        `<p>A token copied from a forgotten laptop stops working once the owner has been away long enough.</p>`,
        `A card nobody has used for a month stops opening the door.`),
      send('browser', 'api', 'token', 'POST /logout', 'Sign out means deleting it on the server',
        `<p>Removing the cookie isn’t enough: anyone holding a copy of the token could keep using it. Delete the session record.</p>`,
        `You hand the card back and the desk switches it off. Throwing it in a bin wouldn’t.`),
      send('api', 'db', 'data', 'deleteOne({ _id }) · or deleteMany({ userId })', 'This device, or every device',
        `<p>Offer both “sign out” and “sign out of all devices”.</p>`,
        `The desk can switch off one card or every card for your room.`),
      send('browser', 'api', 'cred', 'POST /account/verify (password again)', 'Risky action: verify again',
        `<p>Changing the password, registering a passkey, deleting the account: these need fresh proof even inside a valid session.</p>`,
        `To open the room safe you show ID again, even though your card works.`),
      proc('api', 'token', 'action session: "update-password", single use', 'Scope the verification to one action',
        `<p>The verification creates an <b>action-specific session</b> that allows exactly one action, once. It’s consumed when used.</p>`,
        `The desk opens the safe once; it doesn’t leave it unlocked for the rest of your stay.`),
      block('attacker', 'api', 'hijacked session → “sign out the owner’s devices”', 'needs identity verification', 'Managing sessions is a high-privilege action',
        `<p>If a hijacker could revoke individual sessions, they could kick the real owner out and keep the account. Verify identity before granular session management.</p>`,
        `A thief with your card can’t switch off your other cards without your ID.`),
    ],
    concept: `
<h3>The lifecycle</h3>
<ol>
  <li><b>Create</b> a new session on every successful sign-in.</li>
  <li><b>Expire</b> it after a fixed time, or slide the expiry forward on use.</li>
  <li><b>Refresh</b> the expiry periodically (hourly or daily), not on every request.</li>
  <li><b>Delete</b> it server-side on sign-out; offer “sign out of all devices”.</li>
</ol>
<h3>When a valid session isn’t enough</h3>
<p>Sensitive actions (updating the password, registering or deleting a passkey, deleting the account) need fresh verification tied to that one action and usable once. Treat managing other sessions the same way.</p>
<h3>Password changes and other devices</h3>
<p>The book’s view: ask users whether to sign out of other devices after a password change, rather than forcing it. If you do sign everyone out, make that clear. Signing sessions out when passkeys are added or removed is uncommon.</p>
<div class="table-wrap"><table>
  <thead><tr><th>Choice</th><th>Fixed expiry</th><th>Sliding expiry</th></tr></thead>
  <tbody>
    <tr><td>Who gets signed out</td><td>Everyone, on schedule</td><td>Only inactive users</td></tr>
    <tr><td>Best for</td><td>High-security apps</td><td>Most consumer apps</td></tr>
    <tr><td>Database writes</td><td>None after creation</td><td>One per refresh window</td></tr>
  </tbody>
</table></div>`,
    threats: [
      { name: 'Session fixation', risk: 'An attacker plants a session in the victim’s browser and reuses it after the victim signs in.', fix: 'Always create a brand-new session on sign-in.' },
      { name: 'Client-only sign-out', risk: 'The cookie is gone but a copied token still works.', fix: 'Delete the session record server-side.' },
      { name: 'Endless sessions', risk: 'A token stolen months ago still works.', fix: 'Fixed or sliding expiry; MongoDB TTL index for cleanup.' },
      { name: 'Hijacker locks the owner out', risk: 'With a stolen session, an attacker changes the password or revokes the owner’s devices.', fix: 'Fresh, single-use, action-specific verification for sensitive actions.' },
    ],
    code: [
      {
        file: 'server/src/middleware/session.js',
        note: 'Loads the auth session from the cookie and slides its expiry at most once an hour.',
        code: code`
import { Session } from '../models/Session.js';
import { validateSessionToken, SESSION_TTL } from '../services/session.js';
import { setSessionCookie } from '../lib/cookies.js';

const REFRESH_EVERY = 60 * 60 * 1000;   // write at most once an hour

export async function loadSession(req, res, next) {
  const session = await validateSessionToken(req.cookies.session);
  req.session = session;                  // null when signed out
  if (session && Date.now() - session.lastUsedAt.getTime() > REFRESH_EVERY) {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_TTL);
    await Session.updateOne({ _id: session._id }, { $set: { lastUsedAt: now, expiresAt } });
    setSessionCookie(res, req.cookies.session, expiresAt);   // keep the cookie in step
  }
  next();
}

export function requireSession(req, res, next) {
  if (!req.session) return res.status(401).json({ error: 'Sign in to continue' });
  next();
}`,
      },
      {
        file: 'server/src/services/actionSession.js',
        note: 'Fresh, single-use verification for one sensitive action.',
        code: code`
import crypto from 'node:crypto';
import mongoose from 'mongoose';

const ActionSession = mongoose.model('ActionSession', new mongoose.Schema({
  _id: String,                             // random, sent to the client
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  authSessionId: { type: String, required: true },   // only valid inside this sign-in
  action: { type: String, enum: ['update-password', 'register-passkey', 'delete-passkey', 'delete-account'] },
  expiresAt: { type: Date, required: true, expires: 0 },   // TTL: deleted once expired
}));

// Call right after the user re-enters their password (or a code, or a passkey)
export async function startAction(req, action) {
  const id = crypto.randomBytes(24).toString('base64url');
  await ActionSession.create({
    _id: id,
    userId: req.session.userId,
    authSessionId: req.session._id,
    action,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),   // 10 minutes
  });
  return id;
}

// Atomically find and delete: works exactly once
export async function consumeAction(req, id, action) {
  const found = await ActionSession.findOneAndDelete({
    _id: String(id),
    action,
    authSessionId: req.session._id,
    expiresAt: { $gt: new Date() },
  });
  return Boolean(found);
}`,
      },
      {
        file: 'server/src/routes/account.routes.js',
        code: code`
import { Router } from 'express';
import argon2 from 'argon2';
import { User } from '../models/User.js';
import { requireSession } from '../middleware/session.js';
import { invalidateSession, invalidateAllSessions } from '../services/session.js';
import { startAction, consumeAction } from '../services/actionSession.js';
import { hashPassword, validatePassword } from '../services/password.js';
import { clearSessionCookie } from '../lib/cookies.js';
import { Session } from '../models/Session.js';

export const accountRouter = Router();
accountRouter.use(requireSession);

accountRouter.post('/logout', async (req, res) => {
  await invalidateSession(req.session._id);
  clearSessionCookie(res);
  res.status(204).end();
});

accountRouter.post('/logout-all', async (req, res) => {
  await invalidateAllSessions(req.session.userId);
  clearSessionCookie(res);
  res.status(204).end();
});

// Step 1: re-verify, get a single-use permission for one action
accountRouter.post('/verify', async (req, res) => {
  const { password, action } = req.body;
  const user = await User.findById(req.session.userId).select('+passwordHash');
  if (!user.passwordHash || !(await argon2.verify(user.passwordHash, String(password)))) {
    return res.status(400).json({ error: 'Incorrect password' });
  }
  res.json({ actionId: await startAction(req, action) });
});

// Step 2: perform the action, consuming the permission
accountRouter.post('/password', async (req, res) => {
  const { actionId, newPassword, signOutOthers } = req.body;
  if (!(await consumeAction(req, actionId, 'update-password'))) {
    return res.status(403).json({ error: 'Please confirm your identity again' });
  }
  const problem = validatePassword(newPassword);
  if (problem) return res.status(400).json({ error: problem });

  await User.updateOne({ _id: req.session.userId }, { $set: { passwordHash: await hashPassword(newPassword) } });
  // The book: ask the user rather than forcing it
  if (signOutOthers) await Session.deleteMany({ userId: req.session.userId, _id: { $ne: req.session._id } });
  res.json({ message: 'Password updated' });
});`,
      },
    ],
    checklist: [
      'A new session is created on every sign-in',
      'Sessions expire, and sliding refreshes happen at most hourly',
      'Sign-out deletes the session server-side',
      'Users can sign out of all devices',
      'Password changes, passkey changes and account deletion require fresh, single-use verification',
      'After a password change, users choose whether to sign out other devices',
    ],
  });
})();
