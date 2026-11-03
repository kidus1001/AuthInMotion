/* Passwords: input rules, hashing, rate limiting
   Concepts adapted from Pilcrow's Auth book: https://auth.pilcrowonpaper.com */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block, book } = AIM;

  // ================================================================ 04 · Passwords
  AIM.chapters.push({
    id: 'passwords',
    num: '04',
    group: 'Passwords',
    short: 'Handling passwords',
    title: 'Handling passwords',
    flowName: 'Sign-up and sign-in with a password',
    lede: 'Accepting passwords gives you four jobs: reject bad ones, hash them properly, stop hashing from overwhelming your server, and make guessing painfully slow.',
    sources: [book('passwords', 'Passwords')],
    glance: [
      ['10–100', 'characters, min to max'],
      ['Printable ASCII', 'no leading or trailing space'],
      ['HIBP', 'reject breached passwords'],
      ['Argon2id', 'one-way, salted, memory-hard'],
    ],
    analogy: {
      title: 'The smoothie bar',
      intro: 'Hashing is like blending fruit. The same fruit always makes the same smoothie, but nobody can un-blend a smoothie back into fruit. Each customer also gets a secret spice, so two people with the same fruit get different smoothies.',
      map: [
        ['Password', 'The fruit you bring'],
        ['Hash', 'The smoothie'],
        ['Salt', 'A secret spice unique to each customer'],
        ['Verify', 'Blend the new fruit and compare the taste'],
        ['Breach list', 'Fruit that everyone already guesses'],
        ['Hashing limit', 'Only four blenders run at once'],
      ],
    },
    actors: ['browser', 'api', 'db', 'redis', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /signup { email, password }', 'The user picks a password',
        `<p>The password travels once, inside HTTPS. Use <code>autocomplete="new-password"</code> so password managers offer to generate a strong one.</p>`,
        `You bring your fruit to the counter.`),
      proc('api', 'cred', 'printable ASCII · 10–100 chars · no edge spaces', 'Check the input, never quietly “fix” it',
        `<p>Reject with a clear reason; never trim, lowercase or strip anything. Allow 10 to 100 characters so long passphrases and generated passwords fit. Skip complexity rules like “one symbol”. If you allow all of Unicode, normalise to NFC before hashing.</p>`,
        `The bar turns away rotten fruit and tells you why. It never secretly swaps your fruit.`),
      proc('api', 'cred', 'HIBP range: first 5 chars of SHA-1', 'Reject passwords that have already leaked',
        `<p>Have I Been Pwned lists hundreds of millions of breached passwords. Its range API receives only the first five characters of the password’s SHA-1, so the password itself never leaves your server.</p>`,
        `The bar checks your fruit isn’t on the “everyone guesses this one” list.`),
      proc('api', 'cred', 'argon2id(password, 16-byte salt)', 'Hash it with a password-hashing function',
        `<p>Hashing is one-way, unlike encryption. Use Argon2id (or bcrypt or scrypt) with a fresh salt of at least 16 random bytes. Chapter 05 explains the settings.</p>`,
        `The fruit goes into the blender with your personal spice.`,
        `$argon2id$v=19$m=19456,t=3,p=1$Zk9xS3pRa1h2bWJtR2RqUQ$9dJ3l0u4mRk2nBqN8m1T0q3Q6m5rK4b1sY0bR3dZ2aQ`),
      send('api', 'db', 'data', 'users.insertOne({ passwordHash })', 'Only the hash is stored',
        `<p>The password itself is never written anywhere: not the database, not logs, not error trackers.</p>`,
        `Only the smoothie goes in the fridge.`),
      proc('api', 'data', 'hashing queue: at most 4 at once', 'Protect the server from its own hashing',
        `<p>Each Argon2 hash needs tens of megabytes of memory. A burst of sign-ins could exhaust memory, so cap how many hashes run at once and queue the rest.</p>`,
        `The bar has four blenders. Extra orders wait in line instead of blowing the fuse.`),
      send('browser', 'api', 'cred', 'POST /login (wrong password)', 'Later: a sign-in attempt',
        `<p>Every endpoint that hashes a password is a guessing machine and a denial-of-service target.</p>`,
        `Someone orders “the same smoothie as last time”.`),
      send('api', 'redis', 'data', 'take 1 token · bucket user:66f1', 'Rate-limit per user before hashing',
        `<p>The book’s starting point: about 1 attempt per minute per user, as a token bucket holding 5 that refills 1 per minute. Chapter 06 shows the mechanics.</p>`,
        `Each customer has five tasting tokens; one comes back every minute.`),
      block('attacker', 'api', 'guess #6 within a minute', '429 · try again in 60 s', 'Fast guessing hits the wall',
        `<p>No lockouts and no exponential delays: both can be abused to lock a real user out. Just a steady trickle.</p>`,
        `Out of tokens? Wait a minute. Nobody gets banned from the bar.`),
      proc('api', 'cred', 'argon2.verify(hash, guess)', 'Verify by hashing the guess',
        `<p>The library reads the salt and settings from the stored string, hashes the guess the same way and compares in constant time.</p>`,
        `Blend the new fruit with the same spice and compare the taste.`),
      send('api', 'browser', 'ok', '400 “Incorrect password”', 'Say what went wrong',
        `<p>The usual advice is one vague message for “no such account” and “wrong password”. The book doesn’t fully recommend it: slow hashing still leaks the difference through timing, and vague errors hurt real users. Prefer clear errors. If email addresses must stay private, sign users in with a username or other opaque identifier instead.</p>`,
        `The bartender simply says the taste didn’t match.`,
        `HTTP/1.1 400 Bad Request
{ "error": "Incorrect password" }`),
    ],
    concept: `
<h3>Input rules</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Rule</th><th>Value</th><th>Why</th></tr></thead>
  <tbody>
    <tr><td>Characters</td><td>Printable ASCII</td><td>Predictable everywhere; no invisible or look-alike characters</td></tr>
    <tr><td>Edges</td><td>No leading or trailing space</td><td>Usually a copy-paste accident the user can’t see</td></tr>
    <tr><td>Minimum length</td><td>8–10</td><td>Length beats complexity rules</td></tr>
    <tr><td>Maximum length</td><td>50–100</td><td>Fits passphrases and generated passwords, caps hashing cost</td></tr>
    <tr><td>Breach check</td><td>Have I Been Pwned</td><td>Known passwords are guessed first</td></tr>
    <tr><td>Changes to input</td><td><span class="bad">Never</span></td><td>Reject with a clear message instead</td></tr>
  </tbody>
</table></div>
<h3>Rate limiting, the book’s way</h3>
<ul>
  <li>Strict limits on <b>every</b> endpoint that hashes a password.</li>
  <li>Per user: about 1 attempt per minute (token bucket: 5 capacity, 1 per minute refill).</li>
  <li>No account lockouts and no exponential throttling. Both can be abused to lock users out.</li>
  <li>No strict per-IP limits. They block shared networks and are bypassed with proxies.</li>
</ul>
<h3>Error messages and enumeration</h3>
<p>Hiding whether an email is registered is hard to do completely (slow hashing leaks timing) and frustrates real users. The book prefers explicit errors. If privacy of email addresses matters for your app, use a username or another identifier for sign-in instead.</p>`,
    threats: [
      { name: 'Weak and breached passwords', risk: 'Guessed first by every attacker, online and offline.', fix: 'Minimum length plus a Have I Been Pwned check at sign-up and password change.' },
      { name: 'Online guessing', risk: 'Scripts try thousands of passwords against one account.', fix: 'A per-user token bucket on every endpoint that hashes.' },
      { name: 'Hashing DoS', risk: 'A flood of sign-ins makes the server run out of memory or CPU.', fix: 'Cap concurrent hashes with a queue or semaphore; rate-limit first.' },
      { name: 'Abusable lockouts', risk: 'Locking an account after N failures lets anyone lock anyone out.', fix: 'Throttle with a steady refill instead of locking.' },
      { name: 'Silent input changes', risk: 'Trimming or normalising differently in two places means the user’s real password stops matching.', fix: 'Validate and reject; never modify.' },
    ],
    code: [
      {
        file: 'server/src/services/password.js',
        code: code`
import crypto from 'node:crypto';
import argon2 from 'argon2';
import pLimit from 'p-limit';

// The book's minimum is 16 MiB, 3 iterations, parallelism 1. 19 MiB also meets OWASP's baseline.
const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 3, parallelism: 1 };

// Each hash holds ~19 MiB. Run at most 4 at once; the rest wait in a queue.
const limit = pLimit(4);

export const hashPassword = (password) => limit(() => argon2.hash(password, OPTIONS));
export const verifyPassword = (hash, password) => limit(() => argon2.verify(hash, password).catch(() => false));
export const needsRehash = (hash) => argon2.needsRehash(hash, OPTIONS);

/** Returns an error message, or null if the password is acceptable. Never modifies it. */
export function validatePassword(password) {
  if (typeof password !== 'string' || password.length === 0) return 'Enter a password';
  if (password.length < 10) return 'Use at least 10 characters';
  if (password.length > 100) return 'Use at most 100 characters';
  if (!/^[\x20-\x7E]+$/.test(password)) return 'Use only letters, numbers, spaces and keyboard symbols';
  if (password.startsWith(' ') || password.endsWith(' ')) return 'Remove the space at the start or end';
  return null;
}

// Have I Been Pwned range API: only 5 hex characters of the SHA-1 leave the server
export async function isBreached(password) {
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  try {
    const res = await fetch(\`https://api.pwnedpasswords.com/range/\${sha1.slice(0, 5)}\`, {
      headers: { 'Add-Padding': 'true' },
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return false;
    const lines = (await res.text()).split('\n');
    return lines.some((line) => {
      const [suffix, count] = line.trim().split(':');
      return suffix === sha1.slice(5) && Number(count) > 0;
    });
  } catch {
    return false;   // the API being down shouldn't block sign-ups
  }
}`,
      },
      {
        file: 'server/src/controllers/password.controller.js',
        code: code`
import { User } from '../models/User.js';
import { createSession } from '../services/session.js';
import { hashPassword, verifyPassword, needsRehash, validatePassword, isBreached } from '../services/password.js';
import { takeToken } from '../lib/tokenBucket.js';
import { setSessionCookie } from '../lib/cookies.js';

export async function signIn(req, res) {
  const email = String(req.body.email ?? '');
  const password = String(req.body.password ?? '');

  const user = await User.findOne({ email }).select('+passwordHash');
  // Explicit errors, as the book prefers. Use a username instead if emails must stay private.
  if (!user) return res.status(404).json({ error: 'No account uses this email address' });
  if (!user.passwordHash) return res.status(400).json({ error: 'This account signs in with an email code or a passkey' });

  // 1 attempt per minute per user, bursts of up to 5, before any hashing
  const bucket = await takeToken(\`password:\${user.id}\`);
  if (!bucket.allowed) {
    res.set('Retry-After', String(bucket.retryAfterSec));
    return res.status(429).json({ error: \`Too many attempts. Try again in \${bucket.retryAfterSec} seconds.\` });
  }

  if (!(await verifyPassword(user.passwordHash, password))) {
    return res.status(400).json({ error: 'Incorrect password' });
  }
  if (needsRehash(user.passwordHash)) {
    user.passwordHash = await hashPassword(password);
    await user.save();
  }

  const { token, expiresAt } = await createSession(user._id, req);   // always a new session
  setSessionCookie(res, token, expiresAt);
  res.json({ user: user.toPublic() });
}

export async function setPassword(userId, password) {
  const problem = validatePassword(password);
  if (problem) return problem;
  if (await isBreached(password)) return 'This password has appeared in a data breach. Choose another one.';
  await User.updateOne({ _id: userId }, { $set: { passwordHash: await hashPassword(password) } });
  return null;
}`,
      },
    ],
    checklist: [
      'Passwords are printable ASCII, 10–100 characters, with no edge spaces',
      'Input is rejected with a reason, never silently changed',
      'New passwords are checked against Have I Been Pwned',
      'Passwords are hashed with Argon2id (or bcrypt/scrypt), with a fresh salt',
      'Concurrent hashing is capped',
      'Every endpoint that hashes has a per-user rate limit, with no lockouts',
    ],
  });

  // ================================================================ 05 · Argon2 + bcrypt
  AIM.chapters.push({
    id: 'hashing',
    num: '05',
    group: 'Passwords',
    short: 'Argon2 & bcrypt',
    title: 'Argon2 and bcrypt',
    flowName: 'Hashing, storing, and an attacker’s GPU',
    lede: 'Password hashes are slow on purpose. Argon2id goes further and makes every guess need its own chunk of memory, which is the one thing a GPU full of tiny cores doesn’t have much of.',
    sources: [book('argon2', 'Argon2'), book('bcrypt', 'Bcrypt')],
    glance: [
      ['16 MiB+', 'Argon2id memory'],
      ['t = 3', 'iterations (passes)'],
      ['p = 1', 'parallelism'],
      ['~20,000 /s', 'guesses per rented H100'],
      ['72 bytes', 'bcrypt’s input limit'],
    ],
    analogy: {
      title: 'The busy kitchen',
      intro: 'Cracking a hash means cooking every possible recipe until one tastes right. A GPU is a kitchen with thousands of cooks but tiny counters. Argon2id makes every dish need a big counter, so most cooks stand idle.',
      map: [
        ['Attacker’s GPU', 'A kitchen with thousands of cooks'],
        ['Iterations (t)', 'How many times each dish is reworked'],
        ['Memory (m)', 'The counter space each dish needs'],
        ['Parallelism (p)', 'Cooks working on one dish together'],
        ['Salt', 'A secret spice unique to each diner'],
        ['PHC string', 'The recipe card stapled to the dish'],
      ],
    },
    actors: ['api', 'db', 'attacker'],
    steps: [
      proc('api', 'cred', 'salt = randomBytes(16)', 'Start with a fresh salt',
        `<p>At least 16 bytes from a cryptographically secure generator. The salt isn’t secret and is stored openly next to the hash. Its job is to make every user’s hash unique.</p>`,
        `Choose this diner’s unique spice.`),
      proc('api', 'cred', 'fill 16 MiB · 3 passes · 1 lane', 'Argon2id fills memory, then works over it',
        `<p><b>Memory</b> (m) is the main dial: doubling it doubles the time and the hardware an attacker needs. <b>Iterations</b> (t) should be at least 3. <b>Parallelism</b> (p) of 1 maximises how many users your server can serve at once.</p>`,
        `Each dish needs a full counter of ingredients, reworked three times by one cook.`),
      send('api', 'db', 'data', '$argon2id$v=19$m=16384,t=3,p=1$…', 'Store one self-describing string',
        `<p>The PHC string format holds the algorithm, version, settings, salt and hash. Memory is in KiB, salt and hash are base64. Verifying later needs nothing but this string and the guess.</p>`,
        `The recipe card is stapled to the dish so it can be remade exactly.`,
        `$argon2id $v=19 $m=16384,t=3,p=1 $Zk9xS3pRa1h2bWJtR2RqUQ $9dJ3l0u4mRk2nBqN8m1T0q3Q6m5rK4b1sY0bR3dZ2aQ
 algorithm  version  memory KiB, passes, lanes  salt (base64)           hash (base64, 32 bytes)`),
      send('attacker', 'db', 'attack', 'dump of the users collection', 'The hashes are stolen',
        `<p>Assume it happens eventually: a leaked backup, an exposed database, an injection bug.</p>`,
        `A rival kitchen gets a crate of finished dishes.`),
      proc('attacker', 'attack', 'RTX 5090 ≈ 10,000/s · H100 ≈ 20,000/s', 'Cracking costs real money',
        `<p>At the book’s settings, a top consumer GPU manages about 10,000 Argon2id guesses a second and a rented H100 about 20,000, at $2–5 per hour. A long random password is far out of reach. Common passwords still fall, which is why the breach check matters.</p>`,
        `Even a huge kitchen only plates so many dishes a second, and it rents by the hour.`),
      block('attacker', 'db', 'precomputed hash tables', 'unique salt per user', 'Salts defeat precomputation',
        `<p>Without salts, one table of precomputed hashes cracks every user at once. With a unique salt per user, each hash must be attacked on its own.</p>`,
        `A cookbook of famous recipes is useless when every diner’s spice is different.`),
      proc('api', 'cred', 'bcrypt: cost ≥ 10 · input ≤ 72 bytes', 'If you use bcrypt',
        `<p>bcrypt is older and still fine. Each +1 to its cost doubles the work; use at least 10. Two traps: it reads at most 72 bytes (counting a null terminator, so 71 usable), measured in <b>bytes</b>, not characters, and it can’t take raw binary input. The book prefers Argon2 for having fewer footguns.</p>`,
        `The older oven works, but it only reads the first 72 letters of any recipe.`,
        `$2a$10$TEBu87xaQfRF3lrFq2mfxe.HScQPBKFpmuvhCywrIAri3gvTtwhwO
 └ ver └ cost └ salt (22 chars)      └ hash`),
      proc('api', 'cred', 'raise m · keep t and p · rehash on login', 'Tuning over the years',
        `<p>To strengthen hashing later, increase memory and leave iterations and parallelism alone. Old hashes upgrade when users next sign in: verify, then re-hash with the new settings.</p>`,
        `Give each dish a bigger counter rather than more rework, and re-plate old dishes when diners return.`),
    ],
    concept: `
<h3>The three Argon2 variants</h3>
<dl>
  <dt>Argon2d</dt><dd>Strongest against GPUs, but vulnerable to side-channel attacks.</dd>
  <dt>Argon2i</dt><dd>Resists side channels, weaker against GPUs.</dd>
  <dt>Argon2id</dt><dd>A blend of both. <b>Use this one</b>, and don’t mix it up with the others in your library’s options.</dd>
</dl>
<h3>Reading the parameters</h3>
<div class="anatomy"><span class="seg a">$argon2id</span><span class="seg">$v=19</span><span class="seg b">$m=16384,t=3,p=1</span><span class="seg c">$&lt;salt&gt;</span><span class="seg d">$&lt;hash&gt;</span></div>
<div class="table-wrap"><table>
  <thead><tr><th>Parameter</th><th>Book’s value</th><th>Effect of raising it</th></tr></thead>
  <tbody>
    <tr><td>Memory (m)</td><td>≥ 16 MiB</td><td>Doubles time and attacker hardware per doubling. Ideally over 128 MiB, rarely realistic for web apps.</td></tr>
    <tr><td>Iterations (t)</td><td>≥ 3</td><td>Linear time increase. Prefer raising memory instead.</td></tr>
    <tr><td>Parallelism (p)</td><td>1</td><td>Faster single hash, but fewer concurrent users per server.</td></tr>
    <tr><td>Output</td><td>32 bytes</td><td>Configurable; 32 is standard.</td></tr>
  </tbody>
</table></div>
<h3>bcrypt’s footguns</h3>
<ul>
  <li>72-byte limit, so a 30-character emoji password can be cut short without warning. Check <code>Buffer.byteLength</code>, not <code>.length</code>.</li>
  <li>Null-terminated input: never feed it the raw output of another hash or cipher.</li>
  <li>Specialised hardware (ASICs, FPGAs) attacks it about 10× more efficiently than GPUs.</li>
</ul>`,
    threats: [
      { name: 'GPU cracking', risk: 'Fast hashes fall at billions of guesses per second.', fix: 'Argon2id with memory cost, so each guess needs megabytes of memory.' },
      { name: 'Rainbow tables', risk: 'Precomputed hashes crack unsalted databases instantly.', fix: 'A unique 16-byte salt per hash (built in to Argon2 and bcrypt libraries).' },
      { name: 'Wrong Argon2 variant', risk: 'Argon2i or Argon2d chosen by accident trades away protection.', fix: 'Set <code>type: argon2.argon2id</code> explicitly.' },
      { name: 'bcrypt truncation', risk: 'Long or non-ASCII passwords are silently cut at 72 bytes.', fix: 'Reject inputs over 71 bytes, or use Argon2id.' },
      { name: 'Settings that never change', risk: 'Hardware gets faster every year.', fix: 'Raise memory over time and rehash at sign-in.' },
    ],
    code: [
      {
        file: 'server/src/services/hashing.js',
        code: code`
import argon2 from 'argon2';
import bcrypt from 'bcrypt';

// ---------- Argon2id (recommended)
export const ARGON2 = {
  type: argon2.argon2id,   // not argon2i or argon2d
  memoryCost: 16384,       // KiB = 16 MiB, the book's minimum. Raise this first.
  timeCost: 3,             // iterations, at least 3
  parallelism: 1,          // best overall throughput on a server
  hashLength: 32,
};

export const argon2Hash = (password) => argon2.hash(password, ARGON2);   // salt generated for you
export const argon2Verify = (hash, password) => argon2.verify(hash, password);
export const argon2NeedsRehash = (hash) => argon2.needsRehash(hash, ARGON2);

// ---------- bcrypt (fine for existing systems)
const BCRYPT_COST = 12;    // the book's minimum is 10; each +1 doubles the work

export async function bcryptHash(password) {
  // bcrypt reads at most 72 bytes including a null terminator: 71 usable, counted in BYTES
  if (Buffer.byteLength(password, 'utf8') > 71) {
    throw new Error('Password is too long for bcrypt (71 bytes maximum)');
  }
  return bcrypt.hash(password, BCRYPT_COST);   // the salt is generated and embedded for you
}

export const bcryptVerify = (hash, password) => bcrypt.compare(password, hash);

// ---------- measure on your own server: aim for roughly 50–250 ms
// const t = performance.now(); await argon2Hash('benchmark'); console.log(performance.now() - t);`,
      },
    ],
    checklist: [
      'The hash type is explicitly Argon2id',
      'Memory ≥ 16 MiB, iterations ≥ 3, parallelism 1',
      'The full PHC string is stored as one field',
      'Hashes are upgraded at sign-in when settings change',
      'If using bcrypt: cost ≥ 10 and inputs over 71 bytes are rejected',
    ],
  });

  // ================================================================ 06 · Rate limiting
  AIM.chapters.push({
    id: 'rate-limiting',
    num: '06',
    group: 'Passwords',
    short: 'Rate limiting',
    title: 'Rate limiting with a token bucket',
    flowName: 'Five tokens, one more every minute',
    lede: 'Rate limits turn online guessing from a sprint into a crawl. The book uses one shape everywhere: a bucket per user that holds 5 tokens and gets 1 back every minute.',
    sources: [book('passwords', 'Passwords'), book('email-code-authentication', 'Email code authentication')],
    glance: [
      ['5', 'tokens: the allowed burst'],
      ['+1 / minute', 'refill rate'],
      ['≈ 525,000', 'guesses a year, at most'],
      ['Per user', 'not per IP'],
    ],
    analogy: {
      title: 'The arcade token cup',
      intro: 'Every account has a cup with room for five tokens. Each try costs one. The arcade drops one token back in every minute, up to five. A normal player never notices; someone hammering the machine runs dry immediately.',
      map: [
        ['Bucket', 'The token cup, five slots'],
        ['Attempt', 'Putting one token in the machine'],
        ['Refill', 'One token dropped back in each minute'],
        ['Bucket key', 'The name on the cup: the account, not the seat'],
        ['IP address', 'The seat number, easy to change'],
        ['429 response', '“Cup’s empty, come back in a minute”'],
      ],
    },
    actors: ['browser', 'api', 'redis', 'attacker'],
    steps: [
      send('browser', 'api', 'cred', 'POST /login (attempt 1)', 'A sign-in attempt arrives',
        `<p>Before any expensive work (hashing a password, checking a code), the server asks: may this account try again yet?</p>`,
        `A player walks up to the machine.`),
      send('api', 'redis', 'data', 'takeToken("password:66f1")', 'Look up this account’s bucket',
        `<p>The bucket lives in Redis, so every server instance shares one count. The key is the <b>user</b> (or email address), not the IP.</p>`,
        `The attendant finds the cup with this player’s name on it.`),
      proc('redis', 'data', 'refill for time passed, then take 1', 'Refill first, then spend',
        `<p>An atomic script adds one token per full minute since the last update (never above 5), then takes one if available.</p>`,
        `First drop in any tokens earned while away, then take one out.`,
        `tokens = min(5, tokens + floor(elapsed / 60s))
if tokens ≥ 1 → tokens -= 1, allow
else          → deny, retry after the next refill`),
      send('redis', 'api', 'data', 'allowed · 4 left', 'Allowed: continue to the real check',
        `<p>Only now does the server hash the password or verify the code.</p>`,
        `One token in, and the game starts.`),
      block('attacker', 'api', 'attempts 6 to 1,000 in one minute', '429 · Retry-After: 60', 'A burst empties the bucket',
        `<p>After five quick tries the bucket is empty. Each further try is refused instantly and costs the server almost nothing.</p>`,
        `The cup is empty; the machine won’t start.`),
      proc('api', 'data', '1/min × 525,600 min ≈ 525,600 tries/year', 'What the limit buys you',
        `<p>The most anyone can try is about half a million guesses per account per year. That’s nothing against a decent password, and enough to stop slow guessing of common ones once combined with a breach check.</p>`,
        `Even playing all year, one cup only buys about half a million games.`),
      block('attacker', 'api', 'rotate through 10,000 IP addresses', 'the limit is per account', 'Why not limit by IP?',
        `<p>IP limits block whole offices, schools and mobile carriers that share one address, while attackers just rotate proxies. Keying by account means new IPs don’t buy new tokens.</p>`,
        `Changing seats doesn’t get you a new cup. It has your name on it.`),
      proc('api', 'ok', 'no lockouts · no exponential backoff', 'Never lock the account',
        `<p>Lockouts and doubling delays can be triggered on purpose to lock out a real user. A steady refill keeps the real user at most a minute away from their next try.</p>`,
        `The arcade never confiscates your cup. It just refills slowly.`),
    ],
    concept: `
<h3>Where the book applies it</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Endpoint</th><th>Bucket key</th><th>Capacity / refill</th></tr></thead>
  <tbody>
    <tr><td>Password sign-in, password change, re-verify</td><td>User ID</td><td>5 / 1 per minute</td></tr>
    <tr><td>Email verification code</td><td>Email address</td><td>5 / 1 per minute</td></tr>
    <tr><td>Email sign-in or reset code</td><td>User ID</td><td>5 / 1 per minute</td></tr>
  </tbody>
</table></div>
<h3>Why a token bucket?</h3>
<ul>
  <li><b>Bursts are fine.</b> A user who mistypes twice in a row isn’t punished.</li>
  <li><b>Sustained guessing isn’t.</b> The long-run rate is fixed at the refill speed.</li>
  <li><b>No cliff edges.</b> Unlike a fixed window, there’s no moment where the counter resets and allows a double burst.</li>
</ul>
<p class="callout"><b>The trade-off.</b> Someone can deliberately drain a victim’s bucket so their sign-ins are delayed. With a 1-minute refill the real user is never more than a minute from trying again, which is far better than a lockout.</p>`,
    threats: [
      { name: 'Online brute force', risk: 'Unlimited guesses against one account.', fix: 'A per-account token bucket in front of every check.' },
      { name: 'Distributed guessing', risk: 'A botnet spreads guesses across thousands of IPs.', fix: 'Key the bucket by account or email, not IP.' },
      { name: 'Lockout abuse', risk: 'Failed-attempt lockouts let attackers lock real users out.', fix: 'Steady refill instead of lockouts or exponential delays.' },
      { name: 'Per-instance counters', risk: 'In-memory limits multiply with every server instance.', fix: 'Keep buckets in Redis, updated atomically with a Lua script.' },
    ],
    code: [
      {
        file: 'server/src/lib/tokenBucket.js',
        note: 'A token bucket in Redis. The Lua script runs atomically, so parallel requests can’t both take the last token.',
        code: code`
import IORedis from 'ioredis';

export const redis = new IORedis(process.env.REDIS_URL);

redis.defineCommand('takeToken', {
  numberOfKeys: 1,
  lua: \`
    local key       = KEYS[1]
    local capacity  = tonumber(ARGV[1])
    local refillMs  = tonumber(ARGV[2])
    local now       = tonumber(ARGV[3])

    local state     = redis.call('HMGET', key, 'tokens', 'updatedAt')
    local tokens    = tonumber(state[1]) or capacity
    local updatedAt = tonumber(state[2]) or now

    -- one token back for every full refill interval that has passed
    local refills = math.floor((now - updatedAt) / refillMs)
    if refills > 0 then
      tokens = math.min(capacity, tokens + refills)
      updatedAt = updatedAt + refills * refillMs
    end
    if tokens >= capacity then updatedAt = now end

    local allowed = 0
    if tokens >= 1 then
      tokens = tokens - 1
      allowed = 1
    end

    redis.call('HSET', key, 'tokens', tokens, 'updatedAt', updatedAt)
    redis.call('PEXPIRE', key, capacity * refillMs)   -- a full bucket needs no record

    local waitMs = 0
    if allowed == 0 then waitMs = refillMs - (now - updatedAt) end
    return { allowed, tokens, waitMs }
  \`,
});

/** Take one token. Defaults to the book's bucket: 5 capacity, 1 token per minute. */
export async function takeToken(key, { capacity = 5, refillMs = 60_000 } = {}) {
  const [allowed, remaining, waitMs] = await redis.takeToken(\`bucket:\${key}\`, capacity, refillMs, Date.now());
  return { allowed: allowed === 1, remaining, retryAfterSec: Math.max(1, Math.ceil(waitMs / 1000)) };
}

/** Express middleware for routes where the key is known up front (e.g. an email in the body). */
export const bucket = (keyFor, options) => async (req, res, next) => {
  const key = keyFor(req);
  if (!key) return res.status(400).json({ error: 'Missing identifier' });
  const result = await takeToken(key, options);
  if (!result.allowed) {
    res.set('Retry-After', String(result.retryAfterSec));
    return res.status(429).json({ error: \`Too many attempts. Try again in \${result.retryAfterSec} seconds.\` });
  }
  next();
};

// Usage:
// router.post('/signup/verify', bucket((req) => 'verify:' + req.signup?.email), verifyEmailCode);`,
      },
    ],
    checklist: [
      'Every endpoint that hashes or checks a code takes a token first',
      'Buckets are keyed by account or email address, not IP',
      'Buckets live in Redis and update atomically',
      'Responses include <code>Retry-After</code> with a clear message',
      'There are no lockouts or exponential delays',
    ],
  });
})();
