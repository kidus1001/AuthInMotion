/* Passkeys: concepts, registration, authentication
   Concepts adapted from Pilcrow's Auth book: https://auth.pilcrowonpaper.com */
(function () {
  'use strict';
  const AIM = window.AIM;
  const { code, send, proc, block, book } = AIM;

  // ================================================================ 11 · Passkeys
  AIM.chapters.push({
    id: 'passkeys',
    num: '11',
    group: 'Passkeys',
    short: 'How passkeys work',
    title: 'How passkeys work',
    flowName: 'A key pair, a challenge and a signature',
    lede: 'A passkey is a key pair. The private half never leaves the user’s device; your server keeps only the public half. Nothing secret crosses the network, nothing can be guessed, and the key only works on your domain.',
    sources: [book('passkeys', 'Passkeys'), book('webauthn', 'Web Authentication API')],
    glance: [
      ['Public key', 'all your server stores'],
      ['Domain-bound', 'useless on look-alike sites'],
      ['UV required', 'PIN, fingerprint or face'],
      ['Up to 10', 'passkeys per account'],
    ],
    analogy: {
      title: 'The signet ring',
      intro: 'You own a ring that presses a unique seal. The bank keeps a wax impression of it, which can check a seal but can’t make one. To prove it’s you, the bank hands you a fresh slip and you press the ring onto it.',
      map: [
        ['Private key', 'The ring, which never leaves your hand'],
        ['Public key', 'The wax impression the bank keeps on file'],
        ['Challenge', 'A fresh slip with a random number on it'],
        ['Signature', 'Your seal pressed onto that slip'],
        ['User verification', 'Unlocking the ring’s case with your fingerprint'],
        ['RP ID (your domain)', 'The ring only stamps slips from this one bank'],
      ],
    },
    actors: ['browser', 'api', 'db', 'phone', 'attacker'],
    steps: [
      proc('phone', 'cred', 'generate key pair', 'A passkey is a key pair made on the device',
        `<p>The authenticator (a phone, laptop, security key or password manager) creates a private and public key. The book’s definition: a <b>discoverable</b> WebAuthn credential that <b>requires user verification</b>.</p>`,
        `A ring is cut that nobody else has.`),
      send('phone', 'api', 'data', 'public key + credential ID', 'Only the public key is shared',
        `<p>The public key can check signatures but can’t create them.</p>`,
        `The bank takes a wax impression of your ring.`),
      send('api', 'db', 'data', 'store { credentialId, publicKey, algorithm }', 'The server files the public key',
        `<p>The credential ID identifies the passkey; the algorithm says how to check its signatures.</p>`,
        `The impression is filed under your name.`),
      send('api', 'browser', 'cred', 'challenge: 32 random bytes', 'Sign-in starts with a fresh challenge',
        `<p>The server sends a new random value for every attempt, so no signature can be reused.</p>`,
        `The bank hands you a fresh slip with today’s random number.`),
      send('browser', 'phone', 'cred', 'navigator.credentials.get()', 'The browser asks the authenticator',
        `<p>The browser tells the authenticator which website is asking. Your code can’t lie about this.</p>`,
        `You’re asked to stamp the slip.`),
      proc('phone', 'token', 'Face ID / PIN → sign(challenge)', 'User verification, then a signature',
        `<p><b>User presence</b> means someone touched the device; <b>user verification</b> means it was the right person (PIN or biometric). Then the private key signs the challenge.</p>`,
        `You unlock the ring’s case with your fingerprint and press the seal.`),
      send('phone', 'api', 'token', 'signature + credential ID', 'The signature goes back',
        `<p>The signature is only valid for this challenge, on this website.</p>`,
        `You hand the stamped slip to the teller.`),
      proc('api', 'ok', 'verify(publicKey, signature)', 'The server checks it with the public key',
        `<p>A valid signature proves the user holds the private key, without the key ever leaving the device.</p>`,
        `The seal matches the impression on file.`),
      block('attacker', 'db', 'leaked table of public keys', 'public keys can’t sign', 'A database leak gives away nothing useful',
        `<p>There’s no password hash to crack and no shared secret to replay.</p>`,
        `A stolen box of wax impressions can’t stamp anything.`),
      block('attacker', 'phone', 'phishing site: “sign in with your passkey”', 'wrong domain: no passkey offered', 'Phishing fails',
        `<p>Passkeys are bound to your domain (the RP ID). On <code>examp1e.com</code> the device has no passkey to offer.</p>`,
        `The ring refuses to stamp slips from a fake bank.`),
      proc('api', 'data', 'up to 10 · user-named · verify before changes', 'Account policy',
        `<p>Let users register several passkeys (at least 5, ideally 10) so one lost phone isn’t a lockout, and let them name each one. Ask for identity verification before adding or removing a passkey.</p>`,
        `Keep spare rings on file, label each one, and show ID before adding or removing any.`),
    ],
    concept: `
<h3>The three actors</h3>
<dl>
  <dt>Authenticator</dt><dd>Stores the private key and verifies the user: a phone, a laptop’s secure chip, a security key, or a password manager. Each model has an AAGUID that identifies it.</dd>
  <dt>Relying party</dt><dd>Your app: server plus front-end code. Its RP ID is your domain.</dd>
  <dt>Client</dt><dd>The browser, which connects the two and reports which origin is asking.</dd>
</dl>
<h3>Synced or device-bound?</h3>
<div class="table-wrap"><table>
  <thead><tr><th></th><th>Device-bound passkey</th><th>Synced passkey (iCloud, Google, 1Password)</th></tr></thead>
  <tbody>
    <tr><td>Where the key lives</td><td>One device or security key</td><td>Backed up across the user’s devices</td></tr>
    <tr><td>Strictly two-factor?</td><td>Yes: possession + PIN/biometric</td><td>Mostly not (the cloud account replaces the device)</td></tr>
    <tr><td>Book’s verdict</td><td colspan="2">Both are very secure. Strict MFA isn’t necessary.</td></tr>
  </tbody>
</table></div>
<h3>Why passkeys beat passwords</h3>
<ul>
  <li><b>Unguessable</b>: there’s nothing to brute-force.</li>
  <li><b>Domain-bound</b>: phishing pages can’t use them.</li>
  <li><b>No shared secret</b>: your database only holds public keys.</li>
</ul>
<p class="callout"><b>One method is enough.</b> If an account signs in with a passkey (which already checks a PIN or biometric), the book says it doesn’t need an extra second factor on top.</p>`,
    threats: [
      { name: 'Phishing', risk: 'Look-alike sites collect credentials and replay them.', fix: 'Passkeys are bound to the RP ID, so they never work on the wrong domain.' },
      { name: 'Database breach', risk: 'Stolen credentials let attackers sign in.', fix: 'Only public keys are stored, and they can’t sign.' },
      { name: 'Replay', risk: 'A captured sign-in message is sent again.', fix: 'A fresh, single-use challenge per attempt.' },
      { name: 'Lost device', risk: 'The only passkey disappears with the phone.', fix: 'Allow up to 10 passkeys and keep a recovery method such as email.' },
      { name: 'Hijacker adds a passkey', risk: 'Someone with a stolen session registers their own passkey for permanent access.', fix: 'Verify identity before registering or deleting passkeys.' },
    ],
    code: [
      {
        file: 'server/src/models/Passkey.js',
        code: code`
import mongoose from 'mongoose';

const passkeySchema = new mongoose.Schema(
  {
    _id: { type: String },                         // credential ID (base64url), unique by design
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    publicKey: { type: Buffer, required: true },   // never a private key: the server never sees one
    algorithm: { type: Number, enum: [-7, -257, -8] },   // ES256, RS256, EdDSA
    counter: { type: Number, default: 0 },
    transports: [String],
    aaguid: String,                                // which authenticator model made it
    name: { type: String, maxlength: 60 },         // "Work laptop", "iPhone"
    lastUsedAt: Date,
  },
  { timestamps: true },
);

export const MAX_PASSKEYS = 10;
export const Passkey = mongoose.model('Passkey', passkeySchema);`,
      },
      {
        file: 'server/src/routes/passkeys.routes.js',
        note: 'Listing is free; renaming is low-risk; deleting needs fresh verification (chapter 03).',
        code: code`
import { Router } from 'express';
import { Passkey } from '../models/Passkey.js';
import { requireSession } from '../middleware/session.js';
import { consumeAction } from '../services/actionSession.js';

export const passkeysRouter = Router();
passkeysRouter.use(requireSession);

passkeysRouter.get('/', async (req, res) => {
  const passkeys = await Passkey.find({ userId: req.session.userId })
    .select('name aaguid createdAt lastUsedAt').sort({ createdAt: 1 }).lean();
  res.json(passkeys);
});

passkeysRouter.patch('/:id', async (req, res) => {
  const name = String(req.body.name ?? '').trim();
  if (!name || name.length > 60) return res.status(400).json({ error: 'Use a name of 1–60 characters' });
  await Passkey.updateOne({ _id: req.params.id, userId: req.session.userId }, { $set: { name } });
  res.status(204).end();
});

passkeysRouter.delete('/:id', async (req, res) => {
  if (!(await consumeAction(req, req.body.actionId, 'delete-passkey'))) {
    return res.status(403).json({ error: 'Confirm your identity first' });
  }
  await Passkey.deleteOne({ _id: req.params.id, userId: req.session.userId });   // only your own
  res.status(204).end();
});`,
      },
    ],
    checklist: [
      'Passkeys are discoverable and require user verification',
      'The server stores only credential ID, public key and algorithm',
      'Users can register up to 10 passkeys and name each one',
      'Adding or removing a passkey requires fresh identity verification',
      'A recovery method (like email sign-in) exists for lost devices',
    ],
  });

  // ================================================================ 12 · Registration
  AIM.chapters.push({
    id: 'passkey-registration',
    num: '12',
    group: 'Passkeys',
    short: 'Registering a passkey',
    title: 'Registering a passkey',
    flowName: 'Verify, create, check, store, name',
    lede: 'Registering a passkey means asking the user’s device to create a key pair and checking what comes back before you trust it. Most of the work is choosing the right options.',
    sources: [book('passkey-registration', 'Passkey registration'), book('webauthn', 'Web Authentication API')],
    glance: [
      ['-7 & -257', 'ES256 + RS256, both required'],
      ['residentKey', '“required” (discoverable)'],
      ['attestation', '“none”'],
      ['excludeCredentials', 'one passkey per device'],
    ],
    analogy: {
      title: 'Registering your ring at the bank',
      intro: 'Before the bank files a new ring, you show ID at the counter. They give you a numbered slip, you press the new ring onto it, the bank checks it’s a proper seal, and files the impression under a label you choose.',
      map: [
        ['Identity check first', 'Showing ID before adding a ring'],
        ['Challenge', 'Today’s numbered slip'],
        ['excludeCredentials', '“We already have this ring on file”'],
        ['Algorithm list', 'The seal shapes the bank can read'],
        ['Public key validation', 'Checking the impression is a real, well-formed seal'],
        ['Passkey name', 'The label on the file: “Work laptop”'],
      ],
    },
    actors: ['browser', 'api', 'db', 'redis', 'phone'],
    steps: [
      send('browser', 'api', 'cred', 'POST /account/verify (password or email code)', 'Verify the user first',
        `<p>Registering a passkey is a sensitive action. Use any existing method to verify identity; it doesn’t have to be a passkey. This creates a single-use <code>register-passkey</code> permission (chapter 03).</p>`,
        `You show ID at the counter.`),
      send('browser', 'api', 'token', 'POST /passkeys/register/options', 'Ask for registration options',
        `<p>The server checks the user has fewer than 10 passkeys and consumes the permission.</p>`,
        `You ask to register a new ring.`),
      proc('api', 'cred', 'challenge · user.id · excludeCredentials', 'Build the creation options',
        `<p>The book’s settings: discoverable credential, user verification required, no attestation, three algorithms, and the user’s existing credentials excluded so one device can’t register twice.</p>`,
        `The clerk prepares a slip that lists the seal shapes the bank accepts.`,
        `{
  challenge: <random bytes>,
  rp: { id: "app.example.com" },
  user: { id: <bytes of user ID>, displayName: "ana@example.com" },
  pubKeyCredParams: [ { type: "public-key", alg: -8 },     // EdDSA (optional)
                      { type: "public-key", alg: -7 },     // ES256 (required)
                      { type: "public-key", alg: -257 } ], // RS256 (older Windows)
  excludeCredentials: [ { type: "public-key", id: <existing ID> } ],
  authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
  attestation: "none",
  extensions: { credentialProtectionPolicy: "userVerificationRequired", enforceCredentialProtectionPolicy: false }
}`),
      send('api', 'redis', 'data', 'SET reg-challenge → userId (5 min)', 'Remember the challenge',
        `<p>Single-use and short-lived, tied to this user.</p>`,
        `The slip number is noted in the ledger.`),
      send('api', 'browser', 'data', 'creation options', 'Send the options to the browser',
        `<p>The front end passes them to <code>navigator.credentials.create()</code>.</p>`,
        `You’re handed the slip.`),
      send('browser', 'phone', 'cred', 'navigator.credentials.create()', 'The browser asks the authenticator',
        `<p>If the user cancels you get <code>NotAllowedError</code>; if the device can’t meet the requirements, <code>NotSupportedError</code>.</p>`,
        `You take out your new ring.`),
      proc('phone', 'cred', 'verify user → new key pair', 'The device creates the passkey',
        `<p>After a PIN or biometric check, the authenticator makes a new key pair and keeps the private key.</p>`,
        `You unlock the case and press the new ring onto the slip.`),
      send('phone', 'browser', 'token', 'attestationObject + clientDataJSON', 'The device returns the public key',
        `<p>Wrapped in authenticator data (encoded as CBOR) along with client data that records the origin and challenge.</p>`,
        `The stamped slip comes back with the impression.`),
      send('browser', 'api', 'token', 'POST /passkeys/register/verify', 'Send it to the server',
        `<p>Libraries like <code>@simplewebauthn/browser</code> encode everything as JSON.</p>`,
        `You hand the slip to the clerk.`),
      proc('api', 'token', 'challenge ✓ origin ✓ UV ✓ alg ✓ key ✓', 'Check everything before trusting it',
        `<p>Consume the challenge. Check the origin and RP ID, the user-verified flag, that the algorithm is one you asked for, and that the public key is valid (P-256 for ES256; 2048-bit+ RSA with exponent 65537 for RS256; Ed25519 for EdDSA). Reject a credential ID that already exists.</p>`,
        `The clerk checks the slip number, the bank’s name, and that the seal is a proper shape.`),
      send('api', 'db', 'data', 'insert passkey { _id: credentialId, publicKey, alg, counter }', 'Store the passkey',
        `<p>Credential ID (unique and searchable), public key, algorithm, and optionally the signature counter and AAGUID.</p>`,
        `The impression is filed.`),
      send('api', 'browser', 'ok', '“Name this passkey” · default: “iCloud Keychain”', 'Let the user name it',
        `<p>Suggest a name from the AAGUID when available (password managers usually provide one; security keys often don’t without attestation) and let the user change it.</p>`,
        `The clerk asks what label to put on the file.`),
    ],
    concept: `
<h3>Options that matter</h3>
<div class="table-wrap"><table>
  <thead><tr><th>Option</th><th>Value</th><th>Why</th></tr></thead>
  <tbody>
    <tr><td><code>authenticatorSelection.residentKey</code></td><td><code>"required"</code></td><td>Discoverable: the user can sign in without typing a username. Also set the deprecated <code>requireResidentKey: true</code>.</td></tr>
    <tr><td><code>userVerification</code></td><td><code>"required"</code></td><td>PIN or biometric, not just a tap.</td></tr>
    <tr><td><code>pubKeyCredParams</code></td><td>-8, -7, -257</td><td>ES256 is the most common; RS256 for older Windows; EdDSA for many security keys. Don’t use -9 or -19.</td></tr>
    <tr><td><code>attestation</code></td><td><code>"none"</code></td><td>Proving the device’s make and model is mostly for enterprises.</td></tr>
    <tr><td><code>excludeCredentials</code></td><td>User’s existing IDs</td><td>No duplicate passkey on the same authenticator.</td></tr>
    <tr><td><code>user.id</code></td><td>Bytes of your user ID</td><td>Or random bytes if you don’t want to expose IDs. Same <code>user.id</code> replaces an existing passkey on that device.</td></tr>
    <tr><td><code>credentialProtectionPolicy</code></td><td><code>"userVerificationRequired"</code></td><td>Stops credential enumeration on security keys. Keep <code>enforce…: false</code> so password managers aren’t blocked.</td></tr>
  </tbody>
</table></div>
<p><code>rp.name</code> and <code>user.name</code> are deprecated in the spec, though some libraries still ask for them.</p>
<h3>Public key checks by algorithm</h3>
<dl>
  <dt>ES256 (-7)</dt><dd>P-256 curve. Optionally check the point is on the curve; if you skip it, make sure your library doesn’t crash on invalid keys later.</dd>
  <dt>RS256 (-257)</dt><dd>2048-bit modulus (3072 or 4096 optional), exponent 65537.</dd>
  <dt>EdDSA (-8)</dt><dd>Ed25519.</dd>
</dl>
<p class="callout"><b>Don’t assume extension data is present.</b> Password managers often omit it, even when you asked for <code>credProtect</code>.</p>`,
    threats: [
      { name: 'Hijacker registers their own passkey', risk: 'A stolen session becomes permanent access.', fix: 'Require fresh verification, consumed once, before registration.' },
      { name: 'Replayed registration', risk: 'An old registration response is submitted again.', fix: 'Single-use challenges that expire in minutes.' },
      { name: 'Weak or malformed keys', risk: 'Invalid keys crash verification later or weaken it.', fix: 'Accept only the algorithms you asked for; validate key parameters.' },
      { name: 'Duplicate credentials', risk: 'The same credential ID gets attached to two accounts.', fix: 'Credential ID as a unique primary key; reject duplicates.' },
      { name: 'Unlimited passkeys', risk: 'Unbounded storage, and a cluttered list hides unknown passkeys.', fix: 'Cap at 10 and let users name them.' },
    ],
    code: [
      {
        file: 'server/src/controllers/passkeyRegister.controller.js',
        note: 'Uses @simplewebauthn/server v13, which does the CBOR parsing and signature checks for you.',
        code: code`
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { Passkey, MAX_PASSKEYS } from '../models/Passkey.js';
import { User } from '../models/User.js';
import { consumeAction } from '../services/actionSession.js';
import { redis } from '../lib/tokenBucket.js';

const RP_ID = process.env.RP_ID;          // "app.example.com"
const ORIGIN = process.env.APP_ORIGIN;    // "https://app.example.com"
const ALGORITHMS = [-8, -7, -257];        // EdDSA, ES256, RS256

// POST /passkeys/register/options { actionId }
export async function registrationOptions(req, res) {
  if (!(await consumeAction(req, req.body.actionId, 'register-passkey'))) {
    return res.status(403).json({ error: 'Confirm your identity first' });
  }
  const userId = req.session.userId;
  const existing = await Passkey.find({ userId }).select('_id transports').lean();
  if (existing.length >= MAX_PASSKEYS) {
    return res.status(400).json({ error: \`You can register up to \${MAX_PASSKEYS} passkeys. Remove one first.\` });
  }
  const user = await User.findById(userId);

  const options = await generateRegistrationOptions({
    rpName: 'Your App',                                  // deprecated in the spec, still required by the library
    rpID: RP_ID,
    userID: new TextEncoder().encode(String(user._id)),
    userName: user.email,
    userDisplayName: user.email,
    attestationType: 'none',
    excludeCredentials: existing.map((p) => ({ id: p._id, transports: p.transports })),
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    supportedAlgorithmIDs: ALGORITHMS,
  });

  // Single-use, 5 minutes, tied to this user
  await redis.set(\`webauthn:register:\${options.challenge}\`, String(userId), 'EX', 300);
  res.json(options);
}

// POST /passkeys/register/verify { response, name }
export async function verifyRegistration(req, res) {
  const { response } = req.body;
  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));

  const owner = await redis.getdel(\`webauthn:register:\${clientData.challenge}\`);   // consume it
  if (owner !== String(req.session.userId)) return res.status(400).json({ error: 'This request expired. Try again.' });

  let result;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: clientData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGORITHMS,
    });
  } catch {
    return res.status(400).json({ error: 'This passkey could not be verified' });
  }
  if (!result.verified) return res.status(400).json({ error: 'This passkey could not be verified' });

  const { credential, aaguid } = result.registrationInfo;
  if (await Passkey.exists({ _id: credential.id })) return res.status(409).json({ error: 'This passkey is already registered' });
  if ((await Passkey.countDocuments({ userId: req.session.userId })) >= MAX_PASSKEYS) {
    return res.status(400).json({ error: 'Passkey limit reached' });
  }

  await Passkey.create({
    _id: credential.id,
    userId: req.session.userId,
    publicKey: Buffer.from(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports,
    aaguid,
    name: String(req.body.name ?? 'Passkey').slice(0, 60),   // suggest one from the AAGUID in the UI
  });
  res.status(201).json({ message: 'Passkey added' });
}`,
      },
      {
        file: 'client/src/passkeys/register.js',
        code: code`
import { startRegistration } from '@simplewebauthn/browser';
import { api } from '../api';

export async function registerPasskey(actionId, name) {
  const optionsJSON = await api('/passkeys/register/options', { method: 'POST', body: { actionId } });
  try {
    const response = await startRegistration({ optionsJSON });   // calls navigator.credentials.create()
    return await api('/passkeys/register/verify', { method: 'POST', body: { response, name } });
  } catch (err) {
    if (err.name === 'NotAllowedError') throw new Error('Passkey creation was cancelled');
    if (err.name === 'InvalidStateError') throw new Error('This device already has a passkey for your account');
    throw err;
  }
}`,
      },
      {
        file: 'client/src/passkeys/under-the-hood-create.js',
        note: 'What the library does: the raw browser call with the book’s options.',
        code: code`
// challenge, userId, email and existingCredentialIds come from your server
const credential = await navigator.credentials.create({
  publicKey: {
    challenge,
    rp: { id: new URL(window.location.href).hostname },
    user: {
      id: new TextEncoder().encode(userId),
      displayName: email,
      name: email,                     // deprecated, but some browsers still expect it
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 },     // EdDSA (Ed25519), optional
      { type: 'public-key', alg: -7 },     // ES256 (P-256), required
      { type: 'public-key', alg: -257 },   // RS256, required for older Windows
    ],
    excludeCredentials: existingCredentialIds.map((id) => ({ type: 'public-key', id })),
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,          // deprecated, still include it
      userVerification: 'required',
    },
    attestation: 'none',
    extensions: {
      credentialProtectionPolicy: 'userVerificationRequired',
      enforceCredentialProtectionPolicy: false,   // don't block password managers
    },
  },
});

// Without attestation, these give you what to store:
const credentialId = credential.rawId;                            // bytes
const publicKey = credential.response.getPublicKey();             // SPKI DER (Safari: ES256 only)
const algorithm = credential.response.getPublicKeyAlgorithm();    // -7, -257 or -8
const authenticatorData = credential.response.getAuthenticatorData();   // AAGUID lives in here`,
      },
    ],
    checklist: [
      'Registration requires fresh, single-use identity verification',
      'Options request a discoverable credential with user verification and no attestation',
      'ES256 and RS256 are both supported',
      'Existing credentials are excluded',
      'Challenges are single-use and expire within minutes',
      'Credential IDs are unique; the passkey count is capped at 10',
      'Users can name each passkey',
    ],
  });

  // ================================================================ 13 · Authentication
  AIM.chapters.push({
    id: 'passkey-sign-in',
    num: '13',
    group: 'Passkeys',
    short: 'Signing in with a passkey',
    title: 'Signing in with a passkey',
    flowName: 'Challenge, sign, verify',
    lede: 'Signing in is a short conversation: the server sends a challenge, the device signs it after checking the user, and the server verifies the signature with the public key it stored at registration.',
    sources: [book('passkey-authentication', 'Passkey authentication'), book('webauthn', 'Web Authentication API')],
    glance: [
      ['authData ‖ SHA-256(clientData)', 'what gets signed'],
      ['UP + UV', 'flags you must check'],
      ['Counter', 'log mismatches, don’t block'],
      ['autocomplete="webauthn"', 'passkey autofill'],
    ],
    analogy: {
      title: 'Stamping the bank slip',
      intro: 'Each visit, the bank hands you a new numbered slip. You unlock your ring with your fingerprint and press it on. The teller checks the slip number is today’s and that the seal matches the impression on file.',
      map: [
        ['Challenge', 'Today’s numbered slip'],
        ['authenticatorData', 'The slip’s printed header: bank name, flags, a counter'],
        ['clientDataJSON', 'A note saying which website asked'],
        ['Signature', 'The wax seal over header and note'],
        ['Signature counter', 'A tally of how often the ring was used'],
        ['Passkey autofill', 'The teller offering “stamp here” as you walk up'],
      ],
    },
    actors: ['browser', 'api', 'db', 'redis', 'phone', 'attacker'],
    steps: [
      send('browser', 'api', 'data', 'GET /login', 'The sign-in page offers passkey autofill',
        `<p>Give the email field <code>autocomplete="webauthn"</code> and call <code>navigator.credentials.get()</code> with <code>mediation: "conditional"</code>. The browser offers passkeys in the field’s autofill menu.</p>`,
        `The teller notices you and offers a slip before you ask.`),
      send('api', 'redis', 'data', 'SET login-challenge (5 min)', 'Create a single-use challenge',
        `<p>The challenge is what gets signed. Abort or refresh the request when it expires, because users leave sign-in pages open for hours.</p>`,
        `A slip number is written in the ledger.`),
      send('api', 'browser', 'cred', 'challenge', 'Send it to the page',
        `<p>The conditional request waits until the user picks a passkey, possibly forever, so start it at the end of your page script.</p>`,
        `You hold the numbered slip.`),
      send('browser', 'phone', 'cred', 'navigator.credentials.get({ userVerification: "required" })', 'The user picks a passkey',
        `<p>Leaving out <code>allowCredentials</code> lets the user choose any discoverable passkey, with no username needed.</p>`,
        `You choose which ring to use.`),
      proc('phone', 'token', 'Face ID → sign(authData ‖ SHA-256(clientData))', 'Verify the user, then sign',
        `<p>The signed message is the authenticator data followed by the SHA-256 of the client data JSON.</p>`,
        `You unlock the case and press the seal across the slip.`,
        `authenticatorData = rpIdHash (32 B) | flags (1 B) | signCount (4 B)
clientDataJSON    = {"type":"webauthn.get","challenge":"…","origin":"https://app.example.com"}
signed message    = authenticatorData ‖ SHA-256(clientDataJSON)`),
      send('phone', 'browser', 'token', 'authenticatorData · clientDataJSON · signature · rawId · userHandle', 'The device returns the signed response',
        `<p><code>rawId</code> is the credential ID; <code>userHandle</code> is the <code>user.id</code> set at registration.</p>`,
        `The stamped slip comes back.`),
      send('browser', 'api', 'token', 'POST /passkeys/login', 'Send everything to the server',
        `<p>All five fields go to the server as base64url-encoded JSON.</p>`,
        `You hand the slip to the teller.`),
      send('api', 'redis', 'data', 'GETDEL login-challenge', 'Consume the challenge',
        `<p>Invalidate it after every attempt, successful or not.</p>`,
        `The teller crosses the slip number off the ledger.`),
      send('api', 'db', 'data', 'Passkey.findById(rawId)', 'Look up the public key',
        `<p>Unknown credential ID: maybe the passkey was deleted. Tell the user so they can pick another.</p>`,
        `The teller pulls your impression from the files.`),
      proc('api', 'token', 'clientData ✓ · rpIdHash ✓ · signature ✓', 'Verify the client data and signature',
        `<p>Client data: <code>type</code> is <code>webauthn.get</code>, the challenge matches, the origin is yours. Authenticator data: <code>rpIdHash</code> equals SHA-256 of your RP ID. Then check the signature over the signed message with the stored public key.</p>`,
        `Right bank, right slip number, and the seal matches the impression.`),
      proc('api', 'token', 'UP ✓ · UV ✓ · counter > stored?', 'Check the flags and the counter',
        `<p>The <b>user present</b> and <b>user verified</b> flags must both be set. If the stored counter isn’t 0, the new one should be higher. If it isn’t, log it for review, but don’t block the sign-in or disable the account: synced passkeys often report 0 or repeat values.</p>`,
        `The tally should go up. If it doesn’t, the teller makes a note, but still serves you.`),
      send('api', 'browser', 'ok', 'Set-Cookie: session=…', 'Signed in',
        `<p>A brand-new auth session (chapter 03).</p>`,
        `You’re let in.`),
      block('attacker', 'api', 'replay yesterday’s signed response', 'challenge already used', 'Replays fail',
        `<p>A captured response contains an old challenge, which has already been consumed.</p>`,
        `Yesterday’s stamped slip has a number that’s already crossed off.`),
    ],
    concept: `
<h3>The authenticator data header</h3>
<div class="anatomy"><span class="seg a">rpIdHash · 32 bytes</span><span class="seg b">flags · 1 byte</span><span class="seg c">signCount · 4 bytes</span><span class="seg">extensions…</span></div>
<dl>
  <dt>rpIdHash</dt><dd>SHA-256 of your RP ID (domain). Must match.</dd>
  <dt>flags</dt><dd>Bit 0 = user present (UP), bit 2 = user verified (UV). Require both.</dd>
  <dt>signCount</dt><dd>Big-endian counter. 0 means unsupported (common for synced passkeys).</dd>
</dl>
<h3>Server checklist</h3>
<ol>
  <li>Consume the challenge (on success and on failure).</li>
  <li>Parse <code>clientDataJSON</code>: type <code>webauthn.get</code>, matching challenge, your origin.</li>
  <li>Parse <code>authenticatorData</code>: matching <code>rpIdHash</code>, UP and UV set.</li>
  <li>Find the credential by ID and verify the signature over <code>authenticatorData ‖ SHA-256(clientDataJSON)</code>. ECDSA signatures arrive in ASN.1 DER format.</li>
  <li>Counter: log mismatches; don’t block.</li>
  <li>Create a new auth session.</li>
</ol>
<h3>Passkey autofill (conditional UI)</h3>
<pre class="inline-code">&lt;input name="email" type="email" autocomplete="webauthn"&gt;

navigator.credentials.get({ mediation: "conditional", publicKey: { challenge, userVerification: "required" } })</pre>`,
    threats: [
      { name: 'Replay', risk: 'A captured response is submitted again.', fix: 'Single-use challenges, consumed after every attempt.' },
      { name: 'Wrong site', risk: 'A response produced for another origin is accepted.', fix: 'Check the origin in client data and the RP ID hash in authenticator data.' },
      { name: 'Presence without verification', risk: 'A tap on an unlocked device counts as sign-in.', fix: 'Require the UV flag, not just UP.' },
      { name: 'Over-reacting to counters', risk: 'Blocking on a counter mismatch locks out synced-passkey users.', fix: 'Log and review mismatches; don’t block.' },
      { name: 'Stale challenges', risk: 'A sign-in page left open for hours holds an expired challenge.', fix: 'Abort and refresh the conditional request when the challenge expires.' },
    ],
    code: [
      {
        file: 'server/src/controllers/passkeyLogin.controller.js',
        code: code`
import { generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { Passkey } from '../models/Passkey.js';
import { createSession } from '../services/session.js';
import { setSessionCookie } from '../lib/cookies.js';
import { redis } from '../lib/tokenBucket.js';
import { logger } from '../lib/logger.js';

const RP_ID = process.env.RP_ID;
const ORIGIN = process.env.APP_ORIGIN;

// POST /passkeys/login/options
export async function loginOptions(req, res) {
  const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'required' });
  await redis.set(\`webauthn:login:\${options.challenge}\`, '1', 'EX', 300);   // single use, 5 minutes
  res.json(options);
}

// POST /passkeys/login { ...authentication response }
export async function login(req, res) {
  const response = req.body;
  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));

  // Consume the challenge whatever happens next
  if (!(await redis.getdel(\`webauthn:login:\${clientData.challenge}\`))) {
    return res.status(400).json({ error: 'This sign-in expired. Try again.' });
  }

  const passkey = await Passkey.findById(response.id);
  if (!passkey) return res.status(400).json({ error: 'This passkey isn’t registered. It may have been removed.' });

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: clientData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,           // UV flag, not just UP
      credential: {
        id: passkey._id,
        publicKey: passkey.publicKey,
        counter: 0,                            // we check the counter ourselves below: log, don't block
        transports: passkey.transports,
      },
    });
  } catch {
    return res.status(400).json({ error: 'Passkey sign-in failed' });
  }
  if (!result.verified) return res.status(400).json({ error: 'Passkey sign-in failed' });

  const { newCounter } = result.authenticationInfo;
  if (passkey.counter !== 0 && newCounter <= passkey.counter) {
    logger.warn({ passkeyId: passkey._id, stored: passkey.counter, received: newCounter }, 'passkey counter did not increase');
  }
  passkey.counter = Math.max(passkey.counter, newCounter);
  passkey.lastUsedAt = new Date();
  await passkey.save();

  const session = await createSession(passkey.userId, req);
  setSessionCookie(res, session.token, session.expiresAt);
  res.json({ ok: true });
}`,
      },
      {
        file: 'client/src/passkeys/autofill.js',
        note: 'Pair with <input name="email" type="email" autocomplete="webauthn"> on the sign-in page.',
        code: code`
import { startAuthentication } from '@simplewebauthn/browser';
import { api } from '../api';

// Call once, at the end of the sign-in page's setup. It resolves only when the user picks a passkey.
export async function startPasskeyAutofill(onSignedIn) {
  const optionsJSON = await api('/passkeys/login/options', { method: 'POST' });

  // The challenge expires after 5 minutes: start over before that if the page is still open
  const refresh = setTimeout(() => startPasskeyAutofill(onSignedIn), 4.5 * 60 * 1000);
  try {
    const response = await startAuthentication({ optionsJSON, useBrowserAutofill: true });
    clearTimeout(refresh);
    await api('/passkeys/login', { method: 'POST', body: response });
    onSignedIn();
  } catch (err) {
    clearTimeout(refresh);
    if (err.name !== 'AbortError') console.warn('Passkey sign-in failed', err);
  }
}`,
      },
      {
        file: 'server/src/passkeys/under-the-hood-verify.js',
        note: 'What the library checks, written with Node’s crypto. Assumes you stored the SPKI public key from getPublicKey() at registration.',
        code: code`
import crypto from 'node:crypto';

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

export function verifyAssertion({ authenticatorData, clientDataJSON, signature, publicKeySpki, algorithm, expected }) {
  // 1. Client data: what the browser says happened
  const clientData = JSON.parse(clientDataJSON.toString('utf8'));
  if (clientData.type !== 'webauthn.get') return { ok: false, reason: 'wrong type' };
  if (clientData.challenge !== expected.challenge) return { ok: false, reason: 'wrong challenge' };
  if (clientData.origin !== expected.origin) return { ok: false, reason: 'wrong origin' };

  // 2. Authenticator data: rpIdHash (32 bytes) | flags (1) | signCount (4, big-endian)
  if (!authenticatorData.subarray(0, 32).equals(sha256(expected.rpId))) return { ok: false, reason: 'wrong RP ID' };
  const flags = authenticatorData[32];
  if (!(flags & 0x01)) return { ok: false, reason: 'user not present' };    // UP
  if (!(flags & 0x04)) return { ok: false, reason: 'user not verified' };   // UV
  const signCount = authenticatorData.readUInt32BE(33);

  // 3. Signature over authenticatorData ‖ SHA-256(clientDataJSON)
  const message = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  const key = crypto.createPublicKey({ key: publicKeySpki, format: 'der', type: 'spki' });
  let valid;
  if (algorithm === -7) {
    valid = crypto.verify('sha256', message, { key, dsaEncoding: 'der' }, signature);   // ES256: ASN.1 DER signature
  } else if (algorithm === -257) {
    valid = crypto.verify('sha256', message, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
  } else if (algorithm === -8) {
    valid = crypto.verify(null, message, key, signature);                              // Ed25519
  } else {
    return { ok: false, reason: 'unsupported algorithm' };
  }
  return valid ? { ok: true, signCount } : { ok: false, reason: 'bad signature' };
}`,
      },
    ],
    checklist: [
      'Every attempt gets a fresh challenge, consumed after use',
      'The origin, type and RP ID hash are checked',
      'Both UP and UV flags are required',
      'Counter mismatches are logged, not blocked',
      'The sign-in page offers passkey autofill',
      'Conditional requests are refreshed before their challenge expires',
    ],
  });
})();
