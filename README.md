# Auth in Motion

**A visual way to learn web authentication: 3D animations, everyday analogies and MERN code, built on [Pilcrow's Auth book](https://auth.pilcrowonpaper.com).**

🔗 **Live:** [kidus.work/Auth-In-Motion](https://kidus.work/Auth-In-Motion/)

> **Source and credit:** every concept, recommendation and number on this site comes from the **[Auth book](https://auth.pilcrowonpaper.com)** by **[Pilcrow](https://pilcrowonpaper.com)**, a free guide to implementing auth with zero ads. This project doesn't replace it; it's a visual companion to it. Please read the original for the full reasoning, and consider [supporting Pilcrow on GitHub Sponsors](https://github.com/sponsors/pilcrowonpaper).

---

## Why I made this

I learn best by seeing things move. Reading about session tokens, password hashing or passkey signatures made sense on the page, but it didn't stick until I could picture where the data goes, who holds which secret and where an attacker gets stopped.

So I took the chapters of Pilcrow's Auth book and turned each one into:

- a **3D flow** where every request, token, email and attack is a packet moving between the browser, server, database and other parties
- an **everyday analogy** (a coat check, a hotel key card, a signet ring…) that explains each step in plain terms
- **MERN code** (Express, MongoDB, React) that follows the book's recommendations

I'm sharing it in case it helps you learn the same way. Any mistakes in the visuals or code are mine, not the book's.

---

## What you'll learn

13 chapters, medium to intermediate level, each linked to the book page it's based on.

| # | Chapter | The analogy | Book page |
|---|---|---|---|
| **Foundations** | | | |
| 01 | Choosing a sign-in method | Getting into an office building | [Authentication methods](https://auth.pilcrowonpaper.com/authentication-methods) |
| 02 | Sessions & session tokens | The coat check | [Sessions](https://auth.pilcrowonpaper.com/sessions) |
| 03 | Auth sessions & sign-out | The hotel key card | [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions) |
| **Passwords** | | | |
| 04 | Handling passwords | The smoothie bar | [Passwords](https://auth.pilcrowonpaper.com/passwords) |
| 05 | Argon2 & bcrypt | The busy kitchen | [Argon2](https://auth.pilcrowonpaper.com/argon2), [Bcrypt](https://auth.pilcrowonpaper.com/bcrypt) |
| 06 | Rate limiting | The arcade token cup | [Passwords](https://auth.pilcrowonpaper.com/passwords) |
| **Email** | | | |
| 07 | Email addresses & verification | The parcel locker PIN | [Email addresses](https://auth.pilcrowonpaper.com/email-addresses), [Verification codes](https://auth.pilcrowonpaper.com/email-address-verification-codes) |
| 08 | Email-code sign-in & password reset | The bank's one-time combination | [Email code authentication](https://auth.pilcrowonpaper.com/email-code-authentication) |
| **The browser** | | | |
| 09 | Cookies vs. Web Storage | Your membership card | [Browser client-side storage](https://auth.pilcrowonpaper.com/browser-client-side-storage) |
| 10 | Cross-site request forgery | The forged letter | [CSRF](https://auth.pilcrowonpaper.com/csrf) |
| **Passkeys** | | | |
| 11 | How passkeys work | The signet ring | [Passkeys](https://auth.pilcrowonpaper.com/passkeys), [WebAuthn](https://auth.pilcrowonpaper.com/webauthn) |
| 12 | Registering a passkey | Registering your ring at the bank | [Passkey registration](https://auth.pilcrowonpaper.com/passkey-registration) |
| 13 | Signing in with a passkey | Stamping the bank slip | [Passkey authentication](https://auth.pilcrowonpaper.com/passkey-authentication) |

Left out on purpose: the book's low-level WebAuthn pages (CBOR encoding, authenticator/client data internals, ECDSA, RSA, EdDSA). They're excellent, but beyond the level this guide aims for.

### Inside every chapter

1. **Key numbers:** the book's concrete values at a glance (token sizes, limits, lifetimes)
2. **3D flow:** an animation you can play, step through and rotate
3. **Analogy panel:** the everyday version of the current step, plus a who's-who list
4. **How it works:** the concepts, with comparison tables
5. **Threats & defenses:** what goes wrong and what stops it
6. **MERN code:** copy-ready files labelled with where they go in a project
7. **Checklist:** what to confirm before shipping (ticks are saved in your browser)

---

## Using the guide

| Action | How |
|---|---|
| Change chapter | Sidebar on desktop, dropdown on mobile |
| Play the animation | **Play flow**, or press `P` |
| Step through it | ◀ ▶ buttons, or the `←` `→` keys |
| Jump to a step | Click it in the step list or progress bar |
| Rotate the scene | Drag; double-click to reset |
| Why this exists | Hover "Based on Pilcrow's Auth book" in the top bar, or tap the **?** |

**Packet colors**

| Color | Meaning |
|---|---|
| Gold | Credentials and secrets |
| Green | Tokens and cookies |
| Mauve | Email |
| Blue | Data and queries |
| Moss | Success |
| Terracotta | Attacks (a green shield appears when one is blocked) |

---

## Run it locally

No build step. Double-click `index.html`, or:

```bash
open index.html          # macOS
python3 -m http.server   # or serve it, then visit http://localhost:8000
```

An internet connection is needed the first time: Three.js, Prism and the fonts load from a CDN.

---

## Deploy

Static site, nothing to build. On Vercel run `vercel --prod`, or import the GitHub repo with the framework preset set to **Other**.

To serve it under another domain's path (as on kidus.work), add these rewrites to that site's `vercel.json`, above any catch-all rule:

```json
{ "source": "/Auth-In-Motion", "destination": "https://auth-in-motion.vercel.app/index.html" },
{ "source": "/Auth-In-Motion/", "destination": "https://auth-in-motion.vercel.app/index.html" },
{ "source": "/Auth-In-Motion/:path*", "destination": "https://auth-in-motion.vercel.app/:path*" }
```

The page adds the trailing slash itself so its relative script paths resolve.

---

## Design

Rectangular and quiet, so the animation is the loudest thing on the page.

- **Palette:** charcoal `#2C2C2C`, forest `#374C3A`, butter `#FDEAAD`, terracotta `#CD745B`, mauve `#7E5E6E`, plus a deep gold, dusty blue and moss so the six packet types stay distinct. Every text color is checked for at least 4.5:1 contrast in both themes.
- **Light and dark:** follows the system setting. Light is the default; dark swaps to a charcoal page with butter accents.
- **Shapes:** square corners (2px), hairline rules, cube packets and square pedestals in the 3D scene, and square markers on section headings.
- **Top bar:** charcoal with a butter rule, holding the logo, the book credit, a breadcrumb of the current chapter, and GitHub/Telegram links.
- **Type:** Figtree for text, JetBrains Mono for code and labels.

All colors live as CSS variables at the top of `index.html`, so changing the palette is a one-place edit.

---

## Project structure

```
.
├── index.html                    Layout, all styles, light + dark themes
└── js/
    ├── content-1-foundations.js  Shared helpers + chapters 01–03
    ├── content-2-passwords.js    Chapters 04–06
    ├── content-3-email.js        Chapters 07–08
    ├── content-4-browser.js      Chapters 09–10
    ├── content-5-passkeys.js     Chapters 11–13
    └── app.js                    3D engine (Three.js) and page rendering
```

`content-1-foundations.js` must load first: it defines the helpers the other content files use.

---

## Tech stack

**This site:** HTML, CSS and vanilla JavaScript, [Three.js](https://threejs.org) r128 for 3D, [Prism](https://prismjs.com) for code highlighting, Google Fonts.

**The code it teaches:** Node.js + Express, MongoDB + Mongoose, Redis (ioredis), argon2, bcrypt, helmet, @simplewebauthn/server and /browser, React.

### The auth design in one paragraph (following the book)

Database-backed sessions, not JWTs: each token is an ID plus a 32-byte secret, stored as a SHA-256 hash and sent in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Passwords use Argon2id (16 MiB+, 3 iterations, parallelism 1) with clear error messages. Every guessable check sits behind a Redis token bucket (5 capacity, 1 per minute, per user). Email uses codes instead of links: 8 digits for verification, 40-bit Argon2-hashed codes for sign-in and reset. CSRF is blocked by checking `Sec-Fetch-Site`. Passkeys are discoverable credentials with user verification required.

---

## Editing content

Chapters are plain objects in `js/content-*.js`:

```js
AIM.chapters.push({
  id: 'sessions', num: '02', group: 'Foundations',
  short: 'Sidebar label', title: 'Full title', flowName: 'Stage label', lede: '…',
  sources: [book('sessions', 'Sessions')],          // links back to the book
  glance: [['32 bytes', 'random secret per session']],
  analogy: { title: 'The coat check', intro: '…', map: [['Session ID', 'The ticket number']] },
  actors: ['browser', 'api', 'db'],
  steps: [ /* see below */ ],
  concept: `<h3>…</h3>`, threats: [{ name, risk, fix }], code: [{ file, lang, code: code`…` }], checklist: ['…'],
});
```

Steps (the last argument, `payload`, is optional):

```js
send(from, to, kind, label, title, text, analogy, payload)    // a packet travels
proc(at, kind, label, title, text, analogy, payload)          // work happens on one node
block(from, to, label, result, title, text, analogy, payload) // an attack hits a shield
```

- **Nodes:** `browser`, `api`, `db`, `redis`, `mail`, `phone` (authenticator), `site` (evil.example), `attacker`
- **Kinds:** `cred`, `token`, `mail`, `data`, `ok`, `attack`
- **Code samples:** inside `` code`…` ``, write `` \` `` for a backtick and `\${` for `${`

If you add a chapter, keep the book as the source of truth and link the page it comes from in `sources`.

---

## A note on the code

The samples fit together as one codebase and follow the book's recommendations, but they're **reference code, not a drop-in package**. Adapt them to your app, test them, and have your security setup reviewed before handling real users' data.

---

## Credits

- **Content:** [Pilcrow's Auth book](https://auth.pilcrowonpaper.com), written and maintained by [Pilcrow](https://pilcrowonpaper.com). All concepts, recommendations and numbers are theirs. [Support their work](https://github.com/sponsors/pilcrowonpaper).
- **Visuals, analogies and MERN code:** [Kidus Yosef](https://kidus.work).
- **Built with:** [Three.js](https://threejs.org), [Prism](https://prismjs.com), [Figtree](https://fonts.google.com/specimen/Figtree) and [JetBrains Mono](https://www.jetbrains.com/lp/mono/).
- **Further reading:** the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org) for broader security topics.

Questions or ideas? Open an issue, or join the Telegram: [t.me/SoftwareAspirer](https://t.me/SoftwareAspirer).
