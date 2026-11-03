# Auth in Motion

**A 3D, step-by-step guide to production authentication for MERN apps.**

Watch data move between the browser, the API, the database and an attacker, one packet at a time. Every chapter pairs an animated flow with the security risks at that stage and working Express, MongoDB and React code.

No framework and no build step: it's one HTML page plus a few JavaScript files.

---

## What you'll learn

| # | Chapter | In one line |
|---|---|---|
| 01 | The big picture | Authentication vs authorization, sessions vs JWT |
| 02 | Storing passwords | argon2id hashing, salts, checking against breached passwords |
| 03 | Sign-up & email verification | One-time tokens, email queues, not leaking who has an account |
| 04 | Login & tokens | Rate limits, short-lived access tokens, HttpOnly cookies |
| 05 | Refresh token rotation | Silent refresh and catching stolen tokens |
| 06 | Authorization | Roles, ownership, blocking access to other users' data |
| 07 | Sessions & logout | Real logout, "sign out everywhere", password changes |
| 08 | Password recovery | Safe reset links that work once and expire |
| 09 | Two-factor auth | Authenticator app codes (TOTP) and backup codes |
| 10 | Sign in with Google | OAuth 2.0 + OpenID Connect with PKCE |
| 11 | Attacks & defenses | XSS, CSRF, CORS, NoSQL injection, clickjacking |
| 12 | The React client | Auth context, protected routes, auto-refresh |
| 13 | Going to production | Deployment, secrets, logging, alerts, tests |

Each chapter has five parts:

1. **3D flow:** an animation you can play, pause, step through and rotate
2. **How it works:** the concepts in plain language
3. **Threats & defenses:** what attackers try at this stage and what stops them
4. **MERN code:** copy-ready files, labeled with where they go in a project
5. **Checklist:** what to confirm before you ship (ticks are saved in your browser)

---

## Run it locally

**Easiest:** double-click `index.html`, or run:

```bash
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux
```

**With a local server** (if your browser blocks anything when opened as a file):

```bash
python3 -m http.server 8000
# then open http://localhost:8000
```

> You need an internet connection the first time: Three.js, Prism and the fonts load from a CDN.

---

## Deploy to Vercel

The site is static, so there's nothing to build.

**Using the CLI:**

```bash
npm i -g vercel
vercel          # first deploy: log in and accept the defaults
vercel --prod   # publish to production
```

**Using GitHub:** push this folder to a repo, then in Vercel choose **Add New → Project**, import the repo, set the framework preset to **Other**, leave the build settings empty and click **Deploy**. Every push redeploys.

The same folder works on Netlify, GitHub Pages and Cloudflare Pages.

---

## Using the guide

| Action | How |
|---|---|
| Change chapter | Sidebar on desktop, dropdown on mobile |
| Play the animation | **Play flow** button, or press `P` |
| Step through it | ◀ ▶ buttons, or the `←` `→` keys |
| Jump to a step | Click it in the step list or the progress bar |
| Rotate the 3D scene | Drag it |
| Reset the camera | Double-click the scene |
| Copy code | **Copy** button on each file |

**Packet colors**

| Color | Meaning |
|---|---|
| Amber | Credentials and secrets |
| Teal | Tokens and cookies |
| Violet | Email |
| Blue | Data and queries |
| Green | Success |
| Red | Attacks (a green shield shows when one is blocked) |

---

## Project structure

```
.
├── index.html                 Page layout and all styles (light + dark theme)
└── js/
    ├── app.js                 3D engine (Three.js) and page rendering
    ├── content-foundations.js Chapters 01–02, plus shared helpers
    ├── content-flows.js       Chapters 03–07
    ├── content-recovery.js    Chapters 08–10
    └── content-hardening.js   Chapters 11–13
```

Load order matters: `content-foundations.js` must come first because it defines the helpers the other content files use.

---

## Tech stack

**This website:** HTML, CSS, vanilla JavaScript, [Three.js](https://threejs.org) r128 for 3D, [Prism](https://prismjs.com) for code highlighting and Google Fonts.

**The auth system it teaches:**

| Layer | Tools |
|---|---|
| API | Node.js, Express 5 |
| Database | MongoDB, Mongoose 8 |
| Cache, rate limits, queue | Redis, ioredis, BullMQ |
| Security | argon2, jsonwebtoken, helmet, cors, zod |
| Email | nodemailer (Amazon SES, Resend or any SMTP) |
| Two-factor | otplib v12, qrcode |
| Google sign-in | google-auth-library |
| Frontend | React 18, Vite, React Router, axios, TanStack Query |
| Testing | Vitest, supertest, mongodb-memory-server |

### The design in one paragraph

Passwords are hashed with **argon2id**. Login returns a **15-minute access token** (JWT), which the React app keeps in memory, and a **refresh token** in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Refresh tokens **rotate on every use**, and a reused one revokes that device's whole session. **Redis** handles rate limits and a 60-second user cache, which lets you revoke tokens instantly. Emails go through a **background queue**, so response times don't reveal which accounts exist.

---

## Editing or adding content

All content lives in the `js/content-*.js` files as plain objects. A chapter looks like this:

```js
AIM.chapters.push({
  id: 'my-chapter',          // used in the URL: index.html#my-chapter
  num: '14',
  group: 'Hardening & shipping',
  short: 'Sidebar label',
  title: 'Full chapter title',
  flowName: 'Label shown on the 3D stage',
  lede: 'One or two sentence intro.',
  actors: ['browser', 'api', 'db'],   // which 3D nodes appear
  steps: [ /* see below */ ],
  concept: `<h3>…</h3><p>…</p>`,        // HTML
  threats: [{ name: '…', risk: '…', fix: '…' }],
  code: [{ file: 'server/src/x.js', lang: 'javascript', code: code`…` }],
  checklist: ['…'],
});
```

**Steps** use three helpers:

```js
send(from, to, kind, label, title, text, payload?)          // a packet travels between nodes
proc(at, kind, label, title, text, payload?)                // work happens on one node
block(from, to, label, result, title, text, payload?)       // an attack hits a shield
```

- **Nodes:** `browser`, `api`, `db`, `redis`, `mail`, `phone`, `google`, `attacker`
- **Kinds:** `cred`, `token`, `mail`, `data`, `ok`, `attack`
- `payload` is optional text, such as an HTTP request, shown under the explanation.

**Code samples** use the `code` template tag. Inside a sample, write `` \` `` for a backtick and `\${` for `${`. Everything else, including backslashes, is shown exactly as typed.

---

## A note on the code

The samples fit together as one consistent codebase and are written to follow current best practice (OWASP and NIST guidance). They are **reference code, not a drop-in package**: adapt them to your app, add tests, and have someone review your security setup before you handle real users' data.

---

## Credits

Built with Three.js and Prism.js. Typefaces: Bricolage Grotesque, IBM Plex Sans and JetBrains Mono, from Google Fonts.
