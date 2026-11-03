/* Auth in Motion: 3D flow stage + chapter renderer */
(function () {
  'use strict';

  const CHAPTERS = window.AIM.chapters;
  const byId = Object.fromEntries(CHAPTERS.map((c) => [c.id, c]));
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------- actors
  const ACTORS = {
    browser:  { name: 'Browser',        sub: 'your React app',         pos: [-6.6, 0, 0.6],  shape: 'screen',   tone: '--c-data' },
    api:      { name: 'Server',         sub: 'Express API',            pos: [0, 0, 0],       shape: 'server',   tone: '--accent' },
    db:       { name: 'Database',       sub: 'MongoDB',                pos: [6.6, 0, 0.6],   shape: 'db',       tone: '--c-ok' },
    redis:    { name: 'Redis',          sub: 'rate limits · challenges', pos: [4.9, 0, -4.9], shape: 'cache',   tone: '--c-cache' },
    mail:     { name: 'Email',          sub: 'provider → inbox',       pos: [0.3, 0, -6.4],  shape: 'mail',     tone: '--c-mail' },
    phone:    { name: 'Authenticator',  sub: 'passkey on a device',    pos: [-5.4, 0, 5.4],  shape: 'phone',    tone: '--c-token' },
    site:     { name: 'evil.example',   sub: 'another website',        pos: [-5.0, 0, -5.0], shape: 'idp',      tone: '--c-idp' },
    attacker: { name: 'Attacker',       sub: 'untrusted network',      pos: [3.8, 0, 5.6],   shape: 'attacker', tone: '--c-attack' },
  };
  const KIND = {
    cred:   { token: '--c-cred',   name: 'Credential or secret' },
    token:  { token: '--c-token',  name: 'Token or cookie' },
    mail:   { token: '--c-mail',   name: 'Email' },
    data:   { token: '--c-data',   name: 'Data or query' },
    ok:     { token: '--c-ok',     name: 'Success' },
    attack: { token: '--c-attack', name: 'Attack' },
  };
  const DURATION = { send: 1.7, process: 1.4, blocked: 2.1 };

  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const kindVar = (kind) => `var(${(KIND[kind] || KIND.data).token})`;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------------------------------------------------------------- player state (works with or without WebGL)
  const player = { chapter: null, index: 0, t: 1, playing: false, hold: 0 };
  let gl = null;

  // ================================================================= WebGL stage
  function createStage() {
    const THREE = window.THREE;
    if (!THREE) return null;
    const host = $('stage-canvas');
    const labelLayer = $('stage-labels');
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch (e) {
      return null;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);
    host.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 200);
    const UP = new THREE.Vector3(0, 1, 0);
    const paint = []; // { target, prop, token, opacity? } recolored on theme change

    const color = (name) => new THREE.Color(css(name) || '#888888');
    const painted = (material, token, prop = 'color') => { paint.push({ material, token, prop }); return material; };

    // lights
    const hemi = new THREE.HemisphereLight(0xffffff, 0x223344, 0.75);
    scene.add(hemi);
    const sun = new THREE.DirectionalLight(0xffffff, 0.75);
    sun.position.set(6, 14, 9);
    scene.add(sun);
    const rim = new THREE.DirectionalLight(0xffffff, 0.25);
    rim.position.set(-8, 6, -10);
    scene.add(rim);

    // floor
    const floor = new THREE.Mesh(
      new THREE.PlaneGeometry(34, 34),
      painted(new THREE.MeshStandardMaterial({ roughness: 0.95, metalness: 0, transparent: true, opacity: 0.55 }), '--bg-2'),
    );
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -0.01;
    scene.add(floor);
    let grid = null;
    function buildGrid() {
      if (grid) { scene.remove(grid); grid.geometry.dispose(); grid.material.dispose(); }
      grid = new THREE.GridHelper(34, 34, color('--line'), color('--line'));
      grid.material.transparent = true;
      grid.material.opacity = 0.55;
      scene.add(grid);
    }
    buildGrid();

    // shared glow texture
    const glowTex = (() => {
      const c = document.createElement('canvas');
      c.width = c.height = 128;
      const g = c.getContext('2d');
      const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
      grad.addColorStop(0, 'rgba(255,255,255,1)');
      grad.addColorStop(0.25, 'rgba(255,255,255,0.55)');
      grad.addColorStop(1, 'rgba(255,255,255,0)');
      g.fillStyle = grad;
      g.fillRect(0, 0, 128, 128);
      return new THREE.CanvasTexture(c);
    })();

    // ---------------------------------------------------------- actor models
    const actors = {};
    const nodeMat = painted(new THREE.MeshStandardMaterial({ roughness: 0.55, metalness: 0.2 }), '--node');
    const box = (w, h, d, m) => new THREE.Mesh(new THREE.BoxGeometry(w, h, d), m);
    const cyl = (rt, rb, h, seg, m) => new THREE.Mesh(new THREE.CylinderGeometry(rt, rb, h, seg), m);

    function toneMaterial(token, emissive = 0.35) {
      const m = new THREE.MeshStandardMaterial({ roughness: 0.4, metalness: 0.15, emissiveIntensity: emissive });
      painted(m, token);
      painted(m, token, 'emissive');
      return m;
    }

    function phoneTexture() {
      const c = document.createElement('canvas');
      c.width = 160; c.height = 290;
      const tex = new THREE.CanvasTexture(c);
      tex.redraw = () => {
        const g = c.getContext('2d');
        g.fillStyle = css('--surface-2'); g.fillRect(0, 0, 160, 290);
        // a fingerprint: concentric arcs, the passkey prompt
        g.strokeStyle = css('--c-token'); g.lineWidth = 5; g.lineCap = 'round';
        for (let r = 10; r <= 50; r += 10) {
          g.beginPath(); g.arc(80, 120, r, Math.PI * 1.08, Math.PI * 1.92 + (r % 20 ? 0.35 : 0)); g.stroke();
          g.beginPath(); g.arc(80, 120, r, Math.PI * 0.15, Math.PI * (r % 20 ? 0.62 : 0.8)); g.stroke();
        }
        g.fillStyle = css('--fg');
        g.font = '600 20px system-ui, sans-serif';
        g.textAlign = 'center';
        g.fillText('Use passkey', 80, 214);
        g.fillStyle = css('--muted');
        g.font = '500 15px system-ui, sans-serif';
        g.fillText('Touch to sign in', 80, 244);
        tex.needsUpdate = true;
      };
      tex.redraw();
      return tex;
    }

    function buildShape(shape, tone) {
      const g = new THREE.Group();
      const tm = toneMaterial(tone);
      const spin = [];
      if (shape === 'screen') {
        const frame = box(2.5, 1.6, 0.16, nodeMat); frame.position.y = 1.55; g.add(frame);
        const face = new THREE.Mesh(new THREE.PlaneGeometry(2.26, 1.36), tm); face.position.set(0, 1.55, 0.085); g.add(face);
        const bar = new THREE.Mesh(new THREE.PlaneGeometry(1.9, 0.12), painted(new THREE.MeshBasicMaterial(), '--surface')); bar.position.set(0, 2.04, 0.09); g.add(bar);
        const neck = box(0.16, 0.6, 0.16, nodeMat); neck.position.y = 0.5; g.add(neck);
        const foot = box(1.0, 0.08, 0.6, nodeMat); foot.position.y = 0.24; g.add(foot);
      } else if (shape === 'server') {
        [0.48, 1.0, 1.52].forEach((y) => {
          const b = box(1.8, 0.44, 1.3, nodeMat); b.position.y = y; g.add(b);
          const led = box(0.75, 0.07, 0.02, tm); led.position.set(-0.35, y, 0.66); g.add(led);
          const dot = box(0.09, 0.09, 0.02, tm); dot.position.set(0.62, y, 0.66); g.add(dot);
        });
      } else if (shape === 'db') {
        [0.46, 0.96, 1.46].forEach((y) => { const c = cyl(0.95, 0.95, 0.42, 40, nodeMat); c.position.y = y; g.add(c); });
        [0.71, 1.21].forEach((y) => { const c = cyl(0.965, 0.965, 0.06, 40, tm); c.position.y = y; g.add(c); });
        const cap = cyl(0.8, 0.8, 0.04, 40, tm); cap.position.y = 1.69; g.add(cap);
      } else if (shape === 'cache') {
        const hex = cyl(0.95, 0.95, 1.0, 6, nodeMat); hex.position.y = 0.72; g.add(hex);
        const top = cyl(0.99, 0.99, 0.12, 6, tm); top.position.y = 1.28; g.add(top);
        const gem = new THREE.Mesh(new THREE.OctahedronGeometry(0.26), tm); gem.position.y = 1.85; g.add(gem); spin.push(gem);
      } else if (shape === 'mail') {
        const env = new THREE.Group(); env.position.y = 1.3; g.add(env);
        env.add(box(1.9, 1.2, 0.14, nodeMat));
        const l = box(1.15, 0.08, 0.03, tm); l.position.set(-0.475, 0.275, 0.08); l.rotation.z = -0.6; env.add(l);
        const r = box(1.15, 0.08, 0.03, tm); r.position.set(0.475, 0.275, 0.08); r.rotation.z = 0.6; env.add(r);
        const post = box(0.12, 0.7, 0.12, nodeMat); post.position.y = 0.38; g.add(post);
      } else if (shape === 'phone') {
        const body = box(0.95, 1.75, 0.12, nodeMat); body.position.y = 1.35; g.add(body);
        const tex = phoneTexture();
        const screen = new THREE.Mesh(new THREE.PlaneGeometry(0.8, 1.45), new THREE.MeshBasicMaterial({ map: tex }));
        screen.position.set(0, 1.35, 0.065); g.add(screen);
        paint.push({ redraw: tex.redraw });
        g.rotation.x = -0.12;
      } else if (shape === 'idp') {
        const geo = new THREE.IcosahedronGeometry(0.85, 0);
        const ico = new THREE.Mesh(geo, nodeMat); ico.position.y = 1.35; g.add(ico);
        const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo), painted(new THREE.LineBasicMaterial(), tone));
        edges.position.y = 1.35; edges.scale.setScalar(1.01); g.add(edges);
        spin.push(ico, edges);
      } else if (shape === 'attacker') {
        const geo = new THREE.OctahedronGeometry(0.8);
        const o = new THREE.Mesh(geo, tm); o.position.y = 1.45; o.scale.y = 1.3; g.add(o);
        const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo), painted(new THREE.LineBasicMaterial(), '--fg'));
        edges.position.y = 1.45; edges.scale.set(1.02, 1.32, 1.02); g.add(edges);
        spin.push(o, edges);
      }
      return { group: g, spin };
    }

    Object.entries(ACTORS).forEach(([key, def]) => {
      const root = new THREE.Group();
      root.position.set(...def.pos);
      const ped = box(2.7, 0.2, 2.7, nodeMat); ped.position.y = 0.1; root.add(ped);
      const ringMat = painted(new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.35, side: THREE.DoubleSide }), def.tone);
      const ring = new THREE.Mesh(new THREE.RingGeometry(2.05, 2.16, 4, 1, Math.PI / 4), ringMat);
      ring.rotation.x = -Math.PI / 2; ring.position.y = 0.02; root.add(ring);
      const { group, spin } = buildShape(def.shape, def.tone);
      group.position.y = 0.2;
      root.add(group);
      root.scale.setScalar(0.0001);
      root.visible = false;
      scene.add(root);

      const label = document.createElement('div');
      label.className = 'actor-label is-off';
      label.style.setProperty('--k', `var(${def.tone})`);
      label.innerHTML = `<span class="dot"></span><b>${escapeHtml(def.name)}</b><small>${escapeHtml(def.sub)}</small>`;
      labelLayer.appendChild(label);

      actors[key] = { def, root, ring, ringMat, spin, label, vis: 0, goal: 0, flash: 0, anchor: new THREE.Vector3(def.pos[0], 1.5, def.pos[2]) };
    });

    // ---------------------------------------------------------- packet, trail, arcs, effects
    const packetMat = new THREE.MeshBasicMaterial();
    const packet = new THREE.Mesh(new THREE.BoxGeometry(0.32, 0.32, 0.32), packetMat);
    const haloMat = new THREE.SpriteMaterial({ map: glowTex, transparent: true, depthWrite: false, opacity: 0.9 });
    const halo = new THREE.Sprite(haloMat);
    halo.scale.setScalar(1.6);
    packet.add(halo);
    packet.visible = false;
    scene.add(packet);

    const TRAIL = 18;
    const trail = [];
    for (let i = 0; i < TRAIL; i++) {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, transparent: true, depthWrite: false }));
      s.visible = false;
      scene.add(s);
      trail.push(s);
    }

    const ARC_POINTS = 72;
    const activeArcGeo = new THREE.BufferGeometry();
    activeArcGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(ARC_POINTS * 3), 3));
    const activeArcMat = new THREE.LineBasicMaterial({ transparent: true, opacity: 0.95 });
    const activeArc = new THREE.Line(activeArcGeo, activeArcMat);
    activeArc.visible = false;
    scene.add(activeArc);

    let ghostArcs = [];
    const ghostMat = painted(new THREE.LineDashedMaterial({ dashSize: 0.25, gapSize: 0.2, transparent: true, opacity: 0.55 }), '--faint');

    function curveFor(from, to) {
      const A = actors[from].anchor.clone();
      const B = actors[to].anchor.clone();
      const dir = B.clone().sub(A);
      const len = dir.length();
      const side = new THREE.Vector3().crossVectors(dir.normalize(), UP).multiplyScalar(len * 0.1);
      const mid = A.clone().add(B).multiplyScalar(0.5).add(side);
      mid.y += 1.4 + len * 0.22;
      return new THREE.QuadraticBezierCurve3(A, mid, B);
    }

    // process rings
    const procMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.9, side: THREE.DoubleSide });
    const procRing = new THREE.Mesh(new THREE.TorusGeometry(2.0, 0.045, 6, 4), procMat);
    const procRing2 = new THREE.Mesh(new THREE.TorusGeometry(1.15, 0.03, 6, 4), procMat);
    procRing.visible = procRing2.visible = false;
    scene.add(procRing, procRing2);

    // shield + burst for blocked attacks
    const shieldMat = painted(new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.22, side: THREE.DoubleSide, depthWrite: false }), '--c-ok');
    const shieldEdgeMat = painted(new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.95, side: THREE.DoubleSide }), '--c-ok');
    const shield = new THREE.Group();
    shield.add(new THREE.Mesh(new THREE.PlaneGeometry(1.8, 1.8), shieldMat));
    shield.add(new THREE.Mesh(new THREE.RingGeometry(1.27, 1.37, 4, 1, Math.PI / 4), shieldEdgeMat));
    shield.visible = false;
    scene.add(shield);

    const BURST = 36;
    const burstGeo = new THREE.BufferGeometry();
    burstGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(BURST * 3), 3));
    const burstVel = Array.from({ length: BURST }, () => new THREE.Vector3(Math.random() - 0.5, Math.random() - 0.3, Math.random() - 0.5).normalize().multiplyScalar(1.5 + Math.random() * 2.5));
    const burstMat = new THREE.PointsMaterial({ size: 0.16, transparent: true, depthWrite: false, map: glowTex });
    const burst = new THREE.Points(burstGeo, burstMat);
    burst.visible = false;
    scene.add(burst);

    // HTML overlays
    const packetLabel = document.createElement('div');
    packetLabel.className = 'packet-label';
    packetLabel.hidden = true;
    labelLayer.appendChild(packetLabel);
    const procChip = document.createElement('div');
    procChip.className = 'proc-chip';
    procChip.hidden = true;
    labelLayer.appendChild(procChip);

    // ---------------------------------------------------------- theming
    let isDark = true;
    function applyTheme() {
      const bg = color('--bg');
      isDark = (bg.r * 0.299 + bg.g * 0.587 + bg.b * 0.114) < 0.5;
      paint.forEach((p) => {
        if (p.redraw) return p.redraw();
        if (p.prop === 'emissive') p.material.emissive = color(p.token);
        else p.material.color = color(p.token);
      });
      hemi.groundColor = color('--bg');
      hemi.intensity = isDark ? 0.75 : 0.9;
      scene.fog = new THREE.Fog(color('--bg'), 30, 60);
      const blend = isDark ? THREE.AdditiveBlending : THREE.NormalBlending;
      [haloMat, burstMat, ...trail.map((s) => s.material)].forEach((m) => { m.blending = blend; m.needsUpdate = true; });
      buildGrid();
      if (player.chapter) applyStepColors();
    }

    // ---------------------------------------------------------- camera orbit
    const orbit = {
      theta: 0, phi: 1.0, radius: 22, target: new THREE.Vector3(),
      goalTarget: new THREE.Vector3(), goalRadius: 22, centroid: new THREE.Vector3(), fitRadius: 22,
    };
    let dragging = null;
    host.addEventListener('pointerdown', (e) => {
      dragging = { x: e.clientX, y: e.clientY, type: e.pointerType };
      host.setPointerCapture(e.pointerId);
    });
    host.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      const dx = e.clientX - dragging.x;
      const dy = e.clientY - dragging.y;
      dragging.x = e.clientX; dragging.y = e.clientY;
      orbit.theta -= dx * 0.006;
      if (dragging.type === 'mouse') orbit.phi = clamp(orbit.phi - dy * 0.004, 0.42, 1.36);
    });
    const endDrag = () => { dragging = null; };
    host.addEventListener('pointerup', endDrag);
    host.addEventListener('pointercancel', endDrag);
    host.addEventListener('dblclick', () => { orbit.theta = 0; orbit.phi = 1.0; });

    let width = 1, height = 1;
    function resize() {
      const r = host.getBoundingClientRect();
      width = Math.max(1, r.width); height = Math.max(1, r.height);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      fit();
    }
    new ResizeObserver(resize).observe(host);

    function fit() {
      const keys = (player.chapter && player.chapter.actors) || [];
      if (!keys.length) return;
      const c = new THREE.Vector3();
      keys.forEach((k) => c.add(actors[k].anchor));
      c.divideScalar(keys.length);
      c.y = 0.9;
      let r = 0;
      keys.forEach((k) => { r = Math.max(r, Math.hypot(actors[k].anchor.x - c.x, actors[k].anchor.z - c.z)); });
      r += 2.4;
      const vHalf = THREE.MathUtils.degToRad(camera.fov / 2);
      const hHalf = Math.atan(Math.tan(vHalf) * camera.aspect);
      const d = Math.max(r / Math.tan(hHalf), (r * 0.8) / Math.tan(vHalf)) * 1.02;
      orbit.centroid.copy(c);
      orbit.fitRadius = clamp(d, 11, 46);
      orbit.goalRadius = orbit.fitRadius;
    }

    // ---------------------------------------------------------- chapter + step hooks
    let current = null; // { step, curve }

    function setChapter(ch) {
      Object.entries(actors).forEach(([k, a]) => { a.goal = ch.actors.includes(k) ? 1 : 0; });
      ghostArcs.forEach((l) => { scene.remove(l); l.geometry.dispose(); });
      ghostArcs = [];
      const seen = new Set();
      ch.steps.forEach((s) => {
        if (s.type === 'process') return;
        const key = s.from + '>' + s.to;
        if (seen.has(key)) return;
        seen.add(key);
        const geo = new THREE.BufferGeometry().setFromPoints(curveFor(s.from, s.to).getPoints(ARC_POINTS - 1));
        const line = new THREE.Line(geo, ghostMat);
        line.computeLineDistances();
        scene.add(line);
        ghostArcs.push(line);
      });
      fit();
    }

    function applyStepColors() {
      const s = player.chapter.steps[player.index];
      const c = color(KIND[s.kind] ? KIND[s.kind].token : '--c-data');
      packetMat.color = c; haloMat.color = c; activeArcMat.color = c; procMat.color = c; burstMat.color = c;
      trail.forEach((t) => { t.material.color = c; });
    }

    function setStep() {
      const s = player.chapter.steps[player.index];
      applyStepColors();
      current = { step: s, curve: s.type === 'process' ? null : curveFor(s.from, s.to), burstStarted: false, arrived: false };
      if (current.curve) {
        const pts = current.curve.getPoints(ARC_POINTS - 1);
        const arr = activeArcGeo.attributes.position.array;
        pts.forEach((p, i) => { arr[i * 3] = p.x; arr[i * 3 + 1] = p.y; arr[i * 3 + 2] = p.z; });
        activeArcGeo.attributes.position.needsUpdate = true;
        activeArcGeo.computeBoundingSphere();
      }
      trailHistory.length = 0;
      burst.visible = false;
      const kVar = kindVar(s.kind);
      packetLabel.style.setProperty('--k', kVar);
      procChip.style.setProperty('--k', kVar);
      packetLabel.classList.toggle('is-blocked', s.type === 'blocked');
      packetLabel.innerHTML = escapeHtml(s.label || '');
      procChip.textContent = s.label || '';
      const involved = s.type === 'process' ? [s.at] : [s.from, s.to];
      Object.entries(actors).forEach(([k, a]) => {
        a.label.classList.toggle('is-active', involved.includes(k));
        a.label.classList.toggle('is-dim', !involved.includes(k));
      });
      // focus the camera a little toward the action
      const focus = new THREE.Vector3();
      involved.forEach((k) => focus.add(actors[k].anchor));
      focus.divideScalar(involved.length);
      orbit.goalTarget.copy(orbit.centroid).multiplyScalar(0.62).add(focus.multiplyScalar(0.38));
      orbit.goalTarget.y = 0.9;
    }

    // ---------------------------------------------------------- per-frame
    const trailHistory = [];
    const tmp = new THREE.Vector3();
    let clock = 0;

    function placeLabel(el, world, dx = 0, dy = 0, anchorBottom = true) {
      tmp.copy(world).project(camera);
      const behind = tmp.z > 1;
      const x = (tmp.x * 0.5 + 0.5) * width + dx;
      const y = (-tmp.y * 0.5 + 0.5) * height + dy;
      el.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, ${anchorBottom ? '-100%' : '0'})`;
      return !behind;
    }

    function frame(dt) {
      clock += dt;
      // camera
      const k = 1 - Math.exp(-dt * 2.4);
      orbit.target.lerp(orbit.goalTarget, k);
      orbit.radius += (orbit.goalRadius - orbit.radius) * k;
      const th = orbit.theta + (reduceMotion ? 0 : Math.sin(clock * 0.13) * 0.07);
      camera.position.set(
        orbit.target.x + orbit.radius * Math.sin(orbit.phi) * Math.sin(th),
        orbit.target.y + orbit.radius * Math.cos(orbit.phi),
        orbit.target.z + orbit.radius * Math.sin(orbit.phi) * Math.cos(th),
      );
      camera.lookAt(orbit.target);

      // actors
      Object.values(actors).forEach((a) => {
        a.vis += (a.goal - a.vis) * (1 - Math.exp(-dt * 6));
        const s = a.goal ? ease(clamp(a.vis, 0, 1)) : a.vis;
        a.root.scale.setScalar(Math.max(0.0001, s));
        a.root.visible = a.vis > 0.01;
        if (!reduceMotion) a.spin.forEach((m) => { m.rotation.y += dt * (a.def.shape === 'attacker' ? 1.2 : 0.5); });
        a.flash = Math.max(0, a.flash - dt * 1.6);
        const involved = a.label.classList.contains('is-active');
        a.ringMat.opacity = (involved ? 0.85 : 0.28) + a.flash * 0.6;
        a.ring.scale.setScalar(1 + a.flash * 0.18);
        const on = a.vis > 0.5 && a.goal === 1;
        a.label.classList.toggle('is-off', !on);
        if (a.root.visible) placeLabel(a.label, tmp.set(a.def.pos[0], 0, a.def.pos[2] + 1.9).clone(), 0, 4, false);
      });

      if (!current) return;
      const s = current.step;
      const t = player.t;
      packet.visible = false;
      activeArc.visible = false;
      procRing.visible = procRing2.visible = false;
      shield.visible = false;
      packetLabel.hidden = true;
      procChip.hidden = true;
      trail.forEach((sp) => { sp.visible = false; });

      if (s.type === 'process') {
        const a = actors[s.at];
        procRing.visible = procRing2.visible = true;
        procRing.position.set(a.def.pos[0], 0.25, a.def.pos[2]);
        procRing.rotation.set(Math.PI / 2, 0, Math.PI / 4);
        const pulse = (clock * 0.9) % 1;
        procRing.scale.setScalar(0.9 + pulse * 0.35);
        procMat.opacity = 0.9 * (1 - pulse) * (0.4 + 0.6 * ease(clamp(t * 1.5, 0, 1)));
        procRing2.position.set(a.def.pos[0], 1.5, a.def.pos[2]);
        procRing2.rotation.set(Math.PI / 2 + Math.sin(clock * 1.7) * 0.6, clock * 1.8, 0);
        procChip.hidden = false;
        placeLabel(procChip, tmp.set(a.def.pos[0], 3.0, a.def.pos[2]), 0, -6);
        if (t >= 1) a.flash = Math.max(a.flash, 0.12);
        return;
      }

      const blocked = s.type === 'blocked';
      const stopAt = blocked ? 0.74 : 1;
      const travelT = blocked ? clamp(t / 0.62, 0, 1) : t;
      const p = ease(travelT) * stopAt;
      const pos = current.curve.getPoint(p);

      activeArc.visible = true;
      activeArcGeo.setDrawRange(0, Math.max(2, Math.floor(p * (ARC_POINTS - 1)) + 1));

      const exploded = blocked && t > 0.62;
      if (!exploded) {
        packet.visible = true;
        packet.position.copy(pos);
        if (t >= 1 && !blocked) packet.position.y += Math.sin(clock * 3) * 0.06;
        packet.scale.setScalar(1 + Math.sin(clock * 6) * 0.06);
        packet.rotation.set(clock * 1.3, clock * 1.7, 0);
        trailHistory.unshift(pos.clone());
        if (trailHistory.length > TRAIL) trailHistory.length = TRAIL;
        if (t < 1) trailHistory.forEach((hp, i) => {
          const sp = trail[i];
          sp.visible = true;
          sp.position.copy(hp);
          sp.scale.setScalar(0.7 * (1 - i / TRAIL));
          sp.material.opacity = 0.5 * (1 - i / TRAIL);
        });
      }
      if (!blocked && t >= 1 && !current.arrived) { current.arrived = true; actors[s.to].flash = 1; }

      if (blocked) {
        shield.visible = t > 0.2;
        const sp = current.curve.getPoint(stopAt + 0.03);
        shield.position.copy(sp);
        shield.lookAt(camera.position);
        const grow = ease(clamp((t - 0.2) / 0.3, 0, 1));
        shield.scale.setScalar(0.2 + grow * 0.8 + (exploded ? Math.sin(clock * 10) * 0.03 : 0));
        if (exploded && !current.burstStarted) {
          current.burstStarted = true;
          current.burstOrigin = pos.clone();
          current.burstClock = 0;
        }
        if (current.burstStarted) {
          current.burstClock += dt;
          const bt = current.burstClock;
          const arr = burstGeo.attributes.position.array;
          burstVel.forEach((v, i) => {
            arr[i * 3] = current.burstOrigin.x + v.x * bt;
            arr[i * 3 + 1] = current.burstOrigin.y + v.y * bt - 1.5 * bt * bt;
            arr[i * 3 + 2] = current.burstOrigin.z + v.z * bt;
          });
          burstGeo.attributes.position.needsUpdate = true;
          burst.visible = bt < 1.4;
          burstMat.opacity = clamp(1 - bt / 1.4, 0, 1);
        }
        if (exploded && s.result) {
          packetLabel.innerHTML = `${escapeHtml(s.label)}<span class="res">✕ ${escapeHtml(s.result)}</span>`;
        }
      }
      packetLabel.hidden = false;
      const lp = exploded ? current.burstOrigin : pos;
      placeLabel(packetLabel, tmp.copy(lp).add(new THREE.Vector3(0, 0.45, 0)), 0, -4);
    }

    const tex = { applyTheme, setChapter, setStep, frame, render: () => renderer.render(scene, camera) };
    applyTheme();
    resize();
    return tex;
  }

  try { gl = createStage(); } catch (e) { console.warn('3D stage disabled:', e); gl = null; }
  if (!gl) $('stage').classList.add('no-webgl');

  // watch theme changes (system or host toggle)
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const onTheme = () => gl && gl.applyTheme();
  if (mq.addEventListener) mq.addEventListener('change', onTheme);
  new MutationObserver(onTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class', 'style'] });

  // ================================================================= DOM rendering
  const groups = [];
  CHAPTERS.forEach((c) => {
    let g = groups.find((x) => x.name === c.group);
    if (!g) groups.push((g = { name: c.group, items: [] }));
    g.items.push(c);
  });
  $('chapter-nav').innerHTML = groups.map((g) => `
    <div class="nav-group">
      <div class="nav-group-title">${escapeHtml(g.name)}</div>
      ${g.items.map((c) => `<a class="nav-link" href="#${c.id}" data-id="${c.id}"><span class="n">${c.num}</span><span>${escapeHtml(c.short || c.title)}</span></a>`).join('')}
    </div>`).join('');
  $('chapter-select').innerHTML = groups.map((g) => `
    <optgroup label="${escapeHtml(g.name)}">${g.items.map((c) => `<option value="${c.id}">${c.num} · ${escapeHtml(c.short || c.title)}</option>`).join('')}</optgroup>`).join('');
  $('chapter-select').addEventListener('change', (e) => { location.hash = e.target.value; });

  $('legend').innerHTML = Object.values(KIND).map((k) => `<span><i style="--k: var(${k.token})"></i>${k.name}</span>`).join('');

  function renderChapter(ch) {
    player.chapter = ch;
    document.querySelectorAll('.nav-link').forEach((a) => a.toggleAttribute('aria-current', a.dataset.id === ch.id));
    document.querySelectorAll('.nav-link[aria-current]').forEach((a) => a.setAttribute('aria-current', 'page'));
    $('chapter-select').value = ch.id;
    $('ch-num').textContent = 'Chapter ' + ch.num;
    $('ch-group').textContent = ch.group;
    $('ch-title').textContent = ch.title;
    $('ch-lede').textContent = ch.lede;
    $('crumb').innerHTML = `<b>${ch.num}</b>${escapeHtml(ch.group)} / ${escapeHtml(ch.short || ch.title)}`;
    $('stage-badge-text').textContent = ch.flowName || 'Data flow';

    $('step-list').innerHTML = ch.steps.map((s, i) => `
      <li><button type="button" data-i="${i}" style="--k: ${kindVar(s.kind)}"><span class="n">${String(i + 1).padStart(2, '0')}</span><span><i class="k"></i>${escapeHtml(s.title)}</span></button></li>`).join('');
    $('progress').innerHTML = ch.steps.map((s, i) => `<button type="button" data-i="${i}" style="--k: ${kindVar(s.kind)}" aria-label="Step ${i + 1}: ${escapeHtml(s.title)}"></button>`).join('');

    $('glance').innerHTML = (ch.glance || []).map(([value, label]) => `<div><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('');
    $('glance').hidden = !(ch.glance && ch.glance.length);
    $('source-line').innerHTML = (ch.sources || []).length
      ? 'From Pilcrow’s Auth book: ' + ch.sources.map((s) => `<a href="${s.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.title)} ↗</a>`).join(' · ')
      : '';

    const an = ch.analogy || { title: '', intro: '', map: [] };
    $('analogy-title').textContent = an.title;
    $('analogy-intro').textContent = an.intro;
    $('analogy-map').innerHTML = an.map.map(([real, like]) => `<li><span class="real">${escapeHtml(real)}</span><span class="like">${escapeHtml(like)}</span></li>`).join('');

    $('concept').innerHTML = ch.concept;
    $('threats').innerHTML = ch.threats.map((t) => `
      <article class="threat">
        <h3>${t.name}</h3>
        <div class="risk"><span class="lbl">What goes wrong</span><p>${t.risk}</p></div>
        <div class="fix"><span class="lbl">Defense</span><p>${t.fix}</p></div>
      </article>`).join('');

    $('code-block').hidden = !ch.code.length;
    $('code-tabs').innerHTML = ch.code.map((f, i) => `<button class="code-tab" role="tab" type="button" data-i="${i}" aria-selected="${i === 0}">${escapeHtml(f.file.split('/').pop())}</button>`).join('');
    if (ch.code.length) showCode(ch, 0);

    let saved = {};
    try { saved = JSON.parse(localStorage.getItem('aim-check-' + ch.id) || '{}'); } catch (e) { saved = {}; }
    $('checklist').innerHTML = ch.checklist.map((item, i) => `
      <li><label><input type="checkbox" id="chk-${ch.id}-${i}" data-i="${i}" ${saved[i] ? 'checked' : ''}><span>${item}</span></label></li>`).join('');

    const idx = CHAPTERS.indexOf(ch);
    const prev = CHAPTERS[idx - 1];
    const next = CHAPTERS[idx + 1];
    $('pager').innerHTML = (prev ? `<a href="#${prev.id}"><small>Previous · ${prev.num}</small><b>${escapeHtml(prev.title)}</b></a>` : '') +
      (next ? `<a class="next" href="#${next.id}"><small>Next · ${next.num}</small><b>${escapeHtml(next.title)}</b></a>` : '');

    if (gl) gl.setChapter(ch);
    player.playing = false;
    goTo(0);
    document.title = 'Auth in Motion';
  }

  function showCode(ch, i) {
    const f = ch.code[i];
    document.querySelectorAll('.code-tab').forEach((b) => b.setAttribute('aria-selected', String(Number(b.dataset.i) === i)));
    const lang = f.lang || 'javascript';
    $('code-panel').innerHTML = `
      <div class="code-card">
        <div class="code-bar"><span class="code-path">${escapeHtml(f.file)}</span><button class="copy-btn" type="button" id="copy-btn">Copy</button></div>
        ${f.note ? `<p class="code-note">${f.note}</p>` : ''}
        <pre><code class="language-${lang}" id="code-el">${escapeHtml(f.code)}</code></pre>
      </div>`;
    const el = $('code-el');
    if (window.Prism && lang !== 'none') { try { window.Prism.highlightElement(el); } catch (e) { /* plain text is fine */ } }
    $('copy-btn').addEventListener('click', (e) => {
      const btn = e.currentTarget;
      const done = (msg) => { btn.textContent = msg; setTimeout(() => { btn.textContent = 'Copy'; }, 1600); };
      const fallback = () => {
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel.removeAllRanges(); sel.addRange(range);
        done('Selected, press ⌘C');
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(f.code).then(() => done('Copied'), fallback);
      else fallback();
    });
  }

  $('code-tabs').addEventListener('click', (e) => {
    const b = e.target.closest('.code-tab');
    if (b) showCode(player.chapter, Number(b.dataset.i));
  });
  $('checklist').addEventListener('change', (e) => {
    const box = e.target.closest('input[type=checkbox]');
    if (!box) return;
    try {
      const key = 'aim-check-' + player.chapter.id;
      const saved = JSON.parse(localStorage.getItem(key) || '{}');
      saved[box.dataset.i] = box.checked;
      localStorage.setItem(key, JSON.stringify(saved));
    } catch (err) { /* storage unavailable: ticks just won't persist */ }
  });

  // ---------------------------------------------------------------- step UI
  function goTo(i) {
    const steps = player.chapter.steps;
    player.index = clamp(i, 0, steps.length - 1);
    player.t = reduceMotion ? 1 : 0;
    player.hold = 0;
    const s = steps[player.index];
    const kind = KIND[s.kind] || KIND.data;
    $('step-kind').style.setProperty('--k', `var(${kind.token})`);
    $('step-kind').textContent = s.type === 'blocked' ? 'Attack, blocked' : kind.name;
    const route = s.type === 'process' ? `at ${ACTORS[s.at].name}` : `${ACTORS[s.from].name} → ${ACTORS[s.to].name}`;
    $('step-route').textContent = route;
    $('step-title').textContent = s.title;
    $('step-text').innerHTML = s.text;
    $('analogy-step').textContent = s.analogy || '';
    $('analogy-step').hidden = !s.analogy;
    const pl = $('step-payload');
    pl.hidden = !s.payload;
    pl.textContent = s.payload || '';
    $('step-counter').textContent = `${player.index + 1} / ${steps.length}`;
    document.querySelectorAll('#step-list button').forEach((b, j) => b.classList.toggle('current', j === player.index));
    document.querySelectorAll('#progress button').forEach((b, j) => {
      b.classList.toggle('current', j === player.index);
      b.classList.toggle('done', j < player.index);
    });
    if (gl) gl.setStep();
    syncPlay();
  }

  function syncPlay() {
    $('play-text').textContent = player.playing ? 'Pause' : (player.index === player.chapter.steps.length - 1 && player.t >= 1 ? 'Replay flow' : 'Play flow');
    $('play-icon').innerHTML = player.playing ? '<path d="M4 2.5h3v11H4zM9 2.5h3v11H9z"/>' : '<path d="M4 2.5v11l9-5.5Z"/>';
    $('btn-play').setAttribute('aria-label', player.playing ? 'Pause flow' : 'Play flow');
  }
  function togglePlay() {
    const last = player.chapter.steps.length - 1;
    if (!player.playing && player.index === last && player.t >= 1) { player.playing = true; goTo(0); return; }
    player.playing = !player.playing;
    player.hold = 0;
    syncPlay();
  }

  $('btn-play').addEventListener('click', togglePlay);
  $('btn-next').addEventListener('click', () => { player.playing = false; goTo(player.index + 1); });
  $('btn-prev').addEventListener('click', () => { player.playing = false; goTo(player.index - 1); });
  $('btn-restart').addEventListener('click', () => { player.playing = true; goTo(0); });
  $('step-list').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) { player.playing = false; goTo(Number(b.dataset.i)); } });
  $('progress').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) { player.playing = false; goTo(Number(b.dataset.i)); } });
  document.addEventListener('keydown', (e) => {
    if (e.target.closest('input, select, textarea') || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'ArrowRight') { player.playing = false; goTo(player.index + 1); }
    else if (e.key === 'ArrowLeft') { player.playing = false; goTo(player.index - 1); }
    else if (e.key === 'p' || e.key === 'P') togglePlay();
  });

  // ---------------------------------------------------------------- routing
  function route() {
    const id = location.hash.replace('#', '');
    const ch = byId[id] || CHAPTERS[0];
    if (player.chapter === ch) return;
    renderChapter(ch);
    if (id) window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
  }
  window.addEventListener('hashchange', route);
  route();

  // ---------------------------------------------------------------- loop
  let visible = true;
  if ('IntersectionObserver' in window) {
    new IntersectionObserver((entries) => { visible = entries[0].isIntersecting; }).observe($('stage'));
  }
  let last = performance.now();
  function loop(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    const s = player.chapter.steps[player.index];
    if (player.t < 1) {
      player.t = Math.min(1, player.t + dt / (DURATION[s.type] || 1.6));
      if (player.t >= 1) syncPlay();
    } else if (player.playing) {
      player.hold += dt;
      const read = 2.2 + Math.min(4.5, (s.text || '').replace(/<[^>]+>/g, '').length / 70);
      if (player.hold > read) {
        if (player.index < player.chapter.steps.length - 1) goTo(player.index + 1);
        else { player.playing = false; syncPlay(); }
      }
    }
    if (gl && visible && !document.hidden) { gl.frame(dt); gl.render(); }
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
})();
