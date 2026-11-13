/* Console tour viewer, see layouts/shortcodes/console-tour.html.

   Reads the .ct-step sections the tour-step shortcode rendered and builds
   an interactive stage from them. The sections stay in the page (hidden)
   as the source of the text; nothing here is needed to read the tour, a
   browser without javascript shows the plain list. */
(() => {
  "use strict";
  const root = document.querySelector("[data-console-tour]");
  if (!root) return;

  const STEP_MS = 6500; // autoplay time per step
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const esc = (s) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const pad = (n) => String(n).padStart(2, "0");
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const icon = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
  const ICON = {
    compare: icon('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M12 2v20"/>'),
    play: icon('<path d="M7 4.5v15l12-7.5z"/>'),
    pause: icon('<path d="M8 5v14M16 5v14"/>'),
    expand: icon('<path d="M8 3H3v5M16 3h5v5M8 21H3v-5M16 21h5v-5"/>'),
    shrink: icon('<path d="M3 8h5V3M21 8h-5V3M3 16h5v5M21 16h-5v5"/>'),
    left: icon('<path d="M15 6l-6 6 6 6"/>'),
    right: icon('<path d="M9 6l6 6-6 6"/>'),
    grip: icon('<path d="M9 7l-5 5 5 5M15 7l5 5-5 5"/>'),
    down: icon('<path d="M6 9l6 6 6-6"/>'),
  };

  /* ---- data: steps grouped into flows and chapters ---- */
  const steps = [...root.querySelectorAll(".ct-step")].map((el) => {
    const d = el.dataset;
    const user = d.user || "";
    return {
      id: el.id,
      flow: d.flow,
      chapter: d.chapter,
      title: d.title,
      img: d.img,
      w: +d.w,
      h: { light: +d.hLight, dark: +d.hDark },
      user,
      role: d.role || "",
      html: el.querySelector(".ct-step-body").innerHTML,
    };
  });
  if (!steps.length) return;
  const flows = [];
  steps.forEach((s, i) => {
    let f = flows[flows.length - 1];
    if (!f || f.name !== s.flow) flows.push((f = { name: s.flow, first: i, count: 0 }));
    s.index = i;
    s.flowIndex = flows.length - 1;
    s.n = ++f.count;
  });
  const anchors = {}; // heading ids other pages link to -> step index
  root.querySelectorAll(".ct-flow-h, .ct-chapter-h").forEach((h) => {
    const target = root.querySelector(`#${CSS.escape(h.id)} ~ .ct-step`);
    const s = target && steps.find((x) => x.id === target.id);
    if (s && !(h.id in anchors)) anchors[h.id] = s.index;
  });
  steps.forEach((s) => (anchors[s.id] = s.index));

  /* ---- markup ---- */
  const app = document.createElement("div");
  app.className = "ct-app";
  app.innerHTML = `
    <div class="ct-bar">
      <div class="ct-flows" role="tablist" aria-label="Tour">
        ${flows.map((f, i) => `<button class="ct-flow" type="button" role="tab" data-flow="${i}"><span>${esc(f.name)}</span><small>${f.count}</small></button>`).join("")}
      </div>
      <div class="ct-tools">
        <button class="ct-tool" type="button" data-act="compare" aria-pressed="false" title="Compare the light and dark themes (C)">${ICON.compare}<span>Compare themes</span></button>
        <button class="ct-tool" type="button" data-act="play" aria-pressed="false" title="Play the tour (Space)"><i class="ic">${ICON.play}</i><span>Play</span></button>
        <button class="ct-tool" type="button" data-act="theater" aria-pressed="false" aria-label="Full window" title="Full window (F)"><i class="ic">${ICON.expand}</i></button>
      </div>
    </div>
    <div class="ct-body">
      <nav class="ct-rail" aria-label="Tour steps"><div class="ct-rail-scroll"></div></nav>
      <div class="ct-main">
        <div class="ct-frame">
          <div class="ct-chrome">
            <span class="ct-dots" aria-hidden="true"><i></i><i></i><i></i></span>
            <span class="ct-loc"></span>
            <span class="ct-user"></span>
          </div>
          <div class="ct-stage">
            <div class="ct-scroll" tabindex="0" role="img"></div>
            <div class="ct-divider" role="slider" tabindex="0" aria-label="Light and dark split" aria-valuemin="0" aria-valuemax="100"><span class="ct-grip">${ICON.grip}</span></div>
            <span class="ct-tag ct-tag-l">Light</span>
            <span class="ct-tag ct-tag-r">Dark</span>
            <button class="ct-more" type="button" tabindex="-1">Scroll for the full page ${ICON.down}</button>
          </div>
        </div>
        <div class="ct-segs"></div>
        <div class="ct-caption">
          <div class="ct-count" aria-hidden="true"><b></b><span></span></div>
          <div class="ct-text" aria-live="polite">
            <p class="ct-eyebrow"></p>
            <h2 class="ct-title not-prose"></h2>
            <div class="ct-desc"></div>
          </div>
          <div class="ct-nav">
            <button class="ct-btn" type="button" data-act="back" aria-label="Previous step">${ICON.left}Back</button>
            <button class="ct-btn primary" type="button" data-act="next"><span></span>${ICON.right}</button>
          </div>
        </div>
      </div>
    </div>
    <p class="ct-keys">
      <span><kbd>&larr;</kbd><kbd>&rarr;</kbd> step</span>
      <span><kbd>Space</kbd> play</span>
      <span><kbd>C</kbd> compare themes</span>
      <span><kbd>F</kbd> full window</span>
      <span>Drag the handle to compare, scroll inside the window for tall pages</span>
    </p>`;
  root.prepend(app);
  const $ = (s) => app.querySelector(s);
  const stage = $(".ct-stage");
  const scroller = $(".ct-scroll");
  const divider = $(".ct-divider");
  const more = $(".ct-more");
  const railEl = $(".ct-rail-scroll");
  const segsEl = $(".ct-segs");
  const textEl = $(".ct-text");
  const tool = (name) => app.querySelector(`[data-act="${name}"]`);

  /* ---- state ---- */
  let cur = -1;
  let shownFlow = -1;
  let compare = false;
  let split = 0.5; // share of the stage showing light while comparing
  let playing = false;
  let theater = false;
  let shot = null;
  const seen = new Set();
  const siteDark = () => document.documentElement.classList.contains("dark");
  const theme = () => (siteDark() ? "dark" : "light");
  const src = (s, t) => `${s.img}-${t}.png`;

  /* ---- screenshot ---- */
  /* Only the variant in view is fetched; the other one loads when compare
     is turned on or the site theme changes */
  function ensure(el, s, t) {
    const img = el.querySelector(t === "dark" ? ".d" : ".l");
    if (img.getAttribute("src")) return img;
    img.onload = () => img.classList.add("on");
    img.src = src(s, t);
    if (img.complete && img.naturalWidth) img.classList.add("on");
    return img;
  }
  function makeShot(s) {
    const el = document.createElement("div");
    el.className = "ct-shot";
    el.innerHTML = `<img class="l" alt="" draggable="false"><img class="d" alt="" draggable="false">`;
    return el;
  }
  function sizeShot() {
    if (!shot) return;
    const s = steps[cur];
    // comparing: the shorter variant, so neither side runs out
    const h = compare ? Math.min(s.h.light, s.h.dark) : s.h[theme()];
    shot.style.aspectRatio = `${s.w} / ${h}`;
  }
  function paintSplit() {
    const pct = compare ? split : siteDark() ? 0 : 1;
    stage.style.setProperty("--split", pct * 100 + "%");
    stage.style.setProperty("--split-px", pct * scroller.clientWidth + "px");
    stage.classList.toggle("compare", compare);
    divider.setAttribute("aria-valuenow", Math.round(split * 100));
    divider.setAttribute("aria-valuetext", `${Math.round(split * 100)}% light`);
    if (shot) {
      const s = steps[cur];
      if (compare) (ensure(shot, s, "light"), ensure(shot, s, "dark"));
      else ensure(shot, s, theme());
    }
    sizeShot();
    hint();
  }
  function hint() {
    const room = scroller.scrollHeight - scroller.clientHeight;
    more.classList.toggle("on", room > 24 && scroller.scrollTop < 24 && !playing);
  }
  function swapShot(s, dir) {
    // the outgoing screenshot stays as a ghost under the new one until the
    // new one has loaded, so steps cross-fade instead of flashing empty
    const old = shot;
    if (old) {
      const ghost = document.createElement("div");
      ghost.className = "ct-ghost";
      old.style.transform = `translateY(${-scroller.scrollTop}px)`;
      old.style.animation = "none";
      ghost.append(old);
      stage.querySelectorAll(".ct-ghost").forEach((g) => g.remove());
      stage.prepend(ghost);
      const drop = () => {
        ghost.classList.add("out");
        setTimeout(() => ghost.remove(), 340);
      };
      shot = makeShot(s);
      const img = ensure(shot, s, compare ? "light" : theme());
      if (img.complete && img.naturalWidth) setTimeout(drop, 60);
      else {
        img.addEventListener("load", drop, { once: true });
        img.addEventListener("error", drop, { once: true });
        setTimeout(drop, 2500);
      }
    } else {
      shot = makeShot(s);
    }
    shot.style.setProperty("--dir", dir);
    scroller.append(shot);
    scroller.scrollTop = 0;
    scroller.scrollLeft = 0;
    scroller.setAttribute("aria-label", `Screenshot: ${s.title}`);
    paintSplit();
  }
  function preload(i) {
    const s = steps[i];
    if (s) new Image().src = src(s, theme());
  }

  /* ---- rail and segments, per flow ---- */
  function avatar(s) {
    return s.user ? `<span class="ct-avatar" data-tone="${esc(s.role)}" title="${esc(s.user)}${s.role ? ", " + esc(s.role) : ""}">${esc(s.user[0])}</span>` : "";
  }
  function buildFlow(fi) {
    shownFlow = fi;
    const list = steps.filter((s) => s.flowIndex === fi);
    const chapters = [];
    list.forEach((s) => {
      let c = chapters[chapters.length - 1];
      if (!c || c.name !== s.chapter) chapters.push((c = { name: s.chapter, steps: [] }));
      c.steps.push(s);
    });
    railEl.innerHTML = chapters
      .map(
        (c) => `<p class="ct-rail-h">${esc(c.name)}</p><ol>${c.steps
          .map((s) => `<li><button class="ct-step-btn" type="button" data-go="${s.index}"><span class="n">${pad(s.n)}</span><span class="t">${esc(s.title)}</span>${avatar(s)}</button></li>`)
          .join("")}</ol>`,
      )
      .join("");
    segsEl.innerHTML = chapters
      .map(
        (c) => `<div class="ct-seg-group" style="flex:${c.steps.length}">${c.steps
          .map((s) => `<button class="ct-seg" type="button" data-go="${s.index}" aria-label="Step ${s.n}: ${esc(s.title)}"><span>${pad(s.n)} ${esc(s.title)}</span></button>`)
          .join("")}</div>`,
      )
      .join("");
    app.querySelectorAll(".ct-flow").forEach((b) => {
      const on = +b.dataset.flow === fi;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
    });
  }

  /* ---- step ---- */
  function go(i, opts = {}) {
    i = clamp(i, 0, steps.length - 1);
    if (i === cur) return;
    const s = steps[i];
    const dir = cur < 0 ? 0 : i > cur ? 1 : -1;
    const first = cur < 0;
    cur = i;
    seen.add(i);
    if (s.flowIndex !== shownFlow) buildFlow(s.flowIndex);
    const f = flows[s.flowIndex];

    swapShot(s, dir);

    app.querySelectorAll("[data-go]").forEach((b) => {
      const n = +b.dataset.go;
      if (n === i) b.setAttribute("aria-current", "step");
      else b.removeAttribute("aria-current");
      b.classList.toggle("seen", seen.has(n));
      b.style.removeProperty("--p");
    });
    // keep the active rail item in view without scrolling the page
    const item = railEl.querySelector("[aria-current]");
    if (item && railEl.scrollHeight > railEl.clientHeight) {
      const top = item.offsetTop - railEl.clientHeight / 2 + item.offsetHeight / 2;
      railEl.scrollTo({ top, behavior: first || reduced ? "auto" : "smooth" });
    }

    $(".ct-loc").innerHTML = `console / <b>${esc(s.chapter)}</b>`;
    $(".ct-user").innerHTML = s.user
      ? `${avatar(s)}<span class="who">Signed in as <b>${esc(s.user)}</b></span>${s.role ? `<span class="role" data-tone="${esc(s.role)}">${esc(s.role)}</span>` : ""}`
      : "";
    $(".ct-count b").textContent = pad(s.n);
    $(".ct-count span").textContent = "/ " + pad(f.count);
    $(".ct-eyebrow").textContent = `${f.name} · ${s.chapter}`;
    $(".ct-title").textContent = s.title;
    $(".ct-desc").innerHTML = s.html;
    if (!first) {
      textEl.classList.remove("swap");
      void textEl.offsetWidth;
      textEl.classList.add("swap");
    }

    tool("back").disabled = i === 0;
    const next = steps[i + 1];
    tool("next").firstElementChild.textContent = !next ? "Start over" : next.flowIndex !== s.flowIndex ? `Next: ${flows[next.flowIndex].name}` : "Next";

    if (!opts.quiet && history.replaceState) history.replaceState(null, "", "#" + s.id);
    preload(i + 1);
  }
  const next = () => go(cur === steps.length - 1 ? 0 : cur + 1);
  const back = () => go(cur - 1);

  /* ---- autoplay: fills the active segment, pans tall screenshots ---- */
  let raf = 0;
  let t0 = 0;
  function tick(now) {
    if (!playing) return;
    const p = clamp((now - t0) / STEP_MS, 0, 1);
    const seg = segsEl.querySelector("[aria-current]");
    if (seg) seg.style.setProperty("--p", p);
    const room = scroller.scrollHeight - scroller.clientHeight;
    if (room > 24 && !reduced) {
      const q = clamp((p - 0.2) / 0.6, 0, 1);
      scroller.scrollTop = room * (q * q * (3 - 2 * q));
    }
    if (p >= 1) {
      if (cur === steps.length - 1) return setPlaying(false);
      go(cur + 1);
      t0 = now;
    }
    raf = requestAnimationFrame(tick);
  }
  function setPlaying(on) {
    if (playing === on) return;
    playing = on;
    cancelAnimationFrame(raf);
    const b = tool("play");
    b.setAttribute("aria-pressed", String(on));
    b.querySelector(".ic").innerHTML = on ? ICON.pause : ICON.play;
    b.querySelector("span").textContent = on ? "Pause" : "Play";
    const seg = segsEl.querySelector("[aria-current]");
    if (seg) seg.style.removeProperty("--p");
    if (on) {
      if (cur === steps.length - 1) go(0);
      t0 = performance.now();
      raf = requestAnimationFrame(tick);
    }
    hint();
  }
  const stop = () => setPlaying(false);

  /* ---- compare ---- */
  function setCompare(on) {
    compare = on;
    if (on) split = 0.5;
    tool("compare").setAttribute("aria-pressed", String(on));
    paintSplit();
  }
  function dragTo(x) {
    const r = scroller.getBoundingClientRect();
    split = clamp((x - r.left) / scroller.clientWidth, 0.03, 0.97);
    paintSplit();
  }
  divider.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    stop();
    divider.setPointerCapture(e.pointerId);
    stage.classList.add("dragging");
    const move = (ev) => dragTo(ev.clientX);
    const up = () => {
      stage.classList.remove("dragging");
      divider.removeEventListener("pointermove", move);
      divider.removeEventListener("pointerup", up);
      divider.removeEventListener("pointercancel", up);
    };
    divider.addEventListener("pointermove", move);
    divider.addEventListener("pointerup", up);
    divider.addEventListener("pointercancel", up);
  });
  divider.addEventListener("keydown", (e) => {
    const d = { ArrowLeft: -0.05, ArrowRight: 0.05, Home: -1, End: 1 }[e.key];
    if (!d) return;
    e.preventDefault();
    e.stopPropagation();
    split = clamp(split + d, 0.03, 0.97);
    paintSplit();
  });
  // warm the other variant before the first compare
  tool("compare").addEventListener("pointerenter", () => {
    if (!compare && cur >= 0) new Image().src = src(steps[cur], siteDark() ? "light" : "dark");
  });

  /* ---- full window ---- */
  function setTheater(on) {
    theater = on;
    root.classList.toggle("ct-theater", on);
    document.documentElement.classList.toggle("ct-lock", on);
    const b = tool("theater");
    b.setAttribute("aria-pressed", String(on));
    b.setAttribute("aria-label", on ? "Exit full window" : "Full window");
    b.querySelector(".ic").innerHTML = on ? ICON.shrink : ICON.expand;
    requestAnimationFrame(paintSplit);
  }

  /* ---- events ---- */
  app.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (b.dataset.go) return (stop(), go(+b.dataset.go));
    if (b.dataset.flow) return (stop(), go(flows[+b.dataset.flow].first));
    if (b === more) return scroller.scrollBy({ top: scroller.clientHeight * 0.8, behavior: reduced ? "auto" : "smooth" });
    switch (b.dataset.act) {
      case "back":
        return (stop(), back());
      case "next":
        return (stop(), next());
      case "compare":
        return setCompare(!compare);
      case "play":
        return setPlaying(!playing);
      case "theater":
        return setTheater(!theater);
    }
  });
  $(".ct-flows").addEventListener("keydown", (e) => {
    const d = { ArrowLeft: -1, ArrowRight: 1 }[e.key];
    if (!d) return;
    e.preventDefault();
    e.stopPropagation();
    const fi = clamp(shownFlow + d, 0, flows.length - 1);
    stop();
    go(flows[fi].first);
    app.querySelector(`.ct-flow[data-flow="${fi}"]`).focus();
  });
  scroller.addEventListener("scroll", hint, { passive: true });
  scroller.addEventListener("wheel", stop, { passive: true });

  // swipe between steps on touch screens. On phones the screenshot is zoomed
  // and wider than the stage (see the narrow screen css): a sideways drag
  // pans it there, and the Back / Next buttons step
  let touch = null;
  scroller.addEventListener("touchstart", (e) => {
    stop();
    touch = e.touches.length === 1 ? { x: e.touches[0].clientX, y: e.touches[0].clientY } : null;
  }, { passive: true });
  scroller.addEventListener("touchend", (e) => {
    if (!touch) return;
    const dx = e.changedTouches[0].clientX - touch.x;
    const dy = e.changedTouches[0].clientY - touch.y;
    touch = null;
    if (scroller.scrollWidth > scroller.clientWidth + 1) return;
    if (Math.abs(dx) > 60 && Math.abs(dx) > 2 * Math.abs(dy)) dx < 0 ? next() : back();
  }, { passive: true });

  // keyboard, only while the tour is on screen
  let inView = false;
  new IntersectionObserver((es) => (inView = es[0].isIntersecting), { threshold: 0.25 }).observe(app);
  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    if (!inView && !theater) return;
    const t = e.target;
    if (t.closest && t.closest("input, textarea, select, [contenteditable]")) return;
    switch (e.key) {
      case "ArrowRight":
        e.preventDefault();
        stop();
        if (cur < steps.length - 1) go(cur + 1);
        break;
      case "ArrowLeft":
        e.preventDefault();
        stop();
        back();
        break;
      case " ":
        if (t.closest && t.closest("button, a, summary")) return;
        e.preventDefault();
        setPlaying(!playing);
        break;
      case "c":
      case "C":
        setCompare(!compare);
        break;
      case "f":
      case "F":
        setTheater(!theater);
        break;
      case "Escape":
        if (theater) setTheater(false);
        break;
    }
  });

  // the site's light/dark toggle wipes the stage to the other variant
  new MutationObserver(paintSplit).observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  new ResizeObserver(paintSplit).observe(stage);
  document.addEventListener("visibilitychange", () => document.hidden && stop());

  // start on the step or section named in the url
  const fromHash = () => anchors[decodeURIComponent(location.hash.slice(1))];
  const start = fromHash();
  go(start ?? 0, { quiet: true });
  if (start !== undefined) requestAnimationFrame(() => root.scrollIntoView({ block: "start" }));
  addEventListener("hashchange", () => {
    const i = fromHash();
    if (i !== undefined) (stop(), go(i, { quiet: true }));
  });
})();
