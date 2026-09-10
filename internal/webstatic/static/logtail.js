// SPDX-License-Identifier: Apache-2.0
// <log-tail> - streaming log viewer custom element. Served by the openrun
// binary for every app (/_openrun/static, internal/webstatic): the console's
// container logs and the action UI's streamed command output share it.
//
//   <log-tail src="/app/containers/logs_stream?id=X&tail=500" max-lines="5000"></log-tail>
//
// Fetches the src URL and renders the plain-text response as log lines,
// following the stream until it ends or the element is removed. Without a
// src the page drives it: feed(text) appends output (the action UI feeds
// it from server-sent events) and end(status) closes the stream. Designed
// for minimal CPU and memory use: chunk-level fast path for plain text, a
// fixed line cap, and DOM updates batched per animation frame (at most
// max-lines nodes are ever touched in a frame, however fast the stream is).
//
// Console output handling: CRLF, \r overwrite (progress bars), \b; the
// common ANSI SGR codes (16 colors, bold/dim/italic/underline) render as
// styled spans, all other escape sequences are stripped.
//
// The parsing core has no DOM dependency and is exported for Node perf tests
// (module.exports) as well as on window.LogTailCore.

(function () {
	'use strict';

	/* ---------- parsing core ---------- */

	// Style bitfield: fg 0-16 in bits 0-4 (16 = default), bg 0-16 in bits
	// 5-9, bold/dim/italic/underline in bits 10-13
	const FG_DEFAULT = 16;
	const BG_DEFAULT = 16 << 5;
	const STYLE_DEFAULT = FG_DEFAULT | BG_DEFAULT;
	const BOLD = 1 << 10, DIM = 1 << 11, ITALIC = 1 << 12, UNDERLINE = 1 << 13;

	// Anything other than printable + \t + \r + \n needs the slow path
	// (\r is handled cheaply in the fast path, see below)
	const SLOW_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

	const MAX_LINE_CHARS = 16384; // truncation cap, bounds DOM/memory per line

	// applySgr interprets one CSI ... m parameter list against a style value.
	// Unknown/unsupported parameters are ignored (their effect is stripped)
	function applySgr(params, style) {
		if (params === '') return STYLE_DEFAULT;
		const parts = params.split(';');
		for (let i = 0; i < parts.length; i++) {
			const p = parts[i] === '' ? 0 : parts[i] | 0;
			if (p === 0) style = STYLE_DEFAULT;
			else if (p === 1) style |= BOLD;
			else if (p === 2) style |= DIM;
			else if (p === 3) style |= ITALIC;
			else if (p === 4) style |= UNDERLINE;
			else if (p === 22) style &= ~(BOLD | DIM);
			else if (p === 23) style &= ~ITALIC;
			else if (p === 24) style &= ~UNDERLINE;
			else if (p >= 30 && p <= 37) style = (style & ~31) | (p - 30);
			else if (p === 39) style = (style & ~31) | FG_DEFAULT;
			else if (p >= 90 && p <= 97) style = (style & ~31) | (p - 90 + 8);
			else if (p >= 40 && p <= 47) style = (style & ~(31 << 5)) | ((p - 40) << 5);
			else if (p === 49) style = (style & ~(31 << 5)) | BG_DEFAULT;
			else if (p >= 100 && p <= 107) style = (style & ~(31 << 5)) | ((p - 100 + 8) << 5);
			else if (p === 38 || p === 48) {
				// Extended color: 38;5;n (256) or 38;2;r;g;b (truecolor).
				// Palette entries 0-15 map to the base colors, the rest and
				// truecolor are stripped (parameters consumed either way)
				const mode = parts[i + 1] | 0;
				if (mode === 5) {
					const n = parts[i + 2] | 0;
					if (n >= 0 && n <= 15) {
						if (p === 38) style = (style & ~31) | n;
						else style = (style & ~(31 << 5)) | (n << 5);
					}
					i += 2;
				} else if (mode === 2) {
					i += 4;
				}
			}
		}
		return style;
	}

	// parseLine handles a line containing escapes/control chars. Returns a
	// flat segment array [style, text, style, text, ...] and updates
	// state.style (SGR state persists across lines, like a terminal)
	function parseLine(line, state) {
		const segs = [];
		let style = state.style;
		let cur = '';
		let i = 0;
		const n = line.length;
		while (i < n) {
			const c = line.charCodeAt(i);
			if (c === 0x1b) {
				const next = i + 1 < n ? line.charCodeAt(i + 1) : -1;
				if (next === 0x5b) { // CSI: ESC [ params final-byte
					let j = i + 2;
					while (j < n) {
						const fc = line.charCodeAt(j);
						if (fc >= 0x40 && fc <= 0x7e) break;
						j++;
					}
					if (j >= n) break; // unterminated, drop the rest
					if (line.charCodeAt(j) === 0x6d) { // final byte m: SGR
						if (cur) { segs.push(style, cur); cur = ''; }
						style = applySgr(line.slice(i + 2, j), style);
					} // other CSI (cursor movement etc.) stripped
					i = j + 1;
				} else if (next === 0x5d) { // OSC: ESC ] ... (BEL | ESC \)
					let j = i + 2;
					while (j < n && line.charCodeAt(j) !== 0x07 &&
						!(line.charCodeAt(j) === 0x1b && line.charCodeAt(j + 1) === 0x5c)) j++;
					i = j >= n ? n : (line.charCodeAt(j) === 0x07 ? j + 1 : j + 2);
				} else if (next === -1) {
					break;
				} else {
					// Other escape sequence: ESC, intermediates 0x20-0x2f,
					// one final byte (e.g. charset designation ESC ( B) - strip
					let j = i + 1;
					while (j < n && line.charCodeAt(j) >= 0x20 && line.charCodeAt(j) <= 0x2f) j++;
					i = j < n ? j + 1 : n;
				}
			} else if (c === 0x0d) { // interior \r: overwrite from line start
				segs.length = 0;
				cur = '';
				i++;
			} else if (c === 0x08) { // \b: delete the previous visible char
				if (cur) cur = cur.slice(0, -1);
				else if (segs.length) {
					const t = segs[segs.length - 1].slice(0, -1);
					if (t) segs[segs.length - 1] = t;
					else segs.length -= 2;
				}
				i++;
			} else if (c < 0x20 && c !== 0x09) { // strip other C0 controls
				i++;
			} else if (c === 0x7f) {
				i++;
			} else {
				// run of plain characters
				let j = i + 1;
				while (j < n) {
					const rc = line.charCodeAt(j);
					if (rc < 0x20 || rc === 0x7f) break;
					j++;
				}
				cur += line.slice(i, j);
				i = j;
			}
		}
		if (cur) segs.push(style, cur);
		state.style = style;
		return segs;
	}

	// createParser returns a stateful stream parser. feed(text) returns the
	// complete lines in the accumulated input; each line is a plain string
	// (no styling) or a segment array [style, text, ...]. end() flushes a
	// trailing unterminated line
	function createParser() {
		const state = { style: STYLE_DEFAULT, partial: '' };

		function toLine(raw) {
			if (raw.length > MAX_LINE_CHARS) raw = raw.slice(0, MAX_LINE_CHARS) + ' …';
			// CRLF, then \r overwrite: keep the content after the last \r
			if (raw.charCodeAt(raw.length - 1) === 13) raw = raw.slice(0, -1);
			if (state.style === STYLE_DEFAULT && !SLOW_RE.test(raw)) {
				const cr = raw.lastIndexOf('\r');
				return cr === -1 ? raw : raw.slice(cr + 1);
			}
			const segs = parseLine(raw, state);
			if (segs.length === 0) return '';
			if (segs.length === 2 && segs[0] === STYLE_DEFAULT) return segs[1];
			return segs;
		}

		return {
			feed(text) {
				if (state.partial) {
					text = state.partial + text;
					state.partial = '';
				}
				const parts = text.split('\n');
				state.partial = parts.pop();
				// Fast path: plain printable chunk with default style - the
				// single regex test skips per-line parsing for typical logs
				if (state.style === STYLE_DEFAULT && !SLOW_RE.test(text)) {
					for (let i = 0; i < parts.length; i++) {
						let line = parts[i];
						if (line.length > MAX_LINE_CHARS) line = line.slice(0, MAX_LINE_CHARS) + ' …';
						if (line.charCodeAt(line.length - 1) === 13) line = line.slice(0, -1);
						const cr = line.lastIndexOf('\r');
						if (cr !== -1) line = line.slice(cr + 1);
						parts[i] = line;
					}
					return parts;
				}
				const lines = [];
				for (let i = 0; i < parts.length; i++) lines.push(toLine(parts[i]));
				return lines;
			},
			end() {
				if (!state.partial) return [];
				const rest = state.partial;
				state.partial = '';
				return [toLine(rest)];
			},
		};
	}

	// RingBuffer keeps the newest cap entries; used by the perf tests and
	// available for non-DOM consumers (the element trims the DOM directly)
	function createRingBuffer(cap) {
		const items = new Array(cap);
		let head = 0, size = 0;
		return {
			push(v) {
				items[(head + size) % cap] = v;
				if (size < cap) size++;
				else head = (head + 1) % cap;
			},
			get size() { return size; },
			toArray() {
				const out = new Array(size);
				for (let i = 0; i < size; i++) out[i] = items[(head + i) % cap];
				return out;
			},
		};
	}

	const LogTailCore = {
		createParser: createParser,
		createRingBuffer: createRingBuffer,
		STYLE_DEFAULT: STYLE_DEFAULT,
		styleBits: { BOLD, DIM, ITALIC, UNDERLINE, FG_DEFAULT, BG_DEFAULT },
	};

	if (typeof module !== 'undefined' && module.exports) {
		module.exports = LogTailCore;
	}
	if (typeof window === 'undefined') return; // Node (perf tests): core only
	window.LogTailCore = LogTailCore;

	/* ---------- rendering element ---------- */

	// Base palette (xterm-ish, tuned for the dark viewer background); pages
	// can override via the --lt-c* variables
	const PALETTE = [
		'#3b4252', '#e06c75', '#98c379', '#e5c07b', '#61afef', '#c678dd', '#56b6c2', '#c8ccd4',
		'#5c6370', '#ff7a85', '#a9d48b', '#f0cf8f', '#79bdff', '#d78ee8', '#66d0dc', '#e6e6e6',
	];

	function injectStyles() {
		if (document.getElementById('log-tail-style')) return;
		let css = 'log-tail{display:block}' +
			'log-tail .lt-scroll{background:#101418;color:#d6dce4;font-family:var(--font-mono,ui-monospace,SFMono-Regular,Menlo,monospace);' +
			'font-size:0.75rem;line-height:1.45;overflow-y:auto;overflow-x:hidden;padding:0.75rem 1rem;' +
			'border-radius:var(--radius-box,0.5rem);overscroll-behavior:contain}' +
			'log-tail .lt-line{white-space:pre-wrap;word-break:break-all;min-height:1.45em}' +
			'log-tail .lt-status{font-size:0.7rem;opacity:0.6;padding:0.2rem 0.25rem;font-family:var(--font-mono,ui-monospace,monospace)}' +
			'log-tail .lt-live{color:var(--color-success,#3c3)}' +
			'log-tail .lt-bold{font-weight:700}log-tail .lt-dim{opacity:0.6}' +
			'log-tail .lt-italic{font-style:italic}log-tail .lt-underline{text-decoration:underline}';
		for (let i = 0; i < 16; i++) {
			css += 'log-tail .lt-f' + i + '{color:var(--lt-c' + i + ',' + PALETTE[i] + ')}';
			css += 'log-tail .lt-b' + i + '{background:var(--lt-c' + i + ',' + PALETTE[i] + ')}';
		}
		const style = document.createElement('style');
		style.id = 'log-tail-style';
		style.textContent = css;
		document.head.appendChild(style);
	}

	// style bitfield -> class string, cached (few distinct styles per app)
	const classCache = new Map();
	function styleClasses(style) {
		let cls = classCache.get(style);
		if (cls !== undefined) return cls;
		const parts = [];
		const fg = style & 31, bg = (style >> 5) & 31;
		if (fg < 16) parts.push('lt-f' + fg);
		if (bg < 16) parts.push('lt-b' + bg);
		if (style & BOLD) parts.push('lt-bold');
		if (style & DIM) parts.push('lt-dim');
		if (style & ITALIC) parts.push('lt-italic');
		if (style & UNDERLINE) parts.push('lt-underline');
		cls = parts.join(' ');
		classCache.set(style, cls);
		return cls;
	}

	function lineNode(line) {
		const div = document.createElement('div');
		div.className = 'lt-line';
		if (typeof line === 'string') {
			div.textContent = line; // fast path: one text node
			return div;
		}
		for (let i = 0; i < line.length; i += 2) {
			const cls = styleClasses(line[i]);
			if (!cls) {
				div.appendChild(document.createTextNode(line[i + 1]));
			} else {
				const span = document.createElement('span');
				span.className = cls;
				span.textContent = line[i + 1];
				div.appendChild(span);
			}
		}
		return div;
	}

	class LogTail extends HTMLElement {
		static get observedAttributes() { return ['src']; }

		constructor() {
			super();
			this._pending = [];
			this._flushQueued = false;
			this._stick = true; // keep scrolled to the bottom until the user scrolls up
			this._abort = null;
			this._onPagehide = () => this._abort && this._abort.abort();
		}

		connectedCallback() {
			injectStyles();
			if (!this._scroll) {
				this._scroll = document.createElement('div');
				this._scroll.className = 'lt-scroll';
				this._scroll.style.maxHeight = this.getAttribute('height') || '40rem';
				this._scroll.setAttribute('role', 'log');
				// Live announcements stay off: a followed stream can emit
				// hundreds of lines a second, which would swamp a screen
				// reader. The status line below announces state changes
				this._scroll.setAttribute('aria-live', 'off');
				this._scroll.setAttribute('aria-label',
					this.getAttribute('label') || 'Log output');
				// Scrollable region must be keyboard reachable to scroll
				this._scroll.setAttribute('tabindex', '0');
				this._scroll.addEventListener('scroll', () => {
					this._stick = this._scroll.scrollTop + this._scroll.clientHeight >=
						this._scroll.scrollHeight - 8;
				}, { passive: true });
				this._status = document.createElement('div');
				this._status.className = 'lt-status';
				this._status.setAttribute('role', 'status');
				this._status.hidden = true;
				this.appendChild(this._scroll);
				this.appendChild(this._status);
			}
			window.addEventListener('pagehide', this._onPagehide);
			if (this.getAttribute('src')) this._start();
		}

		disconnectedCallback() {
			window.removeEventListener('pagehide', this._onPagehide);
			if (this._abort) this._abort.abort();
		}

		attributeChangedCallback(name, oldVal, newVal) {
			if (name === 'src' && this.isConnected && oldVal !== null && oldVal !== newVal) {
				this._start();
			}
		}

		get maxLines() {
			const v = parseInt(this.getAttribute('max-lines'), 10);
			return v > 0 ? v : 5000;
		}

		// reload restarts the stream (same or new URL)
		reload(src) {
			if (src && src !== this.getAttribute('src')) {
				this.setAttribute('src', src); // restarts via attributeChangedCallback
				return;
			}
			this._start();
		}

		// feed appends a chunk of output pushed by the page (no src fetch);
		// partial lines are held until their newline arrives, like the
		// fetch path
		feed(text) {
			if (!this._parser) {
				this._parser = createParser();
				this._setStatus('● streaming', true);
			}
			this._push(this._parser.feed(text));
		}

		// end closes a page-driven stream: flushes the trailing partial
		// line, shows the outcome in the status line and dispatches
		// logtail-end with the detail {status, error}. status is the
		// command's exit status; error a message when the stream failed
		end(status, error) {
			if (this._parser) this._push(this._parser.end());
			this._parser = null;
			let text;
			if (error) text = '- stream failed: ' + error;
			else if (status === undefined || status === null) text = '- stream ended';
			else text = '- exited with status ' + status;
			this._setStatus(text, false);
			this.dispatchEvent(new CustomEvent('logtail-end', {
				bubbles: true, detail: { status: status, error: error },
			}));
		}

		_setStatus(text, live) {
			this._status.textContent = text;
			this._status.classList.toggle('lt-live', !!live);
			this._status.hidden = !text;
		}

		async _start() {
			if (this._abort) this._abort.abort();
			const ctl = new AbortController();
			this._abort = ctl;
			this._pending = [];
			// Keep the current content visible until the new stream's first
			// lines arrive; clearing here would flash an empty pane when the
			// follow toggle re-streams the same log
			this._clearPending = true;
			this._stick = true;
			this._parser = createParser();
			const follow = this.hasAttribute('follow');
			this._setStatus(follow ? '● streaming' : '', follow);

			try {
				const res = await fetch(this.getAttribute('src'), { signal: ctl.signal });
				if (!res.ok) {
					this._setStatus('error loading logs: HTTP ' + res.status);
					return;
				}
				const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
				for (;;) {
					const { value, done } = await reader.read();
					if (done) break;
					this._push(this._parser.feed(value));
				}
				this._push(this._parser.end());
				if (ctl === this._abort) {
					if (this._clearPending && !this._pending.length) {
						// The new stream had no output at all: the log really
						// is empty now, drop the stale content
						this._scroll.textContent = '';
						this._clearPending = false;
					}
					this._setStatus(follow ? '- stream ended' : '');
					this._parser = null;
					this.dispatchEvent(new CustomEvent('logtail-end', { bubbles: true, detail: {} }));
				}
			} catch (err) {
				if (ctl.signal.aborted) return; // element removed / restarted
				this._setStatus('error loading logs: ' + err.message);
				this.dispatchEvent(new CustomEvent('logtail-error', { bubbles: true, detail: err }));
			}
		}

		_push(lines) {
			if (!lines.length) return;
			const max = this.maxLines;
			for (let i = 0; i < lines.length; i++) this._pending.push(lines[i]);
			// Under a firehose, only the newest max lines ever reach the DOM
			if (this._pending.length > max) {
				this._pending.splice(0, this._pending.length - max);
				this._dropAll = true;
			}
			if (!this._flushQueued) {
				this._flushQueued = true;
				requestAnimationFrame(() => this._flush());
			}
		}

		_flush() {
			this._flushQueued = false;
			const pending = this._pending;
			if (!pending.length) return;
			this._pending = [];
			const scroll = this._scroll;
			if (this._clearPending || this._dropAll) {
				scroll.textContent = '';
				this._clearPending = false;
				this._dropAll = false;
			}
			const frag = document.createDocumentFragment();
			for (let i = 0; i < pending.length; i++) frag.appendChild(lineNode(pending[i]));
			scroll.appendChild(frag);
			const max = this.maxLines;
			while (scroll.childNodes.length > max) scroll.removeChild(scroll.firstChild);
			if (this._stick) scroll.scrollTop = scroll.scrollHeight;
		}
	}

	if (!customElements.get('log-tail')) {
		customElements.define('log-tail', LogTail);
	}
})();
