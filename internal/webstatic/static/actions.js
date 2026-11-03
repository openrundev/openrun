// Theme toggle + nav drawer behaviors, following the console app
// (ui/console/static/console.js). The theme names are app-configurable:
// the layout head script stores them in localStorage as
// theme-light/theme-dark and applies the persisted choice pre-paint.

// The mobile hamburger is a real button (keyboard operable, unlike a bare
// label): toggles the drawer checkbox and keeps aria-expanded in sync,
// moving focus to the sidebar when opening
function toggleNavDrawer(btn) {
	const drawer = document.getElementById('nav-drawer');
	if (!drawer) {
		return;
	}
	drawer.checked = !drawer.checked;
	btn.setAttribute('aria-expanded', drawer.checked ? 'true' : 'false');
	if (drawer.checked) {
		const nav = document.getElementById('sidebar-panel');
		if (nav) {
			nav.focus();
		}
	}
}

// Searchable combobox for list-options and suggest based dropdowns.
// Light DOM: the inner input carries the param name, so plain form
// submission and htmx serialization work unchanged; free text entry is
// allowed (the option list is a helper, same as the old select which the
// server never validated against). Follows the WAI-ARIA combobox pattern:
// role=combobox input, aria-expanded, aria-activedescendant, listbox popup.
//
// The listeners are delegated from the host element and the inner parts
// (input, listbox, toggle) are looked up at event time, never cached at
// connect time: during the initial page parse the element upgrades before
// its children exist, and after an htmx swap the children are present but
// not final. htmx 4 "settles" swapped-in elements whose id matches an
// element being replaced (param_x input, listbox, options): for the settle
// delay the new element carries the OLD element's attributes, so a
// param_x input which was a plain text field before Suggest turned it into
// a dropdown has no role=combobox and the old value when the custom
// element connects. Caching the parts then left a dead dropdown.
class SearchableSelect extends HTMLElement {
	connectedCallback() {
		// connectedCallback re-fires when htmx swaps move the element;
		// bind only once
		if (this.ssInit) {
			return;
		}
		this.ssInit = true;

		this.addEventListener('click', (event) => {
			const input = this.input;
			const toggle = this.toggle;
			if (input && event.target == input) {
				this.open(false);
			} else if (toggle && toggle.contains(event.target)) {
				if (this.listbox.hidden) {
					input.focus();
					this.open(false);
				} else {
					this.close();
				}
			}
		});
		this.addEventListener('input', (event) => {
			if (event.target == this.input) {
				this.open(true);
			}
		});
		this.addEventListener('keydown', (event) => {
			if (event.target == this.input) {
				this.onKey(event);
			}
		});
		// Strict mode (the default, set server side unless the param has the
		// COMBO display type): the value must be one of the options. Typing
		// still filters; text that matches no option reverts on blur/Enter to
		// the last valid value, captured when the user starts editing (the
		// server rendered value is valid by construction; reading it at
		// connect time would see the settle-window value, see above).
		// The server also rejects non-option values for static option lists
		this.addEventListener('focusin', (event) => {
			if (event.target == this.input && this.lastValid === undefined) {
				this.lastValid = this.input.value;
			}
		});
		this.addEventListener('mousedown', (event) => {
			// mousedown, not click: the input's blur would close the
			// listbox before a click event is delivered
			const opt = event.target.closest('li[role="option"]');
			if (opt && this.listbox && this.listbox.contains(opt)) {
				event.preventDefault();
				this.select(opt);
			}
		});
		this.addEventListener('focusout', (event) => {
			if (!this.contains(event.relatedTarget)) {
				this.close();
				this.enforce();
			}
		});
	}

	get input() {
		return this.querySelector('input');
	}

	get listbox() {
		return this.querySelector('ul');
	}

	get toggle() {
		return this.querySelector('button');
	}

	get strict() {
		return this.hasAttribute('data-strict');
	}

	// enforce reverts a strict combobox to the last valid value when the
	// typed text is not one of the options. A case-insensitive unique match
	// is normalized to the option's exact value; empty stays empty (cleared,
	// the handler's own required-param validation reports it)
	enforce() {
		const input = this.input;
		if (!this.strict || !input) {
			return;
		}
		const text = input.value;
		if (text == '') {
			this.lastValid = '';
			return;
		}
		const opts = this.options();
		if (opts.some((o) => o.dataset.value == text)) {
			this.lastValid = text;
			return;
		}
		const ciMatches = opts.filter(
			(o) => o.dataset.value.toLowerCase() == text.toLowerCase());
		if (ciMatches.length == 1) {
			input.value = ciMatches[0].dataset.value;
			this.lastValid = input.value;
			return;
		}
		if (this.lastValid !== undefined) {
			input.value = this.lastValid;
		}
	}

	options() {
		const listbox = this.listbox;
		return listbox ? [...listbox.querySelectorAll('li[role="option"]')] : [];
	}

	// open shows the options; when filter is true only the options
	// containing the typed text (case-insensitive) stay visible
	open(filter) {
		const input = this.input;
		const listbox = this.listbox;
		if (!input || !listbox) {
			return;
		}
		const text = filter ? input.value.trim().toLowerCase() : '';
		let shown = 0;
		for (const opt of this.options()) {
			const match = !text || opt.dataset.value.toLowerCase().includes(text);
			opt.hidden = !match;
			if (match) {
				shown++;
			}
		}
		listbox.hidden = shown == 0;
		input.setAttribute('aria-expanded', shown > 0 ? 'true' : 'false');
		let active = this.options().find(
			(o) => !o.hidden && o.dataset.value == input.value) || null;
		if (!active && filter && this.strict) {
			// Strict mode: pre-activate the first match so typing a prefix
			// and pressing Enter picks it
			active = this.options().find((o) => !o.hidden) || null;
		}
		this.setActive(active);
	}

	close() {
		const input = this.input;
		const listbox = this.listbox;
		if (!input || !listbox) {
			return;
		}
		listbox.hidden = true;
		input.setAttribute('aria-expanded', 'false');
		this.setActive(null);
	}

	setActive(opt) {
		for (const o of this.options()) {
			o.classList.toggle('ss-active', o == opt);
		}
		const input = this.input;
		if (opt) {
			input.setAttribute('aria-activedescendant', opt.id);
			opt.scrollIntoView({ block: 'nearest' });
		} else {
			input.removeAttribute('aria-activedescendant');
		}
	}

	select(opt) {
		const input = this.input;
		input.value = opt.dataset.value;
		this.lastValid = opt.dataset.value;
		for (const o of this.options()) {
			if (o.hasAttribute('aria-selected')) {
				o.removeAttribute('aria-selected');
			}
		}
		opt.setAttribute('aria-selected', 'true');
		this.close();
		input.dispatchEvent(new Event('change', { bubbles: true }));
		input.focus();
	}

	onKey(event) {
		const listbox = this.listbox;
		const visible = this.options().filter((o) => !o.hidden);
		const active = listbox.querySelector('.ss-active');
		const idx = visible.indexOf(active);
		switch (event.key) {
			case 'ArrowDown':
			case 'ArrowUp': {
				event.preventDefault();
				if (listbox.hidden) {
					this.open(false);
					return;
				}
				const dir = event.key == 'ArrowDown' ? 1 : -1;
				const next = visible[(idx + dir + visible.length) % visible.length];
				this.setActive(next || null);
				break;
			}
			case 'Enter':
				// Only intercept while the listbox is open; otherwise Enter
				// submits the form as usual (after strict enforcement)
				if (!listbox.hidden && active) {
					event.preventDefault();
					this.select(active);
				} else if (!listbox.hidden) {
					this.close();
					this.enforce();
				} else {
					this.enforce();
				}
				break;
			case 'Escape':
				if (!listbox.hidden) {
					event.stopPropagation(); // keep the nav drawer open
					this.close();
				}
				break;
			case 'Tab':
				this.close();
				break;
		}
	}
}
customElements.define('searchable-select', SearchableSelect);

// Switching actions keeps the values entered in the current form: the
// sidebar nav links get the form values appended as query params at click
// time (the form GET handler prefills params from the query string).
// Passwords and file uploads are never put in a URL.
function actionNavApplyParams(link) {
	const form = document.getElementById('action_form');
	if (!form) {
		return;
	}
	// Start from the current page's query params: they carry values for
	// params which are HIDDEN in this action (entered in another action,
	// e.g. a checkbox unchecked on Deploy stays off while passing through
	// Logs). The live form values then override their own params; a
	// cleared field removes the param so the target falls back to the
	// default
	const params = new URLSearchParams(location.search);
	for (const el of form.elements) {
		if (!el.name || el.type == 'password' || el.type == 'file' ||
			el.type == 'submit' || el.type == 'button') {
			continue;
		}
		if (el.type == 'checkbox') {
			params.set(el.name, el.checked ? 'true' : 'false');
		} else if (el.value != '') {
			params.set(el.name, el.value);
		} else {
			params.delete(el.name);
		}
	}
	const qs = params.toString();
	link.href = link.href.split('?')[0] + (qs ? '?' + qs : '');
}

// mousedown covers middle/modifier clicks opening a new tab; click covers
// keyboard activation
for (const type of ['mousedown', 'click']) {
	document.addEventListener(type, (event) => {
		const link = event.target.closest && event.target.closest('#action-nav a[href]');
		if (link) {
			actionNavApplyParams(link);
		}
	});
}

// Streamed action output. A run handler returning ace.result(stream=...)
// answers the Run hx-post with server-sent events (hx-sse extension): the
// first event swaps the status line and the <log-tail> pane shell, then
// named events, dispatched by hx-sse as DOM events on the Run button,
// carry the output chunks (JSON string payloads) and the exit status. The
// pane swap is awaited by hx-sse before the next event is dispatched, but
// output arriving before the element exists is queued rather than dropped
const actionStream = { queue: [], exited: true };

function actionLogPane() {
	return document.getElementById('action_log');
}

function actionStreamFlush() {
	const pane = actionLogPane();
	if (!pane || !actionStream.queue.length) {
		return;
	}
	const chunks = actionStream.queue;
	actionStream.queue = [];
	pane.feed(chunks.join(''));
}

// The stream events are dispatched on the Run button; the dev-mode reload
// listener (#cl_reload_listener) is a separate hx-sse connection which
// must not be mistaken for an action stream
function actionFormStream(event) {
	return event.target.closest && event.target.closest('#action_form');
}

document.addEventListener('htmx:sse:after:connection', (event) => {
	if (!actionFormStream(event)) {
		return;
	}
	actionStream.queue = [];
	actionStream.exited = false;
});

document.addEventListener('openrun:output', (event) => {
	actionStream.queue.push(JSON.parse(event.detail.data));
	actionStreamFlush();
});

function actionStreamEnd(status, error) {
	actionStreamFlush();
	actionStream.exited = true;
	const pane = actionLogPane();
	if (pane) {
		pane.end(status, error);
	}
	// A failed command marks the status line, like a handler error
	const message = document.getElementById('ActionMessage');
	if (message && (error || status !== 0)) {
		message.classList.add('text-error');
	}
}

document.addEventListener('openrun:exit', (event) => {
	const result = JSON.parse(event.detail.data);
	actionStreamEnd(result.status, result.error);
});

// A stream cut before openrun:exit (server restart, network drop) ends
// with hx-sse's close event only: report it as a failure rather than
// leaving the pane marked as streaming
document.addEventListener('htmx:sse:close', (event) => {
	if (!actionFormStream(event) || actionStream.exited) {
		return;
	}
	actionStreamEnd(undefined, 'connection closed before the command finished');
});

// applyScheme switches the page to the light or dark theme of the app (the
// theme names the layout head script stored in localStorage).
// data-color-scheme drives the --or-accent-text brand token in openrun.css
// (theme names are app-configurable, so the CSS cannot key off them)
function applyScheme(scheme) {
	const themeName = localStorage.getItem('theme-' + scheme);
	if (themeName) {
		document.documentElement.setAttribute('data-theme', themeName);
	}
	document.documentElement.setAttribute('data-color-scheme', scheme);
}

// An embedding page (the console's action viewer) passes its theme with
// ?_cl_theme= (layout head script) and posts {type: "cl_theme", theme} when
// the user switches it: follow, and remember it for the frame's later
// navigations. Same-origin senders only
window.addEventListener('message', (event) => {
	if (event.origin != location.origin || !event.data || event.data.type != 'cl_theme') {
		return;
	}
	const scheme = event.data.theme == 'dark' ? 'dark' : 'light';
	applyScheme(scheme);
	document.documentElement.setAttribute('data-embed-theme', scheme);
	try { sessionStorage.setItem('_cl_theme', scheme); } catch (e) { /* storage may be unavailable */ }
});

document.addEventListener('DOMContentLoaded', () => {
	// Persist the user's theme choice. The toggle's initial state is set by
	// an inline script next to it in the sidebar, before first paint, so
	// the swap animation does not play on page load. Checked means light
	// (the sun face shows).
	const toggle = document.getElementById('theme-toggle');
	if (toggle) {
		toggle.addEventListener('change', (event) => {
			const scheme = event.target.checked ? 'light' : 'dark';
			applyScheme(scheme);
			localStorage.setItem('theme', scheme);
		});
	}

	// Keep the hamburger's aria-expanded in sync when the drawer is closed
	// by the overlay click instead of the button
	const drawer = document.getElementById('nav-drawer');
	if (drawer) {
		drawer.addEventListener('change', () => {
			for (const btn of document.querySelectorAll('[aria-controls="sidebar-panel"]')) {
				btn.setAttribute('aria-expanded', drawer.checked ? 'true' : 'false');
			}
		});
	}

	// Escape closes the nav drawer when it is open
	document.addEventListener('keydown', (event) => {
		if (event.key == 'Escape') {
			const drawer = document.getElementById('nav-drawer');
			if (drawer && drawer.checked) {
				drawer.checked = false;
				drawer.dispatchEvent(new Event('change'));
				const btn = document.querySelector('[aria-controls="sidebar-panel"]');
				if (btn) {
					btn.focus();
				}
			}
		}
	});
});
