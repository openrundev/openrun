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
class SearchableSelect extends HTMLElement {
	connectedCallback() {
		// connectedCallback re-fires when htmx swaps move the element;
		// initialize only once
		if (this.ssInit) {
			return;
		}
		this.ssInit = true;
		// During the initial page parse the element upgrades at its opening
		// tag, before its children exist; defer until the document is
		// parsed. htmx-inserted elements connect with children present
		if (document.readyState == 'loading') {
			document.addEventListener('DOMContentLoaded', () => this.init(), { once: true });
		} else {
			this.init();
		}
	}

	init() {
		this.input = this.querySelector('input[role="combobox"]');
		this.listbox = this.querySelector('ul[role="listbox"]');
		this.toggle = this.querySelector('button');
		if (!this.input || !this.listbox) {
			return;
		}
		// Strict mode (the default, set server side unless the param has the
		// COMBO display type): the value must be one of the options. Typing
		// still filters; text that matches no option reverts on blur/Enter.
		// The server also rejects non-option values for static option lists
		this.strict = this.hasAttribute('data-strict');
		this.lastValid = this.input.value;

		this.input.addEventListener('click', () => this.open(false));
		this.input.addEventListener('input', () => this.open(true));
		this.input.addEventListener('keydown', (event) => this.onKey(event));
		if (this.toggle) {
			this.toggle.addEventListener('click', () => {
				if (this.listbox.hidden) {
					this.input.focus();
					this.open(false);
				} else {
					this.close();
				}
			});
		}
		this.listbox.addEventListener('mousedown', (event) => {
			// mousedown, not click: the input's blur would close the
			// listbox before a click event is delivered
			const opt = event.target.closest('li[role="option"]');
			if (opt) {
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

	// enforce reverts a strict combobox to the last valid value when the
	// typed text is not one of the options. A case-insensitive unique match
	// is normalized to the option's exact value; empty stays empty (cleared,
	// the handler's own required-param validation reports it)
	enforce() {
		if (!this.strict) {
			return;
		}
		const text = this.input.value;
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
			this.input.value = ciMatches[0].dataset.value;
			this.lastValid = this.input.value;
			return;
		}
		this.input.value = this.lastValid;
	}

	options() {
		return [...this.listbox.querySelectorAll('li[role="option"]')];
	}

	// open shows the options; when filter is true only the options
	// containing the typed text (case-insensitive) stay visible
	open(filter) {
		const text = filter ? this.input.value.trim().toLowerCase() : '';
		let shown = 0;
		for (const opt of this.options()) {
			const match = !text || opt.dataset.value.toLowerCase().includes(text);
			opt.hidden = !match;
			if (match) {
				shown++;
			}
		}
		this.listbox.hidden = shown == 0;
		this.input.setAttribute('aria-expanded', shown > 0 ? 'true' : 'false');
		let active = this.options().find(
			(o) => !o.hidden && o.dataset.value == this.input.value) || null;
		if (!active && filter && this.strict) {
			// Strict mode: pre-activate the first match so typing a prefix
			// and pressing Enter picks it
			active = this.options().find((o) => !o.hidden) || null;
		}
		this.setActive(active);
	}

	close() {
		this.listbox.hidden = true;
		this.input.setAttribute('aria-expanded', 'false');
		this.setActive(null);
	}

	setActive(opt) {
		for (const o of this.options()) {
			o.classList.toggle('ss-active', o == opt);
		}
		if (opt) {
			this.input.setAttribute('aria-activedescendant', opt.id);
			opt.scrollIntoView({ block: 'nearest' });
		} else {
			this.input.removeAttribute('aria-activedescendant');
		}
	}

	select(opt) {
		this.input.value = opt.dataset.value;
		this.lastValid = opt.dataset.value;
		for (const o of this.options()) {
			if (o.hasAttribute('aria-selected')) {
				o.removeAttribute('aria-selected');
			}
		}
		opt.setAttribute('aria-selected', 'true');
		this.close();
		this.input.dispatchEvent(new Event('change', { bubbles: true }));
		this.input.focus();
	}

	onKey(event) {
		const visible = this.options().filter((o) => !o.hidden);
		const active = this.listbox.querySelector('.ss-active');
		const idx = visible.indexOf(active);
		switch (event.key) {
			case 'ArrowDown':
			case 'ArrowUp': {
				event.preventDefault();
				if (this.listbox.hidden) {
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
				if (!this.listbox.hidden && active) {
					event.preventDefault();
					this.select(active);
				} else if (!this.listbox.hidden) {
					this.close();
					this.enforce();
				} else {
					this.enforce();
				}
				break;
			case 'Escape':
				if (!this.listbox.hidden) {
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

document.addEventListener('DOMContentLoaded', () => {
	// Persist the user's theme choice. The toggle's initial state is set by
	// an inline script next to it in the sidebar, before first paint, so
	// the swap animation does not play on page load. Checked means light
	// (the sun face shows).
	const toggle = document.getElementById('theme-toggle');
	if (toggle) {
		toggle.addEventListener('change', (event) => {
			const scheme = event.target.checked ? 'light' : 'dark';
			const themeName = localStorage.getItem('theme-' + scheme);
			if (themeName) {
				document.documentElement.setAttribute('data-theme', themeName);
			}
			// data-color-scheme drives the --or-accent-text brand token in
			// openrun.css (theme names are app-configurable, so the CSS
			// cannot key off them)
			document.documentElement.setAttribute('data-color-scheme', scheme);
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
