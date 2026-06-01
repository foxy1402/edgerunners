const Version = '2026-06-01-ws-vless-trojan';

let proxyIP = '', debugLog = false;
let cachedProxyIP, cachedProxyAddresses, proxyAddressIndex = 0, proxyFallback = false;
let preloadRaceDial = false, tcpRaceDial = 2;

const WS_EARLY_DATA_MAX_BYTES = 8 * 1024;
const WS_EARLY_DATA_MAX_HEAD = Math.ceil(WS_EARLY_DATA_MAX_BYTES * 4 / 3) + 4;
const UPSTREAM_BUNDLE_TARGET = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL = 512;
const DOWNSTREAM_GRAIN_IDLE_MS = 0;

export default {
	async fetch(request, env) {
		let requestUrlText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const hashIndex = requestUrlText.indexOf('#');
		const requestUrlMain = hashIndex === -1 ? requestUrlText : requestUrlText.slice(0, hashIndex);
		if (!requestUrlMain.includes('?') && /%3f/i.test(requestUrlMain)) {
			const hashPart = hashIndex === -1 ? '' : requestUrlText.slice(hashIndex);
			requestUrlText = requestUrlMain.replace(/%3f/i, '?') + hashPart;
		}

		const url = new URL(requestUrlText);
		const userAgent = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
		const adminSecret = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const key = env.KEY || 'change-this-key';
		const envUUID = env.UUID || env.uuid;
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const userIDMD5 = await md5md5(String(adminSecret || '') + key);
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await toArray(env.HOST)).map(normalizeHost).filter(Boolean) : [url.hostname];
		const host = hosts[0] || url.hostname;
		const path = url.pathname.slice(1).toLowerCase();
		const defaultConfig = createDefaultConfig(env, hosts, host);
		const config = await readWorkerConfig(env, defaultConfig);
		const effectiveHosts = env.HOST ? hosts : config.HOSTS.map(normalizeHost).filter(Boolean);

		debugLog = ['1', 'true', 'yes'].includes(String(env.DEBUG || '').toLowerCase());
		preloadRaceDial = ['1', 'true', 'yes'].includes(String(env.PRELOAD_RACE_DIAL || '').toLowerCase());
		tcpRaceDial = Math.max(1, Math.min(8, Number(env.TCP_RACE_DIAL || 2) || 2));

		const proxyIPs = env.PROXYIP ? await toArray(env.PROXYIP) : await toArray(config.PROXYIP);
		proxyIP = proxyIPs.length ? proxyIPs[Math.floor(Math.random() * proxyIPs.length)] : '';
		proxyFallback = ['1', 'true', 'yes'].includes(String(env.PROXYIP_FALLBACK || '').toLowerCase());

		if (url.protocol === 'http:') return Response.redirect(url.href.replace('http://', 'https://'), 301);
		if (path === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
		if (path === 'version' && url.searchParams.get('uuid') === userID) {
			return jsonResponse({ version: Version, build: Number(String(Version).replace(/\D+/g, '')) || 0 });
		}
		if (!adminSecret) return textResponse('Set ADMIN, PASSWORD, TOKEN, KEY, or UUID before using this Worker.', 404);

		const token = await md5md5(host + userID);
		const authenticated = await hasValidAuthCookie(request, userAgent, key, adminSecret);
		if (path === 'login') return handleLogin(request, userAgent, key, adminSecret, authenticated);
		if (path === 'logout') return clearAuthCookie();
		if (path === 'admin' || path.startsWith('admin/')) {
			if (!authenticated) return redirectResponse('/login');
			return handleAdminRoute(request, env, url, config, defaultConfig, token, userID, effectiveHosts);
		}

		if (upgradeHeader === 'websocket') {
			const proxyIPParam = url.searchParams.get('proxyip');
			if (proxyIPParam) { proxyIP = proxyIPParam; proxyFallback = false; }
			log(`[WebSocket] ${url.pathname}${url.search}`);
			return handleWS(request, userID, url);
		}

		if (path === key && key !== 'change-this-key') {
			const params = new URLSearchParams(url.search);
			params.set('token', token);
			return new Response('Redirecting...', { status: 302, headers: { Location: `/sub?${params.toString()}` } });
		}
		if (path === 'sub') {
			if (url.searchParams.get('token') !== token) return textResponse('Forbidden', 403);
			const subscription = buildSubscription({ config, hosts: effectiveHosts.length ? effectiveHosts : hosts, userID });
			const body = url.searchParams.has('base64') || url.searchParams.has('b64') ? btoa(subscription) : subscription;
			return new Response(body, {
				headers: {
					'Content-Type': 'text/plain; charset=utf-8',
					'Cache-Control': 'no-store',
					'Content-Disposition': `attachment; filename*=utf-8''${encodeURIComponent(env.SUB_NAME || 'edgerunners')}`,
				},
			});
		}

		return serveCamouflage(request, url, config.URL);
	}
};

function normalizeHost(value) {
	return String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
}

function normalizePath(value) {
	const raw = String(value || '/').trim() || '/';
	return raw.startsWith('/') ? raw : '/' + raw;
}

function buildSubscription({ config, hosts, userID }) {
	const protocol = String(config.PROTOCOL || 'vless').toLowerCase();
	const nodePath = normalizePath(config.PATH || '/');
	const fingerprint = config.FINGERPRINT || 'chrome';
	const name = config.SUB_NAME || 'edgerunners';
	return hosts.map((h, i) => buildNodeLink({
		protocol, nodePath, fingerprint,
		name: hosts.length > 1 ? `${name}-${i + 1}` : name,
		userID, host: h
	})).join('\n');
}

function buildNodeLink({ protocol, nodePath, fingerprint, name, userID, host }) {
	const scheme = protocol === 'trojan' ? 'trojan' : 'vless';
	return `${scheme}://${userID}@${host}:443?security=tls&type=ws&host=${encodeURIComponent(host)}&fp=${encodeURIComponent(fingerprint)}&sni=${encodeURIComponent(host)}&path=${encodeURIComponent(nodePath)}&encryption=none#${encodeURIComponent(name)}`;
}

function jsonResponse(data, status = 200) {
	return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function textResponse(text, status = 200) {
	return new Response(text, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function htmlResponse(html, status = 200) {
	return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function redirectResponse(location) {
	return new Response('Redirecting...', { status: 302, headers: { Location: location, 'Cache-Control': 'no-store' } });
}

function createDefaultConfig(env, hosts, currentHost) {
	return {
		HOSTS: hosts.length ? hosts : [currentHost],
		PATH: normalizePath(env.PATH || '/'),
		PROTOCOL: String(env.PROTOCOL || 'vless').toLowerCase(),
		SUB_NAME: env.SUB_NAME || 'edgerunners',
		PROXYIP: env.PROXYIP || '',
		URL: env.URL || 'nginx',
		FINGERPRINT: env.FINGERPRINT || 'chrome',
	};
}

async function readWorkerConfig(env, defaults) {
	if (!env.KV || typeof env.KV.get !== 'function') return defaults;
	try {
		const stored = await env.KV.get('config.json');
		if (!stored) {
			await env.KV.put('config.json', JSON.stringify(defaults, null, 2));
			return defaults;
		}
		const parsed = JSON.parse(stored);
		return normalizeConfig({ ...defaults, ...parsed }, defaults);
	} catch (error) {
		console.error('Failed to read config.json:', error.message);
		return defaults;
	}
}

function normalizeConfig(config, defaults) {
	const hosts = Array.isArray(config.HOSTS) ? config.HOSTS : String(config.HOSTS || config.HOST || '').split(/[\n,]+/);
	return {
		...defaults,
		...config,
		HOSTS: hosts.map(normalizeHost).filter(Boolean).length ? hosts.map(normalizeHost).filter(Boolean) : defaults.HOSTS,
		PATH: normalizePath(config.PATH || defaults.PATH),
		PROTOCOL: ['vless', 'trojan'].includes(String(config.PROTOCOL || '').toLowerCase()) ? String(config.PROTOCOL).toLowerCase() : defaults.PROTOCOL,
		SUB_NAME: String(config.SUB_NAME || defaults.SUB_NAME || 'edgerunners').trim(),
		PROXYIP: String(config.PROXYIP || '').trim(),
		URL: String(config.URL || defaults.URL || 'nginx').trim(),
		FINGERPRINT: String(config.FINGERPRINT || defaults.FINGERPRINT || 'chrome').trim(),
	};
}

async function saveWorkerConfig(env, config) {
	if (!env.KV || typeof env.KV.put !== 'function') throw new Error('KV binding is required to save settings.');
	await env.KV.put('config.json', JSON.stringify(config, null, 2));
}

async function authCookieValue(userAgent, key, adminSecret) {
	return md5md5(userAgent + key + adminSecret);
}

async function hasValidAuthCookie(request, userAgent, key, adminSecret) {
	const cookies = request.headers.get('Cookie') || '';
	const authCookie = cookies.split(';').map(c => c.trim()).find(c => c.startsWith('auth='))?.split('=')[1];
	return Boolean(authCookie && authCookie === await authCookieValue(userAgent, key, adminSecret));
}

async function handleLogin(request, userAgent, key, adminSecret, authenticated) {
	if (authenticated) return redirectResponse('/admin');
	let error = '';
	if (request.method === 'POST') {
		const params = new URLSearchParams(await request.text());
		const password = params.get('password') || '';
		if (password === String(adminSecret).replace(/[\r\n]/g, '')) {
			const response = redirectResponse('/admin');
			response.headers.set('Set-Cookie', `auth=${await authCookieValue(userAgent, key, adminSecret)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`);
			return response;
		}
		error = 'Invalid password.';
	}
	return htmlResponse(loginPageHTML(error));
}

function clearAuthCookie() {
	const response = redirectResponse('/login');
	response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
	return response;
}

async function handleAdminRoute(request, env, url, config, defaultConfig, token, userID, hosts) {
	if (url.pathname === '/admin/config.json') return jsonResponse(config);
	if (request.method === 'POST' && url.pathname === '/admin/reset') {
		await saveWorkerConfig(env, defaultConfig);
		return redirectResponse('/admin?saved=reset');
	}
	if (request.method === 'POST' && url.pathname === '/admin/config') {
		const params = new URLSearchParams(await request.text());
		const nextConfig = normalizeConfig({
			HOSTS: params.get('HOSTS') || '',
			PATH: params.get('PATH') || '/',
			PROTOCOL: params.get('PROTOCOL') || 'vless',
			SUB_NAME: params.get('SUB_NAME') || 'edgerunners',
			PROXYIP: params.get('PROXYIP') || '',
			URL: params.get('URL') || 'nginx',
			FINGERPRINT: params.get('FINGERPRINT') || 'chrome',
		}, defaultConfig);
		await saveWorkerConfig(env, nextConfig);
		return redirectResponse('/admin?saved=1');
	}
	const subscriptionURL = `${url.origin}/sub?token=${encodeURIComponent(token)}`;
	const kvReady = Boolean(env.KV && typeof env.KV.get === 'function' && typeof env.KV.put === 'function');
	return htmlResponse(adminPageHTML({ config, subscriptionURL, userID, hosts, kvReady, saved: url.searchParams.get('saved') }));
}

function loginPageHTML(error = '') {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edgerunners Login</title>
${adminStyles()}
</head>
<body>
<main class="login-shell">
	<form class="panel login-panel" method="post" action="/login">
		<h1>Edgerunners</h1>
		<p class="muted">Sign in to manage this Worker.</p>
		${error ? `<p class="alert">${escapeHTML(error)}</p>` : ''}
		<label>Password<input name="password" type="password" autocomplete="current-password" autofocus required></label>
		<button type="submit">Sign In</button>
	</form>
</main>
</body>
</html>`;
}

function adminPageHTML({ config, subscriptionURL, userID, hosts, kvReady, saved }) {
	const hostText = (config.HOSTS || hosts).join('\n');
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edgerunners Admin</title>
${adminStyles()}
</head>
<body>
<main class="admin-shell">
	<header class="topbar">
		<div>
			<h1>Edgerunners</h1>
			<p class="muted">Worker admin &mdash; WebSocket &bull; VLESS / Trojan</p>
		</div>
		<nav><a href="/admin/config.json">JSON</a><a href="/logout">Logout</a></nav>
	</header>
	${!kvReady ? '<p class="alert">KV binding named KV is missing. Settings are readable but cannot be saved.</p>' : ''}
	${saved ? '<p class="success">Settings saved.</p>' : ''}
	<section class="panel">
		<h2>Subscription</h2>
		<div class="copy-row"><input readonly value="${escapeAttr(subscriptionURL)}"><button type="button" data-copy>Copy</button></div>
		<div class="meta-grid">
			<div><span>UUID / Password</span><code>${escapeHTML(userID)}</code></div>
			<div><span>Hosts</span><code>${escapeHTML(hosts.join(', '))}</code></div>
		</div>
	</section>
	<form class="panel grid-form" method="post" action="/admin/config">
		<h2>Settings</h2>
		<label>Hosts<textarea name="HOSTS" rows="3">${escapeHTML(hostText)}</textarea></label>
		<label>Path<input name="PATH" value="${escapeAttr(config.PATH)}"></label>
		<label>Subscription Name<input name="SUB_NAME" value="${escapeAttr(config.SUB_NAME)}"></label>
		<label>ProxyIP<input name="PROXYIP" value="${escapeAttr(config.PROXYIP)}" placeholder="hostname or ip:port"></label>
		<label>Camouflage URL<input name="URL" value="${escapeAttr(config.URL)}" placeholder="nginx, 1101, or https://example.com"></label>
		<label>Protocol<select name="PROTOCOL">${optionList(['vless', 'trojan'], config.PROTOCOL)}</select></label>
		<label>Fingerprint<input name="FINGERPRINT" value="${escapeAttr(config.FINGERPRINT)}"></label>
		<div class="actions">
			<button type="submit">Save Settings</button>
		</div>
	</form>
	<form class="panel danger" method="post" action="/admin/reset">
		<h2>Reset</h2>
		<p class="muted">Restore the current environment-derived defaults.</p>
		<button type="submit">Reset Config</button>
	</form>
</main>
<script>
document.querySelector('[data-copy]')?.addEventListener('click', async function () {
	const input = this.previousElementSibling;
	await navigator.clipboard.writeText(input.value);
	this.textContent = 'Copied';
	setTimeout(() => this.textContent = 'Copy', 1200);
});
</script>
</body>
</html>`;
}

function optionList(values, selected) {
	return values.map(value => `<option value="${escapeAttr(value)}"${value === selected ? ' selected' : ''}>${escapeHTML(value)}</option>`).join('');
}

function adminStyles() {
	return `<style>
:root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f9;color:#111827}
*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#111827}.login-shell{min-height:100vh;display:grid;place-items:center;padding:24px}.admin-shell{max-width:1040px;margin:0 auto;padding:28px 18px 44px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.topbar h1,.panel h1,.panel h2{margin:0}.topbar nav{display:flex;gap:10px}.topbar a{color:#1f5fbf;text-decoration:none}.panel{background:#fff;border:1px solid #d8dde6;border-radius:8px;padding:18px;margin-bottom:16px;box-shadow:0 1px 2px rgba(16,24,40,.05)}.login-panel{width:min(420px,100%)}.muted{color:#667085;margin:.35rem 0 1rem}.alert{border:1px solid #f5b5b5;background:#fff1f1;color:#9f1d1d;border-radius:6px;padding:10px}.success{border:1px solid #b8dfc2;background:#effaf2;color:#166329;border-radius:6px;padding:10px}.grid-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.grid-form h2,.grid-form .actions{grid-column:1/-1}label{display:grid;gap:6px;font-weight:600;color:#344054}input,textarea,select{width:100%;border:1px solid #cfd6e1;border-radius:6px;padding:10px 11px;font:inherit;background:#fff;color:#111827}textarea{resize:vertical}button{border:0;border-radius:6px;background:#1f5fbf;color:#fff;padding:10px 14px;font-weight:700;cursor:pointer}button:hover{background:#174d9c}.copy-row{display:grid;grid-template-columns:1fr auto;gap:10px}.meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}.meta-grid div{border:1px solid #e4e7ec;border-radius:6px;padding:10px}.meta-grid span{display:block;color:#667085;font-size:13px}.meta-grid code{word-break:break-all}.danger button{background:#b42318}.danger button:hover{background:#912018}@media(max-width:720px){.grid-form,.meta-grid,.copy-row{grid-template-columns:1fr}.topbar{align-items:flex-start;flex-direction:column}}
</style>`;
}

function escapeHTML(value) {
	return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function escapeAttr(value) {
	return escapeHTML(value).replace(/`/g, '&#96;');
}

async function serveCamouflage(request, url, target) {
	const normalized = String(target || 'nginx').trim();
	if (normalized === '1101') return htmlResponse(fakeCloudflare1101(url.hostname, request));
	if (!normalized || normalized.toLowerCase() === 'nginx') return htmlResponse(fakeNginxPage());
	let targetURL = normalized;
	if (!/^https?:\/\//i.test(targetURL)) targetURL = 'https://' + targetURL;
	try {
		const upstream = new URL(targetURL);
		const headers = new Headers(request.headers);
		headers.set('Host', upstream.host);
		headers.set('Referer', upstream.origin);
		headers.set('Origin', upstream.origin);
		const response = await fetch(upstream.origin + url.pathname + url.search, { method: request.method, headers, body: request.body });
		const contentType = response.headers.get('content-type') || '';
		if (/text|javascript|json|xml/i.test(contentType)) {
			const body = (await response.text()).replaceAll(upstream.host, url.host);
			const responseHeaders = new Headers(response.headers);
			responseHeaders.set('Cache-Control', 'no-store');
			return new Response(body, { status: response.status, headers: responseHeaders });
		}
		return response;
	} catch (error) {
		return htmlResponse(fakeNginxPage());
	}
}

function fakeNginxPage() {
	return `<!doctype html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`;
}

function fakeCloudflare1101(host, request) {
	const ray = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
	const ip = request.headers.get('CF-Connecting-IP') || 'hidden';
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Worker threw exception | ${escapeHTML(host)} | Cloudflare</title><style>body{font-family:Arial,sans-serif;margin:0;color:#313131}.wrap{max-width:900px;margin:70px auto;padding:0 24px}h1{font-size:44px;margin:0 0 10px}.code{color:#d03d2d}.cols{display:grid;grid-template-columns:1fr 1fr;gap:32px;margin-top:36px}.foot{border-top:1px solid #ddd;margin-top:44px;padding-top:18px;color:#666;font-size:13px}@media(max-width:720px){.cols{grid-template-columns:1fr}}</style></head><body><main class="wrap"><h1>Error <span class="code">1101</span></h1><p>Worker threw exception</p><div class="cols"><section><h2>What happened?</h2><p>You've requested a page on a website (${escapeHTML(host)}) that is on the Cloudflare network. An unknown error occurred while rendering the page.</p></section><section><h2>What can I do?</h2><p>If you are the owner of this website, check Workers logs for ${escapeHTML(host)}.</p></section></div><p class="foot">Cloudflare Ray ID: <strong>${ray}</strong> · Your IP: ${escapeHTML(ip)} · Performance &amp; security by Cloudflare</p></main></body></html>`;
}

// ─── WebSocket Transport ──────────────────────────────────────────────────────

function isValidWSEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && matchUUIDBytes(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;
	const hash = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== hash.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWSEarlyData(header, token) {
	if (!header) return null;
	if (header.length > WS_EARLY_DATA_MAX_HEAD) throw new Error('Early data is too large');
	let bytes;
	const Uint8ArrayAny = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayAny.fromBase64 === 'function') {
		try { bytes = Uint8ArrayAny.fromBase64(header, { alphabet: 'base64url' }); } catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try { binaryString = atob(normalized); } catch (_) { return null; }
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}
	if (bytes.byteLength > WS_EARLY_DATA_MAX_BYTES) throw new Error('Early data is too large');
	return isValidWSEarlyData(bytes, token) ? bytes : null;
}

async function handleWS(request, yourUUID, url) {
	const pair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(pair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }); }
	catch (_) { serverSock.accept(); }
	serverSock.binaryType = 'arraybuffer';

	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUDPCtx = { cache: new Uint8Array(0) };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	let upstreamQueue = null;
	let explicitChain = Promise.resolve();
	let stopReceiving = false, chainFailed = false, finalizerQueued = false;
	let chainQueuedBytes = 0, chainQueuedItems = 0;
	let currentWriteSocket = null, remoteWriter = null;

	const releaseRemoteWriter = () => {
		if (remoteWriter) { try { remoteWriter.releaseLock(); } catch (e) { } remoteWriter = null; }
		currentWriteSocket = null;
	};

	const queue = upstreamQueue = createUpstreamQueue({
		getWriter: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		},
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConn: () => {
			try { remoteConnWrapper.socket?.close(); } catch (e) { }
			closeSocketQuietly(serverSock);
		},
		name: 'WS-upstream'
	});

	const writeToRemote = async (chunk, allowRetry = true) => queue.writeAndWait(chunk, allowRetry);

	const handleInbound = async (chunk) => {
		if (isDnsQuery) {
			if (isTrojan) return forwardTrojanUDP(chunk, serverSock, trojanUDPCtx, request);
			return forwardUDP(chunk, serverSock, null, request);
		}
		if (await writeToRemote(chunk)) return;

		if (isTrojan === null) {
			const bytes = toUint8Array(chunk);
			isTrojan = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
			log(`[WS] Protocol: ${isTrojan ? 'Trojan' : 'VLESS'} | Host: ${url.host}`);
		}

		if (isTrojan) {
			const result = parseTrojanRequest(chunk, yourUUID);
			if (result?.hasError) throw new Error(result.message || 'Invalid Trojan request');
			const { port, hostname, rawClientData, isUDP } = result;
			if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
			if (isUDP) {
				isDnsQuery = true;
				if (validDataLength(rawClientData) > 0) return forwardTrojanUDP(rawClientData, serverSock, trojanUDPCtx, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request);
		} else {
			const bytes = toUint8Array(chunk);
			const result = parseVLESSRequest(bytes, yourUUID);
			if (result?.hasError) throw new Error(result.message || 'Invalid VLESS request');
			const { port, hostname, version, isUDP, rawClientData } = result;
			if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const respHeader = new Uint8Array([version, 0]);
			if (isDnsQuery) return forwardUDP(rawClientData, serverSock, respHeader, request);
			await forwardataTCP(hostname, port, rawClientData, serverSock, respHeader, remoteConnWrapper, yourUUID, request);
		}
	};

	const handleChainError = (err) => {
		if (chainFailed) return;
		chainFailed = true;
		stopReceiving = true;
		chainQueuedBytes = 0;
		chainQueuedItems = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS] Connection ended: ${msg}`);
		} else {
			log(`[WS] Processing failed: ${msg}`);
		}
		queue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
	};

	const enqueueTask = (task) => {
		explicitChain = explicitChain.then(task).catch(handleChainError);
		return explicitChain;
	};

	const enqueueInbound = (data) => {
		if (stopReceiving || chainFailed) return;
		const size = Math.max(0, validDataLength(data));
		const nextBytes = chainQueuedBytes + size;
		const nextItems = chainQueuedItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleChainError(new Error(`WS queue overflow: ${nextBytes}B/${nextItems}`));
			return;
		}
		chainQueuedBytes = nextBytes;
		chainQueuedItems = nextItems;
		enqueueTask(async () => {
			chainQueuedBytes = Math.max(0, chainQueuedBytes - size);
			chainQueuedItems = Math.max(0, chainQueuedItems - 1);
			if (chainFailed) return;
			await handleInbound(data);
		});
	};

	const finalizeInbound = () => {
		if (finalizerQueued) return;
		finalizerQueued = true;
		stopReceiving = true;
		enqueueTask(async () => {
			if (chainFailed) return;
			await queue.waitIdle();
			releaseRemoteWriter();
		});
	};

	serverSock.addEventListener('message', (event) => { enqueueInbound(event.data); });
	serverSock.addEventListener('close', () => { closeSocketQuietly(serverSock); finalizeInbound(); });
	serverSock.addEventListener('error', (err) => { handleChainError(err); });

	if (earlyDataHeader) {
		try {
			const bytes = decodeWSEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueInbound(bytes.buffer);
		} catch (error) {
			handleChainError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

// ─── Trojan Protocol ─────────────────────────────────────────────────────────

const trojanDecoder = new TextDecoder();

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = toUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: 'invalid data' };
	if (data[56] !== 0x0d || data[57] !== 0x0a) return { hasError: true, message: 'invalid header format' };
	for (let i = 0; i < 56; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: 'invalid password' };
	}
	const socks5Start = 58;
	if (data.byteLength < socks5Start + 6) return { hasError: true, message: 'invalid S5 request data' };
	const cmd = data[socks5Start];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: 'unsupported command, only TCP/UDP' };
	const isUDP = cmd === 3;
	const atype = data[socks5Start + 1];
	let addressLength = 0, addressIndex = socks5Start + 2, address = '';
	switch (atype) {
		case 1:
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid IPv4 data' };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3:
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: 'invalid domain data' };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid domain data' };
			address = trojanDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4:
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: 'invalid IPv6 data' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) ipv6.push(((data[addressIndex + i * 2] << 8) | data[addressIndex + i * 2 + 1]).toString(16));
			address = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `invalid addressType: ${atype}` };
	}
	if (!address) return { hasError: true, message: `empty address, atype=${atype}` };
	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: 'invalid port data' };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];
	return { hasError: false, addressType: atype, port: portRemote, hostname: address, isUDP, rawClientData: data.subarray(portIndex + 4) };
}

// ─── VLESS Protocol ──────────────────────────────────────────────────────────

const uuidByteCache = new Map();
const vlessDecoder = new TextDecoder();

function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getUUIDBytes(uuid) {
	const key = String(uuid || '');
	let cached = uuidByteCache.get(key);
	if (cached) return cached;
	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;
	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}
	if (uuidByteCache.size >= 32) uuidByteCache.clear();
	uuidByteCache.set(key, bytes);
	return bytes;
}

function matchUUIDBytes(data, offset, uuid) {
	const expected = getUUIDBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) { if (data[offset + i] !== expected[i]) return false; }
	return true;
}

function parseVLESSRequest(chunk, token) {
	const data = toUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!matchUUIDBytes(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };
	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };
	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) ipv6.push(((data[addrValIdx + i * 2] << 8) | data[addrValIdx + i * 2 + 1]).toString(16));
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

// ─── Data Utilities ───────────────────────────────────────────────────────────

function toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatUint8Arrays(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(toUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength; }
	return result;
}

function validDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

// ─── Trojan UDP / DNS Forwarding ──────────────────────────────────────────────

async function forwardTrojanUDP(chunk, webSocket, ctx, request) {
	const current = toUint8Array(chunk);
	const cached = ctx?.cache instanceof Uint8Array ? ctx.cache : new Uint8Array(0);
	const input = cached.byteLength ? concatUint8Arrays(cached, current) : current;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1, addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;
		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');
		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addrPortHead = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNSQuery = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNSQuery = new Uint8Array(payload.byteLength + 2);
			tcpDNSQuery[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNSQuery[1] = payload.byteLength & 0xff;
			tcpDNSQuery.set(payload, 2);
		}

		const dnsRespCtx = { cache: new Uint8Array(0) };
		await forwardUDP(tcpDNSQuery, webSocket, null, request, (dnsRespChunk) => {
			const respChunk = toUint8Array(dnsRespChunk);
			const respInput = dnsRespCtx.cache.byteLength ? concatUint8Arrays(dnsRespCtx.cache, respChunk) : respChunk;
			const frames = [];
			let rc = 0;
			while (rc + 2 <= respInput.byteLength) {
				const dnsLen = (respInput[rc] << 8) | respInput[rc + 1];
				const dnsStart = rc + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > respInput.byteLength) break;
				const dnsPayload = respInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addrPortHead.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addrPortHead, 0);
				frame[addrPortHead.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addrPortHead.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addrPortHead.byteLength + 2] = 0x0d;
				frame[addrPortHead.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addrPortHead.byteLength + 4);
				frames.push(frame);
				rc = dnsEnd;
			}
			dnsRespCtx.cache = respInput.slice(rc);
			return frames.length ? frames : new Uint8Array(0);
		});
	}

	if (ctx) ctx.cache = input.slice(cursor);
}

// ─── TCP Forwarding ───────────────────────────────────────────────────────────

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null) {
	log(`[TCP] Target: ${host}:${portNum} | ProxyIP: ${proxyIP} | Fallback: ${proxyFallback}`);
	const CONNECTION_TIMEOUT = 1000;
	let proxySentFirstPacket = false;
	const makeTCPConn = createTCPConnector(request);

	async function waitForOpen(sock, timeoutMs = CONNECTION_TIMEOUT) {
		await Promise.race([
			sock.opened,
			new Promise((_, rej) => setTimeout(() => rej(new Error('Connection timeout')), timeoutMs))
		]);
	}

	async function openTCP(address, port) {
		const sock = makeTCPConn({ hostname: address, port });
		try { await waitForOpen(sock); return sock; }
		catch (err) { try { sock?.close?.(); } catch (e) { } throw err; }
	}

	async function writeFirstPacket(sock, data) {
		if (validDataLength(data) <= 0) return;
		const writer = sock.writable.getWriter();
		try { await writer.write(toUint8Array(data)); }
		finally { try { writer.releaseLock(); } catch (e) { } }
	}

	async function connectRacing(candidates) {
		if (candidates.length === 1) {
			const c = candidates[0];
			return { socket: await openTCP(c.hostname, c.port), candidate: c };
		}
		const attempts = candidates.map(c => openTCP(c.hostname, c.port).then(socket => ({ socket, candidate: c })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const p of attempts) {
					p.then(({ socket }) => {
						if (socket !== winner.socket) try { socket?.close?.(); } catch (e) { }
					}).catch(() => { });
				}
			}
		}
	}

	async function buildPreloadCandidates(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, 'A'), dohQuery(address, 'AAAA')]);
		const ipv4List = [...new Set(aRecords.flatMap(r => r.type === 1 && typeof r.data === 'string' && isIPv4(r.data) ? [r.data] : []))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => r.type === 28 && typeof r.data === 'string' ? [r.data] : []))];
		const limit = Math.max(1, tcpRaceDial | 0);
		const ipList = ipv4List.length >= limit ? ipv4List.slice(0, limit) : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
		if (ipList.length === 0) return null;
		return ipList.map((hostname, i) => ({ hostname, port, attempt: i, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, tryPreload = false) {
		const preloadCandidates = tryPreload ? await buildPreloadCandidates(address, port) : null;
		const candidates = preloadCandidates || Array.from({ length: tcpRaceDial }, (_, i) => ({ hostname: address, port, attempt: i }));
		let socket = null;
		try {
			const result = await connectRacing(candidates);
			socket = result.socket;
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.(); } catch (e) { }
			throw err;
		}
	}

	async function connectViaProxyIP(address, port, data = null, allProxies = null, fallback = true) {
		if (allProxies && allProxies.length > 0) {
			for (let i = 0; i < allProxies.length; i += tcpRaceDial) {
				const candidates = [];
				for (let j = 0; j < tcpRaceDial && i + j < allProxies.length; j++) {
					const idx = (proxyAddressIndex + i + j) % allProxies.length;
					const [pAddr, pPort] = allProxies[idx];
					candidates.push({ hostname: pAddr, port: pPort, index: idx });
				}
				let socket = null, candidate = null;
				try {
					const result = await connectRacing(candidates);
					socket = result.socket;
					candidate = result.candidate;
					await writeFirstPacket(socket, data);
					proxyAddressIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.(); } catch (e) { }
					log(`[ProxyIP] Batch failed: ${err.message || err}`);
				}
			}
		}
		if (fallback) return connectDirect(address, port, data, false);
		closeSocketQuietly(ws);
		throw new Error('All proxy connections failed and fallback is disabled.');
	}

	async function connectThroughProxy(sendFirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) { await remoteConnWrapper.connectingPromise; return; }
		const doSendFirstPacket = sendFirstPacket && !proxySentFirstPacket && validDataLength(rawData) > 0;
		const firstPacketData = doSendFirstPacket ? rawData : null;
		const task = (async () => {
			if (!proxyIP) throw new Error('Direct connection failed and PROXYIP is not configured.');
			log(`[ProxyIP] Connecting to: ${host}:${portNum}`);
			const allProxies = await resolveProxyAddresses(proxyIP, host, yourUUID);
			const newSocket = await connectViaProxyIP(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, firstPacketData, allProxies, proxyFallback);
			if (doSendFirstPacket) proxySentFirstPacket = true;
			remoteConnWrapper.socket = newSocket;
			newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
			connectStreams(newSocket, ws, respHeader, null);
		})();
		remoteConnWrapper.connectingPromise = task;
		try { await task; }
		finally { if (remoteConnWrapper.connectingPromise === task) remoteConnWrapper.connectingPromise = null; }
	}

	remoteConnWrapper.retryConnect = async () => connectThroughProxy(!proxySentFirstPacket);

	try {
		log(`[TCP] Trying direct to: ${host}:${portNum}`);
		const initialSocket = await connectDirect(host, portNum, rawData, true);
		remoteConnWrapper.socket = initialSocket;
		connectStreams(initialSocket, ws, respHeader, async () => {
			if (remoteConnWrapper.socket !== initialSocket) return;
			await connectThroughProxy();
		});
	} catch (err) {
		log(`[TCP] Direct failed: ${err.message}`);
		await connectThroughProxy();
	}
}

// ─── UDP / DNS Forwarding ─────────────────────────────────────────────────────

async function forwardUDP(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const reqData = toUint8Array(udpChunk);
	log(`[UDP] DNS query: ${reqData.byteLength}B -> 8.8.4.4:53`);
	try {
		const makeTCPConn = createTCPConnector(request);
		const tcpSocket = makeTCPConn({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(reqData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const raw = toUint8Array(chunk);
				const wrapped = responseWrapper ? await responseWrapper(raw) : raw;
				const fragments = Array.isArray(wrapped) ? wrapped : [wrapped];
				if (!fragments.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of fragments) {
					const data = toUint8Array(fragment);
					if (!data.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + data.byteLength);
						response.set(vlessHeader, 0);
						response.set(data, vlessHeader.length);
						await wsSendAndWait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await wsSendAndWait(webSocket, data);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP] DNS forward failed: ${error?.message || error}`);
	}
}

// ─── Stream / Socket Utilities ────────────────────────────────────────────────

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) socket.close();
	} catch (error) { }
}

async function wsSendAndWait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConn, name = 'upstream' }) {
	let chunks = [], head = 0, queuedBytes = 0, draining = false, closed = false;
	let bundleBuffer = null, idleResolvers = [], activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const c of completions) { if (err) c.reject(err); else c.resolve(); }
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item?.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) { chunks = chunks.slice(head); head = 0; }
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers; idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clearQueue = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) { rejectQueued(closeErr); settleCompletions(activeCompletions, closeErr); activeCompletions = null; }
		chunks = []; head = 0; queuedBytes = 0; resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head]; chunks[head++] = undefined; queuedBytes -= item.chunk.byteLength; compact(); return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET) return first;
		let byteLength = first.chunk.byteLength, end = head, allowRetry = first.allowRetry, completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			if (byteLength + next.chunk.byteLength > UPSTREAM_BUNDLE_TARGET) break;
			byteLength += next.chunk.byteLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head]; chunks[head++] = undefined; queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset); offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try { await writer.write(item.chunk); }
					catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err); throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true; clearQueue(err);
			log(`[${name}] Write failed: ${err?.message || err}`);
			try { closeConn?.(err); } catch (_) { }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clearQueue(err);
			log(`[${name}] Queue overflow, closing`);
			try { closeConn?.(err); } catch (_) { }
			throw err;
		}
		let completionPromise = null, completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		write(data, allowRetry = true) { return enqueue(data, allowRetry, false); },
		writeAndWait(data, allowRetry = true) { return enqueue(data, allowRetry, true); },
		async waitIdle() { if (!queuedBytes && !draining) return; await new Promise(resolve => idleResolvers.push(resolve)); },
		clear() { closed = true; clearQueue(); }
	};
}

function createDownstreamSender(webSocket, headerData = null) {
	const packetCap = DOWNSTREAM_GRAIN_BYTES, tailBytes = DOWNSTREAM_GRAIN_TAIL;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData, pendingBuffer = new Uint8Array(packetCap), pendingBytes = 0;
	let flushTimer = null, microtaskQueued = false, generation = 0, scheduledGeneration = 0, waitRounds = 0, flushPromise = null;

	const sendRaw = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		await wsSendAndWait(webSocket, chunk);
	};
	const attachHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0); merged.set(chunk, header.length); header = null; return merged;
	};
	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null; microtaskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap); pendingBytes = 0; waitRounds = 0;
		flushPromise = sendRaw(output).finally(() => { flushPromise = null; });
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || microtaskQueued) return;
		microtaskQueued = true; scheduledGeneration = generation;
		queueMicrotask(() => {
			microtaskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) { flush().catch(() => closeSocketQuietly(webSocket)); return; }
			flushTimer = setTimeout(() => {
				flushTimer = null;
				if (!pendingBytes) return;
				if (packetCap - pendingBytes < tailBytes) { flush().catch(() => closeSocketQuietly(webSocket)); return; }
				if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
					waitRounds++; scheduledGeneration = generation; scheduleFlush(); return;
				}
				flush().catch(() => closeSocketQuietly(webSocket));
			}, Math.max(DOWNSTREAM_GRAIN_IDLE_MS, 1));
		});
	};
	return {
		async sendDirect(data) {
			let chunk = toUint8Array(data); if (!chunk.byteLength) return;
			chunk = attachHeader(chunk); await sendRaw(chunk);
		},
		async send(data) {
			let chunk = toUint8Array(data); if (!chunk.byteLength) return;
			chunk = attachHeader(chunk);
			let offset = 0; const total = chunk.byteLength;
			while (offset < total) {
				if (!pendingBytes && total - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, total - offset);
					const view = offset || sendBytes !== total ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRaw(view); offset += sendBytes; continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, total - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes; offset += copyBytes; generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let hasData = false, reader, useBYOB = false;
	const BYOB_MAX = 64 * 1024;
	const sender = createDownstreamSender(webSocket, headerData);
	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true; }
	catch (e) { reader = remoteSocket.readable.getReader(); }
	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				await sender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_MAX);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_MAX));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await sender.flush();
					await sender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_MAX);
				} else {
					await sender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_MAX ? value.buffer : new ArrayBuffer(BYOB_MAX);
				}
			}
		}
		await sender.flush();
	} catch (err) { closeSocketQuietly(webSocket); }
	finally { try { reader.cancel(); } catch (e) { } try { reader.releaseLock(); } catch (e) { } }
	if (!hasData && retryFunc) await retryFunc();
}

function isSpeedTestSite(hostname) {
	const blocked = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	return blocked.some(d => hostname === d || hostname.endsWith('.' + d));
}

function createTCPConnector(request) {
	const fetcher = /** @type {any} */ (request)?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try { new URL(`http://[${host}]/`); return true; } catch (e) { return false; }
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

// ─── Utility Functions ────────────────────────────────────────────────────────

function log(...args) {
	if (debugLog) console.log(...args);
}

async function md5md5(text) {
	const encoder = new TextEncoder();
	const hash1 = await crypto.subtle.digest('MD5', encoder.encode(String(text || '')));
	const hex1 = Array.from(new Uint8Array(hash1)).map(b => b.toString(16).padStart(2, '0')).join('');
	const hash2 = await crypto.subtle.digest('MD5', encoder.encode(hex1.slice(7, 27)));
	return Array.from(new Uint8Array(hash2)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function toArray(content) {
	if (content === undefined || content === null) return [];
	if (Array.isArray(content)) return content.map(item => String(item).trim()).filter(Boolean);
	return String(content).split(/[\n,]+/).map(item => item.trim()).filter(Boolean);
}

async function dohQuery(domain, recordType, server = 'https://cloudflare-dns.com/dns-query') {
	const start = performance.now();
	log(`[DoH] Query ${domain} ${recordType}`);
	try {
		const typeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
		const qtype = typeMap[String(recordType || 'A').toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) { const enc = new TextEncoder().encode(label); bufs.push(new Uint8Array([enc.length]), enc); }
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length; }
			return result;
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(server, { method: 'POST', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: query });
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4), ancount = dv.getUint16(6);
		const parseDomain = (pos) => {
			const labels = []; let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break; }
				if ((len & 0xC0) === 0xC0) { if (!jumped) endPos = p + 2; p = ((len & 0x3F) << 8) | buf[p + 1]; jumped = true; continue; }
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len))); p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) { const [, end] = parseDomain(offset); offset = end + 4; }
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDomain(offset); offset = nameEnd;
			const type = dv.getUint16(offset); offset += 2; offset += 2;
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen); offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			else if (type === 28 && rdlen === 16) { const segs = []; for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16)); data = segs.join(':'); }
			else if (type === 16) { let tOff = 0; const parts = []; while (tOff < rdlen) { const tLen = rdata[tOff++]; parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen))); tOff += tLen; } data = parts.join(''); }
			else if (type === 5) { const [cname] = parseDomain(offset - rdlen); data = cname; }
			else data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		log(`[DoH] Done ${domain} ${recordType} in ${(performance.now() - start).toFixed(2)}ms (${answers.length} answers)`);
		return answers;
	} catch (error) {
		console.error(`[DoH] Failed ${domain} ${recordType}:`, error);
		return [];
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4) w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++) x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++) h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) for (let j = 24; j >= 0; j -= 8) hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	return hex;
}

async function resolveProxyAddresses(proxyIPInput, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	if (!proxyIPInput) return [];
	if (!cachedProxyIP || !cachedProxyAddresses || cachedProxyIP !== proxyIPInput) {
		const normalized = proxyIPInput.toLowerCase();
		function parseAddrPort(str) {
			let addr = str, port = 443;
			if (str.includes(']:')) { const parts = str.split(']:'); addr = parts[0] + ']'; port = parseInt(parts[1], 10) || port; }
			else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) { const c = str.lastIndexOf(':'); addr = str.slice(0, c); port = parseInt(str.slice(c + 1), 10) || port; }
			return [addr, port];
		}
		function parseTXTRecords(txtData) {
			return txtData.flatMap(data => {
				if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
				return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
			}).map(prefix => parseAddrPort(prefix));
		}
		const proxyList = await toArray(normalized);
		let allProxies = [];
		const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
		const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
		for (const single of proxyList) {
			let [addr, port] = parseAddrPort(single);
			if (single.includes('.tp')) { const m = single.match(/\.tp(\d+)/); if (m) port = parseInt(m[1], 10); }
			if (ipv4Regex.test(addr) || ipv6Regex.test(addr)) { allProxies.push([addr, port]); continue; }
			const [txtRecords, aRecords] = await Promise.all([dohQuery(addr, 'TXT'), dohQuery(addr, 'A')]);
			const txtAddresses = parseTXTRecords(txtRecords.filter(r => r.type === 16).map(r => r.data));
			if (txtAddresses.length > 0) { allProxies.push(...txtAddresses); continue; }
			const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
			if (ipv4List.length > 0) { allProxies.push(...ipv4List.map(ip => [ip, port])); continue; }
			const aaaaRecords = await dohQuery(addr, 'AAAA');
			const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
			if (ipv6List.length > 0) allProxies.push(...ipv6List.map(ip => [ip, port]));
			else allProxies.push([addr, port]);
		}
		const sorted = allProxies.sort((a, b) => a[0].localeCompare(b[0]));
		const rootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
		let seed = [...(rootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
		const shuffled = [...sorted].sort(() => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
		cachedProxyAddresses = shuffled.slice(0, 8);
		cachedProxyIP = proxyIPInput;
	}
	return cachedProxyAddresses;
}
