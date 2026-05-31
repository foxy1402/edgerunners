const VERSION = '2026-05-31';

// ─── Global mutable state (module-level, shared across requests within an isolate) ───
let config = null;
let proxyType = null;        // 'socks5' | 'http' | null
let proxyGlobal = false;
let proxyAccount = '';
let parsedProxyAddr = {};
let cachedWhitelist = null;
let proxyIP = '';
let cachedProxyIP = null;
let cachedProxyAddrs = null;
let cachedProxyAddrIndex = 0;
let proxyFallback = true;
let debugMode = false;
let socks5Whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];

const WS_EARLY_MAX = 8 * 1024;
const WS_EARLY_MAX_HDR = Math.ceil(WS_EARLY_MAX * 4 / 3) + 4;
const UPLOAD_BUNDLE_TARGET = 16 * 1024;
const UPLOAD_MAX_BYTES = 16 * 1024 * 1024;
const UPLOAD_MAX_ITEMS = 4096;
const DOWNSTREAM_CHUNK = 32 * 1024;
const DOWNSTREAM_TAIL = 512;

// ─────────────────────────── Main Entry ───────────────────────────
export default {
	async fetch(request, env, ctx) {
		let reqURL = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const hashIdx = reqURL.indexOf('#');
		const urlBody = hashIdx === -1 ? reqURL : reqURL.slice(0, hashIdx);
		if (!urlBody.includes('?') && /%3f/i.test(urlBody)) {
			const anchor = hashIdx === -1 ? '' : reqURL.slice(hashIdx);
			reqURL = urlBody.replace(/%3f/i, '?') + anchor;
		}
		const url = new URL(reqURL);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();

		const adminPwd = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const secretKey = env.KEY || 'change-me-please-set-KEY-variable';
		const userIDMD5 = await MD5MD5(adminPwd + secretKey);
		const uuidRe = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRe.test(envUUID))
			? envUUID.toLowerCase()
			: [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');

		const hosts = env.HOST
			? (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0])
			: [url.hostname];
		const host = hosts[0];
		const path = url.pathname.slice(1).toLowerCase();
		const pathRaw = url.pathname.slice(1);

		debugMode = ['1', 'true'].includes(env.DEBUG) || debugMode;

		if (env.PROXYIP) {
			const pips = await normalizeToArray(env.PROXYIP);
			proxyIP = pips[Math.floor(Math.random() * pips.length)];
			proxyFallback = false;
		} else {
			proxyIP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
		}

		const clientIP = request.headers.get('CF-Connecting-IP')
			|| request.headers.get('True-Client-IP')
			|| request.headers.get('X-Real-IP')
			|| request.headers.get('X-Forwarded-For')
			|| 'Unknown';

		if (cachedWhitelist === null) {
			if (env.GO2SOCKS5) socks5Whitelist = [...new Set(socks5Whitelist.concat(await normalizeToArray(env.GO2SOCKS5)))];
			cachedWhitelist = socks5Whitelist;
		} else {
			socks5Whitelist = cachedWhitelist;
		}

		// Version endpoint
		if (path === 'version' && url.searchParams.get('uuid') === userID) {
			return new Response(JSON.stringify({ version: VERSION }), { status: 200, headers: { 'Content-Type': 'application/json' } });
		}

		// WebSocket proxy
		if (adminPwd && upgradeHeader === 'websocket') {
			await parseProxyParams(url, userID);
			log(`[WS] Request: ${url.pathname}${url.search}`);
			return handleWebSocket(request, userID, url);
		}

		// HTTP routes
		if (url.protocol === 'http:') {
			return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
		}
		if (!adminPwd) {
			return new Response(errorPageHTML(
				'Setup Required',
				'The <code>ADMIN</code> environment variable is not set.',
				'Go to <strong>Workers &amp; Pages &#8594; Your Worker &#8594; Settings &#8594; Variables</strong> and add the <code>ADMIN</code> variable with your chosen password.'
			), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
		}

		if (env.KV && typeof env.KV.get === 'function') {
			// Quick subscription via secret key in path
			if (pathRaw === secretKey && secretKey !== 'change-me-please-set-KEY-variable') {
				const params = new URLSearchParams(url.search);
				params.set('token', await MD5MD5(host + userID));
				return new Response('Redirecting...', { status: 302, headers: { Location: `/sub?${params}` } });
			}

			// Login
			if (path === 'login') {
				const cookies = request.headers.get('Cookie') || '';
				const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
				if (authCookie === await MD5MD5(UA + secretKey + adminPwd)) {
					return new Response('Redirecting...', { status: 302, headers: { Location: '/admin' } });
				}
				if (request.method === 'POST') {
					const form = await request.text();
					const pwd = new URLSearchParams(form).get('password');
					if (pwd === (typeof adminPwd === 'string' ? adminPwd.replace(/[\r\n]/g, '') : adminPwd)) {
						const resp = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
						resp.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + secretKey + adminPwd)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`);
						return resp;
					}
				}
				return new Response(loginPageHTML(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
			}

			// Admin panel
			if (path === 'admin' || path.startsWith('admin/')) {
				const cookies = request.headers.get('Cookie') || '';
				const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
				if (!authCookie || authCookie !== await MD5MD5(UA + secretKey + adminPwd)) {
					return new Response('Redirecting...', { status: 302, headers: { Location: '/login' } });
				}

				// Routes that don't need config loaded
				if (pathRaw === 'admin/getADDAPI') {
					if (url.searchParams.get('url')) {
						try {
							new URL(url.searchParams.get('url'));
							const result = await fetchOptimalAPI([url.searchParams.get('url')], url.searchParams.get('port') || '443');
							let ips = result[0].length > 0 ? result[0] : result[1];
							ips = ips.map(i => i.replace(/#(.+)$/, (_, r) => '#' + decodeURIComponent(r)));
							return new Response(JSON.stringify({ success: true, data: ips }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							return new Response(JSON.stringify({ msg: 'Failed to validate API: ' + err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
						}
					}
					return new Response(JSON.stringify({ success: false, data: [] }), { status: 403, headers: { 'Content-Type': 'application/json' } });
				}
				if (path === 'admin/check') {
					const proxyProto = ['socks5', 'http'].find(t => url.searchParams.has(t)) || null;
					if (!proxyProto) {
						return new Response(JSON.stringify({ error: 'Missing proxy parameter (socks5 or http)' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
					}
					const proxyParam = url.searchParams.get(proxyProto);
					const startTime = Date.now();
					let checkResult;
					try {
						parsedProxyAddr = parseProxyAccount(proxyParam, proxyProto === 'http' ? 80 : 1080);
						const { username, password, hostname, port } = parsedProxyAddr;
						const fullProxy = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
						try {
							const tcpConnect = createTCPConnector(request);
							const sock = proxyProto === 'socks5'
								? await socks5Connect('cloudflare.com', 443, new Uint8Array(0), tcpConnect)
								: await httpConnect('cloudflare.com', 443, new Uint8Array(0), false, tcpConnect);
							try { await sock?.close?.(); } catch (e) {}
							checkResult = { success: true, proxy: `${proxyProto}://${fullProxy}`, responseTime: Date.now() - startTime };
						} catch (err) {
							checkResult = { success: false, error: err.message, proxy: `${proxyProto}://${fullProxy}`, responseTime: Date.now() - startTime };
						}
					} catch (err) {
						checkResult = { success: false, error: err.message, proxy: `${proxyProto}://${proxyParam}`, responseTime: Date.now() - startTime };
					}
					return new Response(JSON.stringify(checkResult, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
				}

				// Load config for remaining admin routes
				config = await readConfig(env, host, userID, UA);

				if (path === 'admin/init') {
					try {
						config = await readConfig(env, host, userID, UA, true);
						config.init = 'Config reset to defaults';
						return new Response(JSON.stringify(config, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} catch (err) {
						return new Response(JSON.stringify({ error: 'Reset failed: ' + err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
					}
				}

				if (request.method === 'POST') {
					if (path === 'admin/config.json') {
						try {
							const newConfig = await request.json();
							if (!newConfig.UUID || !newConfig.HOST) {
								return new Response(JSON.stringify({ error: 'Incomplete config: UUID and HOST required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
							}
							await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
							return new Response(JSON.stringify({ success: true, message: 'Config saved' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							return new Response(JSON.stringify({ error: 'Save failed: ' + err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
						}
					}
					if (pathRaw === 'admin/ADD.txt') {
						try {
							await env.KV.put('ADD.txt', await request.text());
							return new Response(JSON.stringify({ success: true, message: 'Custom IPs saved' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							return new Response(JSON.stringify({ error: 'Save failed: ' + err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
						}
					}
					return new Response(JSON.stringify({ error: 'Unsupported POST path' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
				}

				if (path === 'admin/config.json') {
					return new Response(JSON.stringify(config, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
				}
				if (pathRaw === 'admin/ADD.txt') {
					let customIPs = await env.KV.get('ADD.txt') || 'null';
					if (customIPs === 'null') {
						const [ips] = await generateRandomIPs(config['优选订阅生成']['本地IP库']['随机数量'], config['优选订阅生成']['本地IP库']['指定端口']);
						customIPs = ips.join('\n');
					}
					return new Response(customIPs, { status: 200, headers: { 'Content-Type': 'text/plain', 'asn': String(request.cf.asn) } });
				}
				if (path === 'admin/cf.json') {
					return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
				}
			const subToken = await MD5MD5(host + userID);
			return new Response(adminPageHTML(
				config.UUID,
				`${url.protocol}//${url.host}/sub?token=${subToken}`,
				config.PATH || '/',
				config['协议类型'] || 'vless'
			), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
			}

			// Logout clears cookie
			if (path === 'logout' || uuidRe.test(path)) {
				const resp = new Response('Redirecting...', { status: 302, headers: { Location: '/login' } });
				resp.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
				return resp;
			}

			// Subscription
			if (path === 'sub') {
				const subToken = await MD5MD5(host + userID);
				const reqToken = url.searchParams.get('token');
				const isUser = reqToken === subToken;
				const daySeq = Math.floor(Date.now() / 86400000);
				const seed = base64SecretEncode(subToken, userID);
				const [todayToken, yestToken] = await Promise.all([MD5MD5(seed + daySeq), MD5MD5(seed + (daySeq - 1))]);
				const isSubConv = reqToken === todayToken || reqToken === yestToken;

				if (isUser || isSubConv) {
					config = await readConfig(env, host, userID, UA);
					const ua = UA.toLowerCase();
					const respHeaders = {
						'content-type': 'text/plain; charset=utf-8',
						'Profile-Update-Interval': String(config['优选订阅生成'].SUBUpdateTime || 3),
						'Profile-web-page-url': `${url.protocol}//${url.host}/admin`,
						'Cache-Control': 'no-store'
					};
					if (!ua.includes('mozilla')) {
						respHeaders['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(config['优选订阅生成'].SUBNAME)}`;
					}

					const protocol = config['协议类型'];
					const [ipArray, otherLinks, proxyIPPool] = await buildIPList(env, url, config);

					let content = otherLinks + ipArray.map(rawAddr => {
						const re = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
						const m = rawAddr.match(re);
						if (!m) { console.warn(`[sub] Invalid IP format ignored: ${rawAddr}`); return null; }
						const addr = m[1], port = m[2] || '443', remark = m[3] || m[1];
						let nodePath = config['完整节点路径'] || config.PATH || '/';
						if (proxyIPPool.length > 0) {
							const matched = proxyIPPool.find(p => p.includes(addr));
							if (matched) nodePath = (`${config.PATH}/proxyip=${matched}`).replace(/\/\//g, '/');
						}
						if (protocol === 'ss') {
							const tlsPorts = [443, 2053, 2083, 2087, 2096, 8443];
							const noTLSPorts = [80, 2052, 2082, 2086, 2095, 8080];
							const p = config.SS.TLS ? port : String(noTLSPorts[tlsPorts.indexOf(Number(port))] ?? port);
							const np = (nodePath.includes('?')
								? nodePath.replace('?', `?enc=${config.SS['加密方式']}&`)
								: `${nodePath}?enc=${config.SS['加密方式']}`
							).replace(/([=,])/g, '\\$1') + ';mux=0';
							return `ss://${btoa(config.SS['加密方式'] + ':00000000-0000-4000-8000-000000000000')}@${addr}:${p}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=example.com;path=${np}${config.SS.TLS ? ';tls' : ''}`)}#${encodeURIComponent(remark)}`;
						} else {
							return `${protocol}://00000000-0000-4000-8000-000000000000@${addr}:${port}?security=tls&type=ws&host=example.com&fp=${config.Fingerprint}&sni=example.com&path=${encodeURIComponent(nodePath)}&encryption=none${config['跳过证书验证'] ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(remark)}`;
						}
					}).filter(Boolean).join('\n');

					// Replace placeholders with real values for user requests
					if (!ua.includes('subconverter') && isUser) {
						const shuffled = [...config.HOSTS].sort(() => Math.random() - 0.5);
						let dc = 0, ch = null;
						content = content
							.replace(/00000000-0000-4000-8000-000000000000/g, config.UUID)
							.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config.UUID))
							.replace(/example\.com/g, () => {
								if (dc % 2 === 0) { const h = shuffled[Math.floor(dc / 2) % shuffled.length]; ch = h.replace(/\*/g, () => Math.random().toString(36).slice(2, 6)); }
								dc++;
								return ch;
							});
					}

					if (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64')) content = btoa(content);
					return new Response(content, { status: 200, headers: respHeaders });
				}
			}

			if (path === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });

		} else if (!envUUID) {
			return new Response(errorPageHTML(
				'KV Not Bound',
				'No KV namespace is bound to this Worker.',
				'Go to <strong>Workers &amp; Pages &#8594; Your Worker &#8594; Settings &#8594; Bindings</strong>, click <strong>Add</strong>, choose <strong>KV Namespace</strong>, and set the variable name to <code>KV</code>.'
			), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
		}

		// Camouflage / disguise page
		let disguise = env.URL || 'nginx';
		if (disguise && disguise !== 'nginx' && disguise !== '1101') {
			disguise = disguise.trim().replace(/\/$/, '');
			if (!disguise.match(/^https?:\/\//i)) disguise = 'https://' + disguise;
			if (disguise.toLowerCase().startsWith('http://')) disguise = 'https://' + disguise.slice(7);
			try { disguise = new URL(disguise).origin; } catch (e) { disguise = 'nginx'; }
		}
		if (disguise === '1101') return new Response(cloudflareErrorPage(url.host, clientIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const target = new URL(disguise), newHeaders = new Headers(request.headers);
			newHeaders.set('Host', target.host);
			newHeaders.set('Referer', target.origin);
			newHeaders.set('Origin', target.origin);
			if (!newHeaders.has('User-Agent') && UA && UA !== 'null') newHeaders.set('User-Agent', UA);
			const resp = await fetch(target.origin + url.pathname + url.search, { method: request.method, headers: newHeaders, body: request.body, cf: request.cf });
			const ct = resp.headers.get('content-type') || '';
			if (/text|javascript|json|xml/.test(ct)) {
				const text = (await resp.text()).replaceAll(target.host, url.host);
				return new Response(text, { status: resp.status, headers: { ...Object.fromEntries(resp.headers), 'Cache-Control': 'no-store' } });
			}
			return resp;
		} catch (e) {}
		return new Response(nginxPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};

// ─────────────────────────── WebSocket Handler ───────────────────────────
async function handleWebSocket(request, userID, url) {
	const pair = new WebSocketPair();
	const [client, server] = Object.values(pair);
	try { (/** @type {any} */(server)).accept({ allowHalfOpen: true }); } catch (_) { server.accept(); }
	server.binaryType = 'arraybuffer';

	let remoteConn = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUDPCtx = { buffer: new Uint8Array(0) };
	const earlyHeader = request.headers.get('sec-websocket-protocol') || '';
	const ssNoEarlyData = !!url.searchParams.get('enc');
	let uploadQueue = null;
	let explicitChain = Promise.resolve();
	let explicitStop = false, explicitFailed = false, explicitFlushed = false;
	let explicitBytes = 0, explicitItems = 0;
	let protocolType = null, currentWriteSocket = null, remoteWriter = null;
	let ssCtx = null, ssInitTask = null;

	const releaseRemoteWriter = () => {
		if (remoteWriter) { try { remoteWriter.releaseLock(); } catch (e) {} remoteWriter = null; }
		currentWriteSocket = null;
	};

	uploadQueue = createUploadQueue({
		getWriter: () => {
			const sock = remoteConn.socket;
			if (!sock) return null;
			if (sock !== currentWriteSocket) { releaseRemoteWriter(); currentWriteSocket = sock; remoteWriter = sock.writable.getWriter(); }
			return remoteWriter;
		},
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConn.retryConnect !== 'function') throw new Error('Retry unavailable');
			await remoteConn.retryConnect();
		},
		closeConn: () => { try { remoteConn.socket?.close(); } catch (e) {} closeSocket(server); },
		name: 'WS-upload'
	});

	const writeRemote = (data, allowRetry = true) => uploadQueue.writeAndWait(data, allowRetry);

	const getSSCtx = async () => {
		if (ssCtx) return ssCtx;
		if (!ssInitTask) {
			ssInitTask = (async () => {
				const reqCipher = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredCfg = SS_CIPHERS[reqCipher] || SS_CIPHERS['aes-128-gcm'];
				const candidates = [preferredCfg, ...Object.values(SS_CIPHERS).filter(c => c.method !== preferredCfg.method)];
				const mkCache = new Map();
				const getMK = (cfg) => { if (!mkCache.has(cfg.method)) mkCache.set(cfg.method, deriveMasterKey(userID, cfg.keyLen)); return mkCache.get(cfg.method); };
				const inState = { buffer: new Uint8Array(0), hasSalt: false, waitLen: null, decryptKey: null, nonce: new Uint8Array(SS_NONCE_LEN), cipher: null };
				const initDecrypt = async () => {
					const lct = 2 + SS_TAG_LEN;
					const maxSalt = Math.max(...candidates.map(c => c.saltLen));
					const maxScan = Math.min(16, Math.max(0, inState.buffer.byteLength - (lct + Math.min(...candidates.map(c => c.saltLen)))));
					for (let off = 0; off <= maxScan; off++) {
						for (const cfg of candidates) {
							const minLen = off + cfg.saltLen + lct;
							if (inState.buffer.byteLength < minLen) continue;
							const salt = inState.buffer.subarray(off, off + cfg.saltLen);
							const lc = inState.buffer.subarray(off + cfg.saltLen, minLen);
							const mk = await getMK(cfg);
							const dk = await deriveSessionKey(cfg, mk, salt, ['decrypt']);
							const nc = new Uint8Array(SS_NONCE_LEN);
							try {
								const lp = await ssAEADDecrypt(dk, nc, lc);
								if (lp.byteLength !== 2) continue;
								const pl = (lp[0] << 8) | lp[1];
								if (pl < 0 || pl > cfg.maxChunk) continue;
								if (off > 0) log(`[SS] Leading noise ${off}B, aligned`);
								if (cfg.method !== preferredCfg.method) log(`[SS] enc=${reqCipher} mismatch, switched to ${cfg.method}`);
								inState.buffer = inState.buffer.subarray(minLen);
								inState.decryptKey = dk; inState.nonce = nc; inState.waitLen = pl; inState.cipher = cfg; inState.hasSalt = true;
								return true;
							} catch (_) {}
						}
					}
					if (inState.buffer.byteLength >= maxSalt + lct + 16) throw new Error(`SS handshake failed (enc=${reqCipher || 'auto'})`);
					return false;
				};
				const inDecryptor = {
					async feed(chunk) {
						const c = toBytes(chunk);
						if (c.byteLength > 0) inState.buffer = concatBytes(inState.buffer, c);
						if (!inState.hasSalt) { if (!await initDecrypt()) return []; }
						const plain = [];
						while (true) {
							if (inState.waitLen === null) {
								const lct = 2 + SS_TAG_LEN;
								if (inState.buffer.byteLength < lct) break;
								const lc = inState.buffer.subarray(0, lct);
								inState.buffer = inState.buffer.subarray(lct);
								const lp = await ssAEADDecrypt(inState.decryptKey, inState.nonce, lc);
								if (lp.byteLength !== 2) throw new Error('SS length decrypt failed');
								inState.waitLen = (lp[0] << 8) | lp[1];
							}
							const pct = inState.waitLen + SS_TAG_LEN;
							if (inState.buffer.byteLength < pct) break;
							const pc = inState.buffer.subarray(0, pct);
							inState.buffer = inState.buffer.subarray(pct);
							plain.push(await ssAEADDecrypt(inState.decryptKey, inState.nonce, pc));
							inState.waitLen = null;
						}
						return plain;
					}
				};
				let outEncryptor = null;
				const MAX_BATCH = 32 * 1024;
				const getOutEnc = async () => {
					if (outEncryptor) return outEncryptor;
					if (!inState.cipher) throw new Error('SS cipher not negotiated');
					const oc = inState.cipher;
					const omk = await deriveMasterKey(userID, oc.keyLen);
					const salt = crypto.getRandomValues(new Uint8Array(oc.saltLen));
					const ek = await deriveSessionKey(oc, omk, salt, ['encrypt']);
					const enc = new Uint8Array(SS_NONCE_LEN);
					let saltSent = false;
					outEncryptor = {
						async encryptSend(chunk, sendFn) {
							const pt = toBytes(chunk);
							if (!saltSent) { await sendFn(salt); saltSent = true; }
							if (!pt.byteLength) return;
							let off = 0;
							while (off < pt.byteLength) {
								const end = Math.min(off + oc.maxChunk, pt.byteLength);
								const payload = pt.subarray(off, end);
								const lp = new Uint8Array(2); lp[0] = (payload.byteLength >> 8) & 0xff; lp[1] = payload.byteLength & 0xff;
								const lc = await ssAEADEncrypt(ek, enc, lp);
								const pc = await ssAEADEncrypt(ek, enc, payload);
								const frame = new Uint8Array(lc.byteLength + pc.byteLength);
								frame.set(lc, 0); frame.set(pc, lc.byteLength);
								await sendFn(frame);
								off = end;
							}
						}
					};
					return outEncryptor;
				};
				let sendQ = Promise.resolve();
				const ssEnqueue = (chunk) => {
					sendQ = sendQ.then(async () => {
						if (server.readyState !== WebSocket.OPEN) return;
						const enc = await getOutEnc();
						await enc.encryptSend(chunk, async (ec) => {
							if (ec.byteLength > 0 && server.readyState === WebSocket.OPEN) await wsSend(server, ec.buffer);
						});
					}).catch(err => { log(`[SS send] Encrypt failed: ${err?.message}`); closeSocket(server); });
					return sendQ;
				};
				const ssReturnSocket = {
					get readyState() { return server.readyState; },
					send(data) {
						const c = toBytes(data);
						if (c.byteLength <= MAX_BATCH) return ssEnqueue(c);
						for (let i = 0; i < c.byteLength; i += MAX_BATCH) ssEnqueue(c.subarray(i, Math.min(i + MAX_BATCH, c.byteLength)));
						return sendQ;
					},
					close() { closeSocket(server); }
				};
				ssCtx = { decryptor: inDecryptor, returnSocket: ssReturnSocket, headerSent: false, targetHost: '', targetPort: 0 };
				return ssCtx;
			})().finally(() => { ssInitTask = null; });
		}
		return ssInitTask;
	};

	const handleSSData = async (chunk) => {
		const ctx = await getSSCtx();
		let plains;
		try { plains = await ctx.decryptor.feed(chunk); } catch (err) {
			const msg = err?.message || `${err}`;
			if (/Decryption failed|SS handshake failed|SS length decrypt failed/.test(msg)) { log(`[SS] Decrypt failed: ${msg}`); closeSocket(server); return; }
			throw err;
		}
		for (const plain of plains) {
			let written = false;
			try { written = await writeRemote(plain, false); } catch (e) { if ((/** @type {any} */(e))?.isQueueOverflow) throw e; }
			if (written) continue;
			if (ctx.headerSent && ctx.targetHost && ctx.targetPort > 0) {
				await forwardTCP(ctx.targetHost, ctx.targetPort, plain, ctx.returnSocket, null, remoteConn, userID, request);
				continue;
			}
			const data = toBytes(plain);
			if (data.byteLength < 3) throw new Error('Invalid SS data');
			const atype = data[0]; let cur = 1, hostname = '';
			if (atype === 1) { if (data.byteLength < cur + 6) throw new Error('Invalid SS IPv4'); hostname = `${data[cur]}.${data[cur+1]}.${data[cur+2]}.${data[cur+3]}`; cur += 4; }
			else if (atype === 3) { const dl = data[cur++]; hostname = ssTextDecoder.decode(data.subarray(cur, cur + dl)); cur += dl; }
			else if (atype === 4) { const ipv6 = []; const dv = new DataView(data.buffer, data.byteOffset + cur, 16); for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16)); hostname = ipv6.join(':'); cur += 16; }
			else throw new Error(`Invalid SS atype: ${atype}`);
			if (!hostname) throw new Error(`Empty SS hostname: ${atype}`);
			const port = (data[cur] << 8) | data[cur + 1]; cur += 2;
			ctx.headerSent = true; ctx.targetHost = hostname; ctx.targetPort = port;
			await forwardTCP(hostname, port, data.subarray(cur), ctx.returnSocket, null, remoteConn, userID, request);
		}
	};

	const handleInbound = async (chunk) => {
		let bytes = null;
		if (isDnsQuery) {
			if (isTrojan) return forwardTrojanUDP(chunk, server, trojanUDPCtx, request);
			return forwardDNS(chunk, server, null, request);
		}
		if (protocolType === 'ss') { await handleSSData(chunk); return; }
		if (await writeRemote(chunk)) return;
		if (protocolType === null) {
			if (url.searchParams.get('enc')) protocolType = 'ss';
			else {
				bytes = toBytes(chunk);
				protocolType = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
			}
			isTrojan = protocolType === 'trojan';
			log(`[WS] Protocol: ${protocolType}`);
		}
		if (protocolType === 'ss') { await handleSSData(chunk); return; }
		if (await writeRemote(chunk)) return;
		if (protocolType === 'trojan') {
			const res = parseTrojanRequest(chunk, userID);
			if (res?.hasError) throw new Error(res.message || 'Invalid Trojan request');
			const { port, hostname, rawClientData, isUDP } = res;
			if (isUDP) { isDnsQuery = true; if (dataLen(rawClientData) > 0) return forwardTrojanUDP(rawClientData, server, trojanUDPCtx, request); return; }
			await forwardTCP(hostname, port, rawClientData, server, null, remoteConn, userID, request);
		} else {
			isTrojan = false;
			bytes = bytes || toBytes(chunk);
			const res = parseVlessRequest(bytes, userID);
			if (res?.hasError) throw new Error(res.message || 'Invalid VLESS request');
			const { port, hostname, version, isUDP, rawClientData } = res;
			if (isUDP) { if (port === 53) isDnsQuery = true; else throw new Error('UDP not supported'); }
			const respHdr = new Uint8Array([version, 0]);
			if (isDnsQuery) return forwardDNS(rawClientData, server, respHdr, request);
			await forwardTCP(hostname, port, rawClientData, server, respHdr, remoteConn, userID, request);
		}
	};

	const handleError = (err) => {
		if (explicitFailed) return;
		explicitFailed = true; explicitStop = true; explicitBytes = 0; explicitItems = 0;
		const msg = err?.message || `${err}`;
		if (/Network connection lost|ReadableStream is closed/.test(msg)) log(`[WS] Connection ended: ${msg}`);
		else log(`[WS] Error: ${msg}`);
		uploadQueue.clear(); releaseRemoteWriter(); closeSocket(server);
	};

	const enqueue = (data) => {
		if (explicitStop || explicitFailed) return;
		const cs = Math.max(0, dataLen(data));
		if (explicitBytes + cs > UPLOAD_MAX_BYTES || explicitItems + 1 > UPLOAD_MAX_ITEMS) { handleError(new Error(`WS queue overflow`)); return; }
		explicitBytes += cs; explicitItems++;
		explicitChain = explicitChain.then(async () => {
			explicitBytes = Math.max(0, explicitBytes - cs);
			explicitItems = Math.max(0, explicitItems - 1);
			if (explicitFailed) return;
			await handleInbound(data);
		}).catch(handleError);
	};

	const finish = () => {
		if (explicitFlushed) return; explicitFlushed = true;
		explicitChain = explicitChain.then(async () => { await uploadQueue.waitEmpty(); }).catch(handleError);
	};

	// Process WS early data
	let earlyDataBytes = null;
	if (earlyHeader && !ssNoEarlyData) { try { earlyDataBytes = decodeEarlyData(earlyHeader, userID); } catch (e) {} }

	server.addEventListener('message', (event) => { enqueue(event.data); });
	server.addEventListener('close', () => { finish(); uploadQueue.clear(); releaseRemoteWriter(); try { remoteConn.socket?.close(); } catch (e) {} });
	server.addEventListener('error', () => { closeSocket(server); });

	if (earlyDataBytes) enqueue(earlyDataBytes);
	return new Response(null, { status: 101, webSocket: client });
}

// ─────────────────────────── Protocol Parsers ───────────────────────────
const trojanTextDecoder = new TextDecoder();

function parseTrojanRequest(buffer, password) {
	const data = toBytes(buffer);
	const hash = sha224(password);
	if (data.byteLength < 58) return { hasError: true, message: 'Invalid data' };
	if (data[56] !== 0x0d || data[57] !== 0x0a) return { hasError: true, message: 'Invalid header format' };
	for (let i = 0; i < 56; i++) { if (data[i] !== hash.charCodeAt(i)) return { hasError: true, message: 'Invalid password' }; }
	const s5 = 58;
	if (data.byteLength < s5 + 6) return { hasError: true, message: 'Invalid S5 data' };
	const cmd = data[s5];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: 'Unsupported command' };
	const isUDP = cmd === 3;
	const atype = data[s5 + 1];
	let ai = s5 + 2, al = 0, address = '';
	switch (atype) {
		case 1: al = 4; if (data.byteLength < ai + al + 4) return { hasError: true, message: 'Invalid IPv4' }; address = `${data[ai]}.${data[ai+1]}.${data[ai+2]}.${data[ai+3]}`; break;
		case 3: al = data[ai]; ai++; if (data.byteLength < ai + al + 4) return { hasError: true, message: 'Invalid domain' }; address = trojanTextDecoder.decode(data.subarray(ai, ai + al)); break;
		case 4: al = 16; if (data.byteLength < ai + al + 4) return { hasError: true, message: 'Invalid IPv6' }; { const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(((data[ai + i * 2] << 8) | data[ai + i * 2 + 1]).toString(16)); address = ipv6.join(':'); } break;
		default: return { hasError: true, message: `Invalid atype: ${atype}` };
	}
	if (!address) return { hasError: true, message: `Empty address: ${atype}` };
	const pi = ai + al;
	if (data.byteLength < pi + 4) return { hasError: true, message: 'Invalid S5 data' };
	return { hasError: false, addressType: atype, port: (data[pi] << 8) | data[pi + 1], hostname: address, isUDP, rawClientData: data.subarray(pi + 4) };
}

const uuidByteCache = new Map();
const vlessTextDecoder = new TextDecoder();

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
		const hi = readHexNibble(clean.charCodeAt(i * 2)), lo = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (hi < 0 || lo < 0) return null;
		bytes[i] = (hi << 4) | lo;
	}
	if (uuidByteCache.size >= 32) uuidByteCache.clear();
	uuidByteCache.set(key, bytes);
	return bytes;
}

function matchUUID(data, offset, uuid) {
	const expected = getUUIDBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) { if (data[offset + i] !== expected[i]) return false; }
	return true;
}

function parseVlessRequest(chunk, token) {
	const data = toBytes(chunk);
	const len = data.byteLength;
	if (len < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!matchUUID(data, 1, token)) return { hasError: true, message: 'Invalid UUID' };
	const optLen = data[17], cmdIdx = 18 + optLen;
	if (len < cmdIdx + 4) return { hasError: true, message: 'Invalid data' };
	const cmd = data[cmdIdx];
	if (cmd !== 1 && cmd !== 2) return { hasError: true, message: 'Invalid command' };
	const isUDP = cmd === 2;
	const portIdx = cmdIdx + 1, port = (data[portIdx] << 8) | data[portIdx + 1];
	let ai = portIdx + 3, al = 0, hostname = '';
	const atype = data[portIdx + 2];
	switch (atype) {
		case 1: al = 4; if (len < ai + al) return { hasError: true, message: 'Invalid IPv4' }; hostname = `${data[ai]}.${data[ai+1]}.${data[ai+2]}.${data[ai+3]}`; break;
		case 2: al = data[ai]; ai++; if (len < ai + al) return { hasError: true, message: 'Invalid domain' }; hostname = vlessTextDecoder.decode(data.subarray(ai, ai + al)); break;
		case 3: al = 16; if (len < ai + al) return { hasError: true, message: 'Invalid IPv6' }; { const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(((data[ai + i * 2] << 8) | data[ai + i * 2 + 1]).toString(16)); hostname = ipv6.join(':'); } break;
		default: return { hasError: true, message: `Invalid atype: ${atype}` };
	}
	if (!hostname) return { hasError: true, message: `Empty hostname: ${atype}` };
	return { hasError: false, addressType: atype, port, hostname, isUDP, rawClientData: data.subarray(ai + al), version };
}

// ─────────────────────────── Shadowsocks Crypto ───────────────────────────
const SS_CIPHERS = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 }
};
const SS_TAG_LEN = 16, SS_NONCE_LEN = 12;
const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');
const ssTextEncoder = new TextEncoder(), ssTextDecoder = new TextDecoder(), ssMKCache = new Map();

function toBytes(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatBytes(...chunks) {
	if (!chunks || !chunks.length) return new Uint8Array(0);
	const list = chunks.map(toBytes);
	const total = list.reduce((s, c) => s + c.byteLength, 0);
	const result = new Uint8Array(total); let off = 0;
	for (const c of list) { result.set(c, off); off += c.byteLength; }
	return result;
}

function incrementNonce(n) {
	for (let i = 0; i < n.length; i++) { n[i] = (n[i] + 1) & 0xff; if (n[i] !== 0) return; }
}

async function deriveMasterKey(password, keyLen) {
	const key = `${keyLen}:${password}`;
	if (ssMKCache.has(key)) return ssMKCache.get(key);
	const task = (async () => {
		const pw = ssTextEncoder.encode(password || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pw.byteLength);
			input.set(prev, 0); input.set(pw, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = concatBytes(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	ssMKCache.set(key, task);
	try { return await task; } catch (e) { ssMKCache.delete(key); throw e; }
}

async function deriveSessionKey(cfg, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltKey, masterKey));
	const prkKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(cfg.keyLen);
	let prev = new Uint8Array(0), written = 0, ctr = 1;
	while (written < cfg.keyLen) {
		const input = concatBytes(prev, SS_SUBKEY_INFO, new Uint8Array([ctr]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkKey, input));
		const copy = Math.min(prev.byteLength, cfg.keyLen - written);
		subKey.set(prev.subarray(0, copy), written);
		written += copy; ctr++;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: cfg.aesLength }, false, usages);
}

async function ssAEADEncrypt(key, nonce, plaintext) {
	const iv = nonce.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext);
	incrementNonce(nonce);
	return new Uint8Array(ct);
}

async function ssAEADDecrypt(key, nonce, ciphertext) {
	const iv = nonce.slice();
	try {
		const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertext);
		incrementNonce(nonce);
		return new Uint8Array(pt);
	} catch (e) { throw new Error('Decryption failed'); }
}

// ─────────────────────────── WS Early Data ───────────────────────────
function isValidEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && matchUUID(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;
	const hash = sha224(token);
	for (let i = 0; i < 56; i++) { if (bytes[i] !== hash.charCodeAt(i)) return false; }
	return true;
}

function decodeEarlyData(header, token) {
	if (!header) return null;
	if (header.length > WS_EARLY_MAX_HDR) throw new Error('Early data too large');
	let bytes;
	const U8 = /** @type {any} */(Uint8Array);
	if (typeof U8.fromBase64 === 'function') { try { bytes = U8.fromBase64(header, { alphabet: 'base64url' }); } catch (_) {} }
	if (!bytes) {
		let norm = header.replace(/-/g, '+').replace(/_/g, '/');
		const pad = norm.length % 4; if (pad) norm += '='.repeat(4 - pad);
		let bin; try { bin = atob(norm); } catch (_) { return null; }
		bytes = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	}
	if (bytes.byteLength > WS_EARLY_MAX) throw new Error('Early data too large');
	return isValidEarlyData(bytes, token) ? bytes : null;
}

// ─────────────────────────── Trojan UDP Forward ───────────────────────────
async function forwardTrojanUDP(chunk, ws, ctx, request) {
	const cur = toBytes(chunk);
	const buf = ctx?.buffer?.byteLength ? concatBytes(ctx.buffer, cur) : cur;
	let cursor = 0;
	while (cursor < buf.byteLength) {
		const ps = cursor, at = buf[cursor];
		let ac = cursor + 1, al = 0;
		if (at === 1) al = 4;
		else if (at === 4) al = 16;
		else if (at === 3) { if (buf.byteLength < ac + 1) break; al = 1 + buf[ac]; }
		else throw new Error(`Invalid Trojan UDP atype: ${at}`);
		const pc = ac + al;
		if (buf.byteLength < pc + 6) break;
		const port = (buf[pc] << 8) | buf[pc + 1];
		const payloadLen = (buf[pc + 2] << 8) | buf[pc + 3];
		if (buf[pc + 4] !== 0x0d || buf[pc + 5] !== 0x0a) throw new Error('Invalid Trojan UDP delimiter');
		const ps2 = pc + 6, pe = ps2 + payloadLen;
		if (buf.byteLength < pe) break;
		const addrHdr = buf.slice(ps, pc + 2), payload = buf.slice(ps2, pe);
		cursor = pe;
		if (port !== 53) throw new Error('UDP not supported');
		if (!payload.byteLength) continue;
		let dnsPkt = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			dnsPkt = new Uint8Array(payload.byteLength + 2);
			dnsPkt[0] = (payload.byteLength >> 8) & 0xff; dnsPkt[1] = payload.byteLength & 0xff; dnsPkt.set(payload, 2);
		}
		const dnsCtx = { buffer: new Uint8Array(0) };
		await forwardDNS(dnsPkt, ws, null, request, (resp) => {
			const rc = toBytes(resp);
			const inp = dnsCtx.buffer.byteLength ? concatBytes(dnsCtx.buffer, rc) : rc;
			const frames = []; let rc2 = 0;
			while (rc2 + 2 <= inp.byteLength) {
				const dl = (inp[rc2] << 8) | inp[rc2 + 1], ds = rc2 + 2, de = ds + dl;
				if (de > inp.byteLength) break;
				const dp = inp.slice(ds, de);
				const frame = new Uint8Array(addrHdr.byteLength + 4 + dp.byteLength);
				frame.set(addrHdr, 0);
				frame[addrHdr.byteLength] = (dp.byteLength >> 8) & 0xff; frame[addrHdr.byteLength + 1] = dp.byteLength & 0xff;
				frame[addrHdr.byteLength + 2] = 0x0d; frame[addrHdr.byteLength + 3] = 0x0a;
				frame.set(dp, addrHdr.byteLength + 4);
				frames.push(frame); rc2 = de;
			}
			dnsCtx.buffer = inp.slice(rc2);
			return frames.length ? frames : new Uint8Array(0);
		});
	}
	if (ctx) ctx.buffer = buf.slice(cursor);
}

// ─────────────────────────── Upload Queue ───────────────────────────
function createUploadQueue({ getWriter, releaseWriter, retryConnect, closeConn, name = 'queue' }) {
	let chunks = [], head = 0, queuedBytes = 0, draining = false, closed = false;
	let bundleBuffer = null, idleResolvers = [], activeCompletions = null;

	const settle = (completions, err = null) => {
		if (!completions) return;
		for (const c of completions) { if (err) c.reject(err); else c.resolve(); }
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) { const item = chunks[i]; if (item?.completions) settle(item.completions, err); }
	};
	const compact = () => { if (head > 32 && head * 2 >= chunks.length) { chunks = chunks.slice(head); head = 0; } };
	const resolveIdle = () => { if (queuedBytes || draining || !idleResolvers.length) return; const rs = idleResolvers; idleResolvers = []; for (const r of rs) r(); };
	const clearQueue = (err = null) => {
		const e = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (e) { rejectQueued(e); settle(activeCompletions, e); activeCompletions = null; }
		chunks = []; head = 0; queuedBytes = 0; resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head]; chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength; compact();
		return item;
	};
	const bundle = () => {
		const first = shift(); if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPLOAD_BUNDLE_TARGET) return first;
		let byteLength = first.chunk.byteLength, end = head, allowRetry = first.allowRetry, completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nl = byteLength + next.chunk.byteLength;
			if (nl > UPLOAD_BUNDLE_TARGET) break;
			byteLength = nl; allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPLOAD_BUNDLE_TARGET));
		output.set(first.chunk); let offset = first.chunk.byteLength;
		while (head < end) { const next = chunks[head]; chunks[head++] = undefined; queuedBytes -= next.chunk.byteLength; output.set(next.chunk, offset); offset += next.chunk.byteLength; }
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return; draining = true;
		try {
			for (;;) {
				if (closed) break;
				const item = bundle(); if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try { await writer.write(item.chunk); }
					catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
						await retryConnect(); writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settle(completions);
				} catch (err) { settle(completions, err); throw err; }
				finally { if (activeCompletions === completions) activeCompletions = null; }
			}
		} catch (err) {
			closed = true; clearQueue(err);
			log(`[${name}] Write failed: ${err?.message || err}`);
			try { closeConn?.(err); } catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = toBytes(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength, nextItems = chunks.length - head + 1;
		if (nextBytes > UPLOAD_MAX_BYTES || nextItems > UPLOAD_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clearQueue(err); log(`[${name}] Queue overflow, closing`);
			try { closeConn?.(err); } catch (_) {} throw err;
		}
		let completionPromise = null, completions = null;
		if (waitForFlush) { completions = []; completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject })); }
		chunks.push({ chunk, allowRetry, completions }); queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		write(data, allowRetry = true) { return enqueue(data, allowRetry, false); },
		writeAndWait(data, allowRetry = true) { return enqueue(data, allowRetry, true); },
		async waitEmpty() { if (!queuedBytes && !draining) return; await new Promise(r => idleResolvers.push(r)); },
		clear() { closed = true; clearQueue(); }
	};
}

// ─────────────────────────── TCP/UDP Forwarding ───────────────────────────
async function forwardTCP(host, port, rawData, ws, respHeader, remoteConn, userID, request = null) {
	log(`[TCP] -> ${host}:${port} | proxyType: ${proxyType || 'direct'} | proxyIP: ${proxyIP}`);
	const tcpConnect = createTCPConnector(request);
	let sentData = false;

	const openSocket = async (addr, p) => {
		const sock = tcpConnect({ hostname: addr, port: p });
		await Promise.race([sock.opened, new Promise((_, rej) => setTimeout(() => rej(new Error('Connection timeout')), 5000))]);
		return sock;
	};

	const writeInitial = async (sock, data) => {
		if (dataLen(data) <= 0) return;
		const w = sock.writable.getWriter();
		try { await w.write(toBytes(data)); } finally { try { w.releaseLock(); } catch (e) {} }
	};

	const connectDirect = async (addr, p, data = null) => {
		const sock = await openSocket(addr, p);
		await writeInitial(sock, data);
		return sock;
	};

	const connectViaProxy = async (addr, p, data = null) => {
		if (proxyType === 'socks5') {
			log(`[SOCKS5] -> ${addr}:${p}`);
			return await socks5Connect(addr, p, data, tcpConnect);
		}
		if (proxyType === 'http') {
			log(`[HTTP proxy] -> ${addr}:${p}`);
			return await httpConnect(addr, p, data, false, tcpConnect);
		}
		// ProxyIP fallback
		const addrs = await resolveProxyAddr(proxyIP, addr, userID);
		for (const [pa, pp] of addrs) {
			try {
				log(`[ProxyIP] Trying ${pa}:${pp}`);
				const sock = await openSocket(pa, pp);
				await writeInitial(sock, data);
				return sock;
			} catch (e) { log(`[ProxyIP] Failed ${pa}:${pp}: ${e.message}`); }
		}
		if (proxyFallback) return connectDirect(addr, p, data);
		closeSocket(ws); throw new Error('All ProxyIP connections failed');
	};

	const connect = async (allowSendData = true) => {
		if (remoteConn.connectingPromise) { await remoteConn.connectingPromise; return; }
		const sendData = allowSendData && !sentData && dataLen(rawData) > 0;
		const initData = sendData ? rawData : null;
		const task = (async () => {
			const useProxy = proxyType && (proxyGlobal || socks5Whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)));
			const newSocket = useProxy ? await connectViaProxy(host, port, initData) : (() => { throw new Error('use-direct'); })();
			if (sendData) sentData = true;
			remoteConn.socket = newSocket;
			newSocket.closed.catch(() => {}).finally(() => closeSocket(ws));
			connectStreams(newSocket, ws, respHeader, null);
		})().catch(async (err) => {
			if (!err.message?.includes('use-direct')) throw err;
			// Direct path
			const newSocket = await connectDirect(host, port, initData);
			if (sendData) sentData = true;
			remoteConn.socket = newSocket;
			newSocket.closed.catch(() => {}).finally(() => closeSocket(ws));
			connectStreams(newSocket, ws, respHeader, null);
		});
		remoteConn.connectingPromise = task;
		try { await task; } finally { if (remoteConn.connectingPromise === task) remoteConn.connectingPromise = null; }
	};

	remoteConn.retryConnect = async () => connect(!sentData);
	const useProxy = proxyType && (proxyGlobal || socks5Whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)));

	if (useProxy) {
		await connect();
	} else {
		try {
			log(`[TCP] Direct -> ${host}:${port}`);
			const sock = await connectDirect(host, port, rawData);
			sentData = true;
			remoteConn.socket = sock;
			connectStreams(sock, ws, respHeader, async () => { if (remoteConn.socket !== sock) return; await connect(false); });
		} catch (e) {
			log(`[TCP] Direct failed: ${e.message}, trying ProxyIP`);
			await connect();
		}
	}
}

async function forwardDNS(udpChunk, ws, respHeader, request, wrapper = null) {
	const data = toBytes(udpChunk);
	log(`[DNS] ${data.byteLength}B -> 8.8.4.4:53`);
	try {
		const tcpConnect = createTCPConnector(request);
		const sock = tcpConnect({ hostname: '8.8.4.4', port: 53 });
		let vlessHdr = respHeader;
		const writer = sock.writable.getWriter();
		await writer.write(data); writer.releaseLock();
		await sock.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const resp = toBytes(chunk);
				const frames = wrapper ? await wrapper(resp) : resp;
				const list = Array.isArray(frames) ? frames : [frames];
				if (!list.length || ws.readyState !== WebSocket.OPEN) return;
				for (const f of list) {
					const fr = toBytes(f); if (!fr.byteLength) continue;
					if (vlessHdr) {
						const out = new Uint8Array(vlessHdr.length + fr.byteLength);
						out.set(vlessHdr, 0); out.set(fr, vlessHdr.length);
						await wsSend(ws, out.buffer); vlessHdr = null;
					} else { await wsSend(ws, fr); }
				}
			}
		}));
	} catch (e) { log(`[DNS] Failed: ${e?.message}`); }
}

function closeSocket(socket) {
	try { if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) socket.close(); } catch (e) {}
}

async function wsSend(ws, payload) {
	const r = ws.send(payload);
	if (r && typeof r.then === 'function') await r;
}

// ─────────────────────────── Downlink Sender + Stream Bridge ───────────────────────────
function createDownlinkSender(ws, headerData = null) {
	let header = headerData;
	const packetCap = DOWNSTREAM_CHUNK;
	const tailThreshold = DOWNSTREAM_TAIL;
	let pending = new Uint8Array(packetCap), pendingBytes = 0;
	let flushTimer = null, microtaskQueued = false, flushPromise = null;

	const sendRaw = async (chunk) => { if (ws.readyState !== WebSocket.OPEN) throw new Error('WS not open'); await wsSend(ws, chunk); };
	const prepend = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0); merged.set(chunk, header.length); header = null; return merged;
	};
	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
		microtaskQueued = false;
		if (!pendingBytes) return;
		const out = pending.subarray(0, pendingBytes).slice();
		pending = new Uint8Array(packetCap); pendingBytes = 0;
		flushPromise = sendRaw(out).finally(() => { flushPromise = null; });
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || microtaskQueued) return;
		microtaskQueued = true;
		queueMicrotask(() => {
			microtaskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailThreshold) { flush().catch(() => closeSocket(ws)); return; }
			flushTimer = setTimeout(() => { flushTimer = null; if (pendingBytes) flush().catch(() => closeSocket(ws)); }, 1);
		});
	};
	return {
		async send(data) {
			let chunk = prepend(toBytes(data)); if (!chunk.byteLength) return;
			let off = 0;
			while (off < chunk.byteLength) {
				if (!pendingBytes && chunk.byteLength - off >= packetCap) {
					await sendRaw(off || chunk.byteLength !== chunk.byteLength ? chunk.subarray(off, off + packetCap) : chunk);
					off += packetCap; continue;
				}
				const copy = Math.min(packetCap - pendingBytes, chunk.byteLength - off);
				pending.set(chunk.subarray(off, off + copy), pendingBytes);
				pendingBytes += copy; off += copy;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailThreshold) await flush();
				else scheduleFlush();
			}
		},
		async directSend(data) { let chunk = prepend(toBytes(data)); if (chunk.byteLength) await sendRaw(chunk); },
		flush
	};
}

async function connectStreams(remoteSocket, ws, headerData, retryFunc) {
	let hasData = false;
	const sender = createDownlinkSender(ws, headerData);
	const BYOB_MAX = 64 * 1024;
	let reader, useBYOB = false;
	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true; }
	catch (e) { reader = remoteSocket.readable.getReader(); }
	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read(); if (done) break;
				if (!value || !value.byteLength) continue; hasData = true; await sender.send(value);
			}
		} else {
			let readBuf = new ArrayBuffer(BYOB_MAX);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuf, 0, BYOB_MAX)); if (done) break;
				if (!value || !value.byteLength) continue; hasData = true;
				if (value.byteLength >= DOWNSTREAM_CHUNK) { await sender.flush(); await sender.directSend(value); readBuf = new ArrayBuffer(BYOB_MAX); }
				else { await sender.send(value); readBuf = value.buffer.byteLength >= BYOB_MAX ? value.buffer : new ArrayBuffer(BYOB_MAX); }
			}
		}
		await sender.flush();
	} catch (e) { closeSocket(ws); }
	finally { try { reader.cancel(); } catch (e) {} try { reader.releaseLock(); } catch (e) {} }
	if (!hasData && retryFunc) await retryFunc();
}

// ─────────────────────────── SOCKS5 / HTTP Connectors ───────────────────────────
async function socks5Connect(targetHost, targetPort, initialData, tcpConnect) {
	const { username, password, hostname, port } = parsedProxyAddr;
	const socket = tcpConnect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		await writer.write(username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]));
		let resp = await reader.read();
		if (resp.done || resp.value.byteLength < 2) throw new Error('SOCKS5 method selection failed');
		const method = new Uint8Array(resp.value)[1];
		if (method === 0x02) {
			if (!username || !password) throw new Error('SOCKS5 requires auth');
			const ub = new TextEncoder().encode(username), pb = new TextEncoder().encode(password);
			await writer.write(new Uint8Array([0x01, ub.length, ...ub, pb.length, ...pb]));
			resp = await reader.read();
			if (resp.done || new Uint8Array(resp.value)[1] !== 0x00) throw new Error('SOCKS5 auth failed');
		} else if (method !== 0x00) throw new Error(`SOCKS5 unsupported method: ${method}`);
		const hb = new TextEncoder().encode(targetHost);
		await writer.write(new Uint8Array([0x05, 0x01, 0x00, 0x03, hb.length, ...hb, targetPort >> 8, targetPort & 0xff]));
		resp = await reader.read();
		if (resp.done || new Uint8Array(resp.value)[1] !== 0x00) throw new Error('SOCKS5 connect failed');
		if (dataLen(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock(); return socket;
	} catch (e) { try { writer.releaseLock(); } catch (_) {} try { reader.releaseLock(); } catch (_) {} try { socket.close(); } catch (_) {} throw e; }
}

async function httpConnect(targetHost, targetPort, initialData, useHTTPS = false, tcpConnect) {
	const { username, password, hostname, port } = parsedProxyAddr;
	const socket = useHTTPS ? tcpConnect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false }) : tcpConnect({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder(), decoder = new TextDecoder();
	try {
		if (useHTTPS) await socket.opened;
		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		await writer.write(encoder.encode(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`));
		writer.releaseLock();
		let buf = new Uint8Array(0), hend = -1, bread = 0;
		while (hend === -1 && bread < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error('HTTP proxy closed before CONNECT response');
			buf = concatBytes(buf, value); bread = buf.length;
			const ci = buf.findIndex((_, i) => i < buf.length - 3 && buf[i] === 0x0d && buf[i+1] === 0x0a && buf[i+2] === 0x0d && buf[i+3] === 0x0a);
			if (ci !== -1) hend = ci + 4;
		}
		if (hend === -1) throw new Error('HTTP proxy CONNECT response too long');
		const sm = decoder.decode(buf.slice(0, hend)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const sc = sm ? parseInt(sm[1], 10) : NaN;
		if (!Number.isFinite(sc) || sc < 200 || sc >= 300) throw new Error(`HTTP proxy failed: ${sc}`);
		reader.releaseLock();
		if (dataLen(initialData) > 0) { const w2 = socket.writable.getWriter(); await w2.write(initialData); w2.releaseLock(); }
		if (bread > hend) {
			const { readable, writable } = new TransformStream(), tw = writable.getWriter();
			await tw.write(buf.subarray(hend, bread)); tw.releaseLock();
			socket.readable.pipeTo(writable).catch(() => {});
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}
		return socket;
	} catch (e) { try { writer.releaseLock(); } catch (_) {} try { reader.releaseLock(); } catch (_) {} try { socket.close(); } catch (_) {} throw e; }
}

function createTCPConnector(request) {
	const fetcher = (/** @type {any} */(request))?.fetcher;
	return (addr, opts) => {
		if (fetcher && typeof fetcher.connect === 'function') return fetcher.connect(addr, opts);
		return connect(addr, opts);
	};
}

// ─────────────────────────── Proxy Params Parser ───────────────────────────
async function parseProxyParams(url, userID) {
	const { searchParams, pathname } = url;
	const pathDecoded = decodeURIComponent(pathname);
	const pathLower = pathDecoded.toLowerCase();

	const chainMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainMatch) {
		try {
			const plain = base64SecretDecode(chainMatch[1], userID);
			const { type, ...addr } = JSON.parse(plain);
			if (!type || !PROXY_DEFAULT_PORTS[String(type).toLowerCase()]) throw new Error('Invalid proxy type');
			if (!addr.hostname || !addr.port) throw new Error('Missing hostname or port');
			proxyAccount = ''; proxyIP = 'chain-proxy'; proxyFallback = false; proxyGlobal = true;
			proxyType = String(type).toLowerCase();
			parsedProxyAddr = { username: addr.username, password: addr.password, hostname: addr.hostname, port: Number(addr.port) };
			if (isNaN(parsedProxyAddr.port)) throw new Error('Invalid port');
			return;
		} catch (e) { console.error('Chain proxy parse failed:', e.message); }
	}

	proxyAccount = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || null;
	proxyGlobal = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) proxyType = 'socks5';
	else if (searchParams.get('http') || searchParams.get('https')) proxyType = 'http';

	const parseProxyURL = (val, forceGlobal = true) => {
		const m = /^(socks5|http|https):\/\/(.+)$/i.exec(val || '');
		if (!m) return false;
		proxyType = m[1].toLowerCase() === 'socks5' ? 'socks5' : 'http';
		proxyAccount = m[2].split('/')[0]; if (forceGlobal) proxyGlobal = true; return true;
	};
	const setProxyIP = (val) => { proxyIP = val; proxyType = null; proxyFallback = false; };
	const extractVal = (val) => {
		if (!val.includes('://')) { const si = val.indexOf('/'); return si > 0 ? val.slice(0, si) : val; }
		const parts = val.split('://'); if (parts.length !== 2) return val;
		const si = parts[1].indexOf('/'); return si > 0 ? `${parts[0]}://${parts[1].slice(0, si)}` : val;
	};

	const qPIP = searchParams.get('proxyip');
	if (qPIP !== null) {
		if (!parseProxyURL(qPIP)) return setProxyIP(qPIP);
	} else {
		let m = /\/(socks5?|http|https):\/?\/?([^/?#\s]+)/i.exec(pathDecoded);
		if (m) { const t = m[1].toLowerCase(); proxyType = t === 'sock' || t === 'socks' ? 'socks5' : (t === 'https' ? 'http' : t); proxyAccount = m[2].split('/')[0]; proxyGlobal = true; }
		else if ((m = /\/(g?s5|socks5|g?http|g?https)=([^/?#\s]+)/i.exec(pathDecoded))) { const t = m[1].toLowerCase(); proxyAccount = m[2].split('/')[0]; proxyType = t.includes('http') ? 'http' : 'socks5'; if (t.startsWith('g')) proxyGlobal = true; }
		else if ((m = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) { const val = extractVal(m[2]); if (!parseProxyURL(val)) return setProxyIP(val); }
	}
	if (!proxyAccount) { proxyType = null; return; }
	try { parsedProxyAddr = parseProxyAccount(proxyAccount, getProxyDefaultPort(proxyType)); }
	catch (e) { console.error('Proxy address parse failed:', e.message); proxyType = null; }
}

const PROXY_DEFAULT_PORTS = { socks5: 1080, http: 80, https: 443 };
function getProxyDefaultPort(type) { return PROXY_DEFAULT_PORTS[String(type || '').toLowerCase()] || 80; }

const BASE64_RE = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPV6_BRACKET_RE = /^\[.*\]$/;
function parseProxyAccount(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https):\/\//i, '').split('#')[0].trim();
	const at = address.lastIndexOf('@');
	if (at !== -1) {
		let auth = address.slice(0, at).replaceAll('%3D', '=');
		if (!auth.includes(':') && BASE64_RE.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(at + 1)}`;
	}
	const atIdx = address.lastIndexOf('@');
	const hostPart = (atIdx === -1 ? address : address.slice(atIdx + 1)).split('/')[0];
	const authPart = atIdx === -1 ? '' : address.slice(0, atIdx);
	const [username, password] = authPart ? authPart.split(':') : [];
	if (authPart && !password) throw new Error('Proxy auth must be username:password');
	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes(']:')) { const [h, p = ''] = hostPart.split(']:'); hostname = h + ']'; port = Number(p.replace(/[^\d]/g, '')); }
	else if (!hostPart.startsWith('[')) { const parts = hostPart.split(':'); if (parts.length === 2) { hostname = parts[0]; port = Number(parts[1].replace(/[^\d]/g, '')); } }
	if (isNaN(port)) throw new Error('Invalid port number');
	if (hostname.includes(':') && !IPV6_BRACKET_RE.test(hostname)) throw new Error('IPv6 must be in brackets [...]');
	return { username, password, hostname, port };
}

// ─────────────────────────── Subscription IP List Builder ───────────────────────────
async function buildIPList(env, url, cfg) {
	if (!url.searchParams.has('sub') && cfg['优选订阅生成'].local) {
		const kvCfg = cfg['优选订阅生成']['本地IP库'];
		let fullList;
		if (kvCfg['随机IP']) {
			const [ips] = await generateRandomIPs(kvCfg['随机数量'], kvCfg['指定端口']);
			fullList = ips;
		} else {
			const saved = await env.KV.get('ADD.txt');
			if (saved) fullList = await normalizeToArray(saved);
			else { const [ips] = await generateRandomIPs(kvCfg['随机数量'], kvCfg['指定端口']); fullList = ips; }
		}
		const apiURLs = [], ipList = [], otherNodes = [];
		for (const el of fullList) {
			if (el.toLowerCase().startsWith('sub://')) { apiURLs.push(el); continue; }
			const ri = el.indexOf('#'), addrPart = ri > -1 ? el.slice(0, ri) : el;
			const sm = el.match(/sub\s*=\s*([^\s&#]+)/i);
			if (sm && sm[1].trim().includes('.')) {
				const isProxy = el.toLowerCase().includes('proxyip=true');
				apiURLs.push('sub://' + sm[1].trim() + (isProxy ? '?proxyip=true' : '') + (el.includes('#') ? '#' + el.split('#')[1] : ''));
			} else if (addrPart.toLowerCase().startsWith('https://')) { apiURLs.push(el); }
			else if (addrPart.toLowerCase().includes('://')) { otherNodes.push(el.includes('#') ? el.split('#')[0] + '#' + encodeURIComponent(decodeURIComponent(el.split('#')[1])) : el); }
			else { ipList.push(addrPart.includes('*') ? replaceWildcard(addrPart) + (ri > -1 ? el.slice(ri) : '') : el); }
		}
		const apiResult = await fetchOptimalAPI(apiURLs, '443');
		const merged = [...new Set(otherNodes.concat(apiResult[1]))];
		const otherLinks = merged.length ? merged.join('\n') + '\n' : '';
		return [[...new Set(ipList.concat(apiResult[0]))], otherLinks, apiResult[2] || []];
	} else {
		const subHost = url.searchParams.get('sub') || cfg['优选订阅生成'].SUB;
		const [genIPs, genOther] = await fetchOptimalSubData(subHost);
		return [genIPs, genOther, []];
	}
}

// ─────────────────────────── Config Reader ───────────────────────────
async function readConfig(env, hostname, userID, UA = 'Mozilla/5.0', reset = false) {
	const host = hostname, ph = '{{IP:PORT}}';
	const defaults = {
		TIME: new Date().toISOString(),
		HOST: host, HOSTS: [hostname], UUID: userID, PATH: '/',
		'协议类型': 'vless',
		'跳过证书验证': false,
		'启用0RTT': false,
		'随机路径': false,
		SS: { '加密方式': 'aes-128-gcm', TLS: true },
		Fingerprint: 'chrome',
		'优选订阅生成': {
			local: true,
			'本地IP库': { '随机IP': true, '随机数量': 16, '指定端口': -1 },
			SUB: null, SUBNAME: 'edgerunners', SUBUpdateTime: 3,
			TOKEN: await MD5MD5(hostname + userID)
		},
		'反代': {
			PROXYIP: 'auto',
			SOCKS5: { '启用': proxyType, '全局': proxyGlobal, '账号': proxyAccount, '白名单': socks5Whitelist }
		}
	};
	let cfg;
	try {
		const stored = await env.KV.get('config.json');
		if (!stored || reset) { await env.KV.put('config.json', JSON.stringify(defaults, null, 2)); cfg = defaults; }
		else cfg = JSON.parse(stored);
	} catch (e) { console.error('readConfig error:', e.message); cfg = defaults; }

	cfg.HOST = host;
	if (!cfg.HOSTS) cfg.HOSTS = [hostname];
	if (env.HOST) cfg.HOSTS = (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	cfg.UUID = userID;
	if (!cfg['随机路径']) cfg['随机路径'] = false;
	if (!cfg['启用0RTT']) cfg['启用0RTT'] = false;
	if (env.PATH) cfg.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!cfg.PATH) cfg.PATH = '/';
	if (!cfg.SS) cfg.SS = { '加密方式': 'aes-128-gcm', TLS: false };
	if (!cfg.Fingerprint) cfg.Fingerprint = 'chrome';
	if (!cfg['优选订阅生成']) cfg['优选订阅生成'] = defaults['优选订阅生成'];
	if (!cfg['优选订阅生成']['本地IP库']) cfg['优选订阅生成']['本地IP库'] = { '随机IP': true, '随机数量': 16, '指定端口': -1 };

	// Build full node path
	const proxyCfg = cfg['反代']?.SOCKS5?.['启用']?.toUpperCase();
	const pathTpls = {
		SOCKS5: { global: `socks5://${ph}`, standard: `socks5=${ph}` },
		HTTP: { global: `http://${ph}`, standard: `http=${ph}` }
	};
	let proxyPathParam = '';
	if (proxyCfg && cfg['反代']?.SOCKS5?.['账号']) {
		const tpl = pathTpls[proxyCfg];
		if (tpl) proxyPathParam = (cfg['反代'].SOCKS5['全局'] ? tpl.global : tpl.standard).replace(ph, cfg['反代'].SOCKS5['账号']);
	} else if (cfg['反代']?.PROXYIP && cfg['反代'].PROXYIP !== 'auto') {
		proxyPathParam = `proxyip=${cfg['反代'].PROXYIP}`;
	}

	let proxyQuery = '';
	if (proxyPathParam.includes('?')) { const [pp, pq] = proxyPathParam.split('?'); proxyPathParam = pp; proxyQuery = pq; }

	const normalizedPath = cfg.PATH === '/' ? '' : cfg.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...qParts] = normalizedPath.split('?');
	const queryPart = qParts.length ? '?' + qParts.join('?') : '';
	const finalQuery = proxyQuery ? (queryPart ? queryPart + '&' + proxyQuery : '?' + proxyQuery) : queryPart;
	const zeroRTT = cfg['启用0RTT'] ? (finalQuery ? '&' : '?') + 'ed=2560' : '';
	cfg['完整节点路径'] = (pathPart || '/') + (pathPart && proxyPathParam ? '/' : '') + proxyPathParam + finalQuery + zeroRTT;

	const protocol = cfg['协议类型'], nodePath = cfg['完整节点路径'];
	cfg.LINK = protocol === 'ss'
		? `ss://${btoa(cfg.SS['加密方式'] + ':' + userID)}@${host}:${cfg.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${nodePath + (cfg.SS.TLS ? ';tls' : '')};mux=0`)}#${encodeURIComponent(cfg['优选订阅生成'].SUBNAME)}`
		: `${protocol}://${userID}@${host}:443?security=tls&type=ws&host=${host}&fp=${cfg.Fingerprint}&sni=${host}&path=${encodeURIComponent(nodePath)}&encryption=none${cfg['跳过证书验证'] ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(cfg['优选订阅生成'].SUBNAME)}`;

	cfg['优选订阅生成'].TOKEN = await MD5MD5(hostname + userID);
	return cfg;
}

// ─────────────────────────── Utilities ───────────────────────────
async function MD5MD5(text) {
	const enc = new TextEncoder();
	const h1 = await crypto.subtle.digest('MD5', enc.encode(text));
	const hex1 = Array.from(new Uint8Array(h1)).map(b => b.toString(16).padStart(2, '0')).join('');
	const h2 = await crypto.subtle.digest('MD5', enc.encode(hex1.slice(7, 27)));
	return Array.from(new Uint8Array(h2)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

function base64SecretEncode(plaintext, secret) {
	const data = new TextEncoder().encode(plaintext), key = new TextEncoder().encode(secret);
	const mixed = new Uint8Array(data.length);
	for (let i = 0; i < data.length; i++) mixed[i] = data[i] ^ key[i % key.length];
	let bin = ''; for (let i = 0; i < mixed.length; i++) bin += String.fromCharCode(mixed[i]);
	return btoa(bin);
}

function base64SecretDecode(encoded, secret) {
	const bin = atob(encoded), mixed = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) mixed[i] = bin.charCodeAt(i);
	const key = new TextEncoder().encode(secret), data = new Uint8Array(mixed.length);
	for (let i = 0; i < mixed.length; i++) data[i] = mixed[i] ^ key[i % key.length];
	return new TextDecoder().decode(data);
}

function replaceWildcard(content) {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => { let s = ''; for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += chars[Math.floor(Math.random() * chars.length)]; return s; });
}

function dataLen(data) {
	if (!data) return 0;
	if (data instanceof ArrayBuffer) return data.byteLength;
	if (ArrayBuffer.isView(data)) return data.byteLength;
	if (typeof (/** @type {any} */(data))?.byteLength === 'number') return (/** @type {any} */(data)).byteLength;
	if (typeof (/** @type {any} */(data))?.length === 'number') return (/** @type {any} */(data)).length;
	return 0;
}

function log(...args) { if (debugMode) console.log(...args); }

async function dohQuery(domain, type, server = 'https://cloudflare-dns.com/dns-query') {
	try {
		const typeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
		const qtype = typeMap[type.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = []; for (const label of parts) { const enc = new TextEncoder().encode(label); bufs.push(new Uint8Array([enc.length]), enc); }
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0), result = new Uint8Array(total); let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length; } return result;
		};
		const qname = encodeDomain(domain), query = new Uint8Array(12 + qname.length + 4);
		const qv = new DataView(query.buffer);
		qv.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); qv.setUint16(2, 0x0100); qv.setUint16(4, 1);
		query.set(qname, 12); qv.setUint16(12 + qname.length, qtype); qv.setUint16(12 + qname.length + 2, 1);
		const resp = await fetch(server, { method: 'POST', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: query });
		if (!resp.ok) return [];
		const buf = new Uint8Array(await resp.arrayBuffer()), dv = new DataView(buf.buffer);
		const ancount = dv.getUint16(6), qdcount = dv.getUint16(4);
		const parseName = (pos) => {
			const labels = []; let p = pos, jumped = false, end = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) end = p + 1; break; }
				if ((len & 0xC0) === 0xC0) { if (!jumped) end = p + 2; p = ((len & 0x3F) << 8) | buf[p + 1]; jumped = true; continue; }
				labels.push(new TextDecoder().decode(buf.subarray(p + 1, p + 1 + len))); p += 1 + len;
			}
			return { name: labels.join('.'), end: end !== -1 ? end : p + 1 };
		};
		let pos = 12;
		for (let i = 0; i < qdcount && pos < buf.length; i++) { const r = parseName(pos); pos = r.end + 4; }
		const records = [];
		for (let i = 0; i < ancount && pos + 10 <= buf.length; i++) {
			const { end: nend } = parseName(pos); pos = nend;
			const rtype = dv.getUint16(pos), rdlen = dv.getUint16(pos + 8); pos += 10;
			const rdata = buf.subarray(pos, pos + rdlen); pos += rdlen;
			let data;
			if (rtype === 1 && rdlen === 4) data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			else if (rtype === 28 && rdlen === 16) { const p6 = []; for (let j = 0; j < 8; j++) p6.push(dv.getUint16(pos - rdlen + j * 2).toString(16)); data = p6.join(':'); }
			else if (rtype === 16) { data = ''; let ci = 0; while (ci < rdata.length) { const tlen = rdata[ci++]; data += new TextDecoder().decode(rdata.subarray(ci, ci + tlen)); ci += tlen; } }
			else data = rdata;
			records.push({ type: rtype, data });
		}
		return records;
	} catch (e) { return []; }
}

async function resolveProxyAddr(pip, targetDomain, userID) {
	if (cachedProxyIP === pip && cachedProxyAddrs) return cachedProxyAddrs;
	const ipv4Re = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Re = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
	const parseAP = (str) => {
		let addr = str, port = 443;
		if (str.includes(']:')) { const [h, p = ''] = str.split(']:'); addr = h + ']'; port = parseInt(p, 10) || 443; }
		else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) { const ci = str.lastIndexOf(':'); addr = str.slice(0, ci); port = parseInt(str.slice(ci + 1), 10) || 443; }
		return [addr, port];
	};
	const parseTXTRecs = (txtData) => txtData.flatMap(d => {
		if (d.startsWith('"') && d.endsWith('"')) d = d.slice(1, -1);
		return d.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
	}).map(p => parseAP(p));

	const pipArray = await normalizeToArray(pip.toLowerCase());
	let allAddrs = [];
	for (const single of pipArray) {
		let [addr, port] = parseAP(single);
		if (single.includes('.tp')) { const m = single.match(/\.tp(\d+)/); if (m) port = parseInt(m[1], 10); }
		if (ipv4Re.test(addr) || ipv6Re.test(addr)) { allAddrs.push([addr, port]); continue; }
		const [txtRecs, aRecs] = await Promise.all([dohQuery(addr, 'TXT'), dohQuery(addr, 'A')]);
		const txtAddrs = parseTXTRecs(txtRecs.filter(r => r.type === 16).map(r => r.data));
		if (txtAddrs.length > 0) { allAddrs.push(...txtAddrs); continue; }
		const ipv4s = aRecs.filter(r => r.type === 1).map(r => r.data);
		if (ipv4s.length > 0) { allAddrs.push(...ipv4s.map(ip => [ip, port])); continue; }
		const ipv6s = (await dohQuery(addr, 'AAAA')).filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6s.length > 0) allAddrs.push(...ipv6s.map(ip => [ip, port]));
		else allAddrs.push([addr, port]);
	}
	allAddrs = allAddrs.sort((a, b) => a[0].localeCompare(b[0]));
	const root = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
	let seed = [...(root + userID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	cachedProxyAddrs = [...allAddrs].sort(() => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5).slice(0, 8);
	cachedProxyIP = pip;
	return cachedProxyAddrs;
}

function normalizeToArray(content) {
	let s = content.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (s[0] === ',') s = s.slice(1);
	if (s[s.length - 1] === ',') s = s.slice(0, -1);
	return s.split(',');
}

async function generateRandomIPs(count = 16, fixedPort = -1) {
	const CIDR_RANGES = ['104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '162.158.0.0/15', '198.41.128.0/17', '190.93.240.0/20'];
	const cfPorts = [443, 2053, 2083, 2087, 2096, 8443];
	const fromCIDR = (cidr) => {
		const [base, prefix] = cidr.split('/'), bits = 32 - parseInt(prefix);
		const ip = base.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const offset = Math.floor(Math.random() * Math.pow(2, bits));
		const mask = (0xFFFFFFFF << bits) >>> 0, rand = (((ip & mask) >>> 0) + offset) >>> 0;
		return [(rand >>> 24) & 0xFF, (rand >>> 16) & 0xFF, (rand >>> 8) & 0xFF, rand & 0xFF].join('.');
	};
	const ips = Array.from({ length: count }, (_, idx) => {
		const ip = fromCIDR(CIDR_RANGES[Math.floor(Math.random() * CIDR_RANGES.length)]);
		const port = fixedPort === -1 ? cfPorts[Math.floor(Math.random() * cfPorts.length)] : fixedPort;
		return `${ip}:${port}#CF-IP-${idx + 1}`;
	});
	return [ips, ips.join('\n')];
}

async function fetchOptimalAPI(urls, defaultPort = '443', timeout = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), proxyIPPool = new Set();
	let otherLinks = '';
	await Promise.allSettled(urls.map(async (url) => {
		const hi = url.indexOf('#'), urlClean = hi > -1 ? url.slice(0, hi) : url;
		const remark = hi > -1 ? decodeURIComponent(url.slice(hi + 1)) : null;
		const isProxyIP = url.toLowerCase().includes('proxyip=true');
		if (urlClean.toLowerCase().startsWith('sub://')) {
			try {
				const [ips, other] = await fetchOptimalSubData(urlClean);
				for (const ip of ips) { const tagged = remark ? (ip.includes('#') ? `${ip} [${remark}]` : `${ip}#[${remark}]`) : ip; results.add(tagged); if (isProxyIP) proxyIPPool.add(ip.split('#')[0]); }
				otherLinks += other;
			} catch (e) {} return;
		}
		try {
			const ctrl = new AbortController(), tid = setTimeout(() => ctrl.abort(), timeout);
			const resp = await fetch(urlClean, { signal: ctrl.signal });
			clearTimeout(tid); if (!resp.ok) return;
			const buf = await resp.arrayBuffer();
			let text = '';
			const ct = (resp.headers.get('content-type') || '').toLowerCase();
			for (const enc of [ct.includes('gb') ? 'gb2312' : 'utf-8', 'utf-8']) {
				try { const d = new TextDecoder(enc).decode(buf); if (d && !d.includes('\ufffd')) { text = d; break; } } catch (e) {}
			}
			if (!text) text = new TextDecoder().decode(buf);
			if (!text.trim()) return;
			const clean = text.replace(/\s/g, '');
			let plain = text;
			if (clean.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(clean)) { try { plain = atob(clean); } catch (e) {} }
			const parsedURL = new URL(urlClean);
			plain.split(/\r?\n/).filter(l => l.trim()).forEach(line => {
				if (line.includes('://')) { otherLinks += line + '\n'; return; }
				const [lnh, ...rp] = line.split('#'), lr = rp.length ? '#' + rp.join('#') : '';
				const hasPort = lnh.includes(':') && !/^\[.*\]$/.test(lnh.split(':').slice(0, -1).join(':'));
				const hp = lnh.split('#')[0].split(':')[0], port = parsedURL.searchParams.get('port') || defaultPort;
				const item = hasPort ? line : `${hp}:${port}${lr}`;
				const tagged = remark ? (item.includes('#') ? `${item} [${remark}]` : `${item}#[${remark}]`) : item;
				results.add(tagged); if (isProxyIP) proxyIPPool.add(item.split('#')[0]);
			});
		} catch (e) {}
	}));
	const linkArray = otherLinks.trim() ? [...new Set(otherLinks.split(/\r?\n/).filter(l => l.trim()))] : [];
	return [Array.from(results), linkArray, Array.from(proxyIPPool)];
}

async function fetchOptimalSubData(host) {
	let ips = [], other = '';
	let formatted = (host || '').replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formatted)) formatted = `https://${formatted}`;
	try { formatted = new URL(formatted).origin; } catch (e) { ips.push(`127.0.0.1:1234#SubError:${e.message}`); return [ips, other]; }
	try {
		const resp = await fetch(`${formatted}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`, { headers: { 'User-Agent': 'edgerunners/1.0' } });
		if (!resp.ok) { ips.push(`127.0.0.1:1234#SubError:${resp.statusText}`); return [ips, other]; }
		const content = atob(await resp.text());
		for (const line of content.split(/\r?\n/)) {
			if (!line.trim()) continue;
			if (line.includes('00000000-0000-4000-8000-000000000000') && line.includes('example.com')) {
				const m = line.match(/:\/\/[^@]+@([^?]+)/);
				if (m) { const r = line.match(/#(.+)$/); ips.push(m[1] + (r ? '#' + decodeURIComponent(r[1]) : '')); }
			} else { other += line + '\n'; }
		}
	} catch (e) { ips.push(`127.0.0.1:1234#SubError:${e.message}`); }
	return [ips, other];
}

function sha224(s) {
	const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi>>>24)&0xFF,(hi>>>16)&0xFF,(hi>>>8)&0xFF,hi&0xFF,(lo>>>24)&0xFF,(lo>>>16)&0xFF,(lo>>>8)&0xFF,lo&0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4) w.push((s.charCodeAt(i)<<24)|(s.charCodeAt(i+1)<<16)|(s.charCodeAt(i+2)<<8)|s.charCodeAt(i+3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++) x[j] = w[i+j];
		for (let j = 16; j < 64; j++) { const s0=r(x[j-15],7)^r(x[j-15],18)^(x[j-15]>>>3), s1=r(x[j-2],17)^r(x[j-2],19)^(x[j-2]>>>10); x[j]=(x[j-16]+s0+x[j-7]+s1)>>>0; }
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) { const S1=r(e,6)^r(e,11)^r(e,25),ch=(e&f)^(~e&g),t1=(h0+S1+ch+K[j]+x[j])>>>0,S0=r(a,2)^r(a,13)^r(a,22),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)>>>0; h0=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0; }
		for (let j = 0; j < 8; j++) h[j] = (h[j] + [a,b,c,d,e,f,g,h0][j]) >>> 0;
	}
	let hex = ''; for (let i = 0; i < 7; i++) for (let j = 24; j >= 0; j -= 8) hex += ((h[i]>>>j)&0xFF).toString(16).padStart(2,'0');
	return hex;
}

// ─────────────────────────── HTML Pages ───────────────────────────
function loginPageHTML() {
	return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Edgerunners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;width:100%;max-width:360px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
h1{font-size:1.1rem;font-weight:600;color:#f0f6fc;margin-bottom:.25rem}
.sub{font-size:.8rem;color:#8b949e;margin-bottom:1.5rem}
input{width:100%;padding:.7rem 1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;font-size:.9rem;outline:none;transition:border-color .15s}
input:focus{border-color:#58a6ff;box-shadow:0 0 0 3px rgba(88,166,255,.1)}
button{width:100%;padding:.7rem;background:#238636;border:none;border-radius:8px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer;margin-top:.75rem;transition:background .15s}
button:hover{background:#2ea043}
.err{color:#f85149;font-size:.8rem;margin-top:.5rem;display:none;padding:.4rem .7rem;background:rgba(248,81,73,.1);border-radius:6px}
</style>
</head><body>
<div class="card">
<h1>&#9889; Edgerunners</h1>
<p class="sub">Sign in to manage your proxy node</p>
<input type="password" id="pw" placeholder="Admin password" autofocus>
<button id="btn" onclick="go()">Sign in</button>
<p class="err" id="err">Incorrect password &#8212; try again</p>
</div>
<script>
document.getElementById('pw').addEventListener('keydown',e=>e.key==='Enter'&&go());
async function go(){
const pw=document.getElementById('pw').value;if(!pw)return;
const btn=document.getElementById('btn');btn.disabled=true;btn.textContent='...';
const r=await fetch('/login',{method:'POST',body:new URLSearchParams({password:pw}),headers:{'Content-Type':'application/x-www-form-urlencoded'}});
if(r.ok){const j=await r.json();if(j.success){location.href='/admin';return;}}
document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Sign in';
}
</script>
</body></html>`;
}

function adminPageHTML(uuid, subUrl, wsPath, proto) {
	return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin &#8212; Edgerunners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}
header{background:#161b22;border-bottom:1px solid #30363d;padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
header h1{font-size:1rem;font-weight:600;color:#f0f6fc}
header a{color:#8b949e;font-size:.85rem;text-decoration:none;padding:.3rem .75rem;border:1px solid #30363d;border-radius:6px}
header a:hover{border-color:#8b949e;color:#c9d1d9}
.wrap{max-width:760px;margin:2rem auto;padding:0 1rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1.25rem;margin-bottom:1rem}
.card h2{font-size:.75rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.75rem}
.row{display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem}
.lbl{font-size:.8rem;color:#8b949e;min-width:90px;flex-shrink:0}
.val{font-size:.85rem;color:#c9d1d9;word-break:break-all;flex:1;font-family:ui-monospace,monospace}
.cp{padding:.2rem .55rem;background:#21262d;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;cursor:pointer;font-size:.75rem;white-space:nowrap}
.cp:hover{background:#30363d}
.sub-u{font-size:.85rem;color:#58a6ff;word-break:break-all;font-family:ui-monospace,monospace;line-height:1.5}
textarea{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:.75rem;color:#c9d1d9;font-size:.78rem;font-family:ui-monospace,monospace;resize:vertical;min-height:320px;outline:none;line-height:1.5}
textarea:focus{border-color:#58a6ff}
.save{padding:.5rem 1rem;background:#238636;border:none;border-radius:8px;color:#fff;font-size:.85rem;font-weight:600;cursor:pointer;margin-top:.75rem}
.save:hover{background:#2ea043}
.msg{margin-top:.5rem;font-size:.8rem;display:none;padding:.4rem .7rem;border-radius:6px}
.ok{color:#3fb950;background:rgba(63,185,80,.1)}
.bad{color:#f85149;background:rgba(248,81,73,.1)}
</style></head><body>
<header><h1>&#9889; Edgerunners Admin</h1><a href="/logout">Logout</a></header>
<div class="wrap">
<div class="card"><h2>Connection Info</h2>
<div class="row"><span class="lbl">UUID</span><span class="val" id="u">${uuid}</span><button class="cp" onclick="cp('u',this)">Copy</button></div>
<div class="row"><span class="lbl">Protocol</span><span class="val">${proto}</span></div>
<div class="row"><span class="lbl">WS Path</span><span class="val">${wsPath}</span></div>
</div>
<div class="card"><h2>Subscription URL &#8212; import this link into your proxy client</h2>
<p class="sub-u" id="s">${subUrl}</p>
<button class="cp" style="margin-top:.5rem" onclick="cp('s',this)">Copy URL</button>
</div>
<div class="card"><h2>Edit Config (JSON)</h2>
<textarea id="cfg" spellcheck="false">Loading...</textarea>
<button class="save" onclick="save()">Save Config</button>
<p class="msg" id="m"></p>
</div>
</div>
<script>
const g=id=>document.getElementById(id);
async function cp(id,b){await navigator.clipboard.writeText(g(id).textContent);const t=b.textContent;b.textContent='Copied!';setTimeout(()=>b.textContent=t,1500);}
async function load(){try{const r=await fetch('/admin/config.json');g('cfg').value=JSON.stringify(await r.json(),null,2);}catch(e){g('cfg').value='// Error: '+e.message;}}
async function save(){const m=g('m');m.style.display='none';
try{const j=JSON.parse(g('cfg').value);const r=await fetch('/admin/config.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(j)});const res=await r.json();
m.className='msg '+(res.success?'ok':'bad');m.textContent=res.success?'Config saved successfully':(res.error||'Save failed');}
catch(e){m.className='msg bad';m.textContent='JSON parse error: '+e.message;}m.style.display='block';}
load();
</script>
</body></html>`;
}

function errorPageHTML(title, msg, details) {
	return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} &#8212; Edgerunners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;width:100%;max-width:480px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.icon{font-size:2rem;margin-bottom:1rem}
h1{font-size:1.1rem;font-weight:600;color:#f0f6fc;margin-bottom:.5rem}
p{font-size:.875rem;color:#8b949e;line-height:1.6;margin-bottom:.75rem}
code{background:#0d1117;padding:.1rem .4rem;border-radius:4px;font-family:ui-monospace,monospace;color:#f6931f;font-size:.85em}
.steps{font-size:.875rem;color:#c9d1d9;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;line-height:1.7}
</style>
</head><body>
<div class="card">
<div class="icon">&#9881;&#65039;</div>
<h1>${title}</h1>
<p>${msg}</p>
<div class="steps">${details}</div>
</div>
</body></html>`;
}

function nginxPage() {
	return `<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head><body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body></html>`;
}

function cloudflareErrorPage(host, clientIP) {
	const now = new Date();
	const ts = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
	const ray = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2,'0')).join('');
	return `<!DOCTYPE html>
<!--[if lt IE 7]><html class="no-js ie6 oldie" lang="en-US"><![endif]-->
<!--[if IE 7]><html class="no-js ie7 oldie" lang="en-US"><![endif]-->
<!--[if IE 8]><html class="no-js ie8 oldie" lang="en-US"><![endif]-->
<!--[if gt IE 8]><!--><html class="no-js" lang="en-US"><!--<![endif]-->
<head><title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8"/><meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta name="robots" content="noindex, nofollow"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="stylesheet" href="/cdn-cgi/styles/cf.errors.css"/>
<style>body{margin:0;padding:0}</style>
</head><body>
<div id="cf-wrapper">
<div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert">Please enable cookies.</div>
<div id="cf-error-details" class="cf-error-details-wrapper">
<div class="cf-wrapper cf-header cf-error-overview">
<h1><span class="cf-error-type">Error</span> <span class="cf-error-code">1101</span>
<small class="heading-ray-id">Ray ID: ${ray} &bull; ${ts} UTC</small></h1>
<h2 class="cf-subheadline">Worker threw exception</h2>
</div>
<section></section>
<div class="cf-section cf-wrapper"><div class="cf-columns two">
<div class="cf-column"><h2>What happened?</h2>
<p>You've requested a page on (${host}) on the <a href="https://www.cloudflare.com/" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p></div>
<div class="cf-column"><h2>What can I do?</h2>
<p><strong>If you are the owner:</strong><br/>refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors</a> and check Workers Logs for ${host}.</p></div>
</div></div>
<div class="cf-error-footer cf-wrapper"><p>
<span>Cloudflare Ray ID: <strong>${ray}</strong></span> &bull;
<span>Your IP: <span id="cf-footer-ip">${clientIP}</span></span> &bull;
<span>Performance &amp; security by <a href="https://www.cloudflare.com/" target="_blank">Cloudflare</a></span>
</p></div>
</div></div>
<script>window._cf_translation={};</script>
</body></html>`;
}
