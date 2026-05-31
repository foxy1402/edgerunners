# Edgerunners

A lightweight VPN/proxy node built on Cloudflare Workers, supporting VLESS, Trojan, and Shadowsocks over WebSocket.

> Simplified and translated to English from [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel).

---

## Features

- Protocols: VLESS, Trojan, Shadowsocks (AES-128/256-GCM)
- Transport: WebSocket over TLS
- Outbound: Direct, ProxyIP fallback, SOCKS5, HTTP proxy
- Subscription endpoint at `/sub` — import one URL into any proxy client
- Built-in admin panel at `/admin` (no external dependencies)
- Camouflage: proxy to a real site or serve a fake nginx/Cloudflare error page

---

## Environment Variables

| Variable   | Required          | Description |
|------------|-------------------|-------------|
| `ADMIN`    | **Yes**           | Admin password. Also used to derive the UUID when `UUID` is not set. |
| `KV`       | **Yes** (binding) | KV namespace for config and custom IPs. Must be bound with the variable name `KV`. |
| `UUID`     | No                | Fixed client UUID (valid UUIDv4). Derived from `ADMIN + KEY` if not set. |
| `KEY`      | No                | Secret path shortcut — visiting `/<KEY>` redirects to `/sub`. |
| `PROXYIP`  | No                | Override the default ProxyIP. Accepts `hostname` or `ip:port`. |
| `HOST`     | No                | Override the hostname(s) used in subscription links. |
| `PATH`     | No                | WebSocket path prefix (default `/`). |
| `GO2SOCKS5`| No                | Extra domains to force through SOCKS5 outbound. |
| `URL`      | No                | Camouflage target. Use a URL, `nginx` (fake nginx page), or `1101` (fake Cloudflare error). |
| `DEBUG`    | No                | Set to `1` to enable verbose logging. |

---

## Deploy on Cloudflare Workers (Dashboard — no CLI needed)

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → **Compute (Workers)** in the left sidebar → **Workers & Pages** → **Create application**.
2. Click **Start with Hello World!**, give the worker a name (e.g. `edgerunners`), then click **Deploy**.
3. On the worker's page, click **Edit code** (top-right).
4. Select all the placeholder code in the editor, delete it, paste the full contents of `_worker.js`, then click **Deploy**.
5. Go back to the worker's main page → **Settings → Variables & Secrets** → **Add** → set:
   - Variable name: `ADMIN` — Value: your chosen admin password
   - Add any other optional variables from the table above
6. Still in **Settings** → **Bindings** → **Add**:
   - Type: **KV Namespace**
   - Variable name: `KV`
   - Select or create a namespace (create one first at **Storage & Databases → KV** if you don't have one)
7. Visit `https://your-worker-name.workers.dev/login` to open the admin panel.

> Your subscription URL is shown on the admin panel homepage. Copy it and import it into your proxy client.

---

## Deploy on Cloudflare Pages (via Wrangler CLI)

1. Install Wrangler: `npm install -g wrangler`
2. Log in: `wrangler login`
3. Edit `wrangler.toml` — fill in your KV namespace ID under `[[kv_namespaces]]`
4. Deploy: `wrangler deploy`

---

## Recommended Proxy Clients

Import your subscription URL (`https://your-worker.workers.dev/sub?token=...`) directly into any of these apps.

### Windows
- **[v2rayN](https://github.com/2dust/v2rayN/releases)** — free, open source. Supports VLESS / Trojan / Shadowsocks + subscription import.

### Android
- **[v2rayNG](https://github.com/2dust/v2rayNG/releases)** — free, open source. Same author as v2rayN. Also available on [Google Play](https://play.google.com/store/apps/details?id=com.v2ray.ang). Supports subscription import.

### iOS
- **[Shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118)** — $2.99 on the App Store. Most reliable iOS proxy client, supports VLESS / Trojan / Shadowsocks + subscription import.
- **[Sing-box](https://apps.apple.com/us/app/sing-box/id6451272673)** — free on the App Store. Open source, supports subscription import.

---

## License

GPL-2.0 — see [LICENSE](LICENSE)
