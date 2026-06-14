# Telegram API Proxy

A Cloudflare-based reverse proxy for the Telegram Bot API, designed to provide stable access in regions where `api.telegram.org` is restricted.

---

## Deployment Options

### Option 1 — Cloudflare Pages (Recommended)

1. Fork or upload this repository to GitHub.
2. Go to [Cloudflare Pages](https://pages.cloudflare.com) → Create a Project → Connect to your GitHub repo.
3. No build command is needed. Set the output directory to `/` (root).
4. Deploy. Your API endpoint will be:
   ```
   https://your-project.pages.dev/api/bot
   ```

### Option 2 — Cloudflare Workers (Manual)

1. Go to [Cloudflare Workers](https://workers.cloudflare.com) → Create a Worker.
2. Copy the contents of `manual-worker/worker.js` into the editor.
3. Save and deploy. Your API endpoint will be:
   ```
   https://your-worker.workers.dev/bot
   ```

---

## Usage

Replace `https://api.telegram.org` with your proxy URL in your bot code.

**Python**
```python
import requests

PROXY_URL = "https://your-project.pages.dev/api/bot"
BOT_TOKEN  = "YOUR_BOT_TOKEN"
CHAT_ID    = "YOUR_CHAT_ID"

def send_message(text):
    url = f"{PROXY_URL}{BOT_TOKEN}/sendMessage"
    payload = {
        "text": text,
        "chat_id": CHAT_ID,
        "parse_mode": "Markdown"
    }
    return requests.post(url, json=payload).json()
```

**JavaScript**
```javascript
const PROXY_URL = "https://your-project.pages.dev/api/bot";
const BOT_TOKEN = "YOUR_BOT_TOKEN";
const CHAT_ID   = "YOUR_CHAT_ID";

async function sendMessage(text) {
    const url = PROXY_URL + BOT_TOKEN + "/sendMessage";
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: CHAT_ID, text, parse_mode: "Markdown" })
    });
    return res.json();
}
```

---

## Configuration

Open `functions/api/[[path]].js` (Pages) or `manual-worker/worker.js` (Worker) and edit these constants at the top of the file:

| Constant | Default | Description |
|---|---|---|
| `ALLOWED_COUNTRIES` | `['IR']` | Allowlist of ISO country codes. Set to `[]` to allow all. |
| `BLOCKED_COUNTRIES` | `[]` | Blocklist of ISO country codes (used only if `ALLOWED_COUNTRIES` is empty). |
| `RATE_LIMITS.IP.max` | `100` | Max requests per IP per minute. |
| `RATE_LIMITS.TOKEN.max` | `200` | Max requests per bot token per minute. |
| `RATE_LIMITS.GLOBAL.max` | `5000` | Max total requests per minute across all users. |

---

## Endpoints

| Path | Description |
|---|---|
| `/` | Status dashboard (Worker only) |
| `/api/stats` | JSON stats — uptime, request count, avg latency (Pages) |
| `/stats` | JSON stats (Worker) |
| `/api/bot{TOKEN}/{METHOD}` | Telegram API relay (Pages) |
| `/bot{TOKEN}/{METHOD}` | Telegram API relay (Worker) |

---

## License

[GPL-3.0](LICENSE)