# Telegram API Proxy

A Cloudflare Worker that acts as a reverse proxy for the Telegram Bot API. Designed to provide stable, unfiltered access to `api.telegram.org` for bots running in restricted regions.

---

## Deployment

### Method 1 — Cloudflare Dashboard (Recommended)

1. Go to [Cloudflare Workers](https://workers.cloudflare.com) and sign in.
2. Click **Create a Worker**.
3. Delete all the default code in the editor.
4. Copy the entire contents of `worker.js` and paste it into the editor.
5. Click **Save and Deploy**.
6. Your API endpoint will be:
   ```
   https://your-worker-name.your-subdomain.workers.dev/bot
   ```

### Method 2 — Wrangler CLI

```bash
npm install -g wrangler
wrangler login
wrangler deploy worker.js --name telegram-api-proxy --compatibility-date 2024-01-01
```

---

## Usage

Replace `https://api.telegram.org` with your Worker URL in your bot code.

### Python (`requests`)

```python
import requests

PROXY_URL = "https://your-worker.workers.dev/bot"
BOT_TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID   = "YOUR_CHAT_ID"

def send_message(text):
    url = PROXY_URL + BOT_TOKEN + "/sendMessage"
    payload = {
        "text": text,
        "chat_id": CHAT_ID,
        "parse_mode": "Markdown"
    }
    return requests.post(url, json=payload).json()

print(send_message("Hello from Proxy!"))
```

### Python (`aiogram`)

```python
import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.client.session.aiohttp import AiohttpSession

PROXY_URL = "https://your-worker.workers.dev/bot"
BOT_TOKEN = "YOUR_BOT_TOKEN"

session = AiohttpSession(api=PROXY_URL.replace("/bot", ""))
bot = Bot(token=BOT_TOKEN, session=session)
dp  = Dispatcher()

@dp.message()
async def echo(message: types.Message):
    await message.answer("Echo: " + message.text)

asyncio.run(dp.start_polling(bot))
```

### JavaScript (Vanilla)

```javascript
const BOT_TOKEN = "YOUR_BOT_TOKEN";
const CHAT_ID   = "YOUR_CHAT_ID";
const PROXY_URL = "https://your-worker.workers.dev/bot";

async function sendMessage(text) {
    const url = PROXY_URL + BOT_TOKEN + "/sendMessage";
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: CHAT_ID, text, parse_mode: "Markdown" })
    });
    return response.json();
}

sendMessage("Hello from Proxy!").then(console.log);
```

### Node.js (`node-telegram-bot-api`)

```javascript
const TelegramBot = require("node-telegram-bot-api");

const TOKEN     = "YOUR_BOT_TOKEN";
const PROXY_URL = "https://your-worker.workers.dev/bot";

const bot = new TelegramBot(TOKEN, {
    polling: true,
    baseApiUrl: PROXY_URL.replace("/bot", "")
});

bot.on("message", function (msg) {
    bot.sendMessage(msg.chat.id, "Echo: " + msg.text);
});
```

---

## Endpoints

| Path | Description |
|---|---|
| `/` | Web dashboard — shows API URL, code examples, and connection test |
| `/stats` | JSON stats — uptime, request count, avg latency, blocked count |
| `/bot{TOKEN}/{METHOD}` | Telegram API relay (same format as official API) |
| `/favicon.ico` | Empty 204 response |

---

## Configuration

Open `worker.js` and edit these constants near the top of the file:

| Constant | Default | Description |
|---|---|---|
| `ALLOWED_COUNTRIES` | `['IR']` | ISO country codes allowed to use the proxy. Set to `[]` to allow all. |
| `BLOCKED_COUNTRIES` | `[]` | ISO country codes to block (used only if `ALLOWED_COUNTRIES` is empty). |
| `RATE_LIMITS.IP.max` | `100` | Max requests per IP per minute. |
| `RATE_LIMITS.TOKEN.max` | `200` | Max requests per bot token per minute. |
| `RATE_LIMITS.GLOBAL.max` | `5000` | Max total requests per minute. |

---

## Features

- **Rate limiting** — per IP, per bot token, global, and burst protection
- **Circuit breaker** — automatically stops forwarding on repeated upstream failures and recovers after a timeout
- **Retry with backoff** — up to 3 automatic retries with exponential delay
- **Security headers** — CSP, HSTS, X-Frame-Options, Permissions-Policy, and more
- **Bot token validation** — format and structure check with in-memory caching
- **File upload support** — all Telegram media methods (sendPhoto, sendDocument, etc.)
- **Malicious request detection** — XSS, SQL injection, and path traversal patterns
- **Edge caching** — configurable TTL per Telegram API method via Cloudflare

---

## License

[GPL-3.0](LICENSE)

---

## Engineered by:

Anonymous
