document.addEventListener('DOMContentLoaded', function () {
    var apiUrl = window.location.origin + '/api/bot';

    document.getElementById('apiUrl').textContent = apiUrl;

    var jsCode =
        'const BOT_TOKEN = "YOUR_BOT_TOKEN";\n' +
        'const CHAT_ID   = "YOUR_CHAT_ID";\n' +
        'const PROXY_URL = "' + apiUrl + '";\n\n' +
        'async function sendMessage(text) {\n' +
        '    const url = PROXY_URL + BOT_TOKEN + "/sendMessage";\n' +
        '    const response = await fetch(url, {\n' +
        '        method: "POST",\n' +
        '        headers: { "Content-Type": "application/json" },\n' +
        '        body: JSON.stringify({\n' +
        '            chat_id: CHAT_ID,\n' +
        '            text: text,\n' +
        '            parse_mode: "Markdown"\n' +
        '        })\n' +
        '    });\n' +
        '    return response.json();\n' +
        '}\n\n' +
        'sendMessage("Hello from Proxy!").then(console.log);';

    var pythonCode =
        'import requests\n\n' +
        'PROXY_URL = "' + apiUrl + '"\n' +
        'BOT_TOKEN = "YOUR_BOT_TOKEN"\n' +
        'CHAT_ID   = "YOUR_CHAT_ID"\n\n' +
        'def send_message(text):\n' +
        '    url = f"{PROXY_URL}{BOT_TOKEN}/sendMessage"\n' +
        '    payload = {\n' +
        '        "text": text,\n' +
        '        "chat_id": CHAT_ID,\n' +
        '        "parse_mode": "Markdown",\n' +
        '        "disable_web_page_preview": True\n' +
        '    }\n' +
        '    response = requests.post(url, json=payload)\n' +
        '    return response.json()\n\n' +
        'result = send_message("Hello from Proxy!")\n' +
        'print(result)';

    var nodejsCode =
        'const TelegramBot = require("node-telegram-bot-api");\n\n' +
        'const TOKEN     = "YOUR_BOT_TOKEN";\n' +
        'const PROXY_URL = "' + apiUrl + '";\n\n' +
        'const bot = new TelegramBot(TOKEN, {\n' +
        '    polling: true,\n' +
        '    baseApiUrl: PROXY_URL.replace("/bot", "")\n' +
        '});\n\n' +
        'bot.onText(/\\/start/, function (msg) {\n' +
        '    bot.sendMessage(msg.chat.id, "Hello via Proxy!");\n' +
        '});\n\n' +
        'bot.on("message", function (msg) {\n' +
        '    console.log("Received:", msg.text);\n' +
        '});';

    document.getElementById('code-js').textContent = jsCode;
    document.getElementById('code-python').textContent = pythonCode;
    document.getElementById('code-nodejs').textContent = nodejsCode;

    hljs.highlightAll();

    document.getElementById('copyBtn').addEventListener('click', function () {
        var text = document.getElementById('apiUrl').textContent;
        var btn = this;

        function onCopied() {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function () {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(onCopied);
        } else {
            var el = document.createElement('textarea');
            el.value = text;
            el.style.position = 'fixed';
            el.style.opacity = '0';
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            onCopied();
        }
    });

    document.querySelectorAll('.tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            document.querySelectorAll('.tab').forEach(function (t) {
                t.classList.remove('active');
            });
            document.querySelectorAll('.tab-panel').forEach(function (p) {
                p.classList.remove('active');
            });
            this.classList.add('active');
            document.getElementById('tab-' + this.dataset.tab).classList.add('active');
        });
    });

    document.getElementById('testBtn').addEventListener('click', async function () {
        var btn = this;
        var out = document.getElementById('testOutput');

        btn.innerHTML = '<span class="spinner"></span>Testing...';
        btn.disabled = true;
        out.style.display = 'none';

        try {
            var start = Date.now();
            var res = await fetch('/api/stats');
            var latency = Date.now() - start;
            var data = await res.json();

            if (data.ok) {
                out.className = 'test-output success';
                out.textContent =
                    'Connection successful' +
                    '  \u2014  Ping: ' + latency + 'ms' +
                    '  \u2014  Avg API latency: ' + data.avgLatency + 'ms' +
                    '  \u2014  Requests served: ' + data.totalRequests;
            } else {
                throw new Error('not ok');
            }
        } catch (e) {
            out.className = 'test-output error';
            out.textContent = 'Connection failed. Make sure the deployment is active.';
        }

        out.style.display = 'block';
        btn.textContent = 'Test API Connection';
        btn.disabled = false;
    });
});