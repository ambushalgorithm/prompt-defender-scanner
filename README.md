# 🛡️ prompt-defender-scanner

<p align="center">
  <img src="https://img.shields.io/badge/Scanner-Python-cyan?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

> Standalone security service for scanning and filtering harmful prompts for AI agents.

## ✨ What is this?

**prompt-defender-scanner** is a standalone Python service that scans content for:

- 🎯 **Prompt injection attacks** — Attempts to override AI instructions
- 🔓 **Jailbreak attempts** — Tricks to bypass safety guidelines  
- 🔑 **Secret leaks** — Accidental exposure of API keys, tokens, passwords
- 👤 **PII exposure** — Personal information that shouldn't be shared
- 💉 **Malicious content** — XSS, SQL injection, RCE attempts

## ⚠️ Two Repos

This scanner requires a client to send content for scanning:

| Repo | Description |
|------|-------------|
| **prompt-defender-scanner** | This repo — standalone scanner service |
| **openclaw-prompt-defender** | OpenClaw plugin that calls this scanner |

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- pip or Docker

### Option A: Run Directly

```bash
# Clone
git clone https://github.com/ambushalgorithm/prompt-defender-scanner.git
cd prompt-defender-scanner

# Install dependencies
pip install -r requirements.txt

# Run the service
python -m app
# Service runs on http://localhost:8080
```

### Option B: Docker

```bash
# Build
docker build -t prompt-defender-scanner .

# Run
docker run -d -p 8080:8080 prompt-defender-scanner
```

### Option C: Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  scanner:
    image: prompt-defender-scanner
    ports:
      - "8080:8080"
```

```bash
docker-compose up -d
```

## 📡 API

### Scan Endpoint

```bash
curl -X POST "http://localhost:8080/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "output",
    "tool_name": "web_fetch",
    "content": "Hello world",
    "is_error": false,
    "duration_ms": 100,
    "source": "user123"
  }'
```

### Request

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Content type (e.g., "output") |
| `tool_name` | string | Name of the tool that produced the content |
| `content` | any | Content to scan |
| `is_error` | boolean | Whether this is an error result |
| `duration_ms` | number | Execution time in milliseconds |
| `source` | string | Session/user identifier for owner bypass |

### Response

**Allowed:**
```json
{
  "action": "allow",
  "matches": []
}
```

**Blocked:**
```json
{
  "action": "block",
  "reason": "Potential prompt injection detected",
  "matches": [
    {
      "pattern": "[INST]",
      "type": "prompt_injection",
      "severity": "critical",
      "lang": "en"
    }
  ]
}
```

**Sanitized:**
```json
{
  "action": "sanitize",
  "sanitized_content": "redacted content",
  "matches": [...]
}
```

## 🔧 Configuration

Configuration is passed via the `X-Config` header as a JSON string:

```json
{
  "scan_enabled": true,
  "timeout_ms": 5000,
  "fail_open": true,
  "features": {
    "prompt_guard": true,
    "ml_detection": false,
    "secret_scanner": false
  },
  "prompt_guard": {
    "scan_tier": 1
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `scan_enabled` | `true` | Enable/disable scanning |
| `timeout_ms` | `5000` | Request timeout |
| `fail_open` | `true` | Allow if scanner fails |
| `features.prompt_guard` | `true` | Enable regex pattern scanning |
| `features.ml_detection` | `false` | Enable ML-based detection |
| `features.secret_scanner` | `false` | Enable secrets/PII detection |
| `prompt_guard.scan_tier` | `1` | 0=critical, 1=+high, 2=+medium |

## 🏗️ Architecture

```
Client (Plugin) → HTTP POST /scan → Scanner Service → Response
                                              ↓
                                    ┌───────────────┐
                                    │ 1. Decoder    │ ← Base64/URL decoding
                                    │ 2. Scanner    │ ← Pattern matching
                                    │ 3. ML (opt)   │ ← HuggingFace
                                    │ 4. Moderation │ ← OpenAI
                                    └───────────────┘
```

### Components

| File | Description |
|------|-------------|
| `app.py` | FastAPI application, `/scan` endpoint |
| `scanner.py` | Core scanning engine with tiered patterns |
| `patterns.py` | Detection patterns (500+ regex) |
| `decoder.py` | Base64/URL encoding detection |
| `config.py` | Configuration loading |
| `logger.py` | Structured logging |

## 🔍 Detection Methods

| Method | Patterns | Description |
|--------|----------|-------------|
| **prompt_guard** | 500+ regex | Core injection detection |
| **ml_detection** | HuggingFace DeBERTa | Advanced ML-based detection |
| **secret_scanner** | 50+ patterns | API keys, tokens, passwords |
| **content_moderation** | OpenAI API | Policy violations |

## 🧪 Testing

```bash
# Run tests
pytest -v

# With coverage
pytest --cov=. --cov-report=html
```

## 📁 Project Structure

```
prompt-defender-scanner/
├── app.py             # FastAPI /scan endpoint
├── scanner.py         # Core scanning engine
├── patterns.py        # Detection patterns
├── decoder.py         # Encoding detection
├── config.py          # Configuration
├── logger.py          # Logging
├── Dockerfile         # Container definition
├── requirements.txt   # Python dependencies
├── tests/
│   └── test_scanner.py
└── README.md
```

## 🤝 Contributing

Contributions welcome! To add new detection patterns:

1. Add regex patterns to `patterns.py`
2. Categorize by severity (critical/high/medium)
3. Add tests
4. Submit PR

## 📜 License

MIT License

## 🔗 Related Projects

- [openclaw-prompt-defender](https://github.com/ambushalgorithm/openclaw-prompt-defender) — OpenClaw plugin
- [prompt-injection-testing](https://github.com/ambushalgorithm/prompt-injection-testing) — Test samples
- [prompt-guard](https://github.com/seojoonkim/prompt-guard) — Regex patterns

---

<p align="center">
  <sub>Built with 🔒 for secure AI agents</sub>
</p>
