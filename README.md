# 🛡️ Prompt Defender Scanner

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
- 
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

# Run with friendly name
docker run -d --name prompt-defender-scanner -p 8080:8080 prompt-defender-scanner

# View logs
docker logs -f prompt-defender-scanner

# Stop
docker stop prompt-defender-scanner
```

### Option C: Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  scanner:
    image: prompt-defender-scanner
    container_name: prompt-defender-scanner
    ports:
      - "8080:8080"
```

```bash
# Start
docker-compose up -d

# View logs
docker logs -f prompt-defender-scanner

# Stop
docker-compose down
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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | any | Yes | Content to scan |
| `features` | object | No | Feature flags (see below) |
| `scan_tier` | number | No | 0=critical, 1=+high, 2=+medium |

Example:
```json
{
  "content": "Hello world",
  "features": {
    "prompt_guard": true
  },
  "scan_tier": 1
}
```

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

Configuration is flattened in the request body:

```json
{
  "features": {
    "prompt_guard": true,
    "ml_detection": false,
    "secret_scanner": false
  },
  "scan_tier": 1
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `features.prompt_guard` | `true` | Enable regex pattern scanning |
| `features.ml_detection` | `false` | Enable ML-based detection |
| `features.secret_scanner` | `false` | Enable secrets/PII detection |
| `scan_tier` | `1` | 0=critical only, 1=+high, 2=+medium |

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

- [openclaw-prompt-defender-plugin](https://github.com/ambushalgorithm/openclaw-prompt-defender-plugin) — OpenClaw plugin
- [prompt-injection-testing](https://github.com/ambushalgorithm/prompt-injection-testing) — Test samples
- [prompt-guard](https://github.com/seojoonkim/prompt-guard) — Regex patterns

---

<p align="center">
  <sub>Built with 🔒 for secure AI agents</sub>
</p>
