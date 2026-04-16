# JSAnalSys — JavaScript Security Analyzer

> A Python-based JavaScript analysis platform for bug bounty hunters and security researchers.  
> Inspired by [jxscout](https://jxscout.app/) — built entirely in Python.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-35%20passing-brightgreen)

---

## What It Does

Modern web applications bundle and minify their JavaScript, hiding API endpoints, secrets, DOM sinks, and internal infrastructure. JSAnalSys automates the process of finding all of it:

- **Discovers every JS file** — including lazy-loaded Webpack/Vite/Next.js chunks that never appear in the HTML
- **Reverses source maps** — when developers accidentally expose `.map` files, you get the original unminified source with variable names, comments, and file structure
- **Beautifies minified code** — makes compressed one-liners readable
- **Runs 50+ security patterns** — secrets, API endpoints, DOM XSS sinks, postMessage issues, prototype pollution, weak crypto, and more
- **Saves everything to SQLite** — persistent project storage so you can resume sessions
- **Generates reports** — interactive dark-themed HTML report + JSON export
- **Live proxy mode** — mitmproxy addon to analyze JS as you browse

---

## Features

### Asset Discovery
| Feature | Details |
|---|---|
| HTML crawling | Extracts all `<script src>`, `<link rel="preload">`, inline `<script>` blocks |
| Webpack chunk enumeration | Parses runtime bundle for chunk ID→filename maps, hash maps |
| Vite chunk discovery | Reads `manifest.json`, scans for `/assets/*.js` references |
| Next.js discovery | Parses `_buildManifest.js`, probes standard chunk paths |
| Numeric brute-force | Optional: probe `0.chunk.js`, `1.chunk.js`, ... up to N |
| Cross-origin support | Optionally follow JS from CDNs and third-party domains |

### Source Map Reversal
- Detects `//# sourceMappingURL=` comments
- Handles relative URLs, absolute URLs, and inline `data:` URIs
- Downloads and parses V3 source maps
- Reconstructs all original source files with their real filenames
- Saves to disk: `src/components/App.tsx`, `src/api/client.ts`, etc.
- Probes for `.map` files even when not referenced in JS

### Static Analysis — 50+ Built-in Patterns

| Category | What's detected |
|---|---|
| **Secrets** | AWS keys, GitHub tokens, Stripe keys, JWT, Firebase, SendGrid, Twilio, Mailchimp, Slack webhooks, Discord tokens, Azure connection strings, NPM tokens, private keys, generic credentials |
| **Endpoints** | API paths (`/api/v1/...`), GraphQL endpoints, WebSocket URLs, fetch/axios calls, internal paths (`/admin/`, `/debug/`) |
| **Hostnames** | S3 buckets, GCS buckets, Azure Blob, private IPs (RFC1918), internal hostnames, localhost refs |
| **DOM Sinks** | `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `new Function()`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, jQuery `.html()` |
| **postMessage** | Wildcard origin `*`, missing origin validation, all message listeners |
| **Prototype Pollution** | `.__proto__[`, `constructor.prototype`, `Object.assign` with user input |
| **Storage** | `localStorage`/`sessionStorage` access, sensitive keys (token, auth, jwt, password), `document.cookie` |
| **Crypto** | MD5/SHA1 usage, hardcoded IVs, `Math.random()` for crypto |

### Reports
- Interactive **HTML report** with dark theme, severity badges, collapsible findings, type filters
- **JSON export** for automation and pipeline integration
- Findings sorted by severity (Critical → High → Medium → Low → Info)

### Proxy Mode (mitmproxy)
Intercept live browser traffic and analyze JS in real time as you browse:
```bash
mitmdump -s jsanalsys/proxy/interceptor.py \
  --set jsanalsys_project=myproject \
  --set jsanalsys_db=/path/to/jsanalsys.db
```

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/narenreddy3/jsanalsys-python
cd jsanalsys-python

pip install -r requirements.txt
pip install -e .
```

### Core dependencies
| Package | Purpose |
|---|---|
| `requests` | HTTP client |
| `beautifulsoup4` + `lxml` | HTML parsing |
| `jsbeautifier` | JS formatting |
| `sqlalchemy` | SQLite ORM |
| `click` | CLI framework |
| `rich` | Terminal UI |
| `mitmproxy` | Proxy mode (optional) |

---

## Usage

### Full Scan
```bash
jsanalsys scan https://target.com
```

This runs the full pipeline:
1. Crawl the page, find all JS files
2. Discover Webpack/Vite/Next.js chunks
3. Fetch and beautify all JS
4. Download and reverse source maps
5. Run all 50+ analysis patterns
6. Generate HTML + JSON reports

### Common Options

```bash
# Save output to a specific directory
jsanalsys scan https://target.com --output ./results/target

# Route through Burp Suite
jsanalsys scan https://target.com \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl

# Pass session cookies (for authenticated scans)
jsanalsys scan https://target.com \
  --cookies '{"session": "abc123", "csrftoken": "xyz"}'

# Add custom request headers
jsanalsys scan https://target.com \
  --headers '{"Authorization": "Bearer token123"}'

# Only report high and above
jsanalsys scan https://target.com --min-severity high

# Enable numeric chunk brute-forcing
jsanalsys scan https://target.com --brute-chunks 500

# Follow cross-origin JS (CDNs, third parties)
jsanalsys scan https://target.com --cross-origin

# Save all JS files to disk
jsanalsys scan https://target.com --save-js

# Limit scope to specific patterns
jsanalsys scan https://target.com \
  --scope "api\.target\.com" \
  --scope "static\.target\.com"

# Add request delay (be polite)
jsanalsys scan https://target.com --delay 1.0
```

### Analyze a Local JS File

```bash
# Analyze a downloaded/local JS file
jsanalsys analyze bundle.min.js

# Save findings to JSON
jsanalsys analyze bundle.min.js --output findings.json

# Only critical and high findings
jsanalsys analyze bundle.min.js --min-severity high
```

### Reverse a Source Map

```bash
# Fetch a JS file and reverse its source map
jsanalsys sourcemap https://target.com/static/js/main.abc123.js \
  --output ./source_output

# With proxy
jsanalsys sourcemap https://target.com/static/js/app.js \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl
```

Output structure:
```
source_output/
├── src/
│   ├── components/
│   │   ├── App.tsx
│   │   ├── Dashboard.tsx
│   │   └── Login.tsx
│   ├── api/
│   │   ├── client.ts
│   │   └── endpoints.ts
│   └── utils/
│       └── auth.ts
```

### Project Management

```bash
# List all projects
jsanalsys project list

# Create a project manually
jsanalsys project create myproject https://target.com

# Delete a project
jsanalsys project delete myproject
```

### View Findings

```bash
# All findings for a project
jsanalsys findings myproject

# Filter by type
jsanalsys findings myproject --type secret
jsanalsys findings myproject --type dom_sink
jsanalsys findings myproject --type endpoint

# Filter by severity
jsanalsys findings myproject --severity critical

# Filter by category
jsanalsys findings myproject --category aws_access_key

# Export to JSON
jsanalsys findings myproject --output findings.json
```

### Generate Reports

```bash
# HTML + JSON (default)
jsanalsys report myproject --output ./reports

# HTML only
jsanalsys report myproject --format html

# JSON only
jsanalsys report myproject --format json
```

### List All Patterns

```bash
# Show all 50+ built-in patterns
jsanalsys patterns

# Filter by type
jsanalsys patterns --type secret
jsanalsys patterns --type dom_sink
```

---

## Project Structure

```
jsanalsys-python/
├── jsanalsys/
│   ├── cli.py                  # CLI entry point (Click + Rich)
│   ├── config.py               # Config management (~/.jsanalsys/config.json)
│   ├── core/
│   │   ├── fetcher.py          # HTTP client with proxy/retry/rate-limiting
│   │   ├── crawler.py          # HTML crawler — discovers all JS assets
│   │   ├── chunk_discovery.py  # Webpack/Vite/Next.js chunk enumeration
│   │   ├── sourcemap.py        # Source map download and reversal
│   │   └── beautifier.py       # JS beautification (jsbeautifier)
│   ├── analysis/
│   │   ├── patterns.py         # 50+ built-in regex patterns
│   │   └── engine.py           # Analysis engine with dedup + severity filter
│   ├── db/
│   │   └── models.py           # SQLAlchemy models (Project, Asset, Finding)
│   ├── proxy/
│   │   └── interceptor.py      # mitmproxy addon for live interception
│   └── reporting/
│       └── reporter.py         # HTML + JSON report generation
└── tests/
    └── test_analysis.py        # 35 unit tests
```

---

## Configuration

Settings can be stored in `~/.jsanalsys/config.json` or set via environment variables:

```json
{
  "proxy": "http://127.0.0.1:8080",
  "verify_ssl": false,
  "delay": 0.5,
  "min_severity": "medium",
  "beautify": true,
  "chunk_discovery": true,
  "sourcemaps": true
}
```

| Env Variable | Description |
|---|---|
| `JSANALSYS_PROXY` | Default proxy URL |
| `JSANALSYS_DB` | Custom DB path |
| `JSANALSYS_DELAY` | Request delay in seconds |
| `JSANALSYS_MIN_SEVERITY` | Minimum severity to report |
| `JSANALSYS_VERIFY_SSL` | SSL verification (`true`/`false`) |

---

## Example Report

The HTML report is a self-contained dark-themed interactive page:

- **Stats dashboard** — Critical / High / Medium / Low / Info counts at a glance
- **Filter bar** — one-click filtering by Secrets, Endpoints, DOM Sinks, postMessage, etc.
- **Collapsible findings** — click any finding to expand the matched value and code context
- **Asset list** — all discovered JS files with chunk/sourcemap badges

---

## Proxy Mode (Live Traffic)

Route your browser through mitmproxy with JSAnalSys as an addon to analyze every JS file you encounter while browsing:

```bash
# Start the proxy
mitmdump -s jsanalsys/proxy/interceptor.py \
  --set jsanalsys_project=bugbounty_target \
  --set jsanalsys_db=./session.db \
  -p 8080

# Configure your browser to use 127.0.0.1:8080
# Browse the target — every JS response is automatically captured and analyzed
```

Real-time terminal output:
```
[JSAnalSys] https://target.com/static/js/main.js → 2C 5H 12M 48I findings
[JSAnalSys] https://target.com/static/js/vendor.js → 0C 1H 3M 22I findings
```

Then generate your report:
```bash
jsanalsys report bugbounty_target --output ./reports
```

---

## Running Tests

```bash
pytest tests/ -v
```

```
35 passed in 0.54s
```

Tests cover: analysis engine, all pattern categories, endpoint extraction, hostname extraction, beautifier, URL normalization, and pattern validity.

---

## Finding Types Reference

| `finding_type` | Description |
|---|---|
| `secret` | Hardcoded credentials, API keys, tokens |
| `endpoint` | API paths, full URLs, WebSocket endpoints |
| `hostname` | Domain names, IPs, cloud storage buckets |
| `dom_sink` | Dangerous DOM APIs — XSS vectors |
| `postmessage` | postMessage calls and message listeners |
| `prototype_pollution` | Prototype pollution vectors |
| `storage` | Browser storage access |
| `crypto_weakness` | Weak hash functions, insecure random |

---

## Severity Levels

| Level | Color | Examples |
|---|---|---|
| `critical` | Red | AWS keys, private keys, Stripe live keys, GitHub tokens |
| `high` | Orange | JWT tokens, DOM XSS sinks, postMessage wildcard, Firebase keys |
| `medium` | Yellow | Generic secrets, internal paths, S3 buckets, private IPs |
| `low` | Blue | Localhost refs, Math.random() |
| `info` | Grey | API paths, localStorage access, full URLs |

---

## License

MIT
