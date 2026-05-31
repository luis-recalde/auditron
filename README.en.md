# auditron

Universal security audit agent for Claude Code. Audits any project — Next.js, React, Python, Node.js, FastAPI, WordPress, static sites — and generates a professional report with a 0-100 score, prioritized findings, and ready-to-apply remediation code.

## Installation

```bash
# Clone into your Claude Code skills directory
git clone https://github.com/luis-recalde/auditron ~/.claude/skills/auditron

# Or copy SKILL.md directly into your project
cp ~/.claude/skills/auditron/SKILL.md .claude/SKILL.md
```

## Usage

```
/auditron
```

Or just tell Claude: *"audit this project"*, *"check security"*, *"find vulnerabilities"*, *"run a pentest"*.

## What it analyzes

### Automatic stack detection
The agent detects the project type and adapts the audit accordingly:

| Stack | Detection | Tools |
|---|---|---|
| Next.js | `next.config.*`, `pages/`, `app/` | npm audit, headers, CSP |
| React | `package.json` + react dep | npm audit, XSS patterns |
| Node.js / Express | `express` in deps | npm audit, CORS, middleware |
| Python / FastAPI | `requirements.txt`, `pyproject.toml` | pip audit, SQLI, template injection |
| WordPress | `wp-config.php`, `wp-content/` | PHP patterns, plugin vulns |
| Generic PHP | `*.php`, `composer.json` | composer audit, injection |
| Static site | HTML/CSS/JS only | frontend secrets, headers |

### Security coverage

**Full OWASP 2025 Top 10:**
- A01 Broken Access Control
- A02 Cryptographic Failures
- A03 Injection (SQL, NoSQL, Command, LDAP, XPath)
- A04 Insecure Design
- A05 Security Misconfiguration
- A06 Vulnerable & Outdated Components
- A07 Identification & Authentication Failures
- A08 Software & Data Integrity Failures
- A09 Security Logging & Monitoring Failures
- A10 Server-Side Request Forgery

**CWE Top 25 — applicable by language**

**70+ secret patterns:**
- AWS (Access Key, Secret Key, Session Token, MFA, Account ID)
- GCP (Service Account, API Key, OAuth)
- Azure (Connection String, Storage Key, SAS Token)
- Stripe (Live/Test Secret, Webhook)
- MercadoPago (Access Token, Public Key, Client Secret)
- PayPal (Client ID/Secret, Webhook)
- Supabase (Service Role Key, Anon Key, JWT Secret)
- Firebase (API Key, Admin SDK, Database URL)
- MongoDB Atlas (Connection String with credentials)
- JWT secrets and signing keys
- SSH private keys (RSA, ECDSA, Ed25519)
- SMTP credentials (Gmail, Outlook, custom)
- Twilio (Account SID, Auth Token)
- SendGrid (API Key)
- GitHub (classic PAT, fine-grained, OAuth App)
- GitLab (Personal, Deploy, Group tokens)
- npm auth tokens
- Docker Hub access tokens
- Slack (Bot Token, Webhook URL)
- Discord (Bot Token, Webhook)
- Telegram (Bot Token)
- OpenAI (API Key)
- Anthropic (API Key)
- Cloudflare (Global API Key, Token)
- HubSpot (API Key, Private App Token)
- Salesforce (Instance URL + token)
- Spanish-language variables: CLAVE_, SECRETO_, CONTRASENA_, TOKEN_MP_, USUARIO_DB_, etc.

**LATAM-specific checks:**
- MercadoPago: payment flows, webhooks, IPN validation
- CUIT/CUIL/DNI exposure in code or API responses
- Electronic invoicing: AFIP (Argentina), SAT (Mexico), SII (Chile)
- Unobfuscated Spanish-language environment variables

### Security headers
Reviews and generates configuration for:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-*` headers

### Dependency audit
- `npm audit` with severity analysis
- `pip audit` for Python projects
- `composer audit` for PHP/WordPress
- Detection of abandoned or unmaintained dependencies

## Report format

The report has a **0-100 score** and is organized into sections:

```
FINAL SCORE: 73/100

[CRITICAL]      2 findings  — block deploy
[HIGH]          4 findings  — fix before production
[MEDIUM]        6 findings  — fix in next sprint
[LOW]           8 findings  — recommended improvements
[INFORMATIONAL] 3 findings  — best practices

Each finding includes:
  - Problem description
  - Exact file and line number
  - OWASP / CWE reference
  - Ready-to-apply remediation code
```

## Pre-deploy checklist

At the end of the report, a stack-specific checklist is generated. Example for Next.js:

```
PRE-DEPLOY CHECKLIST — Next.js
[ ] Environment variables in .env.local, not in committed .env
[ ] NEXTAUTH_SECRET set to a strong value (32+ chars)
[ ] next.config.js with security headers configured
[ ] CSP policy defined and tested
[ ] API routes with input validation (zod/yup)
[ ] Rate limiting on auth endpoints
[ ] npm audit with no critical/high findings
[ ] No console.log with sensitive data
[ ] .gitignore includes .env*
[ ] Dependencies up to date (90-day max lag)
```

## Why Auditron

**70+ secret patterns** — the broadest coverage available: AWS, GCP, Azure, Stripe, MercadoPago, Supabase, Firebase, GitHub, OpenAI, Anthropic, and 60+ more. No token goes undetected.

**LATAM-ready** — the first security agent with native support for MercadoPago (webhooks, IPN, tokens), CUIT/CUIL/CBU validation, electronic invoicing for AFIP/SAT/SII, and checks specific to the Latin American ecosystem.

**Spanish-language variables** — detects `CLAVE_`, `SECRETO_`, `CONTRASENA_`, `TOKEN_MP_`, `USUARIO_DB_`, and dozens of Spanish variants that English-first scanners routinely miss.

**7 supported stacks** — Next.js, React, Node.js/Express, Python/FastAPI, WordPress, generic PHP, and static sites. The audit adapts automatically to the project with zero configuration.

**Fix code included** — every critical and high finding ships with a ready-to-apply corrected code snippet. Not just the problem — the solution.

**Pre-deploy checklist** — every audit ends with a stack-specific checklist. Know exactly what to verify before going to production, without relying on memory.

## Author

**Luis Recalde** — [info@luisrecalde.com](mailto:info@luisrecalde.com)

MIT License — 2026
