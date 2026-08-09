# auditron

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Stars](https://img.shields.io/github/stars/luis-recalde/auditron?style=social)
![Forks](https://img.shields.io/github/forks/luis-recalde/auditron?style=social)

Universal security audit skill for Claude Code. Audits any project — Next.js, React, Python, Node.js, FastAPI, WordPress, static sites — and generates a professional report with a 0-100 score, prioritized findings, and ready-to-apply remediation code.

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
Auditron detects the project type and adapts the audit accordingly:

| Stack | Detection | Tools |
|---|---|---|
| Next.js | `next.config.*`, `pages/`, `app/` | npm audit, headers, CSP |
| React | `package.json` + react dep | npm audit, XSS patterns |
| Node.js / Express | `express` in deps | npm audit, CORS, middleware |
| Python / FastAPI | `requirements.txt`, `pyproject.toml` | pip audit, SQLI, template injection |
| WordPress | `wp-config.php`, `wp-content/` | PHP patterns, plugin vulns |
| Generic PHP | `*.php`, `composer.json` | composer audit, injection |
| Static site | HTML/CSS/JS only | frontend secrets, headers |

This detection covers the frontend framework only. If the project also uses Supabase/Firebase, n8n, has payments/subscriptions, or includes Terraform/Kubernetes, Auditron runs those audits **in addition** to whatever stack was detected — a React project with Supabase gets the full React analysis *and* the database privilege audit, and an infrastructure-only repo (no frontend at all) still gets the Cloud/IaC audit.

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

**Backend-as-a-Service — Supabase / Firebase (real privilege audit, not just code):**
- Postgres RLS policies evaluated against the app's actual roles (admin/staff/customer, free/pro) — catches the moment a "fine between coworkers" broad access becomes a PII leak once an external role (customers, end users) joins the same auth pool
- `SECURITY DEFINER` functions: detects privilege escalation from misconfigured execution grants (including the implicit `PUBLIC` grant Postgres applies by default, which a partial `REVOKE` doesn't close)
- Missing `search_path` pinning on elevated-privilege functions (hijacking)
- Public storage buckets holding private user files
- Edge Functions with JWT verification disabled
- Firestore/Firebase Storage rules equivalent to `USING(true)`
- Optional live-verification technique (requires explicit permission): simulates low-privilege sessions against the real database to confirm a closed finding actually stayed closed

**Workflow automation — n8n (and Zapier/Make exports):**
- Webhook nodes with no authentication that trigger costly or sensitive actions (email/SMS to an address taken from the request body, with no rate limit) — validated against a real production workflow
- Credentials pasted directly into an HTTP Request node instead of using n8n's Credential system (ends up in plaintext in every export/backup)
- Code/Execute Command nodes running `eval()` or shell commands on data sourced from an external Webhook
- Exposed `N8N_ENCRYPTION_KEY` (decrypts every credential stored in the instance) and internet-facing instances with no user authentication

**SaaS, marketplaces & monetization (freemium, subscriptions, user-to-user sales):**
- Paywalls/premium features checked only client-side (bypassable by calling the API directly)
- Checkout amount or plan trusted from the client instead of computed server-side
- Payment webhooks with no replay protection (double-crediting) or that ignore a failed signature check
- Paid digital assets served via permanent public URLs instead of short-lived signed ones
- Free-trial / disposable-account abuse with no durable identity check
- "Wallet attacks" — costly features (AI, rendering) with no server-side per-user usage cap
- Marketplaces: seller commission/payout computed client-side
- Multi-tenant isolation: tenant/organization must come from the session, never a URL/body parameter

**Race conditions & business-logic invariants (TOCTOU, check-then-act) — runs on every project, no trigger needed:**
- Quotas/limits/counters checked and incremented in two separate steps instead of one atomic statement (monthly/rate limit bypass under concurrency)
- One-time tokens (password reset, OTP, invite) consumed non-atomically — the same token can succeed twice in parallel
- Idempotency keys stored only in a single process's memory, or not scoped to the calling principal
- Uniqueness (one account per email, one order per click) enforced only in application code, with no backing DB unique constraint
- State-machine transitions (pending→approved→shipped→refunded) applied without validating the current state first — enables double refunds or out-of-order steps
- Inventory/seat/booking reservations with no atomic release path on abandonment or timeout
- Recommended validation: a real concurrent-request test (with explicit authorization) before reporting CRITICAL/HIGH severity

**Advanced & less common vectors (but real):**
- JWT algorithm confusion (RS256/HS256)
- IDOR via sequential/enumerable IDs
- Excessive data exposure (`SELECT *` returned as-is to the client)
- Session fixation, CSRF on state-changing GET requests
- User enumeration via differing messages/response times
- Prototype pollution, ReDoS, dependency confusion, OAuth open redirect
- GraphQL: introspection left on in production, field/resolver-level authorization, missing depth/complexity limits, verbose errors, mutations over GET with cookie auth

**Cloud infrastructure & IaC (Terraform, Kubernetes, CI/CD):**
- Committed `terraform.tfstate` (contains plaintext secrets even when a variable is marked `sensitive = true`)
- IAM policies with `Action: *` + `Resource: *` on application identities, not just humans
- Public S3/GCS buckets holding backups or user files
- Kubernetes containers running `privileged: true` or as root, clusters with zero `NetworkPolicy` resources
- Kubernetes secrets injected as a literal env value instead of `secretKeyRef`
- Long-lived static cloud credentials in CI/CD instead of short-lived OIDC

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

Your website or app handles customer data, processes payments, and keeps your business running. A security breach can mean data loss, regulatory fines, and reputation damage — all at once.

Auditron runs a full security review before that happens:

**Finds what you can't see** — hardcoded passwords and API keys in your code, insecure settings, libraries with known vulnerabilities. These are the most common mistakes and the most expensive ones when attackers exploit them.

**Built for the region** — understands MercadoPago payments, AFIP/SAT/SII electronic invoicing, and sensitive data like CUIT or DNI. Not a generic English-first scanner: built for the Latin American ecosystem.

**No security expertise needed** — a single command audits the entire project. The report explains every issue in plain language with a ready-to-apply fix.

**Professional-grade coverage** — follows the OWASP and CWE international standards used by enterprise security teams. The same rigor, available to any team.

## Author

**Luis Recalde** — [info@luisrecalde.com](mailto:info@luisrecalde.com)

MIT License — 2026
