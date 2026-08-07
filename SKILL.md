# auditron — Universal Security Audit Agent

**TRIGGER:** Run this skill when the user says: "auditá", "audit", "security audit", "security review", "pentest", "buscá vulnerabilidades", "revisá la seguridad", "find vulnerabilities", "security check", "check for secrets", "revisá el código", or invokes /cyber, /security-audit, /auditron.

---

## PHASE 0 — ORIENT

Before anything else, tell the user:
> "Iniciando auditoría de seguridad auditron. Detectando stack..."

Then run these reads in parallel to understand the project:

```
Read: package.json, requirements.txt, pyproject.toml, composer.json, Cargo.toml
Read: next.config.js, next.config.ts, next.config.mjs
Read: wp-config.php (if exists)
Glob: **/*.env*, .env, .env.local, .env.production, .env.example
Glob: **/Dockerfile, docker-compose.yml, docker-compose.yaml
Glob: .github/workflows/*.yml, .github/workflows/*.yaml
Glob: nginx.conf, apache.conf, **/httpd.conf
```

---

## PHASE 1 — STACK DETECTION

Classify the project. Use the first match:

| Signal | Stack |
|---|---|
| `next` in package.json deps OR `next.config.*` exists | **NEXTJS** |
| `react` in deps, no `next` | **REACT** |
| `express` OR `fastify` OR `koa` in deps | **NODE_EXPRESS** |
| `fastapi` OR `flask` OR `django` in requirements.txt | **PYTHON_WEB** |
| `wp-config.php` exists OR `wp-content/` directory | **WORDPRESS** |
| `*.php` files exist, no WP signals | **PHP_GENERIC** |
| Only HTML/CSS/JS, no package.json | **STATIC** |
| Mixed signals | **MULTI_STACK** — audit all applicable |

Announce: `Stack detectado: [STACK]. Adaptando auditoría...`

**Backend-as-a-Service, workflow automation, monetization, and cloud infrastructure are orthogonal layers, not Phase 1 categories.** A project is classified above by its *frontend/framework* stack, but separately check for: a BaaS backend (Supabase, Firebase → Phase 4), n8n or another workflow-automation layer (→ Phase 5), a monetization layer (payments, subscriptions, marketplace → Phase 6), and Terraform/Kubernetes/cloud IAM config (→ Phase 8) — each triggers independently of which row matched above. A `REACT` project with `@supabase/supabase-js` in its dependencies is still `REACT` for Phase 1 purposes, but it also gets the full Phase 4 database-privilege audit; a project with no frontend framework at all but a `terraform/` directory still gets Phase 8. Never skip an orthogonal phase just because the project matched (or didn't cleanly match) a frontend-only row here.

---

## PHASE 2 — SECRET SCANNING (70+ patterns)

Scan ALL files recursively. Use Grep with these patterns. Flag any match as **CRITICAL** unless in `.env.example` or clearly a placeholder (`your_key_here`, `xxxx`, `REPLACE_ME`, `<your_`, `YOUR_`).

### AWS
```
AKIA[0-9A-Z]{16}                          # AWS Access Key ID
(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}   # AWS Secret Access Key
(?i)aws.{0,20}session.{0,20}token         # AWS Session Token
(?i)aws_account_id\s*=\s*['\"]?\d{12}    # AWS Account ID
```

### GCP / Google
```
AIza[0-9A-Za-z\-_]{35}                   # GCP/Firebase API Key
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com  # OAuth Client ID
(?i)"type":\s*"service_account"          # GCP Service Account JSON
ya29\.[0-9A-Za-z\-_]+                    # Google OAuth Access Token
```

### Azure
```
(?i)DefaultEndpointsProtocol=https;AccountName=  # Azure Storage Connection String
(?i)AccountKey=[a-zA-Z0-9+/=]{88}        # Azure Storage Account Key
[?&]sig=[a-zA-Z0-9%+/=]{43,}            # Azure SAS Token
```

### Stripe
```
sk_live_[0-9a-zA-Z]{24,}                 # Stripe Live Secret Key — CRITICAL
sk_test_[0-9a-zA-Z]{24,}                 # Stripe Test Secret Key
rk_live_[0-9a-zA-Z]{24,}                 # Stripe Restricted Live Key
whsec_[0-9a-zA-Z]{32,}                   # Stripe Webhook Secret
pk_live_[0-9a-zA-Z]{24,}                 # Stripe Live Publishable (Medium — exposed in client)
```

### MercadoPago (LATAM PRIORITY)
```
APP_USR-[0-9]+-[0-9]{6}-[0-9a-f]{32}-[0-9]+   # MP Access Token
(?i)(mp_access_token|mercadopago.{0,10}token|TOKEN_MP)\s*[=:]\s*['\"]?APP_USR
TEST-[0-9]+-[0-9]{6}-[0-9a-f]{32}-[0-9]+       # MP Test Access Token
(?i)(mp_public_key|mercadopago.{0,10}public)\s*[=:]\s*['\"]?TEST-
(?i)(mp_client_secret|mercadopago.{0,10}secret)
(?i)(mercadopago|mercado_pago|mp_sdk).*secret
```

### PayPal
```
(?i)paypal.{0,20}client.{0,10}secret\s*[=:]\s*['\"][A-Za-z0-9_-]{32,}
(?i)paypal.{0,20}(access_token|bearer)\s*[=:]\s*['\"]A21AA
```

### Supabase
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+   # JWT (check sub)
(?i)supabase.{0,20}service_role\s*[=:]\s*['\"]eyJ    # Supabase Service Role Key — CRITICAL
(?i)supabase.{0,20}(anon|key)\s*[=:]\s*['\"]eyJ      # Supabase Anon Key
(?i)SUPABASE_SERVICE_ROLE_KEY\s*=\s*['\"]?eyJ
(?i)supabase\.io.*key=[a-zA-Z0-9._-]{100,}
```

### Firebase
```
(?i)firebase.{0,20}(api_?key|apiKey)\s*[=:]\s*['\"]AIza  # Firebase API Key
(?i)firebase.{0,20}(database_url|databaseURL)             # Firebase DB URL
(?i)firebaseio\.com                                        # Firebase DB exposure check
(?i)firebase-adminsdk.*\.json                              # Admin SDK file
```

### MongoDB
```
mongodb(\+srv)?://[^:]+:[^@]+@                # MongoDB connection string with credentials
(?i)MONGO(DB)?_URI\s*=.*@                     # Env var with credentials
(?i)MONGO(DB)?_PASSWORD\s*[=:]\s*['\"]?\S{8,}
```

### Database (generic)
```
(?i)(DATABASE_URL|DB_URL|DB_CONNECTION)\s*=.*(postgres|mysql|mssql)://[^:]+:[^@]+@
(?i)(DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD)\s*[=:]\s*['\"]?\S{6,}
(?i)Data Source=.*Password=\S+               # MSSQL connection string
```

### JWT
```
(?i)(jwt_secret|jwt_key|jwt_signing|JWT_SECRET|SECRET_KEY)\s*[=:]\s*['\"]?\S{8,}
(?i)(nextauth_secret|NEXTAUTH_SECRET)\s*[=:]\s*['\"]?\S{8,}
```

### SSH / TLS
```
-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----   # SSH/TLS Private Key — CRITICAL
-----BEGIN PRIVATE KEY-----                          # PKCS8 Private Key — CRITICAL
-----BEGIN PGP PRIVATE KEY BLOCK-----               # PGP Private Key — CRITICAL
```

### SMTP / Email
```
(?i)(smtp_password|smtp_pass|email_password|MAIL_PASSWORD)\s*[=:]\s*['\"]?\S{6,}
(?i)(sendgrid_api_key|SENDGRID_API_KEY)\s*[=:]\s*['\"]?SG\.[A-Za-z0-9_-]{22,}
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}          # SendGrid API Key direct
```

### Twilio
```
AC[a-z0-9]{32}                                      # Twilio Account SID
(?i)(twilio.{0,10}auth.{0,10}token|TWILIO_AUTH)\s*[=:]\s*['\"]?[a-f0-9]{32}
SK[a-z0-9]{32}                                      # Twilio API Key SID
```

### GitHub / GitLab
```
ghp_[A-Za-z0-9]{36}                               # GitHub Classic PAT
github_pat_[A-Za-z0-9_]{82}                       # GitHub Fine-Grained PAT
gho_[A-Za-z0-9]{36}                               # GitHub OAuth Token
ghs_[A-Za-z0-9]{36}                               # GitHub Actions Token
ghr_[A-Za-z0-9]{36}                               # GitHub Refresh Token
glpat-[A-Za-z0-9\-_]{20}                          # GitLab Personal Access Token
glptt-[A-Za-z0-9\-_]{40}                          # GitLab Pipeline Trigger Token
gldt-[A-Za-z0-9\-_]{20}                           # GitLab Deploy Token
```

### npm / Docker / Package Registries
```
//registry\.npmjs\.org/:_authToken\s*=\s*\S+      # npm auth token in .npmrc
npm_[A-Za-z0-9]{36}                               # npm Access Token
(?i)dockerhub.{0,20}(password|token)\s*[=:]\s*['\"]?\S{8,}
dckr_pat_[A-Za-z0-9_-]{27}                        # Docker Hub Personal Access Token
```

### Slack / Discord / Telegram
```
xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}         # Slack Bot Token
xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-z0-9]{32}  # Slack User Token
https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+  # Slack Webhook
(?i)discord.{0,15}(bot_?token|token)\s*[=:]\s*['\"]?[MN][A-Za-z0-9]{23}\.
https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]{68}  # Discord Webhook
[0-9]{8,10}:[A-Za-z0-9_-]{35}                    # Telegram Bot Token
```

### OpenAI / Anthropic / AI APIs
```
sk-[A-Za-z0-9]{48}                               # OpenAI API Key (legacy)
sk-proj-[A-Za-z0-9_-]{48,}                       # OpenAI Project API Key
sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{93}AA           # Anthropic API Key
(?i)(openai_api_key|OPENAI_KEY)\s*[=:]\s*['\"]?sk-
(?i)(anthropic_api_key|ANTHROPIC_KEY)\s*[=:]\s*['\"]?sk-ant
```

### Cloudflare / CDN
```
(?i)cloudflare.{0,20}(api_key|global_key)\s*[=:]\s*['\"]?[a-f0-9]{37}
(?i)(CF_API_KEY|CLOUDFLARE_API_KEY)\s*[=:]\s*['\"]?\S{37,}
[A-Za-z0-9_-]{40}\.cloudflareaccess\.com
```

### CRM / Marketing
```
(?i)(hubspot_api_key|HUBSPOT_KEY)\s*[=:]\s*['\"]?[a-f0-9-]{36}
pat-[a-z]{2}[0-9]-[a-f0-9-]{36}                  # HubSpot Private App Token
(?i)(salesforce.{0,20}token|SF_ACCESS_TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9!]{80,}
```

### Spanish-Language Variables (LATAM PRIORITY)
```
(?i)(CLAVE|SECRETO|CONTRASENA|CONTRASEÑA)\s*[=:]\s*['\"]?\S{6,}
(?i)(TOKEN_MP|TOKEN_PAGO|CLAVE_PRIVADA|CLAVE_PUBLICA)\s*[=:]\s*['\"]?\S{8,}
(?i)(USUARIO_DB|USUARIO_BD|PASS_DB|PASS_BD)\s*[=:]\s*['\"]?\S{6,}
(?i)(API_CLAVE|CLAVE_API|LLAVE_API|LLAVE_SECRETA)\s*[=:]\s*['\"]?\S{8,}
(?i)(ACCESO_TOKEN|TOKEN_ACCESO|TOKEN_SECRETO)\s*[=:]\s*['\"]?\S{8,}
```

### LATAM Data Exposure
```
\b(20|23|24|25|26|27|30|33|34)\d{8}\b             # CUIT/CUIL Argentina (11 digits starting with valid prefixes)
\b[0-9]{2}\.[0-9]{3}\.[0-9]{3}[-/][0-9]\b         # CUIT formatted (XX.XXX.XXX-X)
(?i)(cuit|cuil|cbu|cvu)\s*[=:]\s*['\"]?\d{11,22}  # Argentine tax/bank IDs in code
```

### Generic High-Entropy Secrets
```
(?i)(secret|password|passwd|pwd|pass|token|apikey|api_key|auth_token|access_token|private_key)\s*[=:]\s*['"]\S{16,}['"]
(?i)(secret|password|token|key)\s*[:=]\s*[a-zA-Z0-9+/]{32,}={0,2}\b  # Base64-looking values
```

**For each secret found, report:**
```
[CRITICO] Secret expuesto — <tipo>
Archivo: <path>:<line>
Patrón: <which pattern matched>
OWASP: A02 - Cryptographic Failures
CWE: CWE-798 (Use of Hard-coded Credentials)
Fix:
  1. Rotar la credencial INMEDIATAMENTE en el proveedor
  2. Mover a variable de entorno:
     # .env.local (nunca commitear)
     <VARIABLE_NAME>=<valor>
  3. Acceder en código:
     process.env.<VARIABLE_NAME>  // Node/Next.js
     os.environ["<VARIABLE_NAME>"]  // Python
  4. Agregar .env* al .gitignore
  5. Verificar historial git: git log -p --all | grep <partial_value>
     Si está en historial: rotar, usar git-filter-repo para purgar
```

---

## PHASE 3 — OWASP 2025 TOP 10

### A01 — Broken Access Control

**All stacks:** Search for:
```
# Missing authorization on sensitive routes
(?i)(admin|dashboard|panel|config|settings)\s*route without auth middleware
# IDOR patterns
/api/users/\$\{id\} or /api/users/:id without ownership check
# Path traversal
\.\./  or  \.\.\\  in file operations
# JWT missing verification
jwt\.decode\( without verify
jsonwebtoken\.decode\( (not jwt.verify)
# Direct object references
findById\(req\.(params|query|body)\.id\) without user check
```

**Check for:**
- Routes without authentication middleware
- `req.user.id` vs `req.params.id` — user can only access their own resources
- Admin functions accessible without admin role check
- CORS `Access-Control-Allow-Origin: *` on authenticated endpoints

**Fix pattern for missing auth (Next.js):**
```typescript
// app/api/user/[id]/route.ts
import { getServerSession } from "next-auth"
export async function GET(req: Request, { params }) {
  const session = await getServerSession(authOptions)
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 })
  if (session.user.id !== params.id && session.user.role !== "admin") {
    return Response.json({ error: "Forbidden" }, { status: 403 })
  }
  // proceed
}
```

---

### A02 — Cryptographic Failures

**Search for:**
```
# Weak hash algorithms
(?i)(md5|sha1)\s*\(              # MD5/SHA1 in use
createHash\(['"]md5['"]          # Node.js crypto MD5
hashlib\.(md5|sha1)\(           # Python MD5/SHA1
password_hash.*MD5              # PHP MD5 passwords

# Hardcoded crypto keys (also caught by secret scan)
(?i)(aes|des|rsa).{0,20}key\s*=\s*['"][a-f0-9]{16,}

# HTTP URLs for sensitive operations
fetch\(['"]http://              # HTTP in fetch calls
axios\.(get|post)\(['"]http://  # HTTP in axios

# Insecure random
Math\.random\(\).*(?i)(token|secret|key|session|nonce)  # Math.random for crypto
random\.random\(\).*(?i)(token|secret|key)              # Python insecure random
```

**Fix for weak hashing (passwords):**
```javascript
// BAD
const hash = crypto.createHash('md5').update(password).digest('hex')

// GOOD — bcrypt
import bcrypt from 'bcryptjs'
const hash = await bcrypt.hash(password, 12)
const valid = await bcrypt.compare(inputPassword, storedHash)
```

```python
# GOOD — Python
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed = pwd_context.hash(password)
valid = pwd_context.verify(plain, hashed)
```

---

### A03 — Injection

**SQL Injection — search for:**
```
# String concatenation in queries
['"`]\s*\+\s*(req\.|params\.|query\.|body\.|user\.)  # JS/TS
['"`]\s*%\s*\(?(request\.|params\.|form\.)           # Python format
\$\{\s*(req|params|query|body|user)\.                # Template literal SQL
\.format\(.*request\.                                 # Python .format() in SQL
f["']SELECT.*\{                                       # Python f-string SQL
"SELECT.*"\s*\+\s*(req|params|query)                 # Java-style concat
mysql_query\s*\(.*\$_                                # PHP raw MySQL + superglobal
```

**Command Injection:**
```
exec\s*\(.*req\.                # exec with user input
execSync\s*\(.*req\.            # execSync with user input
spawn\s*\(.*req\.               # spawn with user input
os\.system\s*\(.*request\.      # Python os.system
subprocess\..*shell=True.*request  # Python shell=True + user input
eval\s*\(.*req\.                # eval with user input (also XSS)
```

**NoSQL Injection (MongoDB):**
```
find\s*\(\s*\{\s*[a-z]+\s*:\s*req\.body\.[a-z]+\s*\}  # Direct req.body in find
\$where.*req\.                                          # $where operator + user input
\$regex.*req\.                                          # Unescaped regex from user
```

**LDAP Injection:**
```
(?i)ldap.*filter.*req\.        # LDAP filter with user input
```

**XPath Injection:**
```
(?i)xpath.*select.*req\.       # XPath with user input
```

**Fix for SQL (parameterized queries):**
```typescript
// BAD
const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)

// GOOD
const user = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id])

// GOOD with ORM (Prisma)
const user = await prisma.user.findUnique({ where: { id: req.params.id } })
```

```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# GOOD
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

---

### A04 — Insecure Design

**Check for:**
- No rate limiting on auth endpoints
- Password reset tokens that don't expire
- Mass assignment vulnerabilities (accepting all body fields)
- Missing input validation schemas
- Business logic: negative quantities in cart, price manipulation

**Search for:**
```
# No rate limiting
app\.(post|put)\s*\(['"]/(auth|login|register|password|reset)  # Auth routes without rate-limit middleware
# Mass assignment
\.save\s*\(\s*req\.body\s*\)   # Direct body to save
\.create\s*\(\s*req\.body\s*\) # Direct body to create
Model\.update\s*\(.*req\.body  # Direct body to update
```

**Fix (rate limiting):**
```typescript
import rateLimit from 'express-rate-limit'
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: { error: "Demasiados intentos. Intenta en 15 minutos." }
})
app.use('/api/auth', authLimiter)
```

---

### A05 — Security Misconfiguration

**Search for:**
```
# Debug mode in production
(?i)DEBUG\s*=\s*(True|true|1|yes)  # Debug enabled
debug:\s*true                       # Express debug
app\.run\s*\(.*debug\s*=\s*True    # Flask debug=True

# Exposed stack traces
(?i)send(Stack|Error)\s*\(\s*err   # Sending raw errors to client
res\.json\s*\(\s*err\s*\)          # Raw error in response
return\s+error\.message            # Leaking error messages

# Default credentials
(?i)(admin:admin|root:root|test:test|admin:password)  # Default creds
(?i)password\s*=\s*['"]?(admin|password|123456|test|root)['"]?

# CORS misconfiguration
origin:\s*['"]?\*['"]?            # Wildcard CORS origin
Access-Control-Allow-Origin.*\*   # Wildcard header
```

**Fix (CORS):**
```typescript
// BAD
app.use(cors({ origin: '*' }))

// GOOD
const allowedOrigins = [process.env.FRONTEND_URL, 'https://app.yourdomain.com']
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) cb(null, true)
    else cb(new Error('Not allowed by CORS'))
  },
  credentials: true
}))
```

---

### A06 — Vulnerable & Outdated Components

**Run dependency audit based on stack:**

For NEXTJS / REACT / NODE_EXPRESS:
```bash
npm audit --json
```
Parse output, report CVEs by severity. Also check:
```bash
npx npm-check-updates --format group 2>/dev/null | head -50
```

For PYTHON_WEB:
```bash
pip audit --format json 2>/dev/null || pip-audit --format json 2>/dev/null
```

For WORDPRESS / PHP_GENERIC:
```bash
composer audit 2>/dev/null
```

**Also grep for:**
```
# Outdated pinned versions with known CVEs (flag common ones)
(?i)"lodash":\s*"[^~^]*[0-3]\.\d+\.\d+"    # Lodash < 4.x (prototype pollution)
(?i)"moment":\s*                              # Moment.js (deprecated, ReDoS)
(?i)"node-uuid":\s*                           # Deprecated in favor of uuid
(?i)"request":\s*                             # Deprecated package
```

---

### A07 — Identification & Authentication Failures

**Search for:**
```
# Weak JWT configuration
jwt\.sign\s*\([^,]+,\s*['"]\w{1,15}['"]    # JWT with short/weak secret
expiresIn.*['"](\d{4,}[smhd]|never)['"]     # Very long or no expiry
algorithm.*none                              # JWT alg:none

# Insecure session config
(?i)session\s*\(\s*\{[^}]*secret\s*:\s*['"]\w{1,15}['"]  # Short session secret
(?i)cookie\s*\{[^}]*secure\s*:\s*false       # Cookie not secure
(?i)cookie\s*\{[^}]*httpOnly\s*:\s*false     # Cookie not httpOnly
(?i)cookie\s*\{[^}]*sameSite\s*:\s*['"]?none # SameSite=None without Secure

# Missing bcrypt / weak password storage
createHash.*password                         # Hashing passwords with crypto (not bcrypt)
\.md5\s*\(.*password                         # MD5 password
```

**Check for:**
- Login endpoint without account lockout
- Password reset without rate limiting
- JWT stored in localStorage (XSS risk) vs httpOnly cookie
- Refresh token rotation implemented
- Sessions invalidated on logout

---

### A08 — Software & Data Integrity Failures

**Search for:**
```
# Subresource integrity missing
<script\s+src=["']https://           # External script without integrity attribute
<link\s+rel=["']stylesheet["']\s+href=["']https://  # External CSS without integrity

# Unsafe deserialization
JSON\.parse\s*\(.*req\.              # Parsing user-controlled JSON (check if used in eval/exec)
pickle\.loads\s*\(.*request\.        # Python pickle with user data — CRITICAL
yaml\.load\s*\(                      # PyYAML load without Loader= (use safe_load)
unserialize\s*\(\$_                  # PHP unserialize with user input

# CI/CD integrity
actions/checkout@main                # Unpinned GitHub Action (use SHA)
uses:.*@v[0-9]+\s*$                  # Mutable tag (use @sha256)
```

**Fix for unsafe YAML:**
```python
# BAD
data = yaml.load(user_input)

# GOOD
data = yaml.safe_load(user_input)
```

---

### A09 — Security Logging & Monitoring Failures

**Search for:**
```
# Logging sensitive data
console\.(log|info|debug).*(?i)(password|token|secret|key|credit|card|ssn|cuit)
print\s*\(.*(?i)(password|token|secret|key)
logger\.(info|debug).*(?i)(password|token|secret)

# Missing audit trail
# Check: are auth events (login/logout/failed-login) logged?
# Check: are admin actions logged?
# Check: are data access events logged?
```

**Check for:**
- Login success/failure events logged with timestamp + IP
- No PII in logs (email masked, no passwords ever)
- Log level appropriate (debug disabled in production)
- Centralized logging configured (not just console.log)

---

### A10 — Server-Side Request Forgery (SSRF)

**Search for:**
```
# SSRF patterns
fetch\s*\(\s*req\.(body|query|params)   # fetch with user-controlled URL
axios\.(get|post)\s*\(\s*req\.          # axios with user URL
https?\.(get|request)\s*\(\s*req\.      # http module with user URL
requests\.(get|post)\s*\(\s*.*request\. # Python requests with user URL
urllib.*open\s*\(\s*.*request\.         # Python urllib with user URL
curl_exec.*\$_                          # PHP curl with user input
file_get_contents\s*\(\$_              # PHP file_get_contents with user input

# Open redirect (related)
res\.redirect\s*\(\s*req\.              # Redirect with user-controlled URL
window\.location\s*=\s*.*query\.        # Frontend redirect from query param
```

**Fix for SSRF:**
```typescript
import { URL } from 'url'
const ALLOWED_HOSTS = ['api.trusted.com', 'cdn.yourdomain.com']

function validateUrl(userUrl: string): string {
  const parsed = new URL(userUrl)
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error(`Host not allowed: ${parsed.hostname}`)
  }
  if (!['https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTPS allowed')
  }
  return userUrl
}
```

---

## PHASE 4 — BACKEND-AS-A-SERVICE & DATABASE PRIVILEGE AUDIT (Supabase / Firebase / PostgREST)

**Why this phase exists:** every other phase in this skill reads source code. This phase reads the *backend's own privilege model* — Postgres RLS policies, `GRANT`s, `SECURITY DEFINER` functions, Firebase security rules. These vulnerabilities are invisible to grep because the vulnerable object (a policy, a grant) lives in the database or the BaaS console, not in a `.ts` file. A project can pass every other phase with a perfect score and still hand out admin access through a single unguarded RPC call. This phase was added after a real production audit where exactly that happened: a `SECURITY DEFINER` function with no internal permission check was reachable by any logged-in user and could mint new admin accounts on demand — zero findings from source-code review, confirmed only by testing live database privileges.

**Trigger this phase when ANY of:**
```
Glob: supabase/config.toml, supabase/schema.sql, supabase/migrations/**
Grep in package.json deps: "@supabase/supabase-js"
Glob: firestore.rules, storage.rules, database.rules.json
Grep in package.json deps: "firebase", "firebase-admin"
Grep in package.json deps: "@prisma/client" + Glob: **/*.sql          (raw SQL access pattern)
```
If none match, skip this phase and note: `Sin backend BaaS/RLS detectado — fase omitida.`

This phase composes with ANY frontend stack from Phase 1 — a REACT or NEXTJS project can also be a Supabase project. Detecting Supabase does not change the Phase 1 classification; it adds this phase on top.

### 4.1 — Get the real schema, not just the code

The repo's `supabase/schema.sql` is often stale (teams forget to regenerate it after making changes in the Supabase Studio SQL editor directly). If the project has the Supabase CLI available and is linked (`supabase status` or a `project_id` in `supabase/config.toml`), prefer a live dump over the committed file:
```bash
npx supabase db dump --linked -s public -f /tmp/audit_schema.sql
```
If this isn't possible (no CLI, no credentials, read-only audit), fall back to `supabase/schema.sql` and **explicitly flag in the report** that findings in this phase are only as current as that file — recommend the user re-run `db dump` to confirm.

### 4.2 — Map the app's own role model first

Before judging any policy, find out if this project has more than one trust level sharing the same Postgres `authenticated` role. Supabase Auth (and Firebase Auth) only has one generic "logged in" role at the database-connection level — app-level roles (admin/staff/customer, free/paid, tenant A/tenant B) live in a table column, not in Postgres/Firebase roles.
```
Grep: CREATE TABLE.*(profiles|perfiles|users|usuarios).*\(
Grep: rol\s+"?text"?|role\s+"?text"?|CHECK.*rol.*=.*ANY.*ARRAY   # role/tier column + allowed values
Grep: is_admin\(\)|is_staff\(\)|has_role\(|auth\.jwt\(\)\s*->>\s*'role'
```
List every distinct role/tier value found (e.g. `admin`, `asesor`, `cliente`, or `free`, `pro`, `creator`). This list is the yardstick for every check below — a policy that's fine when only `admin`/`staff` share `authenticated` becomes a leak the moment a lower-trust role (customer, free-tier user, external portal) joins the same pool.

### 4.3 — RLS enabled on every table

```
Grep: CREATE TABLE (list all)
Grep: ALTER TABLE .* ENABLE ROW LEVEL SECURITY (list all)
```
Any table in the first list missing from the second is **CRITICAL** — with RLS off, the table is readable/writable by anyone holding the anon key, full stop, regardless of any policy text.

### 4.4 — Overly broad policies exposed to the WRONG role

```
Grep: USING\s*\(\s*true\s*\)
Grep: USING\s*\(\s*\(?"?auth"?\."?role"?\(\)\s*=\s*'authenticated'
Grep: TO\s+"?anon"?\s+.*FOR SELECT
```
For each match, identify the table and ask: **does every role from 4.2 legitimately need this data?** A `USING(true)` on a pure catalog/inventory table (price lists, public listings) is fine — flag as informational. A `USING(true)` on a table with PII (names, national ID numbers, phone, email, addresses, payment history) or business-sensitive data (other users'/other tenants'/other creators' records) is **CRITICAL** the moment more than one trust level shares `authenticated`. This is true even if the broad access was an accepted tradeoff for the higher-trust roles (e.g. staff needs to search all customers to avoid duplicates) — the fix is never "leave it open," it's `USING (is_staff() OR owner_id = auth.uid())`, scoping by the caller's own identity for the lower-trust role while preserving the original access for the higher-trust one.

**Also check `FOR ALL` policies specifically — including the implicit form.** In Postgres, `CREATE POLICY name ON table TO role USING (...)` with **no `FOR` clause at all defaults to `FOR ALL`**. This implicit form is the more common one in real schemas (people write `TO authenticated USING (...)` and never realize they skipped specifying the command), so a pattern that only matches the literal text `FOR ALL` will miss most real instances — verified against a real production schema while writing this phase, where every actual "FOR ALL" policy in the file omitted the keyword entirely and the literal-text pattern matched zero of them.
```
Grep: CREATE POLICY.*FOR ALL                                          # explicit form
Grep: CREATE POLICY\s+"[^"]+"\s+ON\s+\S+\s+TO\s+"?\w+"?\s+USING       # implicit form — no FOR keyword between the table and TO/USING
```
For every match from either pattern, confirm there's also an explicit, separately-scoped `FOR SELECT` policy on the same table — if not, the "write-only" policy is actually granting full read access as a side effect. Note this can be a **false positive when harmless**: if the `USING`/gating condition already restricts the policy to a trusted role only (e.g. `is_admin()`), and no lower-trust role can satisfy that same condition, the implicit read grant doesn't create a new leak — still flag it (as **LOW**, not CRITICAL, in that case) and recommend splitting it explicitly, since it's fragile: the moment that gating function's logic changes or a new role is added, the implicit SELECT grant becomes a live leak with no additional code change needed to trigger it.

**Also check that `WITH CHECK` is explicit on every INSERT/UPDATE policy, not implied from `USING`.** When `WITH CHECK` is omitted on an UPDATE policy, Postgres reuses the `USING` expression to validate the new row too — this is *usually* safe, but only when the `USING` condition doesn't depend on a column value the policy itself allows the caller to change (e.g. a self-service `owner_id = auth.uid()` policy is fine because tampering with `owner_id` on the new row would fail that same check; a role/tier/`is_admin` flag stored on the same row the user can otherwise self-update is not, since the check may pass on both the old and attacker-modified new row). Read each UPDATE/INSERT policy's actual condition against the columns that specific table's `UPDATE`/`INSERT` statements in the app are allowed to set — don't flag every missing `WITH CHECK` as critical by pattern alone, but always call out tables where a self-service update policy coexists with a sensitive, self-settable column (role, price, `is_admin`, `verified`, discount %) as **HIGH**, and recommend an explicit `WITH CHECK` that pins those specific columns to their existing value.

### 4.5 — `SECURITY DEFINER` functions: the privilege-escalation class

This is the highest-value check in this phase. `SECURITY DEFINER` functions run with the privileges of whoever created them (usually the Postgres superuser), bypassing RLS entirely. Postgres also grants `EXECUTE` to `PUBLIC` on every new function **by default** — an explicit `REVOKE` is required to close it, and teams routinely forget this even after revoking from `authenticated` specifically (revoking from one role does nothing if `PUBLIC` still has it — verify both).

```
Grep: SECURITY DEFINER                              # list every such function
Grep: GRANT ALL ON FUNCTION|GRANT EXECUTE ON FUNCTION
```
For each `SECURITY DEFINER` function found:
1. **Read the function body.** Does it perform a sensitive action (create/modify a user, change a role, touch another user's row, move money, issue a refund/payout)?
2. **Check its grants** — who can call it? A function reachable by `anon`/`authenticated`/`PUBLIC` that does something sensitive AND has no internal check of the caller's own identity/role (no `auth.uid()`, no `is_admin()`, no ownership comparison inside the function body) is **CRITICAL** — this is a direct, unauthenticated-in-spirit privilege escalation. Any authenticated session (including the lowest-trust role from 4.2) can call it via `supabase.rpc('function_name', {...})` or the PostgREST `/rest/v1/rpc/<name>` endpoint directly, with attacker-controlled parameters, regardless of whether the frontend code ever calls it — **dead code with a live grant is still exploitable.**
3. **Check for `SET search_path`** — a `SECURITY DEFINER` function without a pinned `search_path` (`SET "search_path" TO 'public', 'pg_temp'` or similar) is vulnerable to search-path hijacking: an attacker who can create objects in a schema earlier in the resolution path can shadow a table/function the definer-privileged function calls internally by an unqualified name, achieving code execution as the definer. **Severity depends on whether the function body actually contains unqualified references** — read the body, don't just check for the missing `SET`: if every table/function reference inside is already schema-qualified (`public.table_name`, not bare `table_name`), there is no ambiguous name for an attacker to shadow, and the missing `SET search_path` is a **LOW**/hygiene finding (recommend adding it anyway, as insurance against future edits that introduce an unqualified reference — cheap to fix, easy to regress). If the body has even one unqualified reference, flag as **HIGH** — that's the actual exploitable case.

**Fix pattern:**
```sql
-- Remove the escalation vector — revoke from BOTH roles, PUBLIC included:
REVOKE ALL ON FUNCTION public.fn_name(args) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.fn_name(args) FROM authenticated;
-- If the function must remain callable by end users, add an internal guard instead of an open grant:
CREATE OR REPLACE FUNCTION public.fn_name(...)
  SECURITY DEFINER
  SET search_path = public, pg_temp
AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'permission denied';
  END IF;
  -- ... original logic
END;
$$ LANGUAGE plpgsql;
```

**Verifying the fix (do this before marking CRITICAL findings closed):** if the auditor has a live, linked, non-production-critical way to test (explicit user permission required — never do this against a real project without asking first), the most reliable proof is a real RLS-respecting simulation, not just reading the policy text:
```sql
-- Run via `supabase db query --linked` (or psql) — this actually enforces RLS/GRANTs,
-- unlike inspecting the SQL text alone:
SET ROLE authenticated;
SET request.jwt.claim.sub = '<a real or disposable low-trust user id>';
SELECT * FROM sensitive_table;              -- should return 0 rows / only own rows
SELECT public.fn_name('attacker-controlled-args');  -- should raise permission denied
RESET ROLE;
```
If disposable test accounts are created for this, **always clean them up** (`DELETE FROM auth.users WHERE email = '...'`, cascades to profile tables) before closing the audit — never leave synthetic accounts in a production database.

### 4.6 — Storage buckets & file access

**The bucket's public/private flag is data, not schema — it will NOT appear in the `-s public` schema dump from 4.1.** `storage.buckets.public` is a row value in the `storage` schema, which a `public`-only DDL dump never touches. Query it directly instead (verified working method):
```bash
npx supabase db query --linked "SELECT id, name, public FROM storage.buckets;"
```
Cross-reference every bucket's `public` value against what's actually stored in it, from the app code:
```
Grep: storage\.from\(['"]?(\w+)['"]?\)\.upload            # which bucket receives which kind of file
Grep: createBucket\(.*public.*true                         # bucket created as public in code, if applicable
```
A bucket with `public: true` is only a finding if what it stores is sensitive — **not every public bucket is a bug**: logos, marketing images, and public floor-plan renders are fine public by design. A bucket holding user-uploaded ID scans, contracts, invoices, or paywalled digital assets (Phase 5.7) marked `public: true` is **CRITICAL** — anyone with the object's URL (often guessable/sequential) can read it with no auth at all. Read what the corresponding `upload()` call in the app actually stores before deciding severity.

### 4.7 — Edge Functions / serverless functions bypassing auth

```
Glob: supabase/functions/**/index.ts
Grep in supabase/config.toml: verify_jwt\s*=\s*false
```
A function with `verify_jwt = false` skips Supabase's automatic JWT check entirely — acceptable only for genuinely public endpoints (e.g. public webhooks that verify their own signature instead, like Stripe/MercadoPago). If a `verify_jwt = false` function performs a privileged action (creates users, touches payment state, mutates another user's data) without its own internal auth check in the function body, flag as **CRITICAL**.

### 4.8 — Firebase equivalent (when Firebase, not Supabase, is detected)

```
Grep in firestore.rules / storage.rules: allow (read|write).*if true;
Grep: allow read, write: if request.auth != null;    # "any logged in user" — same class as USING(true)
```
Same reasoning as 4.4: `if request.auth != null` alone means ANY authenticated user, not "the owner" or "the right role" — check it against the role list from 4.2. Also check Cloud Functions `onCall`/`onRequest` handlers for missing `context.auth` / `request.auth` checks before performing writes.

---

## PHASE 5 — WORKFLOW AUTOMATION SECURITY (n8n, Zapier/Make exports, iPaaS)

**Trigger this phase when ANY of:**
```
Glob: **/*.json — check if it parses as a workflow export (top-level "nodes" + "connections" keys, or node "type" strings starting with "n8n-nodes-base.")
Grep: n8n-nodes-base\.                      # node type strings — the strongest signal
Grep in docker-compose.yml / .env*: N8N_
```
n8n workflows usually live in the n8n instance itself, not the git repo — if no exported workflow JSON is found in the project files but `N8N_*` env vars or an n8n Docker service are present, note that this phase could only check instance-level config from what's in the repo, and recommend exporting the active workflows (or using the n8n MCP tools, if connected) for a full pass. If genuinely nothing n8n-related is found, skip silently.

**Node JSON is typically emitted as one long line per node** — a node's entire `parameters` object, `type`, `name`, and `credentials` block are usually on the same line in an export. This matters for how to read grep results: a single matching line IS the whole node, so checking "does this node also have field X" means reading the rest of that same matched line, not a nearby one.

### 5.1 — Webhook (and Form Trigger) nodes with no authentication

```
Grep: "type":\s*"n8n-nodes-base\.(webhook|formTrigger)"
```
For each match, read the full line for an `"authentication"` field. No `authentication` key at all, or `"authentication":"none"`, means the webhook is publicly callable by anyone with the URL — no exception. **This is not automatically a bug** — a public lead-capture form or a payment-provider webhook (which authenticates via its own signature instead, see 5.4) is supposed to be open. Judge it the same way as Phase 4.4: trace what the webhook triggers downstream, and flag it only when the consequence is sensitive.

### 5.2 — Hardcoded credentials instead of n8n's credential system

```
Grep: "type":\s*"n8n-nodes-base\.httpRequest"
```
A properly-configured HTTP Request node uses `"authentication":"genericCredentialType"` (or a named credential type) plus a `"credentials":{...}` block referencing a stored credential ID — the actual secret never appears in the workflow JSON. Flag as **CRITICAL** any HTTP Request (or similar) node where a value inside `headerParameters`, `qs`, `jsonBody`, or `url` matches one of the Phase 2 secret patterns directly (`Bearer sk_...`, `Authorization: ...`, API keys in a query string) instead of coming from a credential reference — that secret is now sitting in plaintext in every export, backup, and version-history snapshot of the workflow.

### 5.3 — Code / Execute Command nodes running unsanitized input

```
Grep: "type":\s*"n8n-nodes-base\.code"          # then check the jsCode/pythonCode value for eval(, Function(, exec(
Grep: "type":\s*"n8n-nodes-base\.executeCommand"   # then check whether "command" is built from an n8n expression (starts with ={{ ) that references upstream/webhook data ($json, $input)
```
A Code node calling `eval()`/`Function()` on data that ultimately originated from a Webhook node's payload is script injection inside your own automation platform. An Execute Command node whose command string is built from `{{ $json... }}` sourced from external input is command injection against the n8n host itself — often with the same OS-level access as the rest of the n8n instance (other workflows' credentials, the encryption key, the database connection). Flag as **CRITICAL**. Trace the data back to its source node before flagging — a Code node processing only internally-generated data (e.g. a value set by an earlier Set node from a fixed list) is not exploitable the same way.

### 5.4 — Unauthenticated webhook driving a costed or reputation-sensitive action (validated against a real workflow while writing this phase)

This is the single most common real finding in this phase, and it doesn't require a code-level bug — the webhook, the credential handling, and the individual nodes can all be configured exactly "correctly" and the workflow is still abusable. The pattern: a public Webhook node (5.1, no auth — correctly so, since it's a public form) feeds a chain that ends in an action with a cost or a blast radius beyond the submitter themselves — most commonly an outbound email/SMS send where the recipient address comes from the request body, not from the authenticated submitter's own identity (because there IS no authenticated submitter). Concretely: `{ "correo": "victim@example.com", ... }` posted to the form's webhook, repeated automatically, turns a legitimate transactional-email workflow into an email-bombing tool against any third party the attacker chooses, and/or a "wallet attack" running up the email provider's sending costs and burning the sending domain's reputation.
```
Grep: "type":\s*"n8n-nodes-base\.webhook"         # find the public entry point (5.1)
```
Trace its downstream connections (the workflow's `connections` object) for any node whose `type` sends email/SMS/push (HTTP Request to a provider like Resend/SendGrid/Twilio, or a dedicated node for one of those services) where the destination address/number is read from the webhook payload. Flag as **HIGH** if there's no per-submitter rate limiting (check for a preceding node that deduplicates/throttles by IP or by the target address — e.g. a lookup against a "recently sent" table before proceeding) and no verification that the target actually requested the message (e.g. a double opt-in / confirmation step). A honeypot field (common anti-bot pattern) filters obvious bots but does **not** stop a targeted human attacker who simply leaves it empty — don't treat a honeypot's presence as sufficient mitigation for this specific finding.

### 5.5 — Instance-level configuration (only checkable when deployment config is in the repo)

```
Grep: N8N_ENCRYPTION_KEY
Grep: N8N_BASIC_AUTH_ACTIVE|N8N_USER_MANAGEMENT_DISABLED
Grep: N8N_SECURE_COOKIE
```
- `N8N_ENCRYPTION_KEY` hardcoded/committed anywhere is **CRITICAL** — it's the key that decrypts every stored credential in that n8n instance's database (every API key, every OAuth token, every webhook secret the instance has ever stored). Treat it with the same severity as a database root password.
- `N8N_USER_MANAGEMENT_DISABLED=true` (or the older `N8N_BASIC_AUTH_ACTIVE` missing/false) on an internet-reachable n8n instance means the editor UI and its `/rest/` management API are reachable with no login at all — anyone who finds the URL can read, edit, and execute every workflow and read every stored credential's metadata. Flag as **CRITICAL** if the instance appears to be internet-facing (no VPN/IP-allowlist signal in the same compose/config file).
- `N8N_SECURE_COOKIE=false` on an instance served over HTTPS unnecessarily weakens session cookie protection — **LOW**, but flag it since it's a one-line fix.

---

## PHASE 6 — SAAS, MARKETPLACE & MONETIZATION SECURITY (freemium, subscriptions, in-app purchases, creator marketplaces)

**Trigger this phase when ANY of:** the project has a pricing/plan model (free vs. paid tiers), a marketplace where users sell to other users (asset stores, game/creator marketplaces), subscriptions, or any payment integration (Stripe, MercadoPago, PayPal, in-app purchase).
```
Grep in package.json deps: "stripe", "@stripe/", "mercadopago", "paypal"
Grep: subscription|plan_id|tier|premium|is_pro|isPaid|free_trial
Glob: **/webhooks/**, **/api/stripe/**, **/api/checkout/**
```

The vulnerabilities in this phase are almost never "missing auth" — they're **business logic trusting the client**. A user who is authenticated as themselves (no privilege escalation needed) manipulates a request to get something they didn't pay for. These are consistently under-tested because they require thinking like a paying customer trying to avoid paying, not like an attacker looking for a broken auth check.

### 5.1 — Client-side-only entitlement / paywall bypass (the #1 real-world finding in this category)

This one doesn't reduce to a single reliable regex — the vulnerable shape varies too much (an `if`, a ternary, a `disabled` prop, a route guard) for a pattern to catch consistently, and testing against realistic snippets while writing this phase confirmed an over-specific regex here just returns zero matches on real code shaped slightly differently. Use these as **candidate anchors** to find where to look, not as the check itself:
```
Grep: isPro|isPremium|hasSubscription|user\.(plan|tier)                  # any file mentioning a plan/tier flag at all
```
For every file that matches, find where that flag actually gates something, then trace forward: **does the backend endpoint that returns the paid feature/asset/export/API result independently verify the caller's current entitlement server-side**, or does it just serve the data because the request arrived? If the only thing standing between a free user and a paid feature is a `disabled` prop or an `if (user.isPro)` in React — with no matching check in the API route/server action it calls — it's **CRITICAL**: trivially bypassed by calling the API directly (devtools, curl) with a valid free-tier session token. This requires reading the actual client→server round trip, not just the frontend file in isolation.

**Fix pattern:**
```typescript
// BAD — trusts a client-sent or client-derived flag
export async function POST(req: Request) {
  const { isPro } = await req.json()   // or reads req.user.isPro from a JWT claim set at login that's now stale
  if (isPro) return exportPremiumReport()
}

// GOOD — re-checks entitlement server-side, from the source of truth, on every privileged call
export async function POST(req: Request) {
  const session = await getServerSession(authOptions)
  const sub = await db.subscription.findUnique({ where: { userId: session.user.id } })
  if (!sub || sub.status !== 'active' || sub.currentPeriodEnd < new Date()) {
    return Response.json({ error: 'Requiere plan pago' }, { status: 402 })
  }
  return exportPremiumReport()
}
```

### 5.2 — Price / amount / plan tampering at checkout

```
Grep: amount\s*[:=]\s*req\.(body|query)|price\s*[:=]\s*req\.(body|query)
Grep: stripe\.checkout\.sessions\.create\(\{[^}]*amount\s*:\s*(body|req)
```
If the checkout/order-creation endpoint accepts `amount`, `price`, or `plan_id` from the client and uses it directly to create the charge, a user can pay $0.01 for anything. The backend must look up the price from its own price table/Stripe Price ID, keyed only by a product/plan identifier — never trust a client-sent amount.

### 5.3 — Payment webhook integrity (signature + replay)

Beyond just "is the signature checked" (already covered in Phase 9 for MercadoPago) — two more common gaps:
```
Grep: stripe\.webhooks\.constructEvent          # present = good, check it's actually used before processing
Grep: (webhook|event)\.id.*(processed|seen|idempotenc)  # idempotency/replay check
```
- **No idempotency check** on payment-confirmed webhooks → an attacker (or a retried delivery from the provider itself, which is normal and expected) that replays the same event can double-credit an account, double-grant a purchased item, or double-extend a subscription. Flag as **HIGH** if there's no check that the event ID was already processed before granting the entitlement.
- **Webhook handler grants access before verifying the signature**, or verifies it but doesn't `return`/`throw` on failure (verifies-then-ignores-the-result is a real, recurring bug). Flag as **CRITICAL**.

### 5.4 — Subscription/entitlement race on cancel-and-reuse

Check whether canceling a subscription immediately revokes access or only revokes it at `current_period_end`. Neither is wrong on its own, but the code must be internally consistent — if cancellation immediately flips `isPro = false` while Stripe still considers the period active (or vice versa), users can exploit the gap. Also check for a downgrade path that doesn't clear out usage tied to the higher tier (e.g. a free-tier user who was briefly Pro keeps Pro-tier resource limits forever because the limit was cached at creation time, not re-checked).

### 5.5 — Free-trial / free-tier abuse (no durable identity check)

```
Grep: (?i)trial|free_tier|freeTier|first_?time_?user
```
If trial eligibility is checked only against the current account/email, a user can create unlimited accounts (disposable emails, `+1`/`+2` Gmail aliases) to get unlimited free trials or repeatedly claim a one-per-user free credit grant. This is rarely "critical" but is a real, common revenue-leak finding — flag as **MEDIUM** and note it as a business-risk item, not just a security one.

### 5.6 — Marketplace-specific: creator payout & commission tampering

Applies directly to any project where users sell to other users (asset marketplaces, game/creator stores, plugin marketplaces):
```
Grep: commission|payout|seller_amount|creator_share
```
If the commission percentage or the seller's payout amount is computed anywhere in client-controllable input (rather than derived server-side from a fixed rate at the time of sale), a seller can manipulate their own payout upward. Also check that a buyer cannot mark their own transaction as refunded/completed without going through the actual payment provider's confirmation.

### 5.7 — Digital asset / paid-content protection (DRM-adjacent)

```
Grep: signedUrl|getSignedUrl|expiresIn
Grep: <a\s+href=.*\/(assets|downloads|exports)\/.*\.(zip|pdf|unitypackage|glb)
```
If paid digital assets (game asset packs, exported files, premium templates) are served via a permanent, unauthenticated, or long-lived public URL rather than a short-lived signed URL re-issued after an entitlement check, the URL can be shared/leaked to bypass payment entirely, and search engines or link-sharing can expose it publicly. Flag as **HIGH**. Recommend signed URLs with short expiry (minutes, not days) re-generated per authorized request.

### 5.8 — Usage-based abuse / "wallet attack" on metered AI or compute features

Applies to any feature that calls a paid third-party API (AI generation, image/video rendering, SMS, email) per user action:
```
Grep: openai\.|anthropic\.|generateImage|generateVideo — check for per-user rate limiting nearby
```
If a free-tier (or even paid-tier) user can trigger unlimited calls to an expensive backend operation with no per-user/per-IP rate limit or daily quota enforced server-side, an attacker can run up the project owner's third-party bill arbitrarily ("wallet attack" / denial of wallet) even without breaking any data confidentiality. Flag as **HIGH** if a metered/costed operation has no server-side quota check independent of the frontend UI's own throttling.

### 5.9 — Multi-tenant / multi-creator data isolation

```
Grep: WHERE.*=\s*req\.(params|body|query)\.(tenant|org|account|creator)Id   # raw SQL — tenant id taken from request instead of session
Grep: (tenant|org|account|creator)Id:\s*req\.(params|body|query)            # ORM style (Prisma/Drizzle/Kysely) — matches `where: { tenantId: req.params.tenantId }`, the more common real-world shape in JS/TS backends
Grep: \.findUnique\(\{\s*where:\s*\{\s*id:\s*(req\.|params\.)               # missing owner/tenant filter entirely
```
Every query for a resource scoped to a tenant/organization/creator must filter by the tenant ID derived from the **authenticated session**, never from a client-supplied `tenantId`/`orgId` parameter (trivial to swap for another tenant's ID otherwise — a direct IDOR at the tenant level, worse than a single-record IDOR because it can expose an entire other business's data: their users, their sales, their analytics). Flag as **CRITICAL**.

---

## PHASE 7 — ADVANCED & RARE ATTACK VECTORS

These are lower-frequency but well-documented, real vulnerability classes that don't fit cleanly into the OWASP Top 10 buckets above. Check for them on every audit regardless of stack; skip silently (no need to report "not applicable") when a pattern genuinely can't apply (e.g. GraphQL checks on a project with no GraphQL layer).

### 6.1 — JWT algorithm confusion

**Ripgrep doesn't support lookaround** (`(?!...)`) — don't write a pattern that depends on it, it will silently match nothing and look like a clean bill of health. Grep for the anchor, then read each result to judge the negative condition:
```
Grep: jwt\.verify\(                                   # every call site — read each one
Grep: jwt\.verify\(.*algorithms\s*:\s*\[.*(RS256.*HS256|HS256.*RS256)
```
If `jwt.verify()` is called without an explicit `algorithms: [...]` allowlist, or with both `RS256` and `HS256` accepted, an attacker who knows the RS256 public key (often published, e.g. at a `/.well-known/jwks.json` endpoint or embedded in the frontend) can forge a token signed with HS256 using the public key as the HMAC secret — the library will accept it as valid. **CRITICAL.** Fix: always pass an explicit single-algorithm allowlist matching what the issuer actually uses.

### 6.2 — IDOR via enumerable identifiers

```
Grep: id\s+(SERIAL|INTEGER|BIGINT)\s+PRIMARY KEY      # auto-increment PK — check if that table's id is ever used in a public URL/route
Grep: /:(id|invoiceId|orderId|userId)\b               # route params — cross-reference each against the schema: is the underlying column a serial/int or a uuid?
```
Beyond "is there an ownership check" (Phase 3, A01) — even WITH an ownership check, using sequential integer IDs as public-facing identifiers (`/invoice/1042`, `/order/883`) lets an attacker infer the existence and approximate volume of other users' records, and turns any future ownership-check regression into full enumeration. Recommend UUIDs (or ULIDs if ordering matters) for any publicly-referenced resource ID.

### 6.3 — Excessive data exposure in API responses

```
Grep: \.select\(\s*['"]?\*|SELECT \*                            # explicit wildcard projection
Grep: \.findMany\(\)\s*$|\.findMany\(\)\s*[;,)]                 # Prisma findMany() called with no arguments at all — no select/include, returns full rows by default
Grep: res\.json\(user\)|res\.json\(req\.user\)                  # returning a full user object as-is
```
An endpoint that returns an entire database row (via `SELECT *` or an ORM call with no field projection) commonly leaks fields never meant for the client: password hashes, internal flags, other users' foreign keys, soft-delete markers, admin notes. This is a real, frequent finding independent of whether the frontend happens to only display some of the fields — the full object is still visible in devtools/network tab. Flag as **MEDIUM**–**HIGH** depending on what's actually in the leaked fields (password hash present = CRITICAL).

### 6.4 — Session fixation

```
Grep: (login|signIn|authenticate).*\(req|Grep: req\.session\.\w+\s*=      # find login handlers / session writes
Grep: \.regenerate\(                                                       # find regenerate() calls
```
Locate the login handler (first pattern), then check with `-A 15` context (or read the surrounding function) whether it calls `req.session.regenerate()` (Express) or the framework's equivalent **before** writing the authenticated user into the session. If a login handler sets session data but no `regenerate()` call appears anywhere in the same file, the session ID likely isn't rotated on login — an attacker who fixes a victim's pre-login session ID (e.g. via a shared link containing a session cookie) can hijack the now-authenticated session. Flag as **HIGH**.

### 6.5 — CSRF on state-changing GET requests

```
Grep: (app|router)\.get\(['"].*\/(delete|remove|update|approve|cancel)   # state-changing action bound to GET
```
Any endpoint that mutates state (delete, cancel, approve, unsubscribe) and responds to `GET` is CSRF-exploitable via a plain `<img src=...>` or link — no JS, no CORS restrictions apply to simple GET navigation. Should be `POST`/`DELETE` behind CSRF protection. Flag as **HIGH**.

### 6.6 — Timing / message-based user enumeration

```
Grep: (User|Usuario) not found|Invalid (email|password|credentials) — check if login/reset-password returns DIFFERENT messages for "no such user" vs "wrong password"
```
A login or password-reset flow that says "no existe esa cuenta" vs. "contraseña incorrecta" lets an attacker enumerate valid emails/usernames at scale. Fix: always return the same generic message ("credenciales inválidas") and, ideally, similar response timing, regardless of which check failed.

### 6.7 — Prototype pollution (JavaScript)

```
Grep: _\.merge\(|_\.defaultsDeep\(|Object\.assign\(\s*\{\s*\}\s*,.*req\.body
Grep: \[.*req\.(body|query|params).*\]\s*=              # dynamic key assignment from user input
```
Deep-merging user-controlled input (`lodash.merge`, hand-rolled recursive merge, dynamic bracket-notation assignment) without blocking `__proto__`/`constructor`/`prototype` keys can pollute `Object.prototype` globally, leading to app-wide logic corruption or, in some frameworks, RCE. Flag as **HIGH**. Fix: use `structuredClone` + explicit allow-listed fields, or a merge library with prototype-pollution protection (lodash ≥ 4.17.21 patched this for its own `merge`, but hand-rolled merges remain vulnerable).

### 6.8 — ReDoS (catastrophic backtracking regex)

```
Grep: \([^)]*[+*]\)[+*]                                # nested quantifiers like (a+)+ or (a*)*
Grep: RegExp\(.*req\.(body|query)                       # regex built from user input directly
```
A regex with nested quantifiers evaluated against attacker-controlled, adversarially-crafted input (especially in validation for emails, URLs, or "looks like X" checks) can hang the event loop for seconds to minutes on a short malicious string — a cheap single-request DoS. Flag as **MEDIUM**, **HIGH** if the vulnerable regex sits on an unauthenticated, public-facing endpoint (contact form, signup).

### 6.9 — Dependency confusion

```
Grep in package.json: "name":\s*"@[a-z0-9-]+/     — check if that scope is actually reserved/private on npm
```
An internal/private package referenced with a scope that isn't actually registered as private on the public npm registry can be squatted by an attacker who publishes a malicious package under that exact name — if the build ever resolves to the public registry (misconfigured `.npmrc`, missing private registry auth), it installs the attacker's code instead. Verify `.npmrc` pins internal scopes to a private registry explicitly.

### 6.10 — Open redirect via OAuth / return_to parameters

```
Grep: redirect_uri=|return_to=|next=.*req\.(query|params)
res\.redirect\(req\.(query|body)\.(url|redirect|next|return_to)\)
```
An unvalidated `redirect_uri`/`return_to`/`next` parameter, especially in an OAuth flow, lets an attacker craft a legitimate-looking login link that redirects the victim (with a valid session/token in the URL fragment or query) to an attacker-controlled domain after authentication. Flag as **HIGH**. Fix: validate against an explicit allowlist of same-origin paths, never accept an absolute external URL.

### 6.11 — GraphQL-specific (only if a GraphQL layer is detected)

```
Grep in deps: "graphql", "apollo-server", "graphql-yoga", "@apollo/server"
Grep: introspection:\s*true                              # introspection left on in production
Grep: depthLimit|queryComplexity|costAnalysis             # presence = good, absence = check further
Grep: resolve:\s*\(|resolve\s*\(                          # enumerate every resolver — read each one, don't rely on a regex for the auth check itself
```
For every resolver found, read its body for a permission check — GraphQL's single-endpoint-many-fields shape means **REST-style route-level auth checks don't exist here**; every resolver that returns sensitive data needs its own check, and it's common for a schema to correctly protect its Query root fields while a nested field resolver (e.g. `User.privateNotes`) has none, because it's reachable through a different, less obviously-sensitive parent query. This is a manual-read step, the same way Phase 5.1's paywall check is — the presence/absence of an auth check inside a function body isn't reliably expressible as a single grep pattern.

Check for:
- **Introspection enabled in production** — exposes the entire schema, including unused/admin-only fields, to anyone. Should be disabled outside development.
- **Field-level authorization gaps** — a query can be allowed while a nested field it returns isn't supposed to be visible to the caller; check resolvers for fields containing PII/internal data specifically, not just the top-level query.
- **Missing query depth/complexity limiting** — a deeply nested or circular query can cause exponential resolver calls, a DoS vector essentially unique to GraphQL's shape.
- **Batching with no per-batch rate limiting** — a batched request turns a rate limit designed for "1 request" into unlimited effective operations per HTTP call.
- **Verbose errors** — default Apollo/GraphQL error formatting can leak resolver stack traces and internal field names to the client; check for a custom `formatError` that strips internals in production.
- **State-changing mutations over GET with cookie auth** — if the GraphQL endpoint accepts queries via `GET` (some setups do, for caching) and auth relies on cookies, mutations become CSRF-exploitable the same way as Phase 6.5 — mutations should only be reachable via `POST`.

---

## PHASE 8 — CLOUD INFRASTRUCTURE & IaC SECURITY (Terraform, CloudFormation, Kubernetes, cloud IAM)

**Trigger this phase when ANY of:**
```
Glob: **/*.tf, **/*.tfvars, **/terraform.tfstate
Glob: **/*.yaml, **/*.yml — check for `kind: Deployment|Pod|Service|Role|ClusterRole` (Kubernetes manifests)
Glob: **/cloudformation*.yaml, **/cloudformation*.json, **/template.yaml (SAM)
Glob: **/*.tf.json, **/pulumi/**, **/cdk.out/**
```
This phase is distinct from Phase 11 (Infrastructure & Config Review) — that one covers app-level Docker/CI-CD hygiene; this one covers cloud provider permission models and orchestration configs, a different failure class (identity and access management, not application config).

### 8.1 — Terraform state file exposure

```
Glob: **/terraform.tfstate, **/*.tfstate
```
A `.tfstate` file contains **plaintext values of every resource it manages, including secrets** — database passwords, generated API keys, private keys — even for resources whose Terraform definition marks the input variable `sensitive = true` (that flag only redacts CLI output, not the state file itself). A `.tfstate` file committed to git, or stored in an S3 backend bucket without encryption and strict access policy, is **CRITICAL**. Fix: remote state backend (S3+DynamoDB lock, Terraform Cloud) with encryption at rest and IAM-restricted access; never commit state; if one was ever committed, treat every secret in it as compromised and rotate.

### 8.2 — Overly broad IAM policies

```
Grep: "Action":\s*"\*"                                    # AWS IAM wildcard action
Grep: "Resource":\s*"\*"                                  # AWS IAM wildcard resource
Grep: roles/owner|roles/editor                            # GCP primitive roles (should use granular predefined/custom roles)
Grep: AssumeRolePolicyDocument.*"Principal":\s*"\*"        # any AWS account can assume this role
```
A policy combining `"Action": "*"` with `"Resource": "*"` grants full administrative access to whatever it's attached to — flag as **CRITICAL** on any role/user attached to an application workload (a Lambda's execution role, an EC2 instance profile, a CI/CD deploy user) rather than a genuinely break-glass human admin role. Recommend scoping to the specific actions and ARNs the workload actually needs.

### 8.3 — Public storage bucket / object storage misconfiguration

```
Grep: "BlockPublicAcls":\s*false|"BlockPublicPolicy":\s*false     # AWS API/CloudFormation JSON style
Grep: block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|restrict_public_buckets\s*=\s*false   # Terraform HCL style (aws_s3_bucket_public_access_block) — the more common real-world shape, verified against a synthetic Terraform snippet where the JSON-style pattern alone matched nothing
Grep: acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"        # Terraform S3 bucket ACL
Grep: allUsers|allAuthenticatedUsers                                # GCP bucket IAM binding to anyone
```
Same reasoning as Phase 4.6 (Supabase storage) — a bucket is only a finding if what it stores is sensitive. Cross-reference against what the application actually writes there before assigning severity; a bucket serving public static assets is fine, one holding backups, user uploads, or Terraform state (8.1) is **CRITICAL**.

### 8.4 — Kubernetes: privileged/root containers and missing isolation

```
Grep: privileged:\s*true
Grep: runAsUser:\s*0
Grep: hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true
Grep: allowPrivilegeEscalation:\s*true
```
A container running `privileged: true` or as `runAsUser: 0` (root) with no explicit `securityContext` restricting capabilities can, if compromised via any application-layer vulnerability inside it, escalate to control the underlying node — a much larger blast radius than the container itself. `hostNetwork`/`hostPID`/`hostIPC: true` similarly break the isolation Kubernetes is supposed to provide between workloads on the same node. Flag as **HIGH**, **CRITICAL** if the container also handles untrusted input (a public-facing API, a webhook receiver, a sandboxed code-execution service).

### 8.5 — Kubernetes: secrets as plain environment variables, missing NetworkPolicy

```
Grep: kind:\s*Deployment — check nearby env: for value: (rather than valueFrom: secretKeyRef:)
Grep: kind:\s*NetworkPolicy                                # presence check — absence across the whole manifest set is the finding
```
Secrets injected via a literal `value:` in a Deployment/Pod spec (instead of `valueFrom: secretKeyRef:` pointing at a Kubernetes `Secret` object) end up readable by anyone with `kubectl describe pod`/`get pod -o yaml` access, and are stored in etcd with the same exposure either way — but the literal form also leaks into version control and CI logs where the spec is defined. Flag as **MEDIUM**. Separately, a cluster with zero `NetworkPolicy` resources defined means every pod can reach every other pod by default ("flat network") — a compromised low-value service (e.g. a public frontend) can then directly reach a database or internal admin service with no network-layer barrier. Flag as **MEDIUM**–**HIGH** depending on what's reachable.

### 8.6 — CI/CD deploy credentials with standing cloud access

```
Grep in .github/workflows, .gitlab-ci.yml: AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY   # long-lived static keys in CI
Grep: aws-actions/configure-aws-credentials                                            # check if it uses OIDC (role-to-assume) vs static keys
```
Long-lived AWS/GCP/Azure static credentials stored as CI secrets are a standing target — if the CI provider or the pipeline config is ever compromised, they're valid indefinitely until manually rotated. Recommend OIDC-based short-lived credentials (`aws-actions/configure-aws-credentials` with `role-to-assume`, no `aws-access-key-id`) instead. Flag static long-lived cloud credentials in CI as **MEDIUM**, or **HIGH** if the role/user they authenticate as has the broad-policy pattern from 8.2.

---

## PHASE 9 — CWE TOP 25 (by language)

### JavaScript / TypeScript
- **CWE-79** (XSS): `dangerouslySetInnerHTML`, `innerHTML =`, `document.write`, unescaped template literals in HTML
- **CWE-89** (SQL Injection): string concatenation in queries (covered in A03)
- **CWE-22** (Path Traversal): `path.join` with user input, `__dirname + req.params`
- **CWE-78** (Command Injection): covered in A03
- **CWE-502** (Unsafe Deserialization): `eval(JSON.parse(...))`, `Function(userCode)()`
- **CWE-611** (XXE): XML parsers without disabling external entities
- **CWE-918** (SSRF): covered in A10
- **CWE-200** (Info Exposure): stack traces in responses, verbose error messages

**Search patterns:**
```
dangerouslySetInnerHTML\s*=\s*\{\s*\{__html  # React XSS — check if sanitized
innerHTML\s*=\s*`[^`]*\$\{               # Template literal in innerHTML
document\.write\s*\(                      # document.write
\.join\s*\(\s*req\.(params|query|body)   # Path traversal via path.join
```

### Python
- **CWE-89**: f-strings in SQL, .format() in SQL
- **CWE-78**: os.system, subprocess shell=True with user data
- **CWE-94** (Code Injection): `exec(user_input)`, `eval(user_input)`
- **CWE-502**: `pickle.loads()` with external data
- **CWE-611**: `lxml` / `xml.etree` without defusedxml
- **CWE-601** (Open Redirect): unvalidated redirect URLs

**Search patterns:**
```
exec\s*\(\s*.*request\.           # Python exec + user data
eval\s*\(\s*.*request\.           # Python eval + user data
pickle\.loads\s*\(                # pickle deserialization
import\s+xml\.etree               # xml.etree without defusedxml
from\s+xml                        # check for defusedxml usage
```

### PHP
- **CWE-89**: mysql_query + $_REQUEST, PDO without prepared statements
- **CWE-78**: system($_), exec($_), shell_exec($_)
- **CWE-22**: include/require with user path
- **CWE-94**: eval with user data
- **CWE-611**: SimpleXML / DOMDocument without LIBXML_NOENT disabled

**Search patterns:**
```
mysql_query\s*\(.*\$_             # Old MySQL + superglobal
system\s*\(\$_                    # Command injection PHP
exec\s*\(\$_                      # Command injection PHP
include\s*\(\$_                   # LFI
eval\s*\(\$_                      # PHP eval injection
```

---

## PHASE 10 — SECURITY HEADERS

Check the project's HTTP header configuration. Look in:
- `next.config.js` / `next.config.ts` / `next.config.mjs`
- `server.js`, `app.js`, `index.js`
- `main.py`, `app.py`
- `nginx.conf`, `apache.conf`

### Required headers:
```
Content-Security-Policy          — prevents XSS, data injection
Strict-Transport-Security        — enforces HTTPS
X-Frame-Options                  — prevents clickjacking (or use CSP frame-ancestors)
X-Content-Type-Options: nosniff  — prevents MIME sniffing
Referrer-Policy                  — controls referrer leakage
Permissions-Policy               — limits browser feature access
```

**Fix for Next.js (`next.config.js`):**
```javascript
const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'",  // tighten in prod
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join('; ')
  }
]

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }]
  }
}
```

**Fix for Express:**
```javascript
import helmet from 'helmet'
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
    }
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}))
```

**Fix for FastAPI:**
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com", "*.yourdomain.com"])

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

---

## PHASE 11 — INFRASTRUCTURE & CONFIG REVIEW

### .env file exposure
```
# Check committed .env files with real values
Glob: .env, .env.production, .env.staging, .env.live
# .env.example is OK, .env.local SHOULD NOT be committed
```

If a `.env` file with real-looking values (not placeholders) is found in git-tracked files:
```
[CRITICO] Archivo .env commiteado con credenciales
Fix:
  git rm --cached .env .env.production
  echo ".env*" >> .gitignore
  git commit -m "chore: remove .env from tracking"
  # Rotar TODAS las credenciales en el archivo
```

### Docker security
```
# Running as root
USER root                                # Docker USER root
# No FROM pinning
FROM node:latest                         # Unpinned base image
FROM python:latest                       # Use specific version: python:3.12-slim
# Exposed secrets in Dockerfile
ENV.*(?i)(password|secret|key|token)=\S+ # Secrets in ENV instruction
ARG.*(?i)(password|secret|key|token)     # Secrets in ARG
```

### CI/CD security
```
# Secrets in GitHub Actions
(?i)(password|secret|token|key)\s*:\s*['\"]?\S{8,}  # Hardcoded in workflow
# Unpinned actions
uses: actions/[a-z-]+@main               # Pinned to branch, not SHA
uses: [^@]+@v[0-9]+$                     # Mutable version tag
# Pull request event without restriction
on:\s*pull_request_target                # Dangerous event — can access secrets
```

### CORS / API exposure
- Check for wildcard CORS on authenticated APIs
- Check for API keys in frontend JS bundles
- Check for `NEXT_PUBLIC_` prefix on secret variables in Next.js

---

## PHASE 12 — LATAM-SPECIFIC CHECKS

### MercadoPago
```
# Insecure webhook — no signature validation
(?i)(webhook|ipn|notification).*mercadopago  # MP webhook handler
# Check for x-signature or x-request-id validation
```

**Fix — MP webhook validation:**
```typescript
import crypto from 'crypto'
function validateMPWebhook(req: Request): boolean {
  const xSignature = req.headers['x-signature'] as string
  const xRequestId = req.headers['x-request-id'] as string
  const dataId = req.query['data.id']

  const manifest = `id:${dataId};request-id:${xRequestId};ts:${Date.now()};`
  const hmac = crypto.createHmac('sha256', process.env.MP_WEBHOOK_SECRET!)
  hmac.update(manifest)
  const digest = hmac.digest('hex')
  return xSignature.includes(`v1=${digest}`)
}
```

### AFIP / Facturación Electrónica (Argentina)
```
# Certificate exposure
(?i)(afip|arca).{0,20}(cert|certificado|crt|key)\s*[=:]  # AFIP cert in code
# CUIT exposure
\b(20|23|24|25|26|27|30|33|34)\d{8}\b  # CUIT hardcoded
(?i)cuit\s*[=:]\s*\d{11}               # CUIT in variable
```

### Datos personales (Ley de Datos Personales — Argentina, LGPD — Brasil)
```
# DNI/CPF/RUT storage
(?i)(dni|cpf|rut|cedula)\s*[=:]\s*['\"]?\d{7,11}   # Identity docs in code
# CBU/CVU (banking)
\b[0-9]{22}\b                                         # 22-digit CBU format
(?i)(cbu|cvu|alias)\s*[=:]\s*['\"]?\S{10,}          # Banking identifiers
```

---

## PHASE 13 — DEPENDENCY AUDIT

Run the appropriate command based on detected stack:

**Node.js / Next.js / React:**
```bash
npm audit --json 2>/dev/null
```
Parse output:
- `critical` vulnerabilities → CRITICO
- `high` → ALTO
- `moderate` → MEDIO
- `low` → BAJO

Also check for:
```bash
cat package.json
```
Flag packages that are:
- `moment` (deprecated, ReDoS vulnerabilities)
- `request` (deprecated)
- `node-uuid` (use `uuid` instead)
- `lodash` < 4.17.21 (prototype pollution)
- `axios` < 1.6.0 (SSRF, XSS)
- `jsonwebtoken` < 9.0.0

**Python:**
```bash
pip audit 2>/dev/null || pip-audit 2>/dev/null
```

Flag packages:
- `django` < 4.2.x (LTS, check CVEs)
- `flask` < 3.0.0
- `cryptography` < 41.0.0
- `pillow` < 10.0.1 (image processing CVEs)
- `pyyaml` < 6.0.1

**PHP / WordPress:**
```bash
composer audit 2>/dev/null
```

---

## PHASE 14 — SCORING ENGINE

Calculate score starting from 100. Apply deductions:

```
CRITICAL findings:
  - Secret exposed (AWS/GCP/Stripe/DB credentials):  -25 each (max -50)
  - SQL/Command Injection:                           -20 each (max -40)
  - Auth bypass / broken access control:             -20 each (max -40)
  - Privilege escalation via DB function/RPC grant:  -25 each (max -50)   [Phase 4.5]
  - RLS/security-rule exposes data across roles      -20 each (max -40)   [Phase 4.4 / 4.8]
    or tenants (multi-tenant isolation failure)
  - Client-side-only paywall / entitlement bypass:   -20 each (max -40)   [Phase 6.1]
  - Insecure deserialization:                        -15 each (max -30)
  - CRITICAL CVE in dependency:                      -15 each (max -30)
  - JWT algorithm confusion (no alg allowlist):      -20 each (max -40)   [Phase 7.1]
  - N8N_ENCRYPTION_KEY committed/hardcoded:          -25 each (max -50)   [Phase 5.5]
  - n8n instance with no auth (internet-facing):     -20 each (max -40)   [Phase 5.5]
  - Command/code injection via n8n Code/Execute      -20 each (max -40)   [Phase 5.3]
    Command node fed by external input:
  - Terraform state file (.tfstate) committed        -20 each (max -40)   [Phase 8.1]
    to git (plaintext secrets):
  - IAM policy: Action:* + Resource:* on a           -20 each (max -40)   [Phase 8.2]
    workload identity (not a human admin role):

HIGH findings:
  - Hardcoded credentials (non-production):          -10 each (max -20)
  - XSS vulnerabilities:                             -10 each (max -20)
  - Missing auth on sensitive endpoint:              -10 each (max -20)
  - SSRF vulnerability:                              -10 each (max -20)
  - HIGH CVE in dependency:                          -8 each (max -16)
  - RLS disabled on a table (no policy evaluated):   -12 each (max -24)   [Phase 4.3]
  - SECURITY DEFINER function missing SET            -8 each (max -16)   [Phase 4.5]
    search_path (hijacking risk):
  - Public storage bucket with private user files:   -12 each (max -24)   [Phase 4.6]
  - Payment webhook: no signature check or           -12 each (max -24)   [Phase 6.3]
    no replay/idempotency protection:
  - Unprotected digital asset URL (paywall bypass    -10 each (max -20)   [Phase 6.7]
    via direct link):
  - Price/amount trusted from client at checkout:    -12 each (max -24)   [Phase 6.2]
  - Session fixation (no regenerate on login):       -8 each (max -16)    [Phase 7.4]
  - CSRF-exploitable state change on GET:            -8 each (max -16)    [Phase 7.5]
  - Prototype pollution via unguarded deep merge:    -10 each (max -20)   [Phase 7.7]
  - Open redirect (OAuth/return_to):                 -8 each (max -16)    [Phase 7.10]
  - Inline secret in n8n workflow JSON instead of    -10 each (max -20)   [Phase 5.2]
    the credential system:
  - Unauthenticated webhook driving costed/          -8 each (max -16)    [Phase 5.4]
    reputation-sensitive action (no rate limit):
  - Public cloud storage bucket with sensitive        -12 each (max -24)   [Phase 8.3]
    data (backups, uploads, state files):
  - Privileged/root Kubernetes container handling    -10 each (max -20)   [Phase 8.4]
    untrusted input:
  - Long-lived static cloud credentials in CI/CD:    -8 each (max -16)    [Phase 8.6]

MEDIUM findings:
  - Weak cryptography (MD5/SHA1 for passwords):      -5 each (max -10)
  - Missing security headers (2+ missing):           -5 (flat)
  - CORS misconfiguration:                           -5 each (max -10)
  - Debug mode in production signals:                -5 (flat)
  - MODERATE CVE in dependency:                      -3 each (max -9)
  - Excessive data exposure (SELECT * to client):    -5 each (max -10)    [Phase 7.3]
  - Free-trial/free-tier abuse (no durable check):   -5 each (max -10)    [Phase 6.5]
  - Timing/message-based user enumeration:           -4 each (max -8)     [Phase 7.6]
  - ReDoS-prone regex on public endpoint:            -5 each (max -10)    [Phase 7.8]
  - Broad USING(true)/anon-readable policy on        -5 each (max -10)    [Phase 4.4]
    non-sensitive catalog data (informational risk):
  - Kubernetes secret as plain env value, or         -5 each (max -10)    [Phase 8.5]
    cluster with no NetworkPolicy at all:

LOW findings:
  - Single missing security header:                  -2 each (max -8)
  - Non-sensitive info in logs:                      -2 each (max -4)
  - Minor misconfigurations:                         -2 each (max -4)
  - Sequential/enumerable public resource IDs:       -2 each (max -6)     [Phase 7.2]
  - N8N_SECURE_COOKIE=false on HTTPS-served instance: -2 each (max -4)    [Phase 5.5]

Minimum score: 0
```

**Score interpretation:**
```
90-100 : EXCELENTE  — Listo para producción
75-89  : BUENO      — Resolver hallazgos altos antes de deploy
60-74  : ACEPTABLE  — Trabajo pendiente importante
40-59  : DEFICIENTE — No desplegar sin resolver críticos y altos
0-39   : CRÍTICO    — Auditoría urgente requerida
```

---

## PHASE 15 — REPORT OUTPUT

Generate the report in this exact format:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AUDITRON — REPORTE DE SEGURIDAD
  Proyecto: <project-name-from-package.json or directory>
  Stack:    <detected stack>
  Fecha:    <current date>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PUNTUACIÓN FINAL: XX/100  [LABEL]

RESUMEN
  Crítico:      X hallazgos
  Alto:         X hallazgos
  Medio:        X hallazgos
  Bajo:         X hallazgos
  Informativo:  X hallazgos
  Total:        X hallazgos

━━━━ HALLAZGOS CRÍTICOS ━━━━━━━━━━━━━━━━━━━━━━━━━

[C-01] <Title>
  Archivo:     <path>:<line>
  OWASP:       <category>
  CWE:         CWE-XXX (<name>)
  Descripción: <clear explanation of the risk>
  Remediación:
    <step 1>
    <step 2>
  Código:
    // ANTES (vulnerable)
    <vulnerable code snippet>

    // DESPUÉS (seguro)
    <fixed code snippet>

[C-02] ...

━━━━ HALLAZGOS ALTOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[A-01] <Title>
  ... (same format)

━━━━ HALLAZGOS MEDIOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━

[M-01] ...

━━━━ HALLAZGOS BAJOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[B-01] ...

━━━━ INFORMATIVOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[I-01] ...

━━━━ DEPENDENCIAS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<npm/pip/composer audit summary>
<CVEs found with package, version, severity>

━━━━ CHECKLIST PRE-DEPLOY ━━━━━━━━━━━━━━━━━━━━━━━

<stack-specific checklist — see Phase 16>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  auditron | Luis Recalde | MIT 2026
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

If no findings in a severity level, omit that section.
If no findings at all in a category, write: `Sin hallazgos en esta categoría.`

---

## PHASE 16 — PRE-DEPLOY CHECKLISTS

### NEXTJS
```
PRE-DEPLOY CHECKLIST — Next.js
[ ] Variables de entorno: .env.local no commiteado, .env.example actualizado
[ ] NEXTAUTH_SECRET: valor fuerte (openssl rand -base64 32)
[ ] next.config.js: headers de seguridad configurados (CSP, HSTS, X-Frame-Options)
[ ] API routes: validación de input con zod o yup en todos los endpoints
[ ] API routes: autenticación verificada (getServerSession / middleware)
[ ] Rate limiting: configurado en /api/auth y endpoints sensibles
[ ] npm audit: sin vulnerabilidades críticas ni altas
[ ] NEXT_PUBLIC_*: ninguna variable con este prefijo contiene secretos
[ ] .gitignore: incluye .env, .env.local, .env*.local
[ ] console.log: ninguno con datos sensibles en código de producción
[ ] Error handling: errores genéricos al cliente, detalles solo en logs del servidor
[ ] CORS: configurado explícitamente, sin wildcard en endpoints autenticados
[ ] Content-Security-Policy: testeada contra ataques XSS
[ ] Dependencias: actualizadas (máximo 90 días de lag en producción)
[ ] Imágenes Docker: base image pinneada a versión específica
```

### REACT (SPA)
```
PRE-DEPLOY CHECKLIST — React SPA
[ ] Variables de entorno: solo REACT_APP_* para valores no sensibles
[ ] Ningún secreto en el bundle de frontend (tokens, keys de API privados)
[ ] Tokens de auth: almacenados en httpOnly cookies, no localStorage
[ ] npm audit: sin vulnerabilidades críticas ni altas
[ ] dangerouslySetInnerHTML: sanitizado con DOMPurify donde se use
[ ] Dependencias: sin packages deprecados (moment, request, node-uuid)
[ ] CSP headers: configurados en el servidor que sirve la SPA
[ ] API base URL: sin hardcodeo, usar variable de entorno
[ ] HTTPS: forzado en producción, no hay mixed content
[ ] Source maps: deshabilitados en build de producción
```

### NODE_EXPRESS
```
PRE-DEPLOY CHECKLIST — Node.js / Express
[ ] helmet: instalado y configurado con opciones de CSP
[ ] Rate limiting: en rutas de auth y endpoints de alta frecuencia
[ ] CORS: lista blanca explícita, sin wildcard con credentials
[ ] Input validation: express-validator o joi en todas las rutas
[ ] SQL/NoSQL queries: 100% parametrizadas, sin concatenación
[ ] JWT: secret fuerte (32+ chars), expiración razonable (15m access, 7d refresh)
[ ] Passwords: bcrypt con cost ≥ 12
[ ] npm audit: sin críticos ni altos
[ ] Variables de entorno: dotenv con .env no commiteado
[ ] Error handling: middleware global sin leakear stack traces
[ ] Logging: Morgan o Winston, sin datos PII en logs
[ ] HTTPS: forzado, redirección HTTP→HTTPS configurada
[ ] Process: corriendo como usuario no-root en producción
[ ] Dependencias: node_modules no en imagen Docker de producción
```

### PYTHON_WEB (FastAPI / Flask / Django)
```
PRE-DEPLOY CHECKLIST — Python Web
[ ] SECRET_KEY: valor fuerte en variable de entorno, no en código
[ ] DEBUG: False en producción (Django/Flask)
[ ] ALLOWED_HOSTS: configurado explícitamente (Django)
[ ] pip audit: sin vulnerabilidades en dependencias
[ ] requirements.txt: versiones pinneadas (no solo >=)
[ ] SQL queries: ORM o queries parametrizadas, sin f-strings en SQL
[ ] Input validation: Pydantic (FastAPI) o WTForms (Flask) en todos los endpoints
[ ] CSRF protection: habilitado para formularios POST
[ ] Passwords: passlib + bcrypt, no hashlib.md5
[ ] File uploads: validación de tipo MIME, no confiar solo en extensión
[ ] yaml.safe_load: usando safe_load, no load()
[ ] defusedxml: usando defusedxml para parseo XML
[ ] HTTPS: forzado, SESSION_COOKIE_SECURE = True
[ ] Logging: sin contraseñas ni tokens en logs
[ ] .env: python-dotenv, archivo no commiteado
```

### WORDPRESS
```
PRE-DEPLOY CHECKLIST — WordPress
[ ] wp-config.php: fuera del webroot o con permisos 640
[ ] Claves y salts: generadas con https://api.wordpress.org/secret-key/1.1/salt/
[ ] DB_PASSWORD: valor fuerte (16+ chars, caracteres especiales)
[ ] Debug: WP_DEBUG = false en producción
[ ] Prefijo de tablas: cambiado de wp_ a valor único
[ ] Usuarios: sin usuario "admin" con ese login
[ ] Contraseña admin: fuerte, 2FA habilitado
[ ] Plugins: actualizados, sin plugins abandonados (>1 año sin update)
[ ] Temas: solo tema activo instalado
[ ] Enumeración de usuarios: deshabilitada (?author=1)
[ ] XML-RPC: deshabilitado si no se usa (Jetpack, etc.)
[ ] File editor: deshabilitado (DISALLOW_FILE_EDIT = true)
[ ] uploads: protegido contra ejecución de PHP (.htaccess)
[ ] Backups: automatizados y verificados
[ ] SSL: certificado válido, forzar HTTPS
[ ] Fail2ban / login limitado: plugin o servidor
```

### STATIC
```
PRE-DEPLOY CHECKLIST — Sitio Estático
[ ] Sin API keys ni tokens en archivos JS del frontend
[ ] Sin comentarios con información sensible en HTML/JS
[ ] HTTPS: configurado en hosting (Netlify, Vercel, Cloudflare Pages)
[ ] Headers de seguridad: configurados en _headers (Netlify) o vercel.json
[ ] CSP: definida para prevenir XSS
[ ] Formularios de contacto: endpoint backend con CSRF y rate limiting
[ ] .gitignore: cualquier archivo de config local excluido
[ ] Dependencias de build: auditadas con npm audit
[ ] Source maps: no expuestos en producción
```

### SUPABASE / FIREBASE (aplica junto con el checklist del frontend, no en su lugar)
```
PRE-DEPLOY CHECKLIST — Backend-as-a-Service
[ ] RLS habilitada en TODAS las tablas (ninguna tabla nueva sin ALTER TABLE ... ENABLE ROW LEVEL SECURITY)
[ ] Ninguna política usa USING(true) sobre datos sensibles si hay más de un rol/tier compartiendo "authenticated"
[ ] Toda política FOR ALL tiene una política SELECT separada y más estricta (o se confirmó que no hace falta)
[ ] Funciones SECURITY DEFINER: cada una revisada — ¿valida el rol/identidad de quien llama internamente?
[ ] Funciones SECURITY DEFINER: GRANT revisado en authenticated Y en PUBLIC (Postgres otorga PUBLIC por default)
[ ] Funciones SECURITY DEFINER: todas tienen SET search_path explícito
[ ] Buckets de Storage con archivos privados/de usuario: NO marcados como public
[ ] Edge Functions con verify_jwt = false: confirmado que son endpoints genuinamente públicos con su propia verificación
[ ] Service role key: nunca en el bundle de frontend, solo en funciones server-side/edge
[ ] Rate limiting de Supabase Auth (sign-in, sign-up, OTP): ajustado a un valor bajo, no el default
[ ] Si el proyecto pasó por un rediseño reciente de schema.sql: se regeneró con `supabase db dump --linked`, no se confía en una copia vieja
```

### SAAS / MARKETPLACE / MONETIZACIÓN (aplica a proyectos con planes pagos, suscripciones o venta entre usuarios)
```
PRE-DEPLOY CHECKLIST — Monetización
[ ] Todo endpoint que sirve contenido/feature pago re-verifica la suscripción activa server-side, no confía en un flag del cliente
[ ] El monto/plan cobrado en checkout se deriva de una tabla de precios propia, nunca de un valor enviado por el cliente
[ ] Webhooks de pago (Stripe/MercadoPago/PayPal): firma verificada Y se corta el flujo si falla (no solo se loguea)
[ ] Webhooks de pago: protegidos contra reenvío/replay (idempotencia por event ID)
[ ] Assets digitales pagos: servidos con URL firmada de corta duración, no un link público permanente
[ ] Límites de uso en features costosas (IA, render, envío de SMS/email): aplicados server-side, no solo en la UI
[ ] Si es marketplace: comisión/payout del vendedor se calcula server-side, no llega como input del cliente
[ ] Si es multi-tenant: el tenant/organización se deriva de la sesión autenticada, nunca de un parámetro de la URL/body
```

### N8N / AUTOMATIZACIÓN DE WORKFLOWS
```
PRE-DEPLOY CHECKLIST — n8n
[ ] Nodos Webhook con authentication: none — revisados uno por uno, cada uno justificado (formulario público, webhook de proveedor con firma propia)
[ ] Ningún Webhook público sin auth dispara envío de email/SMS a una dirección/número tomado del body sin límite de tasa por remitente
[ ] Nodos HTTP Request: credenciales via el sistema de Credentials de n8n, ninguna API key/token pegada directo en headers/URL/body
[ ] Nodos Code/Execute Command: sin eval()/Function()/exec() sobre datos que vienen de un Webhook u otra fuente externa
[ ] N8N_ENCRYPTION_KEY: no committeada en ningún repo, generada una vez y resguardada (perderla o rotarla rompe todas las credenciales guardadas)
[ ] Instancia de n8n expuesta a internet: user management/basic auth activado, no accesible sin login
[ ] N8N_SECURE_COOKIE en true si la instancia se sirve por HTTPS (siempre en producción)
```

### CLOUD / INFRAESTRUCTURA COMO CÓDIGO (Terraform, Kubernetes, CI/CD)
```
PRE-DEPLOY CHECKLIST — Cloud/IaC
[ ] terraform.tfstate: nunca commiteado, backend remoto con cifrado y acceso restringido por IAM
[ ] Políticas IAM de identidades de aplicación (no humanos): sin combinación Action:* + Resource:*
[ ] Buckets S3/GCS: Block Public Access activado salvo excepción justificada y documentada
[ ] Contenedores Kubernetes: sin privileged:true ni runAsUser:0 salvo necesidad real justificada
[ ] Secrets de Kubernetes: via Secret + secretKeyRef, nunca como value: literal en el manifest
[ ] Al menos una NetworkPolicy definida — el cluster no queda en red plana por default
[ ] Credenciales cloud en CI/CD: OIDC de corta duración en vez de access keys estáticas donde el proveedor lo soporte
```

---

## EXECUTION NOTES

1. **Always complete all phases** — do not stop at first finding. A comprehensive report is the goal.
2. **Context-aware severity** — a secret in `.env.example` with `YOUR_KEY_HERE` is NOT a finding.
3. **Real findings only** — report actual matches with file:line. No hypothetical warnings without evidence.
4. **Fix code** — every CRITICAL and HIGH finding must include working remediation code.
5. **LATAM first** — MercadoPago and CUIT patterns have cultural importance. Surface them prominently.
6. **Dependency audit** — if `npm audit` / `pip audit` / `composer audit` is not available, note it but continue.
7. **Score honestly** — a project with no findings deserves 100. Don't invent findings to fill sections.
8. **Language** — write the report in the same language the user used to invoke the skill (Spanish or English).
9. **No hallazgos = good news** — if a section is clean, say so clearly: "Sin hallazgos. ✓"
10. **Rotate first** — when reporting exposed secrets, always lead with "Rotar la credencial INMEDIATAMENTE" before any code fixes.
11. **Never skip Phase 4/5/6/8 checks based on Phase 1 alone** — a BaaS backend, an n8n automation layer, a monetization layer, or cloud/IaC config can sit behind or alongside any frontend stack, or exist with no frontend at all. Actually run the trigger checks in each of those phases for every project; only write "fase omitida" after confirming none of the trigger signals matched, not by assumption.
12. **Code review ≠ privilege review** — findings in Phase 4 (database privileges, RLS, GRANTs) cannot be fully confirmed by reading `schema.sql` alone if that file might be stale. Say so explicitly in the report when a live `supabase db dump --linked` wasn't possible, so the user knows the finding's confidence level.
13. **Ask before testing live** — the live RLS-simulation technique in Phase 4.5 touches a real database (even if only `SELECT`/read-only `SET ROLE` simulation). Always get explicit user confirmation before running it against a production or otherwise live project, and always clean up any disposable test accounts created for the test before closing the audit.
14. **Business logic over pattern-matching in Phase 5** — monetization/entitlement bugs rarely match a clean regex the way a hardcoded secret does. Read the actual request/response flow for checkout, webhook, and paywall-gated endpoints; a missing grep hit is not the same as "no finding" for this phase.
