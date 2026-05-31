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

## PHASE 4 — CWE TOP 25 (by language)

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

## PHASE 5 — SECURITY HEADERS

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

## PHASE 6 — INFRASTRUCTURE & CONFIG REVIEW

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

## PHASE 7 — LATAM-SPECIFIC CHECKS

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

## PHASE 8 — DEPENDENCY AUDIT

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

## PHASE 9 — SCORING ENGINE

Calculate score starting from 100. Apply deductions:

```
CRITICAL findings:
  - Secret exposed (AWS/GCP/Stripe/DB credentials):  -25 each (max -50)
  - SQL/Command Injection:                           -20 each (max -40)
  - Auth bypass / broken access control:             -20 each (max -40)
  - Insecure deserialization:                        -15 each (max -30)
  - CRITICAL CVE in dependency:                      -15 each (max -30)

HIGH findings:
  - Hardcoded credentials (non-production):          -10 each (max -20)
  - XSS vulnerabilities:                             -10 each (max -20)
  - Missing auth on sensitive endpoint:              -10 each (max -20)
  - SSRF vulnerability:                              -10 each (max -20)
  - HIGH CVE in dependency:                          -8 each (max -16)

MEDIUM findings:
  - Weak cryptography (MD5/SHA1 for passwords):      -5 each (max -10)
  - Missing security headers (2+ missing):           -5 (flat)
  - CORS misconfiguration:                           -5 each (max -10)
  - Debug mode in production signals:                -5 (flat)
  - MODERATE CVE in dependency:                      -3 each (max -9)

LOW findings:
  - Single missing security header:                  -2 each (max -8)
  - Non-sensitive info in logs:                      -2 each (max -4)
  - Minor misconfigurations:                         -2 each (max -4)

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

## PHASE 10 — REPORT OUTPUT

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

<stack-specific checklist — see Phase 11>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  auditron | Luis Recalde | MIT 2026
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

If no findings in a severity level, omit that section.
If no findings at all in a category, write: `Sin hallazgos en esta categoría.`

---

## PHASE 11 — PRE-DEPLOY CHECKLISTS

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
