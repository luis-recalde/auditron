# auditron

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Stars](https://img.shields.io/github/stars/luis-recalde/auditron?style=social)
![Forks](https://img.shields.io/github/forks/luis-recalde/auditron?style=social)

Skill de seguridad universal para Claude Code. Audita cualquier proyecto — Next.js, React, Python, Node.js, FastAPI, WordPress, sitios estáticos — y genera un reporte profesional con puntuación 0-100, hallazgos priorizados y código de remediación incluido.

## Instalación

```bash
# Clonar en tu directorio de skills de Claude Code
git clone https://github.com/luis-recalde/auditron ~/.claude/skills/auditron

# O copiar SKILL.md directamente al proyecto
cp ~/.claude/skills/auditron/SKILL.md .claude/SKILL.md
```

## Uso

```
/auditron
```

O simplemente decirle a Claude: *"auditá este proyecto"*, *"revisá la seguridad"*, *"buscá vulnerabilidades"*, *"hacé un pentest"*.

## Qué analiza

### Detección automática de stack
Auditron detecta el tipo de proyecto y adapta la auditoría:

| Stack | Detección | Herramientas |
|---|---|---|
| Next.js | `next.config.*`, `pages/`, `app/` | npm audit, headers, CSP |
| React | `package.json` + react dep | npm audit, XSS patterns |
| Node.js / Express | `express` en deps | npm audit, CORS, middleware |
| Python / FastAPI | `requirements.txt`, `pyproject.toml` | pip audit, SQLI, template injection |
| WordPress | `wp-config.php`, `wp-content/` | PHP patterns, plugin vulns |
| PHP genérico | `*.php`, `composer.json` | composer audit, injection |
| Sitio estático | Solo HTML/CSS/JS | secrets en frontend, headers |

### Cobertura de seguridad

**OWASP 2025 Top 10 completo:**
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

**CWE Top 25 aplicable por lenguaje**

**70+ patrones de secrets:**
- AWS (Access Key, Secret Key, Session Token, MFA, Account ID)
- GCP (Service Account, API Key, OAuth)
- Azure (Connection String, Storage Key, SAS Token)
- Stripe (Live/Test Secret, Webhook)
- MercadoPago (Access Token, Public Key, Client Secret)
- PayPal (Client ID/Secret, Webhook)
- Supabase (Service Role Key, Anon Key, JWT Secret)
- Firebase (API Key, Admin SDK, Database URL)
- MongoDB Atlas (Connection String con credenciales)
- JWT secrets y claves de firma
- SSH private keys (RSA, ECDSA, Ed25519)
- SMTP credenciales (Gmail, Outlook, custom)
- Twilio (Account SID, Auth Token)
- SendGrid (API Key)
- GitHub (PAT clásico, fine-grained, OAuth App)
- GitLab (Personal, Deploy, Group tokens)
- npm (Auth token)
- Docker Hub (Access Token)
- Slack (Bot Token, Webhook URL)
- Discord (Bot Token, Webhook)
- Telegram (Bot Token)
- OpenAI (API Key)
- Anthropic (API Key)
- Cloudflare (Global API Key, Token)
- HubSpot (API Key, Private App Token)
- Salesforce (Instance URL + token)
- Variables en español: CLAVE_, SECRETO_, CONTRASENA_, TOKEN_MP_, USUARIO_DB_, etc.

**Especial LATAM:**
- MercadoPago: flows de pago, webhooks, IPN
- Exposición de CUIT/CUIL/DNI en código o respuestas
- Facturación electrónica: AFIP, SAT, SII
- Variables de entorno en español sin ofuscar

### Headers de seguridad
Revisa y genera configuración para:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-*` headers

### Auditoría de dependencias
- `npm audit` con análisis de severidad
- `pip audit` para proyectos Python
- `composer audit` para PHP/WordPress
- Detección de dependencias abandonadas o sin mantenimiento

## Reporte

El reporte tiene puntuación **0-100** y está organizado en secciones:

```
PUNTUACION FINAL: 73/100

[CRITICO]  2 hallazgos  — bloquean deploy
[ALTO]     4 hallazgos  — resolver antes de producción
[MEDIO]    6 hallazgos  — resolver en próximo sprint
[BAJO]     8 hallazgos  — mejoras recomendadas
[INFO]     3 hallazgos  — buenas prácticas

Cada hallazgo incluye:
  - Descripción del problema
  - Archivo y línea exacta
  - OWASP / CWE referenciado
  - Código de remediación listo para aplicar
```

## Checklist pre-deploy

Al final del reporte se genera un checklist específico para el stack detectado. Ejemplo para Next.js:

```
PRE-DEPLOY CHECKLIST — Next.js
[ ] Variables de entorno en .env.local, no en .env commiteado
[ ] NEXTAUTH_SECRET con valor fuerte (32+ chars)
[ ] next.config.js con headers de seguridad configurados
[ ] CSP policy definida y testeada
[ ] API routes con validación de input (zod/yup)
[ ] Rate limiting en endpoints de auth
[ ] npm audit sin críticos/altos
[ ] No hay console.log con datos sensibles
[ ] .gitignore incluye .env*
[ ] Dependencias actualizadas (90 días max de lag)
```

## Por qué Auditron

Tu sitio web o aplicación maneja datos de clientes, procesa pagos y sostiene tu negocio. Una brecha de seguridad puede significar pérdida de datos, multas regulatorias y daño a tu reputación — todo a la vez.

Auditron hace una revisión completa antes de que eso pase:

**Encuentra lo que no ves** — contraseñas y claves API que quedaron hardcodeadas en el código, configuraciones inseguras, librerías con vulnerabilidades conocidas. Son los errores más comunes y los más costosos cuando los aprovecha un atacante.

**Habla el idioma de la región** — entiende pagos con MercadoPago, facturación electrónica AFIP/SAT/SII y datos sensibles como CUIT o DNI. No es un scanner genérico traducido: fue construido para el ecosistema latinoamericano.

**No necesitás ser experto** — una sola instrucción audita todo el proyecto. El reporte explica cada problema en lenguaje claro con la solución lista para aplicar.

**Cobertura profesional** — sigue los estándares internacionales OWASP y CWE que usan los equipos de seguridad de grandes empresas. La misma rigurosidad, al alcance de cualquier equipo.

## Autor

**Luis Recalde** — [info@luisrecalde.com](mailto:info@luisrecalde.com)

Licencia MIT — 2026
