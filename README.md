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

Esta detección es solo del framework de frontend. Si el proyecto además usa Supabase/Firebase, n8n, tiene pagos/suscripciones, o incluye Terraform/Kubernetes, Auditron corre esas auditorías **además**, sin importar qué stack haya detectado — un proyecto React con Supabase recibe el análisis de React completo *y* la auditoría de privilegios de base de datos, y un repo de solo infraestructura (sin frontend) igual recibe la auditoría de Cloud/IaC.

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

**Backend-as-a-Service — Supabase / Firebase (auditoría de privilegios reales, no solo código):**
- Políticas RLS de Postgres evaluadas contra los roles reales de la app (admin/staff/cliente, free/pro) — detecta cuándo un acceso "aceptable entre compañeros de trabajo" se convierte en una fuga de PII al agregar un rol externo (clientes, usuarios finales)
- Funciones `SECURITY DEFINER`: detecta escalación de privilegios por permisos de ejecución mal configurados (incluyendo el `GRANT` implícito a `PUBLIC` que Postgres aplica por defecto y que un `REVOKE` parcial no cierra)
- `search_path` sin fijar en funciones con privilegios elevados (hijacking)
- Buckets de Storage públicos con archivos privados de usuarios
- Edge Functions con verificación de JWT deshabilitada
- Reglas de seguridad de Firestore/Firebase Storage equivalentes a `USING(true)`
- Técnica de verificación en vivo (opcional, con permiso explícito): simula sesiones de bajo privilegio contra la base real para confirmar que un hallazgo cerrado realmente quedó cerrado

**Automatización de workflows — n8n (y exports de Zapier/Make):**
- Nodos Webhook sin autenticación que disparan acciones costosas o sensibles (email/SMS a una dirección tomada del body, sin límite de tasa) — validado contra un workflow real de producción
- Credenciales pegadas directo en un nodo HTTP Request en vez de usar el sistema de Credentials de n8n (quedan en texto plano en cada export/backup)
- Nodos Code/Execute Command ejecutando `eval()` o comandos de shell sobre datos que vienen de un Webhook externo
- `N8N_ENCRYPTION_KEY` expuesta (descifra todas las credenciales guardadas en la instancia) e instancia sin autenticación de usuario expuesta a internet

**SaaS, marketplaces y monetización (freemium, suscripciones, venta entre usuarios):**
- Paywalls/features pagas verificadas solo en el frontend (bypasseables llamando la API directo)
- Monto o plan de checkout confiado desde el cliente en vez de calculado en el servidor
- Webhooks de pago sin protección contra reenvío (doble acreditación) o que ignoran una firma inválida
- Assets digitales pagos servidos con URLs públicas permanentes en vez de firmadas y expirables
- Abuso de prueba gratuita / cuentas desechables sin verificación de identidad durable
- Ataques de "billetera" — funciones costosas (IA, render) sin límite de uso por usuario del lado del servidor
- Marketplaces: comisión/payout del vendedor calculado del lado del cliente
- Aislamiento multi-tenant: el tenant/organización debe derivarse de la sesión, nunca de un parámetro de la URL

**Race conditions e invariantes de lógica de negocio (TOCTOU, check-then-act) — corre en todo proyecto, sin trigger:**
- Cuotas/límites/contadores chequeados e incrementados en dos pasos separados en vez de una sola sentencia atómica (bypass de límite mensual/rate limit bajo concurrencia)
- Tokens de un solo uso (reset de contraseña, OTP, invite) consumidos sin atomicidad — el mismo token puede usarse dos veces en paralelo
- Idempotency keys guardadas solo en memoria de un proceso, o sin el usuario/principal como parte de la clave
- Unicidad (email único, un pedido por click) garantizada solo por lógica de aplicación, sin constraint UNIQUE real en la base
- Transiciones de estado (pending→approved→shipped→refunded) sin validar el estado actual antes de aplicar la siguiente — permite doble reembolso o pasos fuera de orden
- Reservas de inventario/cupos/asientos sin liberación atómica en caso de abandono o timeout
- Validación recomendada con prueba real de requests concurrentes (con autorización explícita) antes de reportar severidad CRITICAL/HIGH

**Vectores avanzados y menos comunes (pero reales):**
- Confusión de algoritmo JWT (RS256/HS256)
- IDOR por IDs secuenciales/enumerables
- Exposición excesiva de datos (`SELECT *` devuelto tal cual al cliente)
- Fijación de sesión, CSRF en peticiones GET que mutan estado
- Enumeración de usuarios por mensajes/tiempos de respuesta distintos
- Prototype pollution, ReDoS, dependency confusion, open redirect en flujos OAuth
- GraphQL: introspección en producción, autorización a nivel de campo/resolver, falta de límite de profundidad/complejidad, errores verbosos, mutaciones vía GET con auth por cookie

**Cloud e infraestructura como código (Terraform, Kubernetes, CI/CD):**
- Archivo `terraform.tfstate` commiteado (contiene secretos en texto plano aunque la variable tenga `sensitive = true`)
- Políticas IAM con `Action: *` + `Resource: *` en identidades de aplicación, no solo humanos
- Buckets S3/GCS públicos con backups o archivos de usuario
- Contenedores Kubernetes `privileged: true` o corriendo como root, cluster sin ninguna `NetworkPolicy`
- Secrets de Kubernetes como variable de entorno literal en vez de `secretKeyRef`
- Credenciales cloud estáticas de larga duración en CI/CD en vez de OIDC de corta duración

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
