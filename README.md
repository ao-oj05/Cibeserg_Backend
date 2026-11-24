# ScanDev — Backend & RESTful API

Núcleo lógico y motor de auditoría de ciberseguridad no invasiva para la plataforma **ScanDev**. Desarrollado con **Next.js (App Router)**, **TypeScript**, **Prisma ORM**, y **PostgreSQL**.

---

## 🛡️ Propósito del Sistema

ScanDev ejecuta evaluaciones pasivas y defensivas contra aplicaciones web y dominios públicos, auditando:
1. **Cabeceras de Seguridad HTTP:** Verificación de las 7 directivas esenciales (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies`).
2. **Inspección Criptográfica TLS/SSL:** Análisis directo por socket TLS (puerto 443) para extraer entidad emisora, días de vigencia restantes, estado de revocación/confianza y versión de protocolo (`TLSv1.2`, `TLSv1.3`).
3. **Diagnóstico de Conectividad:** Medición precisa de latencia y verificación de redirección obligatoria desde `http://` a `https://`.
4. **Cálculo de Riesgo Dinámico:** Puntuación normalizada de 0 a 100 (`Seguro >= 80`, `Riesgo Medio 60-79`, `Riesgo Alto < 60`).
5. **Generación de Reportes Seguros:** Generación de PDFs ejecutivos y técnicos, almacenados de forma privada fuera de la raíz web, y exportaciones CSV blindadas contra *CSV Formula Injection*.

---

## 🚀 Stack Tecnológico

| Capa | Tecnología |
| :--- | :--- |
| **Entorno de Ejecución** | Node.js v20+ / v22+ LTS (TypeScript ESM) |
| **Framework de API** | Next.js 15 (App Router - `app/api/.../route.ts`) |
| **Acceso a Datos / ORM** | Prisma ORM (`@prisma/client` + `@prisma/adapter-pg`) |
| **Base de Datos** | PostgreSQL 18 (rol restringido `app_user`) |
| **Auditoría Nativa** | `fetch`, `tls`, `https`, `dns`, `net` (Node.js nativo) |
| **Autenticación** | `argon2` (Argon2id) + `jose` (JWT en cookies HttpOnly/Secure) |
| **Validación de Datos** | `zod` |
| **Generación de Reportes** | `pdfkit` |

---

## 🔒 Cumplimiento de Requerimientos de Seguridad

| ID | Requerimiento | Implementación Técnica |
| :--- | :--- | :--- |
| **BK-01** | **Prevención de SSRF** | `src/services/scanner/safe-http.ts` valida cada destino y redirección, conecta a la IP validada y rechaza rangos privados o reservados. |
| **BK-02** | **Control de DoS y Tiempos** | Escaneos limitados a 30 segundos, peticiones externas a 5 segundos, cuerpos de respuesta a 1 MB, cinco redirecciones y 10 escaneos por hora por usuario, con límites compartidos mediante PostgreSQL. |
| **BK-03** | **Validación de Entradas** | Esquemas Zod estrictos en cada endpoint REST (`src/lib/validators.ts`), rechazando payloads malformados o inyecciones. |
| **BK-04** | **Gestión Segura de Sesión** | Tokens JWT `HS256` con expiración de 8 horas en cookies `HttpOnly`, `Secure` y `SameSite=Lax`; cada solicitud comprueba en base de datos que la cuenta existe y no está suspendida. |
| **BK-05** | **Aislamiento Multitenant** | Cada consulta y actualización de recursos propios se filtra por `userId` de la sesión validada. |
| **BK-06** | **Manejo Seguro de Errores** | Respuestas con códigos HTTP canónicos y mensajes controlados que evitan filtrar trazas de error, versiones o queries SQL al cliente. |
| **BK-07** | **Protección de Archivos y CSV** | Archivos PDF almacenados en `storage/reports/` (fuera de `/public`), descarga condicionada a validación de propietario, vigencia de 7 días y ruta canónica dentro del almacenamiento. Las exportaciones CSV neutralizan fórmulas incluso después de espacios o caracteres de control. |

---

## 📁 Estructura del Proyecto

```plaintext
scandev/
├── prisma/
│   ├── schema.prisma              # Modelos de usuarios, escaneos, trabajos, límites y reportes
│   └── migrations/                # Historial de migraciones SQL
├── storage/
│   └── reports/                   # Almacenamiento privado de PDFs generados (fuera de /public)
├── src/
│   ├── app/
│   │   └── api/                   # Endpoints RESTful de Next.js
│   │       ├── auth/
│   │       │   ├── register/route.ts      # POST: Registro de usuario
│   │       │   ├── login/route.ts         # POST: Inicio de sesión y cookie JWT
│   │       │   └── logout/route.ts        # POST: Cierre de sesión y revocación
│   │       ├── scans/
│   │       │   ├── route.ts               # GET: Historial paginado | POST: Iniciar escaneo
│   │       │   └── [id]/route.ts          # GET: Detalle y hallazgos | DELETE: Eliminar escaneo
│   │       ├── reports/
│   │       │   ├── route.ts               # GET: Listar reportes | POST: Generar PDF
│   │       │   ├── [id]/download/route.ts # GET: Descarga segura verificando dueño y expiración
│   │       │   └── export-csv/route.ts    # GET: Exportación CSV sanitizada
│   │       ├── notifications/
│   │       │   └── route.ts               # GET: Alertas no leídas | PATCH: Marcar como leídas
│   │       └── health/
│   │           └── route.ts               # GET: Comprobación de salud del servicio
│   ├── lib/
│   │   ├── db.ts                  # Instancia única de PrismaClient con @prisma/adapter-pg
│   │   ├── auth.ts                # Hashing Argon2id, verificación JWT y cookies de sesión
│   │   ├── rate-limit.ts          # Límites compartidos por PostgreSQL y hash de identidades
│   │   └── validators.ts          # Esquemas Zod y sanitizadores de CSV y SQL LIKE
│   └── services/
│       ├── report-generator.ts    # Generador de reportes PDF con PDFKit
│       └── scanner/               # Motor de Auditoría de Ciberseguridad
│           ├── index.ts           # Orquestador principal y cálculo de Risk Score (0-100)
│           ├── ssrf-guard.ts      # Validación DNS y bloqueo de IPs privadas/locales
│           ├── http-headers.ts    # Auditoría de las 7 cabeceras HTTP de seguridad
│           ├── tls-inspector.ts   # Auditoría de certificado SSL/TLS por socket 443
│           └── connection.ts      # Latencia de respuesta y redirección forzada a HTTPS
├── .env.example                   # Plantilla de variables de entorno
├── next.config.ts                 # Configuración de Next.js
├── package.json                   # Dependencias y scripts
├── prisma.config.ts               # Configuración auxiliar de Prisma
└── tsconfig.json                  # Configuración de TypeScript
```

---

## 🛠️ Instalación y Puesta en Marcha

### 1. Requisitos Previos
* Node.js v20+ o v22+ LTS
* Instancia de PostgreSQL en ejecución

### 2. Configuración de Variables de Entorno
Copia el archivo `.env.example` a `.env` y configura los valores correspondientes:
```bash
cp .env.example .env
```
Edita `.env`:
```env
DATABASE_URL="postgresql://app_user:<contraseña>@localhost:5432/scandev_db?schema=public"
JWT_SECRET="<secreto aleatorio de al menos 32 caracteres>"
PORT=3000
STORAGE_REPORTS_DIR="./storage/reports"
TRUSTED_PROXY_HOPS=0
NODE_ENV="development"
```
Genera un secreto local con `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Configura `DATABASE_URL` y `JWT_SECRET` como secretos en el panel de Render; no uses valores predeterminados ni los guardes en Git. La aplicación valida estas variables al iniciar y no arranca si faltan o son inválidas.

En Render configura `TRUSTED_PROXY_HOPS=1` para confiar únicamente en la IP reenviada por el proxy de entrada. La aplicación rechaza el login y los escaneos si falta una IP válida en producción; no confía en `X-Forwarded-For` sin ese ajuste.

### 3. Instalación de Dependencias
```bash
npm install
```

### 4. Preparación y migración de la base de datos

1. Crea la base `scandev_db` en PostgreSQL 18.
2. Ejecuta como administrador, conectado a esa base:

```bash
psql -U postgres -d scandev_db -f scripts/00_database_setup.sql
```

3. Asigna contraseñas seguras a los roles en la consola interactiva de `psql`:

```text
\password migrator
\password app_user
```

4. En PowerShell, aplica las migraciones con la URL del rol `migrator` y genera Prisma Client:

```powershell
$env:DATABASE_URL = "postgresql://migrator:<password>@localhost:5432/scandev_db?schema=public"
npx prisma migrate deploy
npm run prisma:generate
```

5. Configura `DATABASE_URL` en `.env` con las credenciales de `app_user` para ejecutar la aplicación. No uses ese rol para migraciones.

Las migraciones aplican restricciones de integridad, propiedad de reportes, auditoría append-only y permisos mínimos. `scripts/01_roles.sql` permite volver a aplicar los permisos del rol de runtime después de desplegar.

La migración `202611220005_shared_runtime_state` crea la cola durable de escaneos y los eventos de rate limit. Aplícala antes de desplegar la nueva versión con credenciales del rol `migrator`; la API usa el rol de runtime `app_user`. El worker se inicia con el proceso Node.js de Next.js y no requiere un servicio Redis adicional.

Render Free sirve para pruebas y demos, no para producción: los servicios web se suspenden por inactividad, el disco local es efímero y las bases PostgreSQL gratuitas expiran a los 30 días. En este proyecto los PDFs se guardan en disco local, así que para conservarlos después de reinicios se necesitará almacenamiento persistente/externo o un plan que lo ofrezca. Consulta las [limitaciones actuales de Render Free](https://render.com/docs/free).

### 5. Iniciar en Modo Desarrollo
```bash
npm run dev
```
La API estará disponible en `http://localhost:3000`.

---

## 📡 Referencia de la API REST

### Autenticación
* `POST /api/auth/register` — Registro de usuario (`email`, `password`, `name`); contraseña de 8 a 12 caracteres con mayúscula, minúscula, número y carácter especial.
* `POST /api/auth/login` — Inicio de sesión; emite cookie HTTP-Only `scandev_session`.
* `POST /api/auth/logout` — Destrucción de la cookie de sesión y registro de auditoría.

### Escaneos de Seguridad
* `GET /api/scans?page=1&limit=10&host=ejemplo.com` — Lista paginada con filtrado seguro.
* `POST /api/scans` — Encola un escaneo y responde `202 Accepted` (`{ "targetUrl": "https://ejemplo.com", "confirmedOwnership": true }`).
* `GET /api/scans/:id` — Consulta detalle completo y hallazgos individuales de un escaneo.
* `DELETE /api/scans/:id` — Elimina un escaneo y sus hallazgos asociados.

### Reportes y Exportación
* `GET /api/reports` — Listado de reportes generados para el usuario.
* `POST /api/reports` — Genera un nuevo reporte PDF (`{ "scanId": "uuid", "type": "EXECUTIVE" | "TECHNICAL" }`).
* `GET /api/reports/:id/download` — Descarga del archivo PDF (valida propiedad y caducidad de 7 días).
* `GET /api/reports/export-csv` — Exporta el historial en CSV sanitizado contra inyección de fórmulas.

### Notificaciones y Alertas
* `GET /api/notifications` — Consulta notificaciones y alertas no leídas.
* `PATCH /api/notifications` — Marca notificaciones como leídas (`{ "notificationIds": ["uuid"] }` o vacío para todas).

### Salud del Servicio
* `GET /api/health` — Comprobación de estado y disponibilidad de la API.

---

## Licencia

Este repositorio se distribuye bajo la Licencia MIT. Consulta el archivo [LICENSE](./LICENSE) para conocer los permisos y condiciones. La licencia cubre el material original de este repositorio; las dependencias y componentes de terceros conservan sus propias licencias.
