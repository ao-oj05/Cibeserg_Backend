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
| **BK-02** | **Control de DoS y Tiempos** | Escaneos limitados a 30 segundos, peticiones externas a 5 segundos, cuerpos de respuesta a 1 MB, cinco redirecciones y 10 escaneos por hora por usuario. |
| **BK-03** | **Validación de Entradas** | Esquemas Zod estrictos en cada endpoint REST (`src/lib/validators.ts`), rechazando payloads malformados o inyecciones. |
| **BK-04** | **Gestión Segura de Sesión** | Tokens JWT firmados con algoritmo `HS256`, expiración a 24 horas y almacenados en cookies con banderas `HttpOnly`, `Secure` y `SameSite=Strict`. |
| **BK-05** | **Aislamiento Multitenant** | Extracción obligatoria del `userId` a través de la sesión validada; cláusulas `where: { userId: session.userId }` en todas las consultas de Prisma. |
| **BK-06** | **Manejo Seguro de Errores** | Respuestas con códigos HTTP canónicos y mensajes controlados que evitan filtrar trazas de error, versiones o queries SQL al cliente. |
| **BK-07** | **Protección de Archivos y CSV** | Archivos PDF almacenados en `storage/reports/` (fuera de `/public`), descarga condicionada a validación de propietario y vigencia de 7 días. Saneamiento de prefijos peligrosos (`=`, `+`, `-`, `@`) en exportaciones CSV. |

---

## 📁 Estructura del Proyecto

```plaintext
scandev/
├── prisma/
│   ├── schema.prisma              # Modelo de datos (User, Scan, Finding, Report, Notification, AuditLog)
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
│   │   ├── rate-limit.ts          # Control de límite de peticiones por IP/usuario
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
DATABASE_URL="postgresql://app_user:secret_password@localhost:5432/scandev_db?schema=public"
JWT_SECRET="genera_una_clave_secreta_minimo_32_caracteres_aleatorios"
PORT=3000
STORAGE_REPORTS_DIR="./storage/reports"
NODE_ENV="development"
```

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

### 5. Iniciar en Modo Desarrollo
```bash
npm run dev
```
La API estará disponible en `http://localhost:3000`.

---

## 📡 Referencia de la API REST

### Autenticación
* `POST /api/auth/register` — Registro de usuario (`email`, `password`, `name`).
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
