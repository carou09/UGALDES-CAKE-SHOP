# Ugalde's Cake Shop — Portal Administrativo

Portal privado para administrar clientes, pedidos, pagos, descuentos, finanzas y el catálogo de **Pasteles & Postres**.

## Tecnología

- Node.js 20 y funciones serverless
- MySQL 8
- PDFKit para comprobantes y reportes PDF
- Despliegue compatible con Vercel

## Configuración

1. Crea una base MySQL e importa `ugaldes-cake-shop.sql`.
2. Copia `.env.example` como `.env.local`.
3. Configura `DATABASE_URL`, `SESSION_SECRET`, `DB_SSL` y el dominio final en `CANONICAL_HOST`.
4. Instala dependencias con `npm install`.
5. Ejecuta localmente con `npx vercel dev`.

Nunca subas `.env.local` ni credenciales al repositorio.
