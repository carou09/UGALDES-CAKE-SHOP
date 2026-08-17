import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import PDFDocument from 'pdfkit';

const CANONICAL_HOST = process.env.CANONICAL_HOST || 'admin-ugaldes-cakeshop.ugaldeassociation.com';
const SITE_TITLE = "Ugalde's Cake Shop | Portal Administrativo";
const SITE_DESCRIPTION = 'Gestión de clientes, pedidos, pasteles, postres y pagos.';
const SITE_URL = `https://${CANONICAL_HOST}/`;
const SOCIAL_IMAGE_URL = `https://${CANONICAL_HOST}/img/og-portal-administrativo.png`;
let pool;
let snapshotSchemaPromise;
let portalSchemaPromise;
function db() {
  if (!pool) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL no está configurada');
    const u = new URL(process.env.DATABASE_URL);
    pool = mysql.createPool({
      host: u.hostname,
      port: Number(u.port || 3306),
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: u.pathname.replace(/^\//, '') || 'disenos',
      connectionLimit: 4,
      ssl: process.env.DB_SSL === 'false' ? undefined : { rejectUnauthorized: false }
    });
  }
  return pool;
}

const secret = () => process.env.SESSION_SECRET || 'development-only-change-me';
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' }[c]));
const money = (value) => `${Number(value || 0).toLocaleString("es-MX", {style: "currency", currency: "MXN"})} MXN`;
const sqlDate = (value) => value ? new Date(value).toISOString().slice(0, 10) : '';
const displayDate = (value) => value ? new Date(`${sqlDate(value)}T12:00:00`).toLocaleDateString('es-MX', { day:'2-digit', month:'long', year:'numeric' }) : 'Sin fecha';
const displayTime = (value) => { const match=String(value || '').match(/^(\d{1,2}):(\d{2})/); if (!match) return 'Sin hora'; const date=new Date(2000,0,1,Number(match[1]),Number(match[2])); return date.toLocaleTimeString('es-MX',{hour:'numeric',minute:'2-digit'}); };
const shiftDate = (value, days) => { if (!value) return ''; const date=new Date(`${sqlDate(value)}T12:00:00`); date.setDate(date.getDate()+days); return date.toISOString().slice(0,10); };
const mysqlDateTime = (value) => value ? `${String(value).replace('T',' ').slice(0,16)}:00` : new Date();
const localDateTimeInput = (value) => {
  if (!value) return '';
  const parts = new Intl.DateTimeFormat('en-CA',{timeZone:'America/Mexico_City',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(value));
  const get = type => parts.find(part=>part.type===type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}`;
};
const discountAmountForPackage = (discount, packagePrice) => {
  const price=Math.max(0,Number(packagePrice)||0);
  if(!discount)return 0;
  const value=Math.max(0,Number(discount.valor)||0);
  const amount=discount.tipo==='porcentaje'?price*Math.min(value,100)/100:Math.min(value,price);
  return Math.round(amount*100)/100;
};
const cookieValue = (req, name) => (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`))?.slice(name.length + 1);

function session(req) {
  const token = cookieValue(req, 'ugalde_session');
  if (!token) return null;
  const [payload, sig] = decodeURIComponent(token).split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}

function sessionCookie(user) {
  const payload = Buffer.from(JSON.stringify({ user, exp: Date.now() + 1000 * 60 * 60 * 12 })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  return `ugalde_session=${encodeURIComponent(`${payload}.${sig}`)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`;
}
function clearCookie() { return 'ugalde_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'; }
function passwordValid(password) { return String(password || '').length >= 8 && /[A-ZÁÉÍÓÚÑ]/u.test(password) && /[a-záéíóúñ]/u.test(password) && /[^A-Za-zÁÉÍÓÚÑáéíóúñ0-9]/u.test(password); }
async function passwordMatches(password, hash) { return Boolean(hash) && ((String(hash).startsWith('$2') && await bcrypt.compare(String(password || ''),hash)) || hash === password); }
function signedCookie(name,data,maxAge=1800) {
  const payload=Buffer.from(JSON.stringify({...data,exp:Date.now()+maxAge*1000})).toString('base64url');
  const sig=crypto.createHmac('sha256',secret()).update(payload).digest('base64url');
  return `${name}=${encodeURIComponent(`${payload}.${sig}`)}; Path=/admin/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function verifySignedCookie(req,name) {
  const token=cookieValue(req,name); if(!token)return null;
  const [payload,sig]=decodeURIComponent(token).split('.'); if(!payload||!sig)return null;
  const expected=crypto.createHmac('sha256',secret()).update(payload).digest('base64url');
  if(sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;
  try { const data=JSON.parse(Buffer.from(payload,'base64url').toString()); return data.exp>Date.now()?data:null; } catch { return null; }
}
function send(res, status, content, headers = {}) { res.statusCode = status; Object.entries(headers).forEach(([k,v]) => res.setHeader(k,v)); res.end(content); }
function html(res, content, status = 200, headers = {}) { send(res, status, content, { 'Content-Type':'text/html; charset=utf-8', ...headers }); }
function redirect(res, location, headers = {}) { send(res, 302, '', { Location:location, ...headers }); }
async function formBody(req) { const chunks=[]; for await (const chunk of req) chunks.push(chunk); return new URLSearchParams(Buffer.concat(chunks).toString()); }
async function query(sql, params = []) { const [rows] = await db().execute(sql, params); return rows; }
async function one(sql, params = []) { return (await query(sql, params))[0]; }

async function ensureOrderSnapshotSchema() {
  if (snapshotSchemaPromise) return snapshotSchemaPromise;
  snapshotSchemaPromise = (async () => {
    const conn = await db().getConnection();
    let locked = false;
    try {
      const [lockRows] = await conn.query("SELECT GET_LOCK('ugalde_order_snapshot_schema',10) acquired");
      locked = Number(lockRows[0]?.acquired) === 1;
      if (!locked) throw new Error('No fue posible bloquear la migración de pedidos');
      const [serviceColumns]=await conn.query('SHOW COLUMNS FROM `servicios_adicionales`');
      if(!new Set(serviceColumns.map(column=>column.Field)).has('descripcion'))await conn.query('ALTER TABLE `servicios_adicionales` ADD COLUMN `descripcion` TEXT NULL AFTER `precio`');
      const requiredColumns = {
        pedidos: {
          cliente_nombre_snapshot: 'VARCHAR(255) NULL',
          cliente_email_snapshot: 'VARCHAR(255) NULL',
          cliente_telefono_snapshot: 'VARCHAR(80) NULL',
          invitacion_nombre_snapshot: 'VARCHAR(255) NULL',
          invitacion_descripcion_snapshot: 'TEXT NULL',
          invitacion_precio_snapshot: 'DECIMAL(12,2) NULL',
          fecha_liquidacion: 'DATE NULL',
          formulario_completado: 'TINYINT(1) NOT NULL DEFAULT 0',
          fecha_formulario_completado: 'DATETIME NULL',
          invitacion_entregada: 'TINYINT(1) NOT NULL DEFAULT 0',
          fecha_invitacion_entregada: 'DATETIME NULL',
          fecha_liquidado: 'DATETIME NULL',
          notas: 'TEXT NULL',
          cortesia: 'TINYINT(1) NOT NULL DEFAULT 0',
          descuento_id: 'INT UNSIGNED NULL',
          descuento_nombre_snapshot: 'VARCHAR(180) NULL',
          descuento_tipo_snapshot: 'VARCHAR(20) NULL',
          descuento_valor_snapshot: 'DECIMAL(12,2) NULL',
          descuento_monto_snapshot: 'DECIMAL(12,2) NOT NULL DEFAULT 0'
        },
        pedido_servicios: {
          servicio_nombre_snapshot: 'VARCHAR(255) NULL',
          servicio_precio_snapshot: 'DECIMAL(12,2) NULL',
          servicio_descripcion_snapshot: 'TEXT NULL'
        }
      };
      for (const [table, definitions] of Object.entries(requiredColumns)) {
        const [columns] = await conn.query(`SHOW COLUMNS FROM \`${table}\``);
        const existing = new Set(columns.map(column => column.Field));
        for (const [column, definition] of Object.entries(definitions)) {
          if (!existing.has(column)) await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
        }
      }
      const [clientEmailColumns] = await conn.query("SHOW COLUMNS FROM `clientes` LIKE 'email'");
      if (clientEmailColumns[0]?.Null !== 'YES') await conn.query('ALTER TABLE `clientes` MODIFY `email` VARCHAR(100) NULL');
      await conn.query(`UPDATE clientes c
        SET c.email=(SELECT p.cliente_email_snapshot FROM pedidos p
          WHERE p.cliente_id=c.id AND p.cliente_email_snapshot IS NOT NULL
            AND UPPER(TRIM(p.cliente_email_snapshot)) NOT IN ('NA@NA','NA@NA.COM')
          ORDER BY p.id DESC LIMIT 1)
        WHERE c.email IS NULL AND EXISTS(SELECT 1 FROM pedidos p
          WHERE p.cliente_id=c.id AND p.cliente_email_snapshot IS NOT NULL
            AND UPPER(TRIM(p.cliente_email_snapshot)) NOT IN ('NA@NA','NA@NA.COM'))`);
      await conn.query("UPDATE `clientes` SET `email`=NULL WHERE UPPER(TRIM(`email`)) IN ('NA@NA','NA@NA.COM')");
      await conn.query(`UPDATE pedidos p
        LEFT JOIN clientes c ON c.id=p.cliente_id
        LEFT JOIN tipos_invitacion t ON t.id=p.tipo_id
        SET p.cliente_nombre_snapshot=COALESCE(p.cliente_nombre_snapshot,c.nombre),
            p.cliente_email_snapshot=COALESCE(p.cliente_email_snapshot,c.email),
            p.cliente_telefono_snapshot=COALESCE(p.cliente_telefono_snapshot,c.telefono),
            p.invitacion_nombre_snapshot=COALESCE(p.invitacion_nombre_snapshot,t.nombre),
            p.invitacion_descripcion_snapshot=COALESCE(p.invitacion_descripcion_snapshot,t.caracteristicas),
            p.invitacion_precio_snapshot=COALESCE(p.invitacion_precio_snapshot,t.precio_base)
        WHERE p.cliente_nombre_snapshot IS NULL OR p.invitacion_nombre_snapshot IS NULL`);
      await conn.query(`UPDATE pedido_servicios ps
        LEFT JOIN servicios_adicionales s ON s.id=ps.servicio_id
        SET ps.servicio_nombre_snapshot=COALESCE(ps.servicio_nombre_snapshot,s.nombre),
            ps.servicio_precio_snapshot=COALESCE(ps.servicio_precio_snapshot,s.precio),
            ps.servicio_descripcion_snapshot=COALESCE(ps.servicio_descripcion_snapshot,s.descripcion)
        WHERE ps.servicio_nombre_snapshot IS NULL OR ps.servicio_descripcion_snapshot IS NULL`);
      await conn.query(`UPDATE pedidos
        SET fecha_liquidacion=DATE_ADD(fecha_evento,INTERVAL 1 DAY)
        WHERE fecha_liquidacion IS NULL AND fecha_evento IS NOT NULL`);
      await conn.query(`UPDATE pedidos p
        LEFT JOIN (SELECT pedido_id,SUM(monto) pagado,MAX(fecha_pago) ultimo_pago FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id
        SET p.fecha_liquidado=COALESCE(p.fecha_liquidado,x.ultimo_pago)
        WHERE COALESCE(x.pagado,0)>=p.precio_final AND p.precio_final>0 AND p.fecha_liquidado IS NULL`);
    } finally {
      if (locked) await conn.query("SELECT RELEASE_LOCK('ugalde_order_snapshot_schema')");
      conn.release();
    }
  })().catch(error => { snapshotSchemaPromise = undefined; throw error; });
  return snapshotSchemaPromise;
}

async function ensurePortalSchema() {
  if (portalSchemaPromise) return portalSchemaPromise;
  portalSchemaPromise=(async()=>{
    const conn=await db().getConnection(); let locked=false;
    try {
      const [lockRows]=await conn.query("SELECT GET_LOCK('ugalde_portal_schema',10) acquired");
      locked=Number(lockRows[0]?.acquired)===1;
      if(!locked)throw new Error('No fue posible bloquear la migración del portal');
      const [adminColumns]=await conn.query('SHOW COLUMNS FROM `administradores`');
      const existing=new Set(adminColumns.map(column=>column.Field));
      if(!existing.has('activo'))await conn.query('ALTER TABLE `administradores` ADD COLUMN `activo` TINYINT(1) NOT NULL DEFAULT 1');
      if(!existing.has('fecha_actualizacion'))await conn.query('ALTER TABLE `administradores` ADD COLUMN `fecha_actualizacion` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
      const [serviceColumns]=await conn.query('SHOW COLUMNS FROM `servicios_adicionales`');
      if(!new Set(serviceColumns.map(column=>column.Field)).has('descripcion'))await conn.query('ALTER TABLE `servicios_adicionales` ADD COLUMN `descripcion` TEXT NULL AFTER `precio`');
      await conn.query(`CREATE TABLE IF NOT EXISTS bloqueos_seccion (
        seccion VARCHAR(40) NOT NULL PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        actualizado_por VARCHAR(100) NULL,
        fecha_actualizacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB`);
      await conn.query(`CREATE TABLE IF NOT EXISTS gastos (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        concepto VARCHAR(180) NOT NULL,
        monto DECIMAL(12,2) NOT NULL,
        frecuencia ENUM('unica','mensual') NOT NULL DEFAULT 'unica',
        fecha_inicio DATE NOT NULL,
        fecha_fin DATE NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        creado_por VARCHAR(100) NULL,
        fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB`);
      await conn.query(`CREATE TABLE IF NOT EXISTS configuracion_portal (
        clave VARCHAR(80) NOT NULL PRIMARY KEY,
        valor TEXT NOT NULL,
        fecha_actualizacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB`);
      await conn.query(`INSERT IGNORE INTO configuracion_portal(clave,valor) VALUES('password_administrador','$2a$12$qiwkeemhfkJZ0Th33UqhN.enBA/JkbMsTOK5MNF7Hqz7CA2mMAeCa')`);
      const [principalMigration]=await conn.query("SELECT valor FROM configuracion_portal WHERE clave='migration_admin_principal_20260817'");
      if(!principalMigration.length){
        const principalPasswordHash='$2a$12$qiwkeemhfkJZ0Th33UqhN.enBA/JkbMsTOK5MNF7Hqz7CA2mMAeCa';
        await conn.beginTransaction();
        try{
          const [carolinaRows]=await conn.query("SELECT id FROM administradores WHERE BINARY username='Admin_carolina' LIMIT 1");
          if(carolinaRows[0])await conn.query("UPDATE administradores SET username='Admin_Carolina' WHERE id=?",[carolinaRows[0].id]);
          const [principalRows]=await conn.query("SELECT id FROM administradores WHERE BINARY username='Admin_principal' LIMIT 1");
          if(principalRows[0])await conn.query('UPDATE administradores SET password=?,activo=1 WHERE id=?',[principalPasswordHash,principalRows[0].id]);
          else await conn.query("INSERT INTO administradores(username,password,activo) VALUES('Admin_principal',?,1)",[principalPasswordHash]);
          await conn.query("INSERT INTO configuracion_portal(clave,valor) VALUES('migration_admin_principal_20260817','completed')");
          await conn.commit();
        }catch(error){await conn.rollback();throw error;}
      }
      const [expenseFrequency]=await conn.query("SHOW COLUMNS FROM `gastos` LIKE 'frecuencia'");
      if(!String(expenseFrequency[0]?.Type||'').includes("'anual'"))await conn.query("ALTER TABLE `gastos` MODIFY `frecuencia` ENUM('unica','mensual','anual') NOT NULL DEFAULT 'unica'");
      await conn.query(`CREATE TABLE IF NOT EXISTS descuentos (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(180) NOT NULL,
        tipo ENUM('porcentaje','fijo') NOT NULL DEFAULT 'porcentaje',
        valor DECIMAL(12,2) NOT NULL,
        descripcion TEXT NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY descuentos_nombre_unique (nombre)
      ) ENGINE=InnoDB`);
    } finally {
      if(locked)await conn.query("SELECT RELEASE_LOCK('ugalde_portal_schema')");
      conn.release();
    }
  })().catch(error=>{portalSchemaPromise=undefined;throw error});
  return portalSchemaPromise;
}

async function unread() {
  return Number((await one("SELECT COUNT(id) total FROM notificaciones WHERE leida=0 AND tipo IN ('entrega','pago','pago_retrasado')"))?.total || 0);
}

const SECTION_DEFINITIONS={
  notificaciones:{label:'Notificaciones',path:'/admin/notificaciones.php'},
  dashboard:{label:'Dashboard',path:'/admin/'},
  clientes:{label:'Clientes',path:'/admin/clientes.php'},
  pedidos:{label:'Pedidos',path:'/admin/pedidos.php'},
  pagos:{label:'Pagos',path:'/admin/pagos.php'},
  invitaciones:{label:'Pasteles &amp; Postres',path:'/admin/invitaciones.php'},
  descuentos:{label:'Descuentos',path:'/admin/descuentos.php'},
  finanzas:{label:'Finanzas',path:'/admin/finanzas.php'},
  administracion:{label:'Administración',path:'/admin/administracion.php'}
};
function sectionForPage(page) {
  if(!page)return 'dashboard';
  if(page.includes('notificacion')||page==='marcar_leidas.php')return 'notificaciones';
  if(page.includes('cliente'))return 'clientes';
  if(page.includes('pedido'))return 'pedidos';
  if(page.includes('pago'))return 'pagos';
  if(page.includes('invitacion'))return 'invitaciones';
  if(page.includes('descuento'))return 'descuentos';
  if(page.includes('finanza'))return 'finanzas';
  if(page.includes('administracion'))return 'administracion';
  return null;
}
async function sectionIsUnlocked(req,section,user) {
  const lock=await one('SELECT activo FROM bloqueos_seccion WHERE seccion=?',[section]);
  if(!lock||!Number(lock.activo))return true;
  const data=verifySignedCookie(req,`ugalde_unlock_${section}`);
  return data?.user===user&&data?.section===section;
}
function safeAdminReturn(value,fallback='/admin/') {
  const target=String(value||'');
  return target.startsWith('/admin/')&&!target.startsWith('//')?target:fallback;
}

function layout(title, content, admin = false, unreadCount = 0) {
  const nav = admin
    ? `<aside id="admin-sidebar" class="app-header"><a class="admin-brand" href="/admin/"><img src="/img/LOGO.png" alt="Logo Ugalde's Cake Shop"><span><strong>UGALDE'S CAKE SHOP</strong><small>PORTAL ADMINISTRATIVO</small></span></a><nav class="nav-tabs" aria-label="Secciones administrativas"><a href="/admin/notificaciones.php" class="tab-link" data-section="notificaciones">Notificaciones ${unreadCount ? `<span class="notification-badge">${unreadCount}</span>` : ''}</a><a href="/admin/" class="tab-link" data-section="resumen">Dashboard</a><a href="/admin/clientes.php" class="tab-link" data-section="clientes">Clientes</a><a href="/admin/pedidos.php" class="tab-link" data-section="pedidos">Pedidos</a><a href="/admin/pagos.php" class="tab-link" data-section="pagos">Pagos</a><a href="/admin/invitaciones.php" class="tab-link" data-section="invitaciones">Pasteles &amp; Postres</a><a href="/admin/descuentos.php" class="tab-link" data-section="descuentos">Descuentos</a><a href="/admin/finanzas.php" class="tab-link" data-section="finanzas">Finanzas</a><a href="/admin/administracion.php" class="tab-link" data-section="administracion">Administración</a><a href="/admin/logout.php" class="tab-link btn-logout">Cerrar sesión</a></nav></aside><button type="button" class="sidebar-toggle" aria-controls="admin-sidebar" aria-label="Cerrar menú" aria-expanded="true"><span class="hamburger-icon" aria-hidden="true"><i></i><i></i><i></i></span></button>`
    : `<header class="login-header"><img src="/img/LOGO.png" alt="Logo Ugalde's Cake Shop"><p>PORTAL ADMINISTRATIVO</p></header>`;
  const sidebarInit = admin ? `<script>try{const saved=localStorage.getItem('ugalde_sidebar');if(saved==='closed'||(!saved&&matchMedia('(max-width:900px)').matches))document.documentElement.classList.add('sidebar-collapsed')}catch{}</script><script src="/editable-tables.js" defer></script>` : '';
  const activeScript = admin ? `<script>(()=>{const p=location.pathname;let s='resumen';if(p.includes('cliente'))s='clientes';else if(p.includes('pago'))s='pagos';else if(p.includes('pedido'))s='pedidos';else if(p.includes('invitacion'))s='invitaciones';else if(p.includes('descuento'))s='descuentos';else if(p.includes('notificacion'))s='notificaciones';else if(p.includes('finanza'))s='finanzas';else if(p.includes('administracion'))s='administracion';const a=document.querySelector('[data-section="'+s+'"]');if(a){a.classList.add('active');a.setAttribute('aria-current','page')}const root=document.documentElement,toggle=document.querySelector('.sidebar-toggle');const sync=()=>{const closed=root.classList.contains('sidebar-collapsed');toggle.setAttribute('aria-expanded',String(!closed));toggle.setAttribute('aria-label',closed?'Abrir menú':'Cerrar menú')};toggle?.addEventListener('click',()=>{root.classList.toggle('sidebar-collapsed');try{localStorage.setItem('ugalde_sidebar',root.classList.contains('sidebar-collapsed')?'closed':'open')}catch{}sync()});sync()})();</script>` : '';
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${SITE_TITLE}</title><meta name="description" content="${SITE_DESCRIPTION}"><meta property="og:type" content="website"><meta property="og:locale" content="es_MX"><meta property="og:site_name" content="Ugalde's Cake Shop"><meta property="og:title" content="${SITE_TITLE}"><meta property="og:description" content="${SITE_DESCRIPTION}"><meta property="og:url" content="${SITE_URL}"><meta property="og:image" content="${SOCIAL_IMAGE_URL}"><meta property="og:image:url" content="${SOCIAL_IMAGE_URL}"><meta property="og:image:secure_url" content="${SOCIAL_IMAGE_URL}"><meta property="og:image:type" content="image/png"><meta property="og:image:width" content="1664"><meta property="og:image:height" content="935"><meta property="og:image:alt" content="Ugalde's Cake Shop | Portal Administrativo"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${SITE_TITLE}"><meta name="twitter:description" content="${SITE_DESCRIPTION}"><meta name="twitter:image" content="${SOCIAL_IMAGE_URL}"><meta name="twitter:image:alt" content="Ugalde's Cake Shop | Portal Administrativo"><link rel="icon" type="image/png" sizes="64x64" href="/img/FAVICON-64.png"><link rel="icon" type="image/png" sizes="32x32" href="/img/FAVICON-32.png"><link rel="apple-touch-icon" href="/img/favicon-180.png">${sidebarInit}<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Playfair+Display:wght@500;600&display=swap" rel="stylesheet"><link rel="stylesheet" href="/styles.css"></head><body class="${admin ? 'admin-shell' : ''}">${nav}<main class="${admin ? 'app-content' : 'login-content'}">${content}</main><footer class="admin-footer"><p>© ${new Date().getFullYear()} Ugalde's Cake Shop · Acceso privado.</p></footer>${activeScript}</body></html>`;
}

function requireAdmin(req, res) {
  const current = session(req);
  if (!current?.user) { redirect(res, '/admin/login.php'); return null; }
  return current;
}

async function login(req, res) {
  let error = '';
  if (req.method === 'POST') {
    const form = await formBody(req);
    const user = await one('SELECT password,activo FROM administradores WHERE username=?', [form.get('username')]);
    const password = form.get('password') || '';
    const valid = user && Number(user.activo)!==0 && await passwordMatches(password,user.password);
    if (valid) return redirect(res, '/admin/', { 'Set-Cookie':sessionCookie(form.get('username')) });
    error = 'Usuario o contraseña incorrectos.';
  }
  html(res, layout('Acceso administrativo', `<div class="login-container"><div class="card login-card"><p class="eyebrow">ACCESO PRIVADO</p><h2>UGALDE'S CAKE SHOP</h2><p class="login-copy">Ingresa tus credenciales para acceder.</p>${error ? `<p class="error">${error}</p>` : ''}<form method="POST"><label>Usuario<input name="username" placeholder="Tu usuario" autocomplete="username" required></label><label>Contraseña<input name="password" type="password" placeholder="Tu contraseña" autocomplete="current-password" required></label><button class="btn btn-primary">Iniciar sesión</button></form></div></div>`));
}

async function verifyCurrentPassword(username,password) {
  const user=await one('SELECT password,activo FROM administradores WHERE username=?',[username]);
  return Boolean(user&&Number(user.activo)!==0&&await passwordMatches(password,user.password));
}

async function unlockSectionPage(req,res,url,current) {
  const section=String(url.searchParams.get('section')||'');
  const definition=SECTION_DEFINITIONS[section];
  const returnTo=safeAdminReturn(url.searchParams.get('return'),definition?.path||'/admin/');
  if(!definition)return redirect(res,'/admin/');
  let error='';
  if(req.method==='POST'){
    const form=await formBody(req);
    const lock=await one('SELECT password,activo FROM bloqueos_seccion WHERE seccion=?',[section]);
    if(!lock||!Number(lock.activo))return redirect(res,returnTo);
    if(await passwordMatches(form.get('password'),lock.password)){
      return redirect(res,returnTo,{'Set-Cookie':signedCookie(`ugalde_unlock_${section}`,{user:current.user,section},1800)});
    }
    error='Contraseña incorrecta para este apartado.';
  }
  const content=`<div class="login-container section-unlock"><section class="card login-card"><p class="eyebrow">APARTADO PROTEGIDO</p><h2>${esc(definition.label)}</h2><p class="login-copy">Ingresa la contraseña configurada para acceder a este apartado.</p>${error?`<p class="error">${esc(error)}</p>`:''}<form method="POST"><label>Contraseña del apartado<input type="password" name="password" autocomplete="current-password" required autofocus></label><button class="btn btn-primary">Desbloquear apartado</button><a class="btn btn-secondary" href="/admin/">Cancelar</a></form></section></div>`;
  html(res,layout(`Desbloquear ${definition.label}`,content,true,await unread()));
}

async function administrationPage(req,res,url,current) {
  let error='',success='';
  if(req.method==='POST'){
    const form=await formBody(req),action=form.get('action');
    if(!await verifyAdministratorPassword(form.get('admin_password'))){
      error='La contraseña de administrador es incorrecta.';
    } else if(action==='create_user'){
      const username=String(form.get('username')||'').trim(),password=String(form.get('password')||'');
      if(!username)error='El nombre de usuario es obligatorio.';
      else if(await one('SELECT username FROM administradores WHERE LOWER(username)=LOWER(?)',[username]))error='Ya existe un usuario con ese nombre.';
      else if(!passwordValid(password))error='La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula y un carácter especial.';
      else { await query('INSERT INTO administradores(username,password,activo) VALUES(?,?,1)',[username,await bcrypt.hash(password,12)]); success='Usuario creado correctamente.'; }
    } else if(action==='change_password'){
      const username=String(form.get('username')||''),password=String(form.get('password')||''),confirmation=String(form.get('password_confirmation')||'');
      const target=await one('SELECT password FROM administradores WHERE username=?',[username]);
      if(!target)error='El usuario ya no existe.';
      else if(password!==confirmation)error='Las contraseñas deben ser iguales.';
      else if(await passwordMatches(password,target.password))error='No puede ser igual que la anterior.';
      else if(!passwordValid(password))error='La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula y un carácter especial.';
      else { await query('UPDATE administradores SET password=? WHERE username=?',[await bcrypt.hash(password,12),username]); success='Contraseña actualizada correctamente.'; }
    } else if(action==='toggle_user'||action==='delete_user'){
      const username=String(form.get('username')||'');
      if(username===current.user)error='No puedes eliminar ni desactivar el usuario que está administrando en este momento.';
      else if(action==='delete_user'){ await query('DELETE FROM administradores WHERE username=?',[username]); success='Usuario eliminado.'; }
      else { await query('UPDATE administradores SET activo=IF(activo=1,0,1) WHERE username=?',[username]); success='Estado del usuario actualizado.'; }
    } else if(action==='save_lock'){
      const section=String(form.get('section')||''),password=String(form.get('section_password')||''),confirmation=String(form.get('section_password_confirmation')||'');
      if(!SECTION_DEFINITIONS[section])error='Apartado no válido.';
      else if(password!==confirmation)error='Las contraseñas deben ser iguales.';
      else if(!passwordValid(password))error='La contraseña del apartado debe tener mínimo 8 caracteres, una mayúscula, una minúscula y un carácter especial.';
      else { await query(`INSERT INTO bloqueos_seccion(seccion,password,activo,actualizado_por) VALUES(?,?,1,?) ON DUPLICATE KEY UPDATE password=VALUES(password),activo=1,actualizado_por=VALUES(actualizado_por)`,[section,await bcrypt.hash(password,12),current.user]); success=`Protección actualizada para ${SECTION_DEFINITIONS[section].label}.`; }
    } else if(action==='remove_lock'){
      const section=String(form.get('section')||'');
      await query('DELETE FROM bloqueos_seccion WHERE seccion=?',[section]); success='Protección eliminada.';
    }
  }
  const users=await query('SELECT username,activo,fecha_actualizacion FROM administradores ORDER BY username');
  const locks=await query('SELECT seccion,activo,fecha_actualizacion FROM bloqueos_seccion');
  const lockMap=new Map(locks.map(lock=>[lock.seccion,lock]));
  const userCards=users.map(user=>{
    const isCurrent=user.username===current.user;
    if(isCurrent)return `<article class="portal-user-card is-current"><div><h3>${esc(user.username)}</h3><span class="status paid">Activo</span></div><strong class="current-user-label">Usuario en uso</strong></article>`;
    return `<article class="portal-user-card"><div><h3>${esc(user.username)}</h3><span class="status ${Number(user.activo)?'paid':'pending'}">${Number(user.activo)?'Activo':'Desactivado'}</span></div><div class="movement-buttons"><button type="button" class="btn btn-secondary" data-reveal-movement="user-password-${esc(user.username)}">Cambiar contraseña</button><form method="POST" data-auth-form><input type="hidden" name="action" value="toggle_user"><input type="hidden" name="username" value="${esc(user.username)}"><button class="btn btn-secondary">${Number(user.activo)?'Desactivar usuario':'Activar usuario'}</button></form><form method="POST" data-auth-form><input type="hidden" name="action" value="delete_user"><input type="hidden" name="username" value="${esc(user.username)}"><button class="btn btn-danger">Eliminar usuario</button></form></div><form id="user-password-${esc(user.username)}" method="POST" class="movement-form" data-auth-form hidden><input type="hidden" name="action" value="change_password"><input type="hidden" name="username" value="${esc(user.username)}"><h4>Para realizar el movimiento, favor de llenar los datos solicitados.</h4><label>Nueva contraseña:<input type="password" name="password" placeholder="Escribe la nueva contraseña del usuario..." autocomplete="new-password" required></label><label>Confirmar contraseña:<input type="password" name="password_confirmation" placeholder="Escribe la nueva contraseña del usuario..." autocomplete="new-password" required></label><div class="button-group"><button class="btn btn-primary">Cambiar contraseña</button><button type="button" class="btn btn-secondary" data-close-movement>Cancelar</button></div></form></article>`;
  }).join('');
  const lockCards=Object.entries(SECTION_DEFINITIONS).map(([key,definition])=>{const enabled=lockMap.has(key);const passwordForm=`<form id="section-password-${key}" method="POST" class="movement-form" data-auth-form ${enabled?'hidden':''}><input type="hidden" name="action" value="save_lock"><input type="hidden" name="section" value="${key}"><h4>Para realizar el movimiento, favor de llenar los datos solicitados.</h4><label>Nueva contraseña:<input type="password" name="section_password" placeholder="Escribe la nueva contraseña del apartado..." required></label><label>Confirmar contraseña:<input type="password" name="section_password_confirmation" placeholder="Escribe la nueva contraseña del apartado..." required></label><div class="button-group"><button class="btn btn-primary">${enabled?'Cambiar contraseña':'Proteger apartado'}</button>${enabled?'<button type="button" class="btn btn-secondary" data-close-movement>Cancelar</button>':''}</div></form>`;return `<article class="security-section-card"><div><h3>${esc(definition.label)}</h3><span class="status ${enabled?'pending':'paid'}">${enabled?'Protegido':'Sin bloqueo adicional'}</span></div>${enabled?`<div class="movement-buttons"><button type="button" class="btn btn-secondary" data-reveal-movement="section-password-${key}">Cambiar contraseña</button><form method="POST" data-auth-form><input type="hidden" name="action" value="remove_lock"><input type="hidden" name="section" value="${key}"><button class="btn btn-secondary">Quitar protección</button></form></div>`:''}${passwordForm}</article>`}).join('');
  const alertScript=success?`<script>window.addEventListener('DOMContentLoaded',()=>alert('Movimiento autorizado'))</script>`:'';
  const content=`<div class="page-heading split"><div><p class="eyebrow">SEGURIDAD Y ACCESOS</p><h1>Administración</h1><p>Administra usuarios y contraseñas adicionales para los apartados del portal.</p></div><button type="button" class="btn btn-primary" data-reveal="new-user-panel">Registrar nuevo usuario</button></div>${error?`<p class="error-banner">${esc(error)}</p>`:''}${success?`<p class="success-banner">Movimiento autorizado</p>`:''}<section id="new-user-panel" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registro de nuevo usuario</h2><button type="button" class="btn btn-secondary" data-close-new-user>Cerrar</button></div><form method="POST" class="form-grid admin-create-user" data-auth-form><input type="hidden" name="action" value="create_user"><label>Nombre de usuario<input name="username" autocomplete="off" required></label><label>Contraseña<input type="password" name="password" required><small>8 caracteres, mayúscula, minúscula y carácter especial.</small></label><button class="btn btn-primary">Crear usuario</button></form></section><section class="card"><h2>Usuarios del portal</h2><div class="portal-users-grid">${userCards}</div></section><section class="card"><h2>Protección de apartados</h2><p class="security-help">Estas contraseñas son adicionales al inicio de sesión. El desbloqueo dura 30 minutos por usuario y apartado.</p><div class="security-sections-grid">${lockCards}</div></section><dialog id="authorization-dialog" class="authorization-dialog"><form method="dialog"><h3>Contraseña de administrador:</h3><label><span class="sr-only">Contraseña de administrador:</span><input type="password" data-admin-authorization placeholder="Escribir contraseña" autocomplete="current-password" required></label><div class="button-group"><button type="button" class="btn btn-primary" data-authorize-movement>Autorizar</button><button value="cancel" class="btn btn-secondary">Cancelar</button></div></form></dialog><script>(()=>{const authDialog=document.getElementById('authorization-dialog'),authInput=authDialog.querySelector('[data-admin-authorization]');let pendingForm=null;const requestAuthorization=form=>{pendingForm=form;authInput.value='';authDialog.showModal();authInput.focus()};document.querySelectorAll('[data-auth-form]').forEach(form=>form.addEventListener('submit',event=>{if(form.dataset.authorized==='1')return;event.preventDefault();const password=form.querySelector('[name="password"]'),confirmation=form.querySelector('[name="password_confirmation"]'),sectionPassword=form.querySelector('[name="section_password"]'),sectionConfirmation=form.querySelector('[name="section_password_confirmation"]');if(password&&confirmation&&password.value!==confirmation.value){confirmation.setCustomValidity('Las contraseñas deben ser iguales.');confirmation.reportValidity();return}if(sectionPassword&&sectionConfirmation&&sectionPassword.value!==sectionConfirmation.value){sectionConfirmation.setCustomValidity('Las contraseñas deben ser iguales.');sectionConfirmation.reportValidity();return}requestAuthorization(form)}));authDialog.querySelector('[data-authorize-movement]').addEventListener('click',()=>{if(!authInput.value){authInput.reportValidity();return}let field=pendingForm.querySelector('[name="admin_password"]');if(!field){field=document.createElement('input');field.type='hidden';field.name='admin_password';pendingForm.append(field)}field.value=authInput.value;pendingForm.dataset.authorized='1';authDialog.close();pendingForm.requestSubmit()});document.querySelectorAll('[data-reveal-movement]').forEach(button=>button.addEventListener('click',()=>{const form=document.getElementById(button.dataset.revealMovement);form.hidden=false;button.closest('article').classList.add('is-editing');form.querySelector('input[type="password"]')?.focus()}));document.querySelectorAll('[data-close-movement]').forEach(button=>button.addEventListener('click',()=>{const form=button.closest('.movement-form');form.reset();form.hidden=true;form.closest('article').classList.remove('is-editing')}));const userPanel=document.getElementById('new-user-panel'),openUser=document.querySelector('[data-reveal="new-user-panel"]'),closeUser=document.querySelector('[data-close-new-user]');openUser.addEventListener('click',()=>{userPanel.hidden=false;openUser.setAttribute('aria-expanded','true');userPanel.querySelector('input')?.focus()});closeUser.addEventListener('click',()=>{userPanel.hidden=true;openUser.setAttribute('aria-expanded','false');openUser.focus()})})();</script>${alertScript}`;
  const authorizationFixScript=`<script>(()=>{const dialog=document.getElementById('authorization-dialog'),cancel=dialog?.querySelector('button[value="cancel"]'),input=dialog?.querySelector('[data-admin-authorization]');cancel?.addEventListener('click',event=>{event.preventDefault();if(input)input.value='';dialog.close('cancel')});dialog?.addEventListener('cancel',()=>{if(input)input.value=''})})();</script>`;
  html(res,layout('Administración',content+authorizationFixScript,true,await unread()));
}

async function syncReminders() {
  await query(`INSERT INTO notificaciones(pedido_id,tipo,mensaje,link)
    SELECT p.id,'entrega',CONCAT('Entrega próxima: ',COALESCE(p.cliente_nombre_snapshot,c.nombre),' - ',p.nombre_evento,' (',DATE_FORMAT(p.fecha_entrega,'%d/%m/%Y'),')'),CONCAT('/admin/ver_pedido.php?id=',p.id)
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    WHERE p.entregado=0 AND p.formulario_completado=1 AND p.invitacion_entregada=0
      AND p.fecha_entrega BETWEEN CURDATE() AND DATE_ADD(CURDATE(),INTERVAL 3 DAY)
      AND NOT EXISTS(SELECT 1 FROM notificaciones n WHERE n.pedido_id=p.id AND n.tipo='entrega')`);
  await query(`INSERT INTO notificaciones(pedido_id,tipo,mensaje,link)
    SELECT p.id,'pago_retrasado',CONCAT('Pago retrasado: ',COALESCE(p.cliente_nombre_snapshot,c.nombre),' - ',p.nombre_evento,' (debió liquidarse ',DATE_FORMAT(p.fecha_liquidacion,'%d/%m/%Y'),')'),CONCAT('/admin/historial_pagos.php?id=',p.id)
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    LEFT JOIN (SELECT pedido_id,SUM(monto) pagado FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id
    WHERE p.entregado=0 AND p.invitacion_entregada=1 AND p.fecha_liquidacion IS NOT NULL AND CURDATE()>p.fecha_liquidacion
      AND COALESCE(x.pagado,0)<p.precio_final
      AND NOT EXISTS(SELECT 1 FROM notificaciones n WHERE n.pedido_id=p.id AND n.tipo='pago_retrasado')`);
}

function calendar(month, items, dateField, today) {
  const [year, monthNumber] = month.split('-').map(Number);
  const first = new Date(year, monthNumber - 1, 1);
  const lastDay = new Date(year, monthNumber, 0).getDate();
  const offset = (first.getDay() + 6) % 7;
  const byDay = new Map();
  for (const item of items) {
    const date = sqlDate(item[dateField]);
    if (!date.startsWith(month)) continue;
    const day = Number(date.slice(8,10));
    if (!byDay.has(day)) byDay.set(day, []);
    byDay.get(day).push(item);
  }
  const cells = [];
  for (let i=0;i<offset;i++) cells.push('<div class="calendar-day muted"></div>');
  for (let day=1;day<=lastDay;day++) {
    const events = (byDay.get(day) || []).map(item => `<a class="calendar-event ${item.kind || ''}" href="${esc(item.link || `/admin/ver_pedido.php?id=${item.id}`)}"><b>${esc(item.cliente_nombre)}</b><span>${esc(item.nombre_evento || 'Evento')}</span></a>`).join('');
    const dateValue = `${month}-${String(day).padStart(2,'0')}`;
    cells.push(`<div class="calendar-day${dateValue === today ? ' today' : ''}"><time datetime="${dateValue}">${day}</time>${events}</div>`);
  }
  while (cells.length % 7) cells.push('<div class="calendar-day muted"></div>');
  return `<div class="calendar"><div class="calendar-week"><span>Lun</span><span>Mar</span><span>Mié</span><span>Jue</span><span>Vie</span><span>Sáb</span><span>Dom</span></div><div class="calendar-grid">${cells.join('')}</div></div>`;
}

function monthShift(month, amount) {
  const [year, number] = month.split('-').map(Number);
  const date = new Date(year, number - 1 + amount, 1);
  return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}`;
}

async function dashboard(res, url) {
  await syncReminders();
  const todayParts = new Intl.DateTimeFormat('en-CA',{timeZone:'America/Mexico_City',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
  const todayValues = Object.fromEntries(todayParts.map(part => [part.type,part.value]));
  const today = `${todayValues.year}-${todayValues.month}-${todayValues.day}`;
  const currentMonth = today.slice(0,7);
  const requested = url.searchParams.get('mes');
  const month = /^\d{4}-\d{2}$/.test(requested || '') ? requested : currentMonth;
  const pendingForm = await query(`SELECT p.id,p.nombre_evento,DATE_SUB(p.fecha_entrega,INTERVAL 7 DAY) calendar_date,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,'form' kind,CONCAT('/admin/ver_pedido.php?id=',p.id,'&task=form') link
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    WHERE p.entregado=0 AND p.formulario_completado=0 AND p.fecha_entrega IS NOT NULL ORDER BY p.fecha_entrega`);
  const pendingDelivery = await query(`SELECT p.id,p.nombre_evento,p.fecha_entrega calendar_date,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,'delivery' kind,CONCAT('/admin/ver_pedido.php?id=',p.id,'&task=delivery') link
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    WHERE p.entregado=0 AND p.formulario_completado=1 AND p.invitacion_entregada=0 AND p.fecha_entrega IS NOT NULL ORDER BY p.fecha_entrega`);
  const pendingPayment = await query(`SELECT p.id,p.nombre_evento,p.fecha_liquidacion calendar_date,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,'payment' kind,CONCAT('/admin/historial_pagos.php?id=',p.id) link
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    LEFT JOIN (SELECT pedido_id,SUM(monto) pagado FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id
    WHERE p.entregado=0 AND p.invitacion_entregada=1 AND p.fecha_liquidacion IS NOT NULL AND COALESCE(x.pagado,0)<p.precio_final ORDER BY p.fecha_liquidacion`);
  const liquidatedOrders = await query(`SELECT p.id,p.nombre_evento,DATE(COALESCE(p.fecha_liquidado,p.fecha_liquidacion)) calendar_date,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,'liquidated' kind,CONCAT('/admin/historial_pagos.php?id=',p.id) link
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    LEFT JOIN (SELECT pedido_id,SUM(monto) pagado FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id
    WHERE p.invitacion_entregada=1 AND COALESCE(x.pagado,0)>=p.precio_final AND COALESCE(p.fecha_liquidado,p.fecha_liquidacion) IS NOT NULL ORDER BY COALESCE(p.fecha_liquidado,p.fecha_liquidacion)`);
  const monthLabel = new Date(`${month}-15T12:00:00`).toLocaleDateString('es-MX',{month:'long',year:'numeric'});
  const calendarItems = [...pendingDelivery,...pendingPayment,...liquidatedOrders];
  const content = `<section class="dashboard-heading"><p class="eyebrow">RESUMEN GENERAL</p><h1>Calendario administrativo</h1><p>Selecciona una tarea para consultar al cliente y completar la siguiente etapa del pedido.</p></section><section class="calendar-section"><h2 class="calendar-month-label">${esc(monthLabel)}</h2><div class="month-nav"><a class="btn btn-secondary" href="?mes=${monthShift(month,-1)}">Mes anterior</a><a class="btn btn-primary btn-today" href="?mes=${currentMonth}">DÍA &amp; MES ACTUAL</a><a class="btn btn-secondary" href="?mes=${monthShift(month,1)}">Mes siguiente</a></div><div class="calendar-legends"><div class="section-title"><span class="legend delivery"></span><h2>PEDIDO PENDIENTE POR ENTREGAR</h2></div><div class="section-title"><span class="legend payment"></span><h2>PEDIDO PENDIENTE A LIQUIDAR</h2></div><div class="section-title"><span class="legend liquidated"></span><h2>PEDIDO LIQUIDADO</h2></div></div>${calendar(month,calendarItems,'calendar_date',today)}</section>`;
  html(res, layout('Resumen administrativo', content, true, await unread()));
}

async function clientsPage(req, res, url) {
  const form = req.method === 'POST' ? await formBody(req) : new URLSearchParams();
  if (req.method === 'POST' && form.get('action') === 'save_client') {
    const id = Number(form.get('id'));
    const emailValue = String(form.get('email') || '').trim();
    const email = form.get('sin_email') === '1' || !emailValue ? null : emailValue;
    if (id) await query('UPDATE clientes SET nombre=?,email=?,telefono=? WHERE id=?',[form.get('nombre'),email,form.get('telefono'),id]);
    else await query('INSERT INTO clientes(nombre,email,telefono) VALUES(?,?,?)',[form.get('nombre'),email,form.get('telefono')]);
    return redirect(res,'/admin/clientes.php');
  }
  const search=String(url.searchParams.get('q')||'').trim();
  const clients = search
    ? await query('SELECT * FROM clientes WHERE nombre LIKE ? ORDER BY nombre',[`%${search}%`])
    : await query('SELECT * FROM clientes ORDER BY nombre');
  const rows = clients.map(c => { const noEmail=!c.email; return `<tr><td>${esc(c.nombre)}</td><td>${noEmail?'<span class="muted-note">No Aplica</span>':esc(c.email)}</td><td>${esc(c.telefono||'')}</td><td><button type="button" class="btn btn-secondary" data-edit-client data-client-id="${c.id}" data-client-name="${esc(c.nombre)}" data-client-email="${esc(c.email||'')}" data-client-phone="${esc(c.telefono||'')}" data-client-no-email="${noEmail?'1':'0'}">Editar cliente</button></td></tr>`; }).join('');
  const content = `<div class="page-heading split"><div><p class="eyebrow">DIRECTORIO</p><h1>Clientes</h1></div><button type="button" class="btn btn-primary" data-reveal="nuevo-cliente">REGISTRAR CLIENTE</button></div><section id="nuevo-cliente" class="card reveal-panel" hidden><h2>Registro de cliente</h2><form method="POST" class="order-form compact unified-editor-form"><input type="hidden" name="action" value="save_client"><label>Nombre<input name="nombre" required></label><div class="client-email-field"><label>Correo electrónico<input type="email" name="email" data-client-email required></label><label class="client-no-email"><input type="checkbox" name="sin_email" value="1" data-no-client-email><span>No tiene correo electrónico</span></label></div><label>Número celular<input name="telefono"></label><button class="btn btn-primary">Guardar cliente</button></form></section><section class="card"><h2>CLIENTES REGISTRADOS</h2><form class="search-form" method="GET"><label>Buscar cliente:<input type="search" name="q" value="${esc(search)}" placeholder="Escribe el nombre del cliente" autocomplete="off"></label>${search?'<a class="btn btn-secondary" href="/admin/clientes.php">Descartar</a>':'<button class="btn btn-secondary">Buscar</button>'}</form><div class="table-scroll"><table class="data-table"><thead><tr><th>Cliente</th><th>Correo</th><th>Número celular</th><th>Acción</th></tr></thead><tbody>${rows || `<tr><td colspan="4">${search?'No se encontraron clientes con ese nombre.':'No hay clientes registrados.'}</td></tr>`}</tbody></table></div></section><dialog id="edit-client-dialog" class="catalog-edit-dialog client-edit-dialog"><form method="POST" class="order-form compact unified-editor-form"><input type="hidden" name="action" value="save_client"><input type="hidden" name="id" data-edit-client-id><div class="reveal-panel-heading wide"><h2>Editar cliente</h2><button type="button" class="btn btn-secondary" data-close-client-edit>Cerrar</button></div><label>Nombre<input name="nombre" data-edit-client-name required></label><div class="client-email-field"><label>Correo electrónico<input type="email" name="email" data-client-email data-edit-client-email required></label><label class="client-no-email"><input type="checkbox" name="sin_email" value="1" data-no-client-email data-edit-client-no-email><span>No tiene correo electrónico</span></label></div><label>Número celular<input name="telefono" data-edit-client-phone></label><div class="button-group wide"><button class="btn btn-primary">Guardar cambios</button><button type="button" class="btn btn-secondary" data-close-client-edit>Cancelar</button></div></form></dialog><script>(()=>{const syncEmailChoice=checkbox=>{const scope=checkbox.closest('.client-email-field'),email=scope?.querySelector('[data-client-email]');if(!email)return;email.disabled=checkbox.checked;email.required=!checkbox.checked;email.placeholder=checkbox.checked?'No Aplica':'Correo electrónico';if(checkbox.checked)email.value=''};document.querySelectorAll('[data-no-client-email]').forEach(checkbox=>{syncEmailChoice(checkbox);checkbox.addEventListener('change',()=>syncEmailChoice(checkbox))});document.querySelectorAll('[data-reveal]').forEach(button=>button.addEventListener('click',()=>{const panel=document.getElementById(button.dataset.reveal);panel.hidden=!panel.hidden;button.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden)panel.querySelector('input:not([type=hidden])')?.focus()}));const dialog=document.getElementById('edit-client-dialog');document.querySelectorAll('[data-edit-client]').forEach(button=>button.addEventListener('click',()=>{dialog.querySelector('[data-edit-client-id]').value=button.dataset.clientId;dialog.querySelector('[data-edit-client-name]').value=button.dataset.clientName;dialog.querySelector('[data-edit-client-email]').value=button.dataset.clientEmail;dialog.querySelector('[data-edit-client-phone]').value=button.dataset.clientPhone;const checkbox=dialog.querySelector('[data-edit-client-no-email]');checkbox.checked=button.dataset.clientNoEmail==='1';syncEmailChoice(checkbox);dialog.showModal();dialog.querySelector('[data-edit-client-name]').focus()}));dialog.querySelectorAll('[data-close-client-edit]').forEach(button=>button.addEventListener('click',()=>dialog.close()))})();</script>`;
  const clientContent = content
    .replace('<section id="nuevo-cliente" class="card reveal-panel" hidden><h2>Registro de cliente</h2>','<section id="nuevo-cliente" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registro de cliente</h2><button type="button" class="btn btn-secondary" data-close-new-client>Cerrar</button></div>')
    + `<script>(()=>{const panel=document.getElementById('nuevo-cliente'),openButton=document.querySelector('[data-reveal="nuevo-cliente"]'),closeButton=document.querySelector('[data-close-new-client]');closeButton?.addEventListener('click',()=>{panel.hidden=true;openButton.setAttribute('aria-expanded','false');openButton.focus()})})();</script>`;
  html(res,layout('Clientes',clientContent,true,await unread()));
}

async function invitationsPage(req, res) {
  const form = req.method === 'POST' ? await formBody(req) : new URLSearchParams();
  if (req.method === 'POST' && form.get('action') === 'save_invitation') {
    const id = Number(form.get('id'));
    if (id) await query('UPDATE tipos_invitacion SET nombre=?,precio_base=?,caracteristicas=? WHERE id=?',[form.get('nombre'),Number(form.get('precio')),form.get('descripcion'),id]);
    else await query('INSERT INTO tipos_invitacion(nombre,precio_base,caracteristicas) VALUES(?,?,?)',[form.get('nombre'),Number(form.get('precio')),form.get('descripcion')]);
    return redirect(res,'/admin/invitaciones.php');
  }
  const items = await query('SELECT * FROM tipos_invitacion ORDER BY nombre');
  const rows = items.map(item => { const formId=`invitation-${item.id}`; return `<tr data-edit-row data-catalog-row data-filter-name="${esc(String(item.nombre).toLocaleLowerCase('es-MX'))}"><td><input form="${formId}" name="nombre" value="${esc(item.nombre)}" aria-label="Nombre del pastel o postre" disabled required></td><td><input form="${formId}" type="number" step="0.01" min="0" name="precio" value="${Number(item.precio_base).toFixed(2)}" aria-label="Precio" disabled required></td><td><textarea class="catalog-description" form="${formId}" name="descripcion" rows="4" aria-label="Descripción completa" disabled>${esc(item.caracteristicas)}</textarea></td><td><form id="${formId}" method="POST"><input type="hidden" name="action" value="save_invitation"><input type="hidden" name="id" value="${item.id}"><div class="edit-actions"><button type="button" class="btn btn-secondary" data-edit-button>Editar invitación</button><button type="button" class="btn btn-secondary" data-cancel-edit hidden>Cancelar</button></div></form></td></tr>`; }).join('');
  const options = items.map(item=>`<option value="${esc(item.nombre)}"></option>`).join('');
  const content = `<div class="page-heading split"><div><p class="eyebrow">CATÁLOGO</p><h1>Registro de Pasteles &amp; Postres</h1></div><button type="button" class="btn btn-primary" data-reveal="nueva-invitacion">Crear pastel o postre</button></div><section id="nueva-invitacion" class="card reveal-panel" hidden><h2>Nuevo pastel o postre</h2><form method="POST" class="form-grid"><input type="hidden" name="action" value="save_invitation"><label>Nombre del pastel o postre<input name="nombre" required></label><label>Precio<input type="number" min="0" step="0.01" name="precio" required></label><label class="wide">Descripción del pastel o postre<textarea name="descripcion" rows="3"></textarea></label><button class="btn btn-primary">Guardar</button></form></section><section class="card"><h2>Pasteles &amp; Postres creados</h2><div class="catalog-search"><label>Buscar pastel o postre:<input type="search" data-catalog-search list="invitation-search-options" placeholder="Escribe el nombre del pastel o postre" autocomplete="off"><datalist id="invitation-search-options">${options}</datalist></label><button type="button" class="btn btn-secondary" data-search-action>Buscar</button></div><p class="catalog-no-results" data-no-results hidden>No se encontraron pasteles ni postres.</p><div class="table-scroll"><table class="data-table editable-table invitation-table"><thead><tr><th>Nombre del pastel o postre</th><th>Precio</th><th>Descripción completa</th><th>Acción</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No hay pasteles ni postres creados.</td></tr>'}</tbody></table></div></section><script>(()=>{const search=document.querySelector('[data-catalog-search]'),action=document.querySelector('[data-search-action]'),rows=[...document.querySelectorAll('[data-catalog-row]')],empty=document.querySelector('[data-no-results]');let filtered=false;const size=textarea=>{textarea.style.height='auto';textarea.style.height=textarea.scrollHeight+'px'};document.querySelectorAll('.catalog-description').forEach(size);const run=()=>{if(filtered){search.value='';rows.forEach(row=>row.hidden=false);empty.hidden=true;action.textContent='Buscar';filtered=false;search.focus();return}const value=search.value.trim().toLocaleLowerCase('es-MX');let visible=0;rows.forEach(row=>{const show=!value||row.dataset.filterName.includes(value);row.hidden=!show;if(show)visible++});empty.hidden=visible>0;action.textContent='Descartar';filtered=true};action?.addEventListener('click',run);search?.addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();run()}});document.querySelector('[data-reveal]')?.addEventListener('click',event=>{const button=event.currentTarget,panel=document.getElementById(button.dataset.reveal);panel.hidden=!panel.hidden;button.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden)panel.querySelector('input:not([type=hidden])')?.focus()});document.querySelectorAll('[data-edit-button]').forEach(button=>button.addEventListener('click',()=>{const row=button.closest('[data-edit-row]'),fields=[...row.querySelectorAll('[form]')].filter(field=>!field.matches('form'));if(fields.some(field=>field.disabled)){fields.forEach(field=>field.disabled=false);button.textContent='Guardar cambios';button.classList.replace('btn-secondary','btn-primary');fields[0]?.focus();row.querySelectorAll('textarea').forEach(size)}else button.form.requestSubmit()}))})();</script>`;
  const invitationContent = content
    .replace('<section id="nueva-invitacion" class="card reveal-panel" hidden><h2>Nuevo pastel o postre</h2>','<section id="nueva-invitacion" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Nuevo pastel o postre</h2><button type="button" class="btn btn-secondary" data-close-invitation>Cerrar</button></div>')
    + `<script>(()=>{const panel=document.getElementById('nueva-invitacion'),openButton=document.querySelector('[data-reveal="nueva-invitacion"]'),closeButton=document.querySelector('[data-close-invitation]');closeButton?.addEventListener('click',()=>{panel.hidden=true;openButton.setAttribute('aria-expanded','false');openButton.focus()})})();</script>`;
  html(res,layout('Registro de Pasteles &amp; Postres',invitationContent,true,await unread()));
}

async function extrasPage(req, res) {
  const form = req.method === 'POST' ? await formBody(req) : new URLSearchParams();
  if (req.method === 'POST' && form.get('action') === 'save_extra') {
    const id = Number(form.get('id'));
    if (id) await query('UPDATE servicios_adicionales SET nombre=?,precio=?,descripcion=? WHERE id=?',[form.get('nombre'),Number(form.get('precio')),form.get('descripcion'),id]);
    else await query('INSERT INTO servicios_adicionales(nombre,precio,descripcion) VALUES(?,?,?)',[form.get('nombre'),Number(form.get('precio')),form.get('descripcion')]);
    return redirect(res,'/admin/adicionales.php');
  }
  const items = await query('SELECT * FROM servicios_adicionales ORDER BY nombre');
  const rows = items.map(item => `<tr data-catalog-row data-filter-name="${esc(String(item.nombre).toLocaleLowerCase('es-MX'))}"><td><strong>${esc(item.nombre)}</strong></td><td>${money(item.precio)}</td><td class="service-description-cell">${esc(item.descripcion)||'<span class="muted-note">Sin descripción registrada.</span>'}</td><td><button type="button" class="btn btn-secondary" data-edit-extra data-extra-id="${item.id}" data-extra-name="${esc(item.nombre)}" data-extra-price="${Number(item.precio).toFixed(2)}" data-extra-description="${esc(item.descripcion||'')}">Editar servicio</button></td></tr>`).join('');
  const options = items.map(item=>`<option value="${esc(item.nombre)}"></option>`).join('');
  const content = `<div class="page-heading split"><div><p class="eyebrow">CATÁLOGO</p><h1>Servicios Adicionales</h1></div><button type="button" class="btn btn-primary" data-reveal="nuevo-servicio">Crear servicio adicional</button></div><section id="nuevo-servicio" class="card reveal-panel" hidden><h2>Registrar servicio adicional</h2><form method="POST" class="form-grid"><input type="hidden" name="action" value="save_extra"><label>Nombre del servicio adicional<input name="nombre" required></label><label>Precio<input type="number" min="0" step="0.01" name="precio" required></label><label class="wide">Descripción del servicio<textarea name="descripcion" rows="3" placeholder="Describe lo que incluye este servicio"></textarea></label><button class="btn btn-primary">Guardar servicio</button></form></section><section class="card"><h2>Servicios creados</h2><div class="catalog-search"><label>Buscar servicio adicional:<input type="search" data-catalog-search list="service-search-options" placeholder="Escribe el nombre del servicio" autocomplete="off"><datalist id="service-search-options">${options}</datalist></label><button type="button" class="btn btn-secondary" data-search-action>Buscar</button></div><p class="catalog-no-results" data-no-results hidden>No se encontraron servicios.</p><div class="table-scroll"><table class="data-table editable-table service-table"><thead><tr><th>Nombre del servicio</th><th>Precio</th><th>Descripción</th><th>Acción</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No hay servicios adicionales.</td></tr>'}</tbody></table></div></section><script>(()=>{const search=document.querySelector('[data-catalog-search]'),action=document.querySelector('[data-search-action]'),rows=[...document.querySelectorAll('[data-catalog-row]')],empty=document.querySelector('[data-no-results]');let filtered=false;const size=textarea=>{textarea.style.height='auto';textarea.style.height=textarea.scrollHeight+'px'};document.querySelectorAll('.catalog-description').forEach(size);const run=()=>{if(filtered){search.value='';rows.forEach(row=>row.hidden=false);empty.hidden=true;action.textContent='Buscar';filtered=false;search.focus();return}const value=search.value.trim().toLocaleLowerCase('es-MX');let visible=0;rows.forEach(row=>{const show=!value||row.dataset.filterName.includes(value);row.hidden=!show;if(show)visible++});empty.hidden=visible>0;action.textContent='Descartar';filtered=true};action?.addEventListener('click',run);search?.addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();run()}});document.querySelector('[data-reveal]')?.addEventListener('click',event=>{const button=event.currentTarget,panel=document.getElementById(button.dataset.reveal);panel.hidden=!panel.hidden;button.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden)panel.querySelector('input:not([type=hidden])')?.focus()});document.querySelectorAll('[data-edit-button]').forEach(button=>button.addEventListener('click',()=>{const row=button.closest('[data-edit-row]'),fields=[...row.querySelectorAll('[form]')].filter(field=>!field.matches('form'));if(fields.some(field=>field.disabled)){fields.forEach(field=>field.disabled=false);button.textContent='Guardar cambios';button.classList.replace('btn-secondary','btn-primary');fields[0]?.focus();row.querySelectorAll('textarea').forEach(size)}else button.form.requestSubmit()}))})();</script>`;
  const extraContent = content
    .replace('<section id="nuevo-servicio" class="card reveal-panel" hidden><h2>Registrar servicio adicional</h2>','<section id="nuevo-servicio" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registrar servicio adicional</h2><button type="button" class="btn btn-secondary" data-close-extra>Cerrar</button></div>')
    + `<dialog id="edit-extra-dialog" class="catalog-edit-dialog"><form method="POST" class="form-grid"><input type="hidden" name="action" value="save_extra"><input type="hidden" name="id" data-extra-edit-id><div class="reveal-panel-heading wide"><h2>Editar servicio adicional</h2><button type="button" class="btn btn-secondary" data-close-extra-edit>Cerrar</button></div><label>Nombre del servicio<input name="nombre" data-extra-edit-name required></label><label>Precio<input type="number" min="0" step="0.01" name="precio" data-extra-edit-price required></label><label class="wide">Descripción del servicio<textarea name="descripcion" rows="5" data-extra-edit-description></textarea></label><button class="btn btn-primary">Guardar cambios</button><button type="button" class="btn btn-secondary" data-close-extra-edit>Cancelar</button></form></dialog><script>(()=>{const panel=document.getElementById('nuevo-servicio'),openButton=document.querySelector('[data-reveal="nuevo-servicio"]'),closeButton=document.querySelector('[data-close-extra]'),dialog=document.getElementById('edit-extra-dialog');closeButton?.addEventListener('click',()=>{panel.hidden=true;openButton.setAttribute('aria-expanded','false');openButton.focus()});document.querySelectorAll('[data-edit-extra]').forEach(button=>button.addEventListener('click',()=>{dialog.querySelector('[data-extra-edit-id]').value=button.dataset.extraId;dialog.querySelector('[data-extra-edit-name]').value=button.dataset.extraName;dialog.querySelector('[data-extra-edit-price]').value=button.dataset.extraPrice;dialog.querySelector('[data-extra-edit-description]').value=button.dataset.extraDescription;dialog.showModal();dialog.querySelector('[data-extra-edit-name]').focus()}));dialog.querySelectorAll('[data-close-extra-edit]').forEach(button=>button.addEventListener('click',()=>dialog.close()))})();</script>`;
  html(res,layout('Servicios Adicionales',extraContent,true,await unread()));
}

async function verifyAdministratorPassword(password) {
  const setting=await one("SELECT valor FROM configuracion_portal WHERE clave='password_administrador'");
  return Boolean(setting&&await passwordMatches(password,setting.valor));
}

async function discountsPage(req,res) {
  const form=req.method==='POST'?await formBody(req):new URLSearchParams();
  if(req.method==='POST'&&form.get('action')==='save_discount'){
    const id=Number(form.get('id')),name=String(form.get('nombre')||'').trim();
    const type=form.get('tipo')==='fijo'?'fijo':'porcentaje';
    const value=Math.max(0,Number(form.get('valor'))||0),description=String(form.get('descripcion')||'').trim();
    const active=form.get('activo')==='1'?1:0;
    if(name&&value>0){
      if(id)await query('UPDATE descuentos SET nombre=?,tipo=?,valor=?,descripcion=?,activo=? WHERE id=?',[name,type,value,description,active,id]);
      else await query('INSERT INTO descuentos(nombre,tipo,valor,descripcion,activo) VALUES(?,?,?,?,1)',[name,type,value,description]);
    }
    return redirect(res,'/admin/descuentos.php');
  }
  const items=await query('SELECT * FROM descuentos ORDER BY activo DESC,nombre');
  const rows=items.map(item=>{const formId=`discount-${item.id}`;return `<tr data-edit-row><td><input form="${formId}" name="nombre" value="${esc(item.nombre)}" disabled required></td><td><select form="${formId}" name="tipo" disabled><option value="porcentaje" ${item.tipo==='porcentaje'?'selected':''}>Porcentaje</option><option value="fijo" ${item.tipo==='fijo'?'selected':''}>Cantidad fija</option></select></td><td><input form="${formId}" type="number" min="0.01" step="0.01" name="valor" value="${Number(item.valor).toFixed(2)}" disabled required></td><td><textarea form="${formId}" name="descripcion" rows="2" disabled>${esc(item.descripcion||'')}</textarea></td><td><label class="inline-checkbox"><input form="${formId}" type="checkbox" name="activo" value="1" ${Number(item.activo)?'checked':''} disabled>Disponible</label></td><td><form id="${formId}" method="POST"><input type="hidden" name="action" value="save_discount"><input type="hidden" name="id" value="${item.id}"><div class="edit-actions"><button type="button" class="btn btn-secondary" data-edit-button>Editar descuento</button><button type="button" class="btn btn-secondary" data-cancel-edit hidden>Cancelar</button></div></form></td></tr>`}).join('');
  const content=`<div class="page-heading split"><div><p class="eyebrow">CATÁLOGO</p><h1>Descuentos</h1><p>Los descuentos se aplican al precio del paquete de invitación, antes de sumar servicios adicionales.</p></div><button type="button" class="btn btn-primary" data-reveal="nuevo-descuento">Crear descuento</button></div><section id="nuevo-descuento" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Nuevo descuento</h2><button type="button" class="btn btn-secondary" data-close-discount>Cerrar</button></div><form method="POST" class="form-grid"><input type="hidden" name="action" value="save_discount"><label>Nombre<input name="nombre" required></label><label>Tipo<select name="tipo"><option value="porcentaje">Porcentaje</option><option value="fijo">Cantidad fija</option></select></label><label>Valor<input type="number" name="valor" min="0.01" step="0.01" required></label><label class="wide">Descripción<textarea name="descripcion" rows="3"></textarea></label><button class="btn btn-primary">Guardar descuento</button></form></section><section class="card"><h2>Descuentos registrados</h2><div class="table-scroll"><table class="data-table editable-table"><thead><tr><th>Nombre</th><th>Tipo</th><th>Valor</th><th>Descripción</th><th>Estado</th><th>Acción</th></tr></thead><tbody>${rows||'<tr><td colspan="6">No hay descuentos registrados.</td></tr>'}</tbody></table></div></section><script>(()=>{const panel=document.getElementById('nuevo-descuento'),open=document.querySelector('[data-reveal="nuevo-descuento"]'),close=document.querySelector('[data-close-discount]');open?.addEventListener('click',()=>{panel.hidden=false;open.setAttribute('aria-expanded','true');panel.querySelector('input:not([type=hidden])')?.focus()});close?.addEventListener('click',()=>{panel.hidden=true;open.setAttribute('aria-expanded','false');open.focus()})})();</script>`;
  html(res,layout('Descuentos',content,true,await unread()));
}

async function ordersPage(req, res, url) {
  const form = req.method === 'POST' ? await formBody(req) : new URLSearchParams();
  if (req.method === 'POST' && form.get('action') === 'create_order') {
    const conn = await db().getConnection();
    try {
      await conn.beginTransaction();
      const clientId = Number(form.get('cliente_id'));
      const invitationId = Number(form.get('tipo_id'));
      const courtesy = form.get('cortesia') === '1';
      const discountId = Number(form.get('descuento_id')) || null;
      const [[client]] = await conn.execute('SELECT nombre,email,telefono FROM clientes WHERE id=?',[clientId]);
      const [[invitation]] = await conn.execute('SELECT nombre,precio_base,caracteristicas FROM tipos_invitacion WHERE id=?',[invitationId]);
      const [[discount]] = discountId ? await conn.execute('SELECT id,nombre,tipo,valor FROM descuentos WHERE id=? AND activo=1',[discountId]) : [[null]];
      if (!client || !invitation) throw new Error('Cliente o invitación inválidos');
      if (discountId && !discount) throw new Error('Descuento inválido');
      const chosenServices=[];
      for (const serviceId of form.getAll('servicios')) {
        const [[service]] = await conn.execute('SELECT nombre,precio,descripcion FROM servicios_adicionales WHERE id=?',[Number(serviceId)]);
        if (!service) throw new Error('Servicio adicional inválido');
        chosenServices.push({id:Number(serviceId),...service});
      }
      const discountAmount=discountAmountForPackage(discount,invitation.precio_base);
      const calculatedPrice=Math.max(0,Number(invitation.precio_base)-discountAmount+chosenServices.reduce((sum,item)=>sum+Number(item.precio),0));
      const finalPrice=courtesy?0:calculatedPrice;
      const [created] = await conn.execute(`INSERT INTO pedidos(
        cliente_id,tipo_id,nombre_evento,fecha_evento,fecha_entrega,fecha_liquidacion,hora_evento,precio_final,
        cliente_nombre_snapshot,cliente_email_snapshot,cliente_telefono_snapshot,
        invitacion_nombre_snapshot,invitacion_descripcion_snapshot,invitacion_precio_snapshot,notas,cortesia,
        descuento_id,descuento_nombre_snapshot,descuento_tipo_snapshot,descuento_valor_snapshot,descuento_monto_snapshot
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,[
        clientId,invitationId,form.get('nombre_evento'),form.get('fecha_evento') || null,form.get('fecha_entrega') || null,
        form.get('fecha_liquidacion') || shiftDate(form.get('fecha_evento'),1) || null,
        form.get('hora_evento') || null,finalPrice,client.nombre,client.email,client.telefono,
        invitation.nombre,invitation.caracteristicas,invitation.precio_base,String(form.get('notas')||'').trim()||null,courtesy?1:0,
        discount?.id||null,discount?.nombre||null,discount?.tipo||null,discount?.valor||null,discountAmount
      ]);
      for (const service of chosenServices) {
        await conn.execute('INSERT INTO pedido_servicios(pedido_id,servicio_id,servicio_nombre_snapshot,servicio_precio_snapshot,servicio_descripcion_snapshot) VALUES(?,?,?,?,?)',[created.insertId,service.id,service.nombre,service.precio,service.descripcion]);
      }
      await conn.commit();
      return redirect(res,'/admin/pedidos.php?creado=1');
    } catch (error) { await conn.rollback(); throw error; } finally { conn.release(); }
  }
  const clients = await query('SELECT id,nombre FROM clientes ORDER BY nombre');
  const invitations = await query('SELECT id,nombre,precio_base FROM tipos_invitacion ORDER BY nombre');
  const extras = await query('SELECT id,nombre,precio,descripcion FROM servicios_adicionales ORDER BY nombre');
  const discounts = await query('SELECT id,nombre,tipo,valor,descripcion FROM descuentos WHERE activo=1 ORDER BY nombre');
  const currentSearch = (url.searchParams.get('actual') || '').trim();
  const finishedSearch = (url.searchParams.get('finalizado') || '').trim();
  const baseSql = `SELECT p.*,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,COALESCE(p.cliente_email_snapshot,c.email) email,COALESCE(p.invitacion_nombre_snapshot,t.nombre) invitacion_nombre,COALESCE((SELECT SUM(monto) FROM pagos WHERE pedido_id=p.id),0) pagado FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id LEFT JOIN tipos_invitacion t ON t.id=p.tipo_id`;
  const current = await query(`${baseSql} WHERE p.entregado=0 AND COALESCE(p.cliente_nombre_snapshot,c.nombre) LIKE ? ORDER BY COALESCE(p.fecha_entrega,p.fecha_evento)`,[`%${currentSearch}%`]);
  const finished = await query(`${baseSql} WHERE p.entregado=1 AND COALESCE(p.cliente_nombre_snapshot,c.nombre) LIKE ? ORDER BY p.fecha_entrega_real DESC`,[`%${finishedSearch}%`]);
  const orderCards = rows => rows.map(r => `<article class="order-card"><div><span class="status ${r.entregado ? 'done' : 'pending'}">${r.entregado ? 'Finalizado' : 'Actual'}</span><h3>${esc(r.nombre_evento || 'Evento')}</h3><p>${esc(r.cliente_nombre)} · ${esc(r.invitacion_nombre)} · ${displayDate(r.fecha_evento)}</p></div><div class="order-money"><b>${money(r.precio_final)}</b><small>Pagado ${money(r.pagado)}</small></div><a class="btn btn-secondary" href="/admin/ver_pedido.php?id=${r.id}">Ver pedido</a></article>`).join('') || '<p class="empty-state">No se encontraron pedidos.</p>';
  const clientOptions = clients.map(c=>`<option value="${c.id}">${esc(c.nombre)}</option>`).join('');
  const clientPickerOptions = clients.map(c=>`<button type="button" class="client-picker-option" role="option" data-client-option data-client-id="${c.id}" data-client-name="${esc(c.nombre)}" data-client-filter="${esc(String(c.nombre).toLocaleLowerCase('es-MX'))}">${esc(c.nombre)}</button>`).join('') || '<p class="empty-state">No hay clientes registrados.</p>';
  const clientPickerField = `<label>Cliente registrado<div class="client-picker"><input id="client_search" type="search" placeholder="Escribe el nombre del cliente" autocomplete="off" role="combobox" aria-autocomplete="list" aria-controls="client_search_results" aria-expanded="false" required><input id="client_id" type="hidden" name="cliente_id"><div id="client_search_results" class="client-picker-results" role="listbox" hidden>${clientPickerOptions}</div></div></label>`;
  const invitationOptions = invitations.map(i=>`<option value="${i.id}" data-price="${Number(i.precio_base)}">${esc(i.nombre)} - ${money(i.precio_base)}</option>`).join('');
  const invitationPickerOptions = invitations.map(i=>`<button type="button" class="client-picker-option invitation-picker-option" role="option" data-invitation-option data-invitation-id="${i.id}" data-invitation-name="${esc(i.nombre)}" data-invitation-price="${Number(i.precio_base)}" data-invitation-filter="${esc(String(i.nombre).toLocaleLowerCase('es-MX'))}"><span>${esc(i.nombre)}</span><small>${money(i.precio_base)}</small></button>`).join('') || '<p class="empty-state">No hay invitaciones registradas.</p>';
  const invitationPickerField = `<label class="invitation-picker-field">Pastel o postre<div class="client-picker invitation-picker"><input id="invitation_search" type="search" placeholder="Escribe el nombre del pastel o postre" autocomplete="off" role="combobox" aria-autocomplete="list" aria-controls="invitation_search_results" aria-expanded="false" required><input id="tipo_id" type="hidden" name="tipo_id" data-price=""><div id="invitation_search_results" class="client-picker-results" role="listbox" hidden>${invitationPickerOptions}</div></div></label>`;
  const extrasOptions = extras.map(x=>`<label class="check-option"><input type="checkbox" name="servicios" value="${x.id}" data-extra-price="${Number(x.precio)}"><span>${esc(x.nombre)} <small>${money(x.precio)}${x.descripcion?` · ${esc(x.descripcion)}`:''}</small></span></label>`).join('') || '<p>No hay servicios adicionales registrados.</p>';
  const discountOptions=discounts.map(x=>`<option value="${x.id}" data-discount-type="${x.tipo}" data-discount-value="${Number(x.valor)}">${esc(x.nombre)} - ${x.tipo==='porcentaje'?`${Number(x.valor)}%`:money(x.valor)}</option>`).join('');
  const createdNotice = url.searchParams.get('creado') === '1' ? '<p class="success-banner">Pedido guardado. La lista de pedidos actuales ya está actualizada.</p>' : '';
  const currentSearchForm = `<form class="search-form"><label>Buscar pedido:<input name="actual" value="${esc(currentSearch)}" placeholder="Escribir nombre del cliente"></label>${currentSearch ? '<a class="btn btn-secondary" href="/admin/pedidos.php">Descartar</a>' : '<button class="btn btn-secondary">Buscar</button>'}</form>`;
  const finishedSearchForm = `<form class="search-form"><label>Buscar pedido:<input name="finalizado" value="${esc(finishedSearch)}" placeholder="Escribir nombre del cliente"></label>${finishedSearch ? '<a class="btn btn-secondary" href="/admin/pedidos.php?tab=finished">Descartar</a>' : '<button class="btn btn-secondary">Buscar</button>'}</form>`;
  const content = `<div class="page-heading split"><div><p class="eyebrow">OPERACIÓN</p><h1>Pedidos</h1></div><button type="button" class="btn btn-primary" data-reveal="nuevo-pedido">CREAR NUEVO PEDIDO</button></div>${createdNotice}<section id="nuevo-pedido" class="card new-order reveal-panel" hidden><h2>Crear nuevo pedido</h2><form method="POST" class="order-form"><input type="hidden" name="action" value="create_order"><label>Cliente registrado<select name="cliente_id" required><option value="">Selecciona un cliente</option>${clientOptions}</select></label><label>Evento<input name="nombre_evento" required></label><label>Fecha del evento<input id="fecha_evento_nuevo" type="date" name="fecha_evento" required></label><label>Hora del evento<input type="time" name="hora_evento"></label><label>Fecha de entrega<input id="fecha_entrega_nueva" type="date" name="fecha_entrega" required><small>Se calcula 35 días antes del evento y puedes modificarla.</small></label><label>Pastel o postre<select id="tipo_id" name="tipo_id" required><option value="">Selecciona una invitación</option>${invitationOptions}</select></label><fieldset class="wide"><legend>Servicios adicionales</legend><div class="check-grid">${extrasOptions}</div></fieldset><label>Costo total<input id="precio_final" type="number" min="0" step="0.01" name="precio_final" required></label><button class="btn btn-primary">Guardar pedido</button></form></section><section class="orders-workspace card"><div class="order-view-tabs" role="tablist" aria-label="Estado de los pedidos"><button type="button" class="order-view-tab active" role="tab" aria-selected="true" aria-controls="pedidos-actuales" data-order-tab="current">PEDIDOS ACTUALES <span>${current.length}</span></button><button type="button" class="order-view-tab" role="tab" aria-selected="false" aria-controls="pedidos-finalizados" data-order-tab="finished">PEDIDOS FINALIZADOS <span>${finished.length}</span></button></div><div id="pedidos-actuales" class="order-tab-panel" role="tabpanel" data-order-panel="current"><form class="search-form"><input name="actual" value="${esc(currentSearch)}" placeholder="Buscar por nombre del cliente"><button class="btn btn-secondary">Buscar</button></form><div class="order-list">${orderCards(current)}</div></div><div id="pedidos-finalizados" class="order-tab-panel" role="tabpanel" data-order-panel="finished" hidden><form class="search-form"><input name="finalizado" value="${esc(finishedSearch)}" placeholder="Buscar por nombre del cliente"><button class="btn btn-secondary">Buscar</button></form><div class="order-list">${orderCards(finished)}</div></div></section><script>(()=>{const reveal=document.querySelector('[data-reveal="nuevo-pedido"]'),panel=document.getElementById('nuevo-pedido');reveal?.addEventListener('click',()=>{panel.hidden=!panel.hidden;reveal.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden)panel.querySelector('select')?.focus()});const eventDate=document.getElementById('fecha_evento_nuevo'),deliveryDate=document.getElementById('fecha_entrega_nueva');eventDate?.addEventListener('change',()=>{if(!eventDate.value)return;const date=new Date(eventDate.value+'T12:00:00');date.setDate(date.getDate()-35);deliveryDate.value=date.toISOString().slice(0,10)});const type=document.querySelector('#tipo_id'),total=document.querySelector('#precio_final'),extras=[...document.querySelectorAll('[data-extra-price]')];const calc=()=>{const base=Number(type?.selectedOptions[0]?.dataset.price||0);total.value=(base+extras.filter(x=>x.checked).reduce((sum,x)=>sum+Number(x.dataset.extraPrice),0)).toFixed(2)};type?.addEventListener('change',calc);extras.forEach(x=>x.addEventListener('change',calc));const tabs=[...document.querySelectorAll('[data-order-tab]')],panels=[...document.querySelectorAll('[data-order-panel]')];const show=key=>{tabs.forEach(tab=>{const active=tab.dataset.orderTab===key;tab.classList.toggle('active',active);tab.setAttribute('aria-selected',String(active))});panels.forEach(item=>item.hidden=item.dataset.orderPanel!==key)};tabs.forEach(tab=>tab.addEventListener('click',()=>show(tab.dataset.orderTab)));if(new URLSearchParams(location.search).has('finalizado'))show('finished')})();</script>`;
  const enhancedContent = content
    .replace('<section id="nuevo-pedido" class="card new-order reveal-panel" hidden><h2>Crear nuevo pedido</h2>','<section id="nuevo-pedido" class="card new-order reveal-panel" hidden><div class="reveal-panel-heading"><h2>Crear nuevo pedido</h2><button type="button" class="btn btn-secondary" data-close-new-order>Cerrar</button></div>')
    .replace(`<label>Cliente registrado<select name="cliente_id" required><option value="">Selecciona un cliente</option>${clientOptions}</select></label>`,clientPickerField)
    .replace(`<label>Pastel o postre<select id="tipo_id" name="tipo_id" required><option value="">Selecciona una invitación</option>${invitationOptions}</select></label>`,invitationPickerField)
    .replace(`${invitationPickerField}<fieldset class="wide"><legend>Servicios adicionales</legend>`,`${invitationPickerField}<label>Descuento del paquete<select id="descuento_id" name="descuento_id"><option value="">Sin descuento</option>${discountOptions}</select></label><fieldset class="wide"><legend>Servicios adicionales</legend>`)
    .replace('<label>Costo total<input id="precio_final"',`<label class="wide">Notas del pedido<textarea name="notas" rows="4" placeholder="Indicaciones, acuerdos o detalles importantes"></textarea></label><label>Costo total<input id="precio_final" readonly`)
    .replace('</label><button class="btn btn-primary">Guardar pedido</button>',`</label><label class="courtesy-option"><input id="cortesia" type="checkbox" name="cortesia" value="1"><span><b>Cortesía</b><small>El pedido se registrará sin costo.</small></span></label><button class="btn btn-primary">Guardar pedido</button>`)
    .replace("const type=document.querySelector('#tipo_id'),total=document.querySelector('#precio_final'),extras=[...document.querySelectorAll('[data-extra-price]')];const calc=()=>{const base=Number(type?.selectedOptions[0]?.dataset.price||0);total.value=(base+extras.filter(x=>x.checked).reduce((sum,x)=>sum+Number(x.dataset.extraPrice),0)).toFixed(2)};type?.addEventListener('change',calc);extras.forEach(x=>x.addEventListener('change',calc));","const type=document.querySelector('#tipo_id'),discount=document.querySelector('#descuento_id'),total=document.querySelector('#precio_final'),courtesy=document.querySelector('#cortesia'),extras=[...document.querySelectorAll('[data-extra-price]')];const calc=()=>{const base=Number(type?.dataset.price||0),option=discount?.selectedOptions[0],value=Number(option?.dataset.discountValue||0),reduction=option?.dataset.discountType==='porcentaje'?base*Math.min(value,100)/100:Math.min(value,base);total.value=courtesy?.checked?'0.00':(Math.max(0,base-reduction)+extras.filter(x=>x.checked).reduce((sum,x)=>sum+Number(x.dataset.extraPrice),0)).toFixed(2)};type?.addEventListener('change',calc);discount?.addEventListener('change',calc);courtesy?.addEventListener('change',()=>{discount.disabled=courtesy.checked;extras.forEach(item=>item.disabled=courtesy.checked);calc()});extras.forEach(x=>x.addEventListener('change',calc));")
    .replace(/<form class="search-form"><input name="actual"[\s\S]*?<\/form>/,currentSearchForm)
    .replace(/<form class="search-form"><input name="finalizado"[\s\S]*?<\/form>/,finishedSearchForm)
    .replace("if(new URLSearchParams(location.search).has('finalizado'))show('finished')","const params=new URLSearchParams(location.search);if(params.has('finalizado')||params.get('tab')==='finished')show('finished')")
    + `<script>(()=>{const panel=document.getElementById('nuevo-pedido'),form=document.querySelector('#nuevo-pedido .order-form'),reveal=document.querySelector('[data-reveal="nuevo-pedido"]'),closeButton=document.querySelector('[data-close-new-order]'),search=document.getElementById('client_search'),clientId=document.getElementById('client_id'),results=document.getElementById('client_search_results'),options=[...document.querySelectorAll('[data-client-option]')];let selectedName='';const close=()=>{results.hidden=true;search.setAttribute('aria-expanded','false')};const filter=()=>{if(search.value!==selectedName){clientId.value='';search.setCustomValidity('Selecciona un cliente de la lista.')}const value=search.value.trim().toLocaleLowerCase('es-MX');let visible=0;options.forEach(option=>{const show=!value||option.dataset.clientFilter.includes(value);option.hidden=!show;if(show)visible++});results.hidden=!visible;search.setAttribute('aria-expanded',String(Boolean(visible)))};search?.addEventListener('input',filter);search?.addEventListener('focus',filter);options.forEach(option=>option.addEventListener('click',()=>{selectedName=option.dataset.clientName;search.value=selectedName;clientId.value=option.dataset.clientId;search.setCustomValidity('');close()}));form?.addEventListener('submit',event=>{if(!clientId.value){event.preventDefault();search.setCustomValidity('Selecciona un cliente de la lista.');search.reportValidity();filter()}});reveal?.addEventListener('click',()=>{if(!panel.hidden)setTimeout(()=>search.focus(),0)});closeButton?.addEventListener('click',()=>{panel.hidden=true;reveal.setAttribute('aria-expanded','false');close();reveal.focus()});document.addEventListener('click',event=>{if(!event.target.closest('.client-picker'))close()})})();</script>`;
  const workflowContent = enhancedContent
    .replace(invitationPickerField,`<label>Fecha de liquidación<input id="fecha_liquidacion_nueva" type="date" name="fecha_liquidacion" required><small>Se calcula un día después del evento y puedes modificarla.</small></label>${invitationPickerField}`)
    + `<script>(()=>{const eventDate=document.getElementById('fecha_evento_nuevo'),liquidationDate=document.getElementById('fecha_liquidacion_nueva');let automatic='';eventDate?.addEventListener('change',()=>{if(!eventDate.value)return;const date=new Date(eventDate.value+'T12:00:00');date.setDate(date.getDate()+1);const next=date.toISOString().slice(0,10);if(!liquidationDate.value||liquidationDate.value===automatic)liquidationDate.value=next;automatic=next});const form=document.querySelector('#nuevo-pedido .order-form'),search=document.getElementById('invitation_search'),invitationId=document.getElementById('tipo_id'),results=document.getElementById('invitation_search_results'),options=[...document.querySelectorAll('[data-invitation-option]')];let selectedName='';const close=()=>{results.hidden=true;search.setAttribute('aria-expanded','false')};const filter=()=>{if(search.value!==selectedName){invitationId.value='';invitationId.dataset.price='';search.setCustomValidity('Selecciona una invitación de la lista.')}const value=search.value.trim().toLocaleLowerCase('es-MX');let visible=0;options.forEach(option=>{const show=!value||option.dataset.invitationFilter.includes(value);option.hidden=!show;if(show)visible++});results.hidden=!visible;search.setAttribute('aria-expanded',String(Boolean(visible)))};search?.addEventListener('input',filter);search?.addEventListener('focus',filter);options.forEach(option=>option.addEventListener('click',()=>{selectedName=option.dataset.invitationName;search.value=selectedName;invitationId.value=option.dataset.invitationId;invitationId.dataset.price=option.dataset.invitationPrice;search.setCustomValidity('');close();invitationId.dispatchEvent(new Event('change',{bubbles:true}))}));form?.addEventListener('submit',event=>{if(!invitationId.value){event.preventDefault();search.setCustomValidity('Selecciona una invitación de la lista.');search.reportValidity();filter()}});document.addEventListener('click',event=>{if(!event.target.closest('.invitation-picker'))close()})})();</script>`;
  html(res,layout('Pedidos',workflowContent,true,await unread()));
}

async function legacyPaymentsPage(req, res, url) {
  if (req.method === 'POST') {
    const form = await formBody(req);
    if (form.get('action') === 'add_payment') {
      const orderId = Number(form.get('pedido_id'));
      const amount = Number(form.get('monto'));
      const method = ['Efectivo','Transferencia','Tarjeta'].includes(form.get('metodo')) ? form.get('metodo') : 'Efectivo';
      const conn = await db().getConnection();
      try {
        await conn.beginTransaction();
        const [[currentOrder]] = orderId > 0 ? await conn.execute('SELECT id,entregado FROM pedidos WHERE id=? FOR UPDATE',[orderId]) : [[]];
        if (!currentOrder || Number(currentOrder.entregado) === 1 || amount <= 0) {
          await conn.rollback();
          return redirect(res,'/admin/pagos.php?error=pedido');
        }
        await conn.execute('INSERT INTO pagos(pedido_id,monto,metodo,fecha_pago) VALUES(?,?,?,?)',[orderId,amount,method,mysqlDateTime(form.get('fecha_pago'))]);
        await conn.commit();
        return redirect(res,'/admin/pagos.php?registrado=1');
      } catch (error) { await conn.rollback(); throw error; } finally { conn.release(); }
    }
  }
  const search = (url.searchParams.get('cliente') || '').trim();
  const rows = await query(`SELECT p.id,p.nombre_evento,p.precio_final,p.entregado,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,COALESCE(p.invitacion_nombre_snapshot,t.nombre) invitacion_nombre,COALESCE(x.pagado,0) pagado
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id LEFT JOIN tipos_invitacion t ON t.id=p.tipo_id
    LEFT JOIN (SELECT pedido_id,SUM(monto) pagado FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id
    WHERE COALESCE(p.cliente_nombre_snapshot,c.nombre) LIKE ? ORDER BY p.fecha_creacion DESC`,[`%${search}%`]);
  const currentOrders = await query(`SELECT p.id,p.nombre_evento,p.fecha_evento,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id
    WHERE p.entregado=0 ORDER BY COALESCE(p.cliente_nombre_snapshot,c.nombre),p.fecha_evento`);
  const orderResults = currentOrders.map(r => `<button type="button" class="payment-order-result" data-current-order data-order-id="${r.id}" data-client="${esc(String(r.cliente_nombre).toLocaleLowerCase('es-MX'))}" data-client-name="${esc(r.cliente_nombre)}" data-event="${esc(r.nombre_evento)}" data-event-date="${sqlDate(r.fecha_evento)}"><strong>${esc(r.cliente_nombre)}</strong><span>${esc(r.nombre_evento)}</span></button>`).join('') || '<p class="empty-state">No hay pedidos actuales disponibles.</p>';
  const tableRows = rows.map(r => { const balance=Number(r.precio_final)-Number(r.pagado); const state=balance<=0?'Liquidado':r.entregado?'Entregado con saldo':'Pendiente'; return `<tr><td>${esc(r.nombre_evento)}</td><td>${esc(r.cliente_nombre)}</td><td>${esc(r.invitacion_nombre)}</td><td>${money(r.precio_final)}</td><td>${money(r.pagado)}</td><td><span class="status ${balance<=0?'paid':'pending'}">${state}</span></td><td><a class="btn btn-secondary" href="/admin/ver_pedido.php?id=${r.id}">Ver pedido</a></td></tr>`; }).join('') || '<tr><td colspan="7">No se encontraron pedidos.</td></tr>';
  const notice = url.searchParams.get('registrado') === '1' ? '<p class="success-banner">Pago registrado correctamente.</p>' : url.searchParams.get('error') ? '<p class="error-banner">Solo puedes registrar pagos en pedidos actuales.</p>' : '';
  const content = `<div class="page-heading split"><div><p class="eyebrow">COBRANZA</p><h1>Pagos y liquidación de las invitaciones</h1></div><button type="button" class="btn btn-primary" data-reveal="registrar-pago">Registrar pago</button></div>${notice}<section id="registrar-pago" class="card reveal-panel" hidden><h2>Registrar pago</h2><form method="POST" class="payment-registration-form"><input type="hidden" name="action" value="add_payment"><input id="pedido_id_pago" type="hidden" name="pedido_id"><label class="payment-order payment-order-picker">Buscar pedido por nombre del cliente<input id="payment_order_search" type="search" placeholder="Escribe el nombre del cliente" autocomplete="off" aria-controls="payment_order_results" aria-expanded="false" required><span class="field-help">Solo aparecen pedidos actuales.</span><span id="payment_order_results" class="payment-order-results" hidden>${orderResults}</span></label><label>Nombre del evento<input id="payment_event_name" readonly disabled></label><label>Fecha del evento<input id="payment_event_date" type="date" readonly disabled></label><label>Monto<input id="payment_amount" type="number" min="0.01" step="0.01" name="monto" disabled required></label><label>Método de pago<select id="payment_method" name="metodo" disabled><option>Efectivo</option><option>Transferencia</option><option>Tarjeta</option></select></label><label>Fecha y hora del pago<input id="fecha_pago_nueva" type="datetime-local" name="fecha_pago" disabled required></label><button id="save_payment_button" class="btn btn-primary" disabled>Guardar pago</button></form></section><div class="card"><form class="search-form"><input name="cliente" value="${esc(search)}" placeholder="Buscar únicamente por nombre del cliente"><button class="btn btn-primary">Buscar cliente</button></form><div class="table-scroll"><table class="data-table"><thead><tr><th>Evento</th><th>Cliente</th><th>Pastel o postre</th><th>Total</th><th>Pagado</th><th>Estado</th><th>Acciones</th></tr></thead><tbody>${tableRows}</tbody></table></div></div><script>(()=>{const reveal=document.querySelector('[data-reveal="registrar-pago"]'),panel=document.getElementById('registrar-pago'),search=document.getElementById('payment_order_search'),results=document.getElementById('payment_order_results'),orders=[...document.querySelectorAll('[data-current-order]')],orderId=document.getElementById('pedido_id_pago'),eventName=document.getElementById('payment_event_name'),eventDate=document.getElementById('payment_event_date'),amount=document.getElementById('payment_amount'),method=document.getElementById('payment_method'),date=document.getElementById('fecha_pago_nueva'),save=document.getElementById('save_payment_button');let selectedClient='';const enable=enabled=>{[eventName,eventDate,amount,method,date,save].forEach(field=>field.disabled=!enabled)};const reset=()=>{orderId.value='';selectedClient='';eventName.value='';eventDate.value='';enable(false)};const filter=()=>{const value=search.value.trim().toLocaleLowerCase('es-MX');if(search.value!==selectedClient)reset();let visible=0;orders.forEach(order=>{const show=!value||order.dataset.client.includes(value);order.hidden=!show;if(show)visible++});results.hidden=!visible;search.setAttribute('aria-expanded',String(Boolean(visible)))};reveal?.addEventListener('click',()=>{panel.hidden=!panel.hidden;reveal.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden)search.focus()});search?.addEventListener('input',filter);search?.addEventListener('focus',filter);orders.forEach(order=>order.addEventListener('click',()=>{selectedClient=order.dataset.clientName;search.value=selectedClient;orderId.value=order.dataset.orderId;eventName.value=order.dataset.event;eventDate.value=order.dataset.eventDate;enable(true);eventName.readOnly=true;eventDate.readOnly=true;const now=new Date(Date.now()-new Date().getTimezoneOffset()*60000);date.value=now.toISOString().slice(0,16);results.hidden=true;search.setAttribute('aria-expanded','false');amount.focus()}));document.addEventListener('click',event=>{if(!event.target.closest('.payment-order-picker')){results.hidden=true;search?.setAttribute('aria-expanded','false')}})})();</script>`;
  const labeledContent = content
    .replace('<form class="search-form"><input name="cliente"','<form class="search-form"><label>Buscar cliente:<input name="cliente"')
    .replace('placeholder="Buscar únicamente por nombre del cliente"><button class="btn btn-primary">Buscar cliente</button>','placeholder="Escribe el nombre del cliente"></label><button class="btn btn-primary">Buscar cliente</button>');
  const paymentContent = labeledContent
    .replace('<section id="registrar-pago" class="card reveal-panel" hidden><h2>Registrar pago</h2>','<section id="registrar-pago" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registrar pago</h2><button type="button" class="btn btn-secondary" data-close-payment>Cerrar</button></div>')
    + `<script>(()=>{const panel=document.getElementById('registrar-pago'),openButton=document.querySelector('[data-reveal="registrar-pago"]'),closeButton=document.querySelector('[data-close-payment]'),results=document.getElementById('payment_order_results'),search=document.getElementById('payment_order_search');closeButton?.addEventListener('click',()=>{panel.hidden=true;openButton.setAttribute('aria-expanded','false');results.hidden=true;search.setAttribute('aria-expanded','false');openButton.focus()})})();</script>`;
  html(res,layout('Pagos y liquidación',paymentContent,true,await unread()));
}

async function paymentsPage(req, res, url) {
  const pendingSearch = (url.searchParams.get('pendiente') || '').trim();
  const liquidatedSearch = (url.searchParams.get('liquidado') || '').trim();
  const select = `SELECT p.id,p.nombre_evento,p.fecha_evento,p.fecha_liquidacion,p.precio_final,p.entregado,
    COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,
    COALESCE(p.invitacion_nombre_snapshot,t.nombre) invitacion_nombre,
    COALESCE(x.pagado,0) pagado
    FROM pedidos p
    LEFT JOIN clientes c ON c.id=p.cliente_id
    LEFT JOIN tipos_invitacion t ON t.id=p.tipo_id
    LEFT JOIN (SELECT pedido_id,SUM(monto) pagado FROM pagos GROUP BY pedido_id) x ON x.pedido_id=p.id`;
  const pending = await query(`${select}
    WHERE COALESCE(p.cliente_nombre_snapshot,c.nombre) LIKE ? AND COALESCE(x.pagado,0)<p.precio_final
    ORDER BY p.fecha_evento IS NULL,p.fecha_evento,p.id`,[`%${pendingSearch}%`]);
  const liquidated = await query(`${select}
    WHERE COALESCE(p.cliente_nombre_snapshot,c.nombre) LIKE ? AND COALESCE(x.pagado,0)>=p.precio_final
    ORDER BY p.fecha_evento IS NULL,p.fecha_evento,p.id`,[`%${liquidatedSearch}%`]);
  const rows = items => items.map(order => {
    const paid = Number(order.pagado);
    const late = paid < Number(order.precio_final) && order.fecha_liquidacion && sqlDate(order.fecha_liquidacion) < sqlDate(new Date());
    const state = paid >= Number(order.precio_final) ? 'Liquidado' : late ? 'Pago retrasado' : 'Pendiente';
    return `<tr><td>${esc(order.nombre_evento)}</td><td>${displayDate(order.fecha_evento)}</td><td>${esc(order.cliente_nombre)}</td><td>${esc(order.invitacion_nombre)}</td><td>${money(order.precio_final)}</td><td>${money(paid)}</td><td><span class="status ${paid>=Number(order.precio_final)?'paid':'pending'}">${state}</span></td><td><a class="btn btn-secondary" href="/admin/historial_pagos.php?id=${order.id}">Historial de pagos</a></td></tr>`;
  }).join('') || '<tr><td colspan="8">No se encontraron pedidos.</td></tr>';
  const pendingSearchForm = `<form class="search-form"><label>Buscar cliente:<input name="pendiente" value="${esc(pendingSearch)}" placeholder="Escribe el nombre del cliente"></label>${pendingSearch ? '<a class="btn btn-secondary" href="/admin/pagos.php">Descartar</a>' : '<button class="btn btn-secondary">Buscar</button>'}</form>`;
  const liquidatedSearchForm = `<form class="search-form"><input type="hidden" name="tab" value="liquidated"><label>Buscar cliente:<input name="liquidado" value="${esc(liquidatedSearch)}" placeholder="Escribe el nombre del cliente"></label>${liquidatedSearch ? '<a class="btn btn-secondary" href="/admin/pagos.php?tab=liquidated">Descartar</a>' : '<button class="btn btn-secondary">Buscar</button>'}</form>`;
  const tableHead = '<thead><tr><th>Evento</th><th>Fecha del evento</th><th>Cliente</th><th>Pastel o postre</th><th>Total</th><th>Pagado</th><th>Estado</th><th>Acciones</th></tr></thead>';
  const content = `<div class="page-heading"><p class="eyebrow">COBRANZA</p><h1>Pagos y liquidaciones de pedidos</h1><p>Consulta los pedidos por fecha del evento y abre su historial para registrar pagos.</p></div><section class="orders-workspace card"><div class="order-view-tabs" role="tablist" aria-label="Estado de liquidación"><button type="button" class="order-view-tab active" role="tab" aria-selected="true" data-payment-tab="pending">PENDIENTES DE PAGO <span>${pending.length}</span></button><button type="button" class="order-view-tab" role="tab" aria-selected="false" data-payment-tab="liquidated">PEDIDOS LIQUIDADOS <span>${liquidated.length}</span></button></div><div class="order-tab-panel" data-payment-panel="pending">${pendingSearchForm}<div class="table-scroll"><table class="data-table">${tableHead}<tbody>${rows(pending)}</tbody></table></div></div><div class="order-tab-panel" data-payment-panel="liquidated" hidden>${liquidatedSearchForm}<div class="table-scroll"><table class="data-table">${tableHead}<tbody>${rows(liquidated)}</tbody></table></div></div></section><script>(()=>{const tabs=[...document.querySelectorAll('[data-payment-tab]')],panels=[...document.querySelectorAll('[data-payment-panel]')];const show=key=>{tabs.forEach(tab=>{const active=tab.dataset.paymentTab===key;tab.classList.toggle('active',active);tab.setAttribute('aria-selected',String(active))});panels.forEach(panel=>panel.hidden=panel.dataset.paymentPanel!==key)};tabs.forEach(tab=>tab.addEventListener('click',()=>show(tab.dataset.paymentTab)));const params=new URLSearchParams(location.search);if(params.get('tab')==='liquidated'||params.has('liquidado'))show('liquidated')})();</script>`;
  html(res,layout('Pagos y liquidaciones de pedidos',content,true,await unread()));
}

async function paymentHistoryPage(req, res, url) {
  const id = Number(url.searchParams.get('id'));
  if (!id) return redirect(res,'/admin/pagos.php');
  if (req.method === 'POST') {
    const form = await formBody(req);
    if (form.get('action') === 'add_payment' || form.get('action') === 'update_payment') {
      const amount = Number(form.get('monto'));
      const method = ['Efectivo','Transferencia','Tarjeta'].includes(form.get('metodo')) ? form.get('metodo') : 'Efectivo';
      const paymentDate = mysqlDateTime(form.get('fecha_pago'));
      const paymentId=Number(form.get('payment_id'));
      const conn = await db().getConnection();
      try {
        await conn.beginTransaction();
        const [[order]] = await conn.execute('SELECT id,entregado,precio_final FROM pedidos WHERE id=? FOR UPDATE',[id]);
        if (!order || Number(order.entregado) === 1 || amount <= 0) {
          await conn.rollback();
          return redirect(res,`/admin/historial_pagos.php?id=${id}&error=locked`);
        }
        if(form.get('action')==='update_payment'){
          const [[payment]]=await conn.execute('SELECT id FROM pagos WHERE id=? AND pedido_id=? FOR UPDATE',[paymentId,id]);
          if(!payment){await conn.rollback();return redirect(res,`/admin/historial_pagos.php?id=${id}&error=payment`)}
          const [[otherTotals]]=await conn.execute('SELECT COALESCE(SUM(monto),0) pagado FROM pagos WHERE pedido_id=? AND id<>?',[id,paymentId]);
          if(Number(otherTotals.pagado)+amount>Number(order.precio_final)+0.005){await conn.rollback();return redirect(res,`/admin/historial_pagos.php?id=${id}&error=overpayment`)}
          await conn.execute('UPDATE pagos SET monto=?,metodo=?,fecha_pago=? WHERE id=? AND pedido_id=?',[amount,method,paymentDate,paymentId,id]);
        } else {
          const [[existingTotals]]=await conn.execute('SELECT COALESCE(SUM(monto),0) pagado FROM pagos WHERE pedido_id=?',[id]);
          if(Number(existingTotals.pagado)+amount>Number(order.precio_final)+0.005){await conn.rollback();return redirect(res,`/admin/historial_pagos.php?id=${id}&error=overpayment`)}
          await conn.execute('INSERT INTO pagos(pedido_id,monto,metodo,fecha_pago) VALUES(?,?,?,?)',[id,amount,method,paymentDate]);
        }
        const [[totals]] = await conn.execute('SELECT COALESCE(SUM(monto),0) pagado FROM pagos WHERE pedido_id=?',[id]);
        const [[lastPayment]]=await conn.execute('SELECT MAX(fecha_pago) fecha FROM pagos WHERE pedido_id=?',[id]);
        await conn.execute('UPDATE pedidos SET fecha_liquidado=CASE WHEN ? >= precio_final THEN ? ELSE NULL END WHERE id=?',[Number(totals.pagado),lastPayment.fecha,id]);
        await conn.commit();
        return redirect(res,`/admin/historial_pagos.php?id=${id}&${form.get('action')==='update_payment'?'actualizado':'registrado'}=1`);
      } catch (error) { await conn.rollback(); throw error; } finally { conn.release(); }
    }
  }
  const order = await loadOrder(id);
  if (!order) return redirect(res,'/admin/pagos.php');
  const balance = Math.max(0,Number(order.precio_final)-Number(order.pagado));
  const liquidated = balance <= 0;
  const payments = order.payments.map((payment,index)=>`<tr data-payment-row><td>${order.payments.length-index}</td><td><span data-payment-display>${money(payment.monto)}</span><input form="payment-${payment.id}" type="number" min="0.01" step="0.01" name="monto" value="${Number(payment.monto).toFixed(2)}" disabled hidden required></td><td><span data-payment-display>${esc(payment.metodo)}</span><select form="payment-${payment.id}" name="metodo" disabled hidden>${['Efectivo','Transferencia','Tarjeta'].map(method=>`<option ${method===payment.metodo?'selected':''}>${method}</option>`).join('')}</select></td><td><span data-payment-display>${new Date(payment.fecha_pago).toLocaleString('es-MX',{dateStyle:'long',timeStyle:'short',timeZone:'America/Mexico_City'})}</span><input form="payment-${payment.id}" type="datetime-local" name="fecha_pago" value="${localDateTimeInput(payment.fecha_pago)}" disabled hidden required></td><td>${order.entregado?'Pedido cerrado':`<form id="payment-${payment.id}" method="POST"><input type="hidden" name="action" value="update_payment"><input type="hidden" name="payment_id" value="${payment.id}"><div class="edit-actions"><button type="button" class="btn btn-secondary" data-edit-payment>Editar pago</button><button type="button" class="btn btn-secondary" data-cancel-payment hidden>Cancelar</button></div></form>`}</td></tr>`).join('') || '<tr><td colspan="5">No hay pagos registrados en este pedido.</td></tr>';
  const errorMessages={locked:'El pedido está cerrado y no acepta cambios hasta que se vuelva a abrir.',overpayment:'El monto excede el saldo disponible del pedido.',payment:'No se encontró el pago que intentas modificar.'};
  const notice = url.searchParams.get('registrado') === '1' ? '<p class="success-banner">Pago registrado correctamente.</p>' : url.searchParams.get('actualizado')==='1'?'<p class="success-banner">Pago actualizado correctamente.</p>':url.searchParams.get('error')?`<p class="error-banner">${esc(errorMessages[url.searchParams.get('error')]||'No fue posible procesar el pago.')}</p>`:'';
  const register = !order.entregado && !liquidated ? `<button type="button" class="btn btn-primary" data-reveal="registrar-pago-pedido">Registrar pago</button>` : '';
  const form = !order.entregado && !liquidated ? `<section id="registrar-pago-pedido" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registrar pago</h2><button type="button" class="btn btn-secondary" data-close-history-payment>Cerrar</button></div><form method="POST" class="payment-registration-form"><input type="hidden" name="action" value="add_payment"><label>Cliente<input value="${esc(order.cliente_nombre)}" readonly></label><label>Evento<input value="${esc(order.nombre_evento)}" readonly></label><label>Monto<input type="number" min="0.01" max="${balance.toFixed(2)}" step="0.01" name="monto" required></label><label>Método de pago<select name="metodo"><option>Efectivo</option><option>Transferencia</option><option>Tarjeta</option></select></label><label>Fecha y hora del pago<input id="fecha_pago_historial" type="datetime-local" name="fecha_pago" required></label><button class="btn btn-primary">Guardar pago</button></form></section>` : '';
  const content = `<div class="page-heading split"><div><p class="eyebrow">HISTORIAL DE PAGOS · PEDIDO #${order.id}</p><h1>${esc(order.cliente_nombre)}</h1><p>${esc(order.nombre_evento)} · ${displayDate(order.fecha_evento)}</p></div><div class="button-group"><a class="btn btn-secondary" href="/admin/pagos.php">Volver a pagos</a>${register}</div></div>${notice}<section class="card summary-card payment-summary-card"><h2>Resumen de liquidación</h2><dl><div><dt>Cliente</dt><dd>${esc(order.cliente_nombre)}</dd></div><div><dt>Evento</dt><dd>${esc(order.nombre_evento)}</dd></div><div><dt>Fecha del evento</dt><dd>${displayDate(order.fecha_evento)}</dd></div><div><dt>Pastel o postre</dt><dd>${esc(order.invitacion_nombre)}</dd></div><div><dt>Fecha programada de liquidación</dt><dd>${displayDate(order.fecha_liquidacion)}</dd></div><div><dt>Estado</dt><dd><span class="status ${liquidated?'paid':'pending'}">${liquidated?'Pedido liquidado':order.entregado?'Pedido cerrado con saldo':'Pendiente de pago'}</span></dd></div></dl><div class="totals"><span>Total <b>${money(order.precio_final)}</b></span><span>Pagado <b>${money(order.pagado)}</b></span><span>Saldo <b>${money(balance)}</b></span></div></section>${form}<section class="card"><h2>Desglose completo de pagos</h2><div class="table-scroll"><table class="data-table"><thead><tr><th>Pago</th><th>Monto</th><th>Método</th><th>Fecha y hora</th></tr></thead><tbody>${payments}</tbody></table></div></section><script>(()=>{const open=document.querySelector('[data-reveal="registrar-pago-pedido"]'),panel=document.getElementById('registrar-pago-pedido'),close=document.querySelector('[data-close-history-payment]'),date=document.getElementById('fecha_pago_historial');open?.addEventListener('click',()=>{panel.hidden=false;const now=new Date(Date.now()-new Date().getTimezoneOffset()*60000);date.value=now.toISOString().slice(0,16);panel.scrollIntoView({behavior:'smooth',block:'start'})});close?.addEventListener('click',()=>{panel.hidden=true;open.focus()})})();</script>`;
  const historyContent = content
    .replace('<a class="btn btn-secondary" href="/admin/pagos.php">Volver a pagos</a>',`<a class="btn btn-secondary" href="/admin/pagos.php">Volver a pagos</a><a class="btn btn-secondary" href="/admin/ver_pedido.php?id=${id}">Ver pedido</a>`)
    .replace('<th>Fecha y hora</th></tr>','<th>Fecha y hora</th><th>Acción</th></tr>')
    .replace("close?.addEventListener('click',()=>{panel.hidden=true;open.focus()})})();</script>","close?.addEventListener('click',()=>{panel.hidden=true;open.focus()});if(new URLSearchParams(location.search).get('registrar')==='1')open?.click()})();</script>");
  const editPaymentScript=`<script>(()=>{document.querySelectorAll('[data-edit-payment]').forEach(button=>button.addEventListener('click',()=>{const row=button.closest('[data-payment-row]'),fields=[...row.querySelectorAll('[form^="payment-"]')].filter(field=>!field.matches('form'));row.querySelectorAll('[data-payment-display]').forEach(item=>item.hidden=true);fields.forEach(field=>{field.hidden=false;field.disabled=false});button.textContent='Guardar cambios';button.classList.replace('btn-secondary','btn-primary');const cancel=row.querySelector('[data-cancel-payment]');cancel.hidden=false;cancel.onclick=()=>location.reload();button.onclick=()=>button.form.requestSubmit()}))})();</script>`;
  html(res,layout(`Historial de pagos #${id}`,historyContent+editPaymentScript,true,await unread()));
}

async function loadOrder(id) {
  const order = await one(`SELECT p.*,
    COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,
    COALESCE(p.cliente_email_snapshot,c.email) email,
    COALESCE(p.cliente_telefono_snapshot,c.telefono) telefono,
    COALESCE(p.invitacion_nombre_snapshot,t.nombre) invitacion_nombre,
    COALESCE(p.invitacion_descripcion_snapshot,t.caracteristicas) caracteristicas,
    COALESCE((SELECT SUM(monto) FROM pagos WHERE pedido_id=p.id),0) pagado
    FROM pedidos p LEFT JOIN clientes c ON c.id=p.cliente_id LEFT JOIN tipos_invitacion t ON t.id=p.tipo_id WHERE p.id=?`,[id]);
  if (!order) return null;
  order.services = await query(`SELECT ps.servicio_id id,COALESCE(ps.servicio_nombre_snapshot,s.nombre) nombre,COALESCE(ps.servicio_precio_snapshot,s.precio) precio,COALESCE(ps.servicio_descripcion_snapshot,s.descripcion) descripcion
    FROM pedido_servicios ps LEFT JOIN servicios_adicionales s ON s.id=ps.servicio_id
    WHERE ps.pedido_id=? ORDER BY COALESCE(ps.servicio_nombre_snapshot,s.nombre)`,[id]);
  order.payments = await query('SELECT * FROM pagos WHERE pedido_id=? ORDER BY fecha_pago DESC',[id]);
  return order;
}

async function orderDetail(req, res, url) {
  const id = Number(url.searchParams.get('id'));
  if (!id) return redirect(res,'/admin/pedidos.php');
  if (req.method === 'POST') {
    const form = await formBody(req);
    const action = form.get('action');
    if (action === 'save_order') {
      const conn = await db().getConnection();
      try {
        await conn.beginTransaction();
        const [[currentOrder]] = await conn.execute('SELECT entregado FROM pedidos WHERE id=? FOR UPDATE',[id]);
        if (!currentOrder || Number(currentOrder.entregado) === 1) {
          await conn.rollback();
          return redirect(res,`/admin/ver_pedido.php?id=${id}&error=closed`);
        }
        const clientId = Number(form.get('cliente_id'));
        const invitationId = Number(form.get('tipo_id'));
        const courtesy = form.get('cortesia') === '1';
        const discountId = Number(form.get('descuento_id')) || null;
        const [[client]] = await conn.execute('SELECT nombre,email,telefono FROM clientes WHERE id=?',[clientId]);
        const [[invitation]] = await conn.execute('SELECT nombre,precio_base,caracteristicas FROM tipos_invitacion WHERE id=?',[invitationId]);
        const [[discount]] = discountId ? await conn.execute('SELECT id,nombre,tipo,valor FROM descuentos WHERE id=? AND activo=1',[discountId]) : [[null]];
        if (!client || !invitation) throw new Error('Cliente o invitación inválidos');
        if(discountId&&!discount)throw new Error('Descuento inválido');
        const chosenServices=[];
        for (const serviceId of form.getAll('servicios')) {
          const [[service]] = await conn.execute('SELECT nombre,precio,descripcion FROM servicios_adicionales WHERE id=?',[Number(serviceId)]);
          if (!service) throw new Error('Servicio adicional inválido');
          chosenServices.push({id:Number(serviceId),...service});
        }
        const discountAmount=discountAmountForPackage(discount,invitation.precio_base);
        const calculatedPrice=Math.max(0,Number(invitation.precio_base)-discountAmount+chosenServices.reduce((sum,item)=>sum+Number(item.precio),0));
        const finalPrice=courtesy?0:calculatedPrice;
        await conn.execute(`UPDATE pedidos SET
          cliente_id=?,tipo_id=?,nombre_evento=?,fecha_evento=?,fecha_entrega=?,fecha_liquidacion=?,hora_evento=?,precio_final=?,
          cliente_nombre_snapshot=?,cliente_email_snapshot=?,cliente_telefono_snapshot=?,
          invitacion_nombre_snapshot=?,invitacion_descripcion_snapshot=?,invitacion_precio_snapshot=?,notas=?,cortesia=?,
          descuento_id=?,descuento_nombre_snapshot=?,descuento_tipo_snapshot=?,descuento_valor_snapshot=?,descuento_monto_snapshot=?
          WHERE id=? AND entregado=0`,[
          clientId,invitationId,form.get('nombre_evento'),form.get('fecha_evento')||null,form.get('fecha_entrega')||null,
          form.get('fecha_liquidacion')||shiftDate(form.get('fecha_evento'),1)||null,
          form.get('hora_evento')||null,finalPrice,client.nombre,client.email,client.telefono,
          invitation.nombre,invitation.caracteristicas,invitation.precio_base,String(form.get('notas')||'').trim()||null,courtesy?1:0,
          discount?.id||null,discount?.nombre||null,discount?.tipo||null,discount?.valor||null,discountAmount,id
        ]);
        await conn.execute('DELETE FROM pedido_servicios WHERE pedido_id=?',[id]);
        for (const service of chosenServices) {
          await conn.execute('INSERT INTO pedido_servicios(pedido_id,servicio_id,servicio_nombre_snapshot,servicio_precio_snapshot,servicio_descripcion_snapshot) VALUES(?,?,?,?,?)',[id,service.id,service.nombre,service.precio,service.descripcion]);
        }
        await conn.execute(`UPDATE pedidos p
          LEFT JOIN (SELECT pedido_id,SUM(monto) pagado,MAX(fecha_pago) ultimo_pago FROM pagos WHERE pedido_id=? GROUP BY pedido_id) x ON x.pedido_id=p.id
          SET p.fecha_liquidado=CASE WHEN COALESCE(x.pagado,0)>=p.precio_final THEN COALESCE(p.fecha_liquidado,x.ultimo_pago,NOW()) ELSE NULL END
          WHERE p.id=?`,[id,id]);
        await conn.commit();
      } catch(error) { await conn.rollback(); throw error; } finally { conn.release(); }
    } else if (action === 'complete_form' || action === 'complete_invitation') {
      const conn = await db().getConnection();
      try {
        await conn.beginTransaction();
        const [[currentOrder]] = await conn.execute('SELECT entregado,formulario_completado,invitacion_entregada FROM pedidos WHERE id=? FOR UPDATE',[id]);
        if (!currentOrder || Number(currentOrder.entregado) === 1) {
          await conn.rollback();
          return redirect(res,`/admin/ver_pedido.php?id=${id}&error=closed`);
        }
        if (action === 'complete_form') {
          await conn.execute('UPDATE pedidos SET formulario_completado=1,fecha_formulario_completado=COALESCE(fecha_formulario_completado,NOW()) WHERE id=?',[id]);
        } else {
          if (!Number(currentOrder.formulario_completado)) {
            await conn.rollback();
            return redirect(res,`/admin/ver_pedido.php?id=${id}&error=form_required`);
          }
          await conn.execute('UPDATE pedidos SET invitacion_entregada=1,fecha_invitacion_entregada=COALESCE(fecha_invitacion_entregada,NOW()) WHERE id=?',[id]);
        }
        await conn.commit();
      } catch(error) { await conn.rollback(); throw error; } finally { conn.release(); }
    } else if (action === 'toggle_delivery') {
      await query('UPDATE pedidos SET entregado=?,fecha_entrega_real=? WHERE id=?',[form.get('entregado')==='1'?1:0,form.get('entregado')==='1'?new Date():null,id]);
    }
    return redirect(res,`/admin/ver_pedido.php?id=${id}`);
  }
  const order = await loadOrder(id);
  if (!order) return html(res,layout('Pedido no encontrado','<div class="card"><h1>Pedido no encontrado</h1></div>',true),404);
  const clients = await query('SELECT id,nombre FROM clientes ORDER BY nombre');
  const invitations = await query('SELECT id,nombre,precio_base FROM tipos_invitacion ORDER BY nombre');
  const allExtras = await query('SELECT id,nombre,precio,descripcion FROM servicios_adicionales ORDER BY nombre');
  const allDiscounts = await query('SELECT id,nombre,tipo,valor FROM descuentos WHERE activo=1 OR id=? ORDER BY activo DESC,nombre',[Number(order.descuento_id)||0]);
  const selected = new Set(order.services.map(x=>Number(x.id)));
  const clientOptions = clients.map(c=>`<option value="${c.id}" ${Number(c.id)===Number(order.cliente_id)?'selected':''}>${esc(c.nombre)}</option>`).join('');
  const invitationOptions = invitations.map(i=>`<option value="${i.id}" data-price="${Number(i.precio_base)}" ${Number(i.id)===Number(order.tipo_id)?'selected':''}>${esc(i.nombre)}</option>`).join('');
  const extras = allExtras.map(x=>`<label class="check-option"><input type="checkbox" name="servicios" value="${x.id}" data-extra-price="${Number(x.precio)}" ${selected.has(Number(x.id))?'checked':''}><span>${esc(x.nombre)} <small>${money(x.precio)}${x.descripcion?` · ${esc(x.descripcion)}`:''}</small></span></label>`).join('');
  const discountOptions=allDiscounts.map(x=>`<option value="${x.id}" data-discount-type="${x.tipo}" data-discount-value="${Number(x.valor)}" ${Number(x.id)===Number(order.descuento_id)?'selected':''}>${esc(x.nombre)} - ${x.tipo==='porcentaje'?`${Number(x.valor)}%`:money(x.valor)}</option>`).join('');
  const paymentRows = order.payments.map(p=>`<div class="payment-row payment-row-readonly"><strong>${money(p.monto)}</strong><span>${esc(p.metodo)}</span><time>${new Date(p.fecha_pago).toLocaleString('es-MX',{dateStyle:'medium',timeStyle:'short',timeZone:'America/Mexico_City'})}</time></div>`).join('') || '<p>No hay pagos registrados.</p>';
  const balance = Math.max(0,Number(order.precio_final)-Number(order.pagado));
  const workflowStatus = `<div class="workflow-status-grid"><article class="workflow-status ${order.formulario_completado?'is-complete':'is-pending'}"><div class="workflow-status-heading"><span class="workflow-status-icon">${order.formulario_completado?'✓':'1'}</span><span><small>PASO 1</small><b>Formulario</b></span></div><strong>${order.formulario_completado?'Completado':'Pendiente'}</strong>${!order.entregado&&!order.formulario_completado?'<form method="POST"><input type="hidden" name="action" value="complete_form"><button class="btn btn-secondary">Completar formulario</button></form>':''}</article><article class="workflow-status ${order.invitacion_entregada?'is-complete':order.formulario_completado?'is-pending':'is-waiting'}"><div class="workflow-status-heading"><span class="workflow-status-icon">${order.invitacion_entregada?'✓':'2'}</span><span><small>PASO 2</small><b>Pastel o postre entregada</b></span></div><strong>${order.invitacion_entregada?'Completada':order.formulario_completado?'Pendiente':'En espera'}</strong>${!order.entregado&&order.formulario_completado&&!order.invitacion_entregada?'<form method="POST"><input type="hidden" name="action" value="complete_invitation"><button class="btn btn-secondary">Completar entrega</button></form>':''}</article><article class="workflow-status ${balance<=0?'is-complete':order.invitacion_entregada?'is-pending':'is-waiting'}"><div class="workflow-status-heading"><span class="workflow-status-icon">${balance<=0?'✓':'3'}</span><span><small>PASO 3</small><b>Liquidación</b></span></div><strong>${balance<=0?'Pedido liquidado':order.invitacion_entregada?'Pendiente de pago':'En espera'}</strong><a class="btn btn-secondary" href="/admin/historial_pagos.php?id=${id}">Historial de pagos</a></article></div>`;
  const paymentActions = `<div class="workflow-payment-actions"><a class="btn btn-secondary" href="/admin/historial_pagos.php?id=${id}">Historial de pagos</a>${!order.entregado&&balance>0?`<a class="btn btn-primary" href="/admin/historial_pagos.php?id=${id}&registrar=1">Registrar pago</a>`:''}</div>`;
  const compactWorkflowStatus = workflowStatus.replace(`<a class="btn btn-secondary" href="/admin/historial_pagos.php?id=${id}">Historial de pagos</a>`,paymentActions);
  const content = `<div class="page-heading split"><div><p class="eyebrow">PEDIDO #${order.id}</p><h1>${esc(order.nombre_evento || 'Evento')}</h1><p>${esc(order.cliente_nombre)} · ${esc(order.invitacion_nombre)}</p></div><div class="button-group"><a class="btn btn-secondary" href="/admin/pedido_pdf.php?id=${id}">Descargar pedido PDF</a><a class="btn btn-secondary" href="/admin/pagos_pdf.php?id=${id}">Descargar pagos PDF</a></div></div><div class="detail-grid single"><section class="card summary-card"><h2>Información completa</h2><dl><div><dt>Cliente</dt><dd>${esc(order.cliente_nombre)}</dd></div><div><dt>Correo</dt><dd>${esc(order.email)}</dd></div><div><dt>Teléfono</dt><dd>${esc(order.telefono)}</dd></div><div><dt>Evento</dt><dd>${esc(order.nombre_evento)}</dd></div><div><dt>Pastel o postre</dt><dd>${esc(order.invitacion_nombre)}</dd></div><div><dt>Descripción</dt><dd>${esc(order.caracteristicas) || 'Sin descripción'}</dd></div><div><dt>Fecha del evento</dt><dd>${displayDate(order.fecha_evento)}</dd></div><div><dt>Fecha de entrega</dt><dd>${displayDate(order.fecha_entrega)}</dd></div><div><dt>Servicios adicionales</dt><dd>${order.services.map(x=>esc(x.nombre)).join(', ') || 'Ninguno'}</dd></div></dl><div class="totals"><span>Total <b>${money(order.precio_final)}</b></span><span>Pagado <b>${money(order.pagado)}</b></span><span>Saldo <b>${money(balance)}</b></span></div><div class="summary-actions"><form method="POST"><input type="hidden" name="action" value="toggle_delivery"><input type="hidden" name="entregado" value="${order.entregado?0:1}"><button class="btn ${order.entregado?'btn-secondary':'btn-primary'}">${order.entregado?'Reabrir pedido':'Cerrar pedido'}</button></form><button type="button" class="btn btn-secondary" data-reveal="editar-pedido">Editar pedido</button></div></section></div><section id="editar-pedido" class="card reveal-panel" hidden><h2>Editar pedido</h2><form method="POST" class="order-form compact"><input type="hidden" name="action" value="save_order"><label>Cliente<select name="cliente_id">${clientOptions}</select></label><label>Evento<input name="nombre_evento" value="${esc(order.nombre_evento)}" required></label><label>Fecha del evento<input type="date" name="fecha_evento" value="${sqlDate(order.fecha_evento)}"></label><label>Hora<input type="time" name="hora_evento" value="${String(order.hora_evento||'').slice(0,5)}"></label><label>Fecha de entrega<input type="date" name="fecha_entrega" value="${sqlDate(order.fecha_entrega)}"></label><label>Pastel o postre<select name="tipo_id">${invitationOptions}</select></label><fieldset class="wide"><legend>Servicios adicionales</legend><div class="check-grid">${extras}</div></fieldset><label>Costo total<input type="number" min="0" step="0.01" name="precio_final" value="${Number(order.precio_final).toFixed(2)}"></label><button class="btn btn-primary">Guardar pedido</button></form></section><section class="card"><h2>Historial de pagos</h2>${order.payments.length?'<div class="payment-head payment-head-readonly"><span>Monto</span><span>Método</span><span>Fecha y hora</span></div>':''}<div class="payment-list">${paymentRows}</div></section><script>(()=>{const button=document.querySelector('[data-reveal="editar-pedido"]'),panel=document.getElementById('editar-pedido');button?.addEventListener('click',()=>{panel.hidden=!panel.hidden;button.textContent=panel.hidden?'Editar pedido':'Ocultar edición';button.setAttribute('aria-expanded',String(!panel.hidden));if(!panel.hidden){panel.scrollIntoView({behavior:'smooth',block:'start'});panel.querySelector('select')?.focus()}})})();</script>`;
  const workflowContent = content
    .replace('<div class="button-group"><a class="btn btn-secondary" href="/admin/pedido_pdf.php',`<div class="button-group"><a class="btn btn-secondary" href="/admin/pedidos.php">Regresar</a><a class="btn btn-secondary" href="/admin/pedido_pdf.php`)
    .replace('>Descargar pedido PDF</a>','>Descargar Pedido</a>')
    .replace('>Descargar pagos PDF</a>','>Descargar desglose de pagos</a>')
    .replace('<div><dt>Servicios adicionales</dt>',`<div><dt>Fecha programada de liquidación</dt><dd>${displayDate(order.fecha_liquidacion)}</dd></div><div><dt>Servicios adicionales</dt>`)
    .replace('<div><dt>Descripción</dt><dd>',`<div><dt>Descripción</dt><dd class="order-description">`)
    .replace('</dd></div></dl><div class="totals">',`</dd></div><div><dt>Descuento del paquete</dt><dd>${order.descuento_nombre_snapshot?`${esc(order.descuento_nombre_snapshot)} (-${money(order.descuento_monto_snapshot)})`:'Sin descuento'}</dd></div><div><dt>Notas</dt><dd class="order-notes">${esc(order.notas)||'Sin notas registradas.'}</dd></div></dl><div class="totals">`)
    .replace('<div class="totals">',`${compactWorkflowStatus}<div class="totals">`)
    .replace('<label>Pastel o postre<select name="tipo_id">',`<label>Fecha de liquidación<input type="date" name="fecha_liquidacion" value="${sqlDate(order.fecha_liquidacion)}" required></label><label>Pastel o postre<select name="tipo_id" id="edit_tipo_id">`)
    .replace('</select></label><fieldset class="wide"><legend>Servicios adicionales</legend>',`</select></label><label>Descuento del paquete<select name="descuento_id" id="edit_descuento_id"><option value="">Sin descuento</option>${discountOptions}</select></label><fieldset class="wide"><legend>Servicios adicionales</legend>`)
    .replace('<label>Costo total<input type="number"',`<label class="wide">Notas del pedido<textarea name="notas" rows="4">${esc(order.notas||'')}</textarea></label><label>Costo total<input type="number" readonly`)
    .replace('</label><button class="btn btn-primary">Guardar pedido</button>',`</label><label class="courtesy-option"><input id="edit_cortesia" type="checkbox" name="cortesia" value="1" ${Number(order.cortesia)===1?'checked':''}><span><b>Cortesía</b><small>El pedido se registrará sin costo.</small></span></label><button class="btn btn-primary">Guardar pedido</button>`)
    .replace('<div><dt>Descuento del paquete</dt>',`<div><dt>Tipo de pedido</dt><dd>${Number(order.cortesia)===1?'Pastel o postre de cortesía':'Pedido con costo'}</dd></div><div><dt>Descuento del paquete</dt>`);
  const closedContent = order.entregado
    ? workflowContent
        .replace('<button type="button" class="btn btn-secondary" data-reveal="editar-pedido">Editar pedido</button>','')
        .replace(/<section id="editar-pedido"[\s\S]*?<\/section>(?=<section class="card"><h2>Historial de pagos<\/h2>)/,'')
    : workflowContent;
  const errorNotice = url.searchParams.get('error') === 'closed'
    ? '<p class="error-banner">El pedido está cerrado. Debes reabrirlo antes de modificarlo.</p>'
    : url.searchParams.get('error') === 'form_required' ? '<p class="error-banner">Primero debes completar el formulario.</p>' : '';
  const taskNotice = url.searchParams.get('task') === 'form' && !order.formulario_completado
    ? '<p class="task-banner">Tarea pendiente: revisa los datos del cliente y completa el formulario.</p>'
    : url.searchParams.get('task') === 'delivery' && !order.invitacion_entregada ? '<p class="task-banner">Tarea pendiente: revisa los datos del cliente y completa la entrega de la invitación.</p>' : '';
  const lockNotice = `${errorNotice}${taskNotice}${order.entregado ? '<p class="success-banner">Pedido cerrado: la información y los pagos están protegidos contra modificaciones.</p>' : ''}`;
  const contentWithEventTime = closedContent
    .replace('<div class="detail-grid single">',`${lockNotice}<div class="detail-grid single">`)
    .replace('<div><dt>Fecha de entrega</dt>',`<div><dt>Hora del evento</dt><dd>${displayTime(order.hora_evento)}</dd></div><div><dt>Fecha de entrega</dt>`);
  const editPricingScript=order.entregado?'':`<script>(()=>{const type=document.getElementById('edit_tipo_id'),discount=document.getElementById('edit_descuento_id'),courtesy=document.getElementById('edit_cortesia'),total=document.querySelector('#editar-pedido [name="precio_final"]'),extras=[...document.querySelectorAll('#editar-pedido [data-extra-price]')];const calc=()=>{const base=Number(type?.selectedOptions[0]?.dataset.price||0),option=discount?.selectedOptions[0],value=Number(option?.dataset.discountValue||0),reduction=option?.dataset.discountType==='porcentaje'?base*Math.min(value,100)/100:Math.min(value,base);total.value=courtesy?.checked?'0.00':(Math.max(0,base-reduction)+extras.filter(x=>x.checked).reduce((sum,x)=>sum+Number(x.dataset.extraPrice),0)).toFixed(2)};const sync=()=>{discount.disabled=courtesy.checked;extras.forEach(item=>item.disabled=courtesy.checked);calc()};type?.addEventListener('change',calc);discount?.addEventListener('change',calc);courtesy?.addEventListener('change',sync);extras.forEach(x=>x.addEventListener('change',calc));sync()})();</script>`;
  html(res,layout(`Pedido #${id}`,contentWithEventTime+editPricingScript,true,await unread()));
}

async function notificationsPage(req, res) {
  await syncReminders();
  if (req.method === 'POST') {
    const form = await formBody(req);
    if (form.get('action') === 'read_all') await query("UPDATE notificaciones SET leida=1,fecha_leida=NOW() WHERE leida=0 AND tipo IN ('entrega','pago','pago_retrasado')");
    return redirect(res,'/admin/notificaciones.php');
  }
  const rows = await query("SELECT n.*,COALESCE(p.cliente_nombre_snapshot,c.nombre) cliente_nombre,p.nombre_evento FROM notificaciones n LEFT JOIN pedidos p ON p.id=n.pedido_id LEFT JOIN clientes c ON c.id=p.cliente_id WHERE n.tipo IN ('entrega','pago','pago_retrasado') ORDER BY n.fecha_creacion DESC");
  const cards = rows.map(n=>`<a class="notification-card ${n.leida?'read':'unread'}" href="${esc(n.link||'#')}"><span class="notification-icon ${n.tipo}">${n.tipo==='entrega'?'E':'$'}</span><div><b>${esc(n.mensaje)}</b><small>${new Date(n.fecha_creacion).toLocaleString('es-MX')}</small></div><em>${n.leida?'Leída':'Nueva'}</em></a>`).join('') || '<p class="empty-state">No hay recordatorios pendientes.</p>';
  const content = `<div class="page-heading split"><div><p class="eyebrow">RECORDATORIOS</p><h1>Notificaciones</h1><p>Entregas próximas y pagos pendientes.</p></div><form method="POST"><input type="hidden" name="action" value="read_all"><button class="btn btn-secondary">Marcar todas como leídas</button></form></div><div class="notification-list">${cards}</div>`;
  html(res,layout('Notificaciones',content,true,await unread()));
}

const monthKey=value=>String(value||'').match(/^\d{4}-(0[1-9]|1[0-2])$/)?.[0]||new Date().toISOString().slice(0,7);
const yearKey=value=>String(value||'').match(/^\d{4}$/)?.[0]||String(new Date().getFullYear());
function monthsInclusive(start,end) {
  const a=new Date(`${start}T12:00:00`),b=new Date(`${end}T12:00:00`);
  return Math.max(0,(b.getFullYear()-a.getFullYear())*12+b.getMonth()-a.getMonth()+1);
}
function expenseAmountForPeriod(expense,start,end) {
  const expenseStart=sqlDate(expense.fecha_inicio),expenseEnd=expense.fecha_fin?sqlDate(expense.fecha_fin):'9999-12-31';
  if(expenseStart>end||expenseEnd<start)return 0;
  if(expense.frecuencia==='unica')return expenseStart>=start&&expenseStart<=end?Number(expense.monto):0;
  if(expense.frecuencia==='anual'){
    const first=new Date(`${expenseStart}T12:00:00`),periodStart=new Date(`${start}T12:00:00`),periodEnd=new Date(`${end}T12:00:00`);
    let occurrences=0;
    for(let year=periodStart.getFullYear();year<=periodEnd.getFullYear();year++){
      const key=new Date(year,first.getMonth(),first.getDate(),12).toISOString().slice(0,10);
      if(key>=expenseStart&&key<=expenseEnd&&key>=start&&key<=end)occurrences++;
    }
    return Number(expense.monto)*occurrences;
  }
  const overlapStart=expenseStart>start?expenseStart:start,overlapEnd=expenseEnd<end?expenseEnd:end;
  return Number(expense.monto)*monthsInclusive(overlapStart,overlapEnd);
}
async function financialData(year,month=null) {
  const start=month?`${month}-01`:`${year}-01-01`;
  const endDate=month?new Date(`${month}-01T12:00:00`):new Date(`${year}-12-01T12:00:00`);
  if(month)endDate.setMonth(endDate.getMonth()+1,0); else endDate.setMonth(12,0);
  const end=endDate.toISOString().slice(0,10);
  const incomes=await query(`SELECT DATE_FORMAT(fecha_pago,'%Y-%m') periodo,SUM(monto) total FROM pagos WHERE DATE(fecha_pago) BETWEEN ? AND ? GROUP BY DATE_FORMAT(fecha_pago,'%Y-%m') ORDER BY periodo`,[start,end]);
  const expenses=await query('SELECT * FROM gastos WHERE fecha_inicio<=? AND (fecha_fin IS NULL OR fecha_fin>=?) ORDER BY fecha_inicio,concepto',[end,start]);
  const paymentDetails=month?await query(`SELECT pa.id,pa.fecha_pago,pa.monto,pa.metodo,p.id pedido_id,p.nombre_evento,
    COALESCE(p.cliente_nombre_snapshot,c.nombre,'Cliente sin nombre') cliente_nombre
    FROM pagos pa JOIN pedidos p ON p.id=pa.pedido_id LEFT JOIN clientes c ON c.id=p.cliente_id
    WHERE DATE(pa.fecha_pago) BETWEEN ? AND ? ORDER BY pa.fecha_pago,pa.id`,[start,end]):[];
  const incomeMap=new Map(incomes.map(row=>[row.periodo,Number(row.total)]));
  const months=month?[month]:Array.from({length:12},(_,index)=>`${year}-${String(index+1).padStart(2,'0')}`);
  const rows=months.map(key=>{
    const monthStart=`${key}-01`,date=new Date(`${key}-01T12:00:00`);date.setMonth(date.getMonth()+1,0);
    const monthEnd=date.toISOString().slice(0,10),income=incomeMap.get(key)||0;
    const expense=expenses.reduce((sum,item)=>sum+expenseAmountForPeriod(item,monthStart,monthEnd),0);
    return {key,label:new Date(`${key}-15T12:00:00`).toLocaleDateString('es-MX',{month:'long',year:'numeric'}),income,expense,net:income-expense};
  });
  const expenseDetails=month?expenses.map(expense=>({...expense,importe_periodo:expenseAmountForPeriod(expense,start,end)})).filter(expense=>expense.importe_periodo>0):[];
  return {year,month,start,end,rows,expenses,paymentDetails,expenseDetails,totalIncome:rows.reduce((s,r)=>s+r.income,0),totalExpense:rows.reduce((s,r)=>s+r.expense,0),get net(){return this.totalIncome-this.totalExpense}};
}

async function financesPage(req,res,url,current) {
  let error='',success='';
  if(req.method==='POST'){
    const form=await formBody(req),action=form.get('action');
    if(action==='create_expense'){
      const concept=String(form.get('concepto')||'').trim(),amount=Number(form.get('monto')),frequency=['mensual','anual'].includes(form.get('frecuencia'))?form.get('frecuencia'):'unica';
      const start=String(form.get('fecha_inicio')||''),end=frequency!=='unica'&&form.get('fecha_fin')?String(form.get('fecha_fin')):null;
      if(!concept||!start||!(amount>0))error='Completa el concepto, monto y fecha del gasto.';
      else if(end&&end<start)error='La fecha final no puede ser anterior a la fecha inicial.';
      else { await query('INSERT INTO gastos(concepto,monto,frecuencia,fecha_inicio,fecha_fin,activo,creado_por) VALUES(?,?,?,?,?,1,?)',[concept,amount,frequency,start,end,current.user]); success='Gasto registrado correctamente.'; }
    } else if(action==='toggle_expense'){
      const id=Number(form.get('id')),expense=await one('SELECT activo,frecuencia FROM gastos WHERE id=?',[id]);
      if(expense){
        if(Number(expense.activo))await query("UPDATE gastos SET activo=0,fecha_fin=IF(frecuencia IN ('mensual','anual'),COALESCE(fecha_fin,CURDATE()),fecha_fin) WHERE id=?",[id]);
        else await query("UPDATE gastos SET activo=1,fecha_fin=IF(frecuencia IN ('mensual','anual'),NULL,fecha_fin) WHERE id=?",[id]);
        success='Estado del gasto actualizado.';
      }
    } else if(action==='delete_expense'){
      await query('DELETE FROM gastos WHERE id=?',[Number(form.get('id'))]); success='Gasto eliminado.';
    }
  }
  const month=monthKey(url.searchParams.get('mes')),year=yearKey(url.searchParams.get('anio')||month.slice(0,4));
  const monthly=await financialData(month.slice(0,4),month),annual=await financialData(year);
  const allExpenses=await query('SELECT * FROM gastos ORDER BY activo DESC,fecha_inicio DESC,id DESC');
  const monthOptions=Array.from({length:24},(_,index)=>{const date=new Date();date.setMonth(date.getMonth()-index);const key=date.toISOString().slice(0,7),label=date.toLocaleDateString('es-MX',{month:'long',year:'numeric'});return `<option value="${key}" ${key===month?'selected':''}>${esc(label)}</option>`}).join('');
  const yearOptions=Array.from({length:8},(_,index)=>String(new Date().getFullYear()-index)).map(value=>`<option value="${value}" ${value===year?'selected':''}>${value}</option>`).join('');
  const annualRows=annual.rows.map(row=>`<tr><td class="capitalize">${esc(row.label)}</td><td>${money(row.income)}</td><td>${money(row.expense)}</td><td class="financial-result ${row.net>=0?'positive':'negative'}">${money(row.net)}</td></tr>`).join('');
  const expenseRows=allExpenses.map(expense=>`<tr><td>${esc(expense.concepto)}</td><td>${money(expense.monto)}</td><td>${expense.frecuencia==='mensual'?'Mensualidad':expense.frecuencia==='anual'?'Anualmente':'Una ocasión'}</td><td>${displayDate(expense.fecha_inicio)}</td><td>${expense.fecha_fin?displayDate(expense.fecha_fin):'Sin fecha final'}</td><td><span class="status ${Number(expense.activo)?'paid':'pending'}">${Number(expense.activo)?'Activo':'Inactivo'}</span></td><td><div class="admin-row-actions"><form method="POST"><input type="hidden" name="action" value="toggle_expense"><input type="hidden" name="id" value="${expense.id}"><button class="btn btn-secondary">${Number(expense.activo)?'Desactivar':'Activar'}</button></form><form method="POST" onsubmit="return confirm('¿Eliminar este gasto?')"><input type="hidden" name="action" value="delete_expense"><input type="hidden" name="id" value="${expense.id}"><button class="btn btn-danger">Eliminar</button></form></div></td></tr>`).join('');
  const summary=(data,label)=>`<section class="finance-summary"><article><small>INGRESOS ${label}</small><strong>${money(data.totalIncome)}</strong></article><article><small>GASTOS ${label}</small><strong>${money(data.totalExpense)}</strong></article><article class="${data.net>=0?'positive':'negative'}"><small>${data.net>=0?'GANANCIA':'PÉRDIDA'} ${label}</small><strong>${money(data.net)}</strong></article></section>`;
  const content=`<div class="page-heading split"><div><p class="eyebrow">CONTROL FINANCIERO</p><h1>Finanzas</h1><p>Consulta ingresos recibidos, gastos y el resultado del negocio.</p></div><button type="button" class="btn btn-primary" data-reveal="nuevo-gasto">Registrar gasto</button></div>${error?`<p class="error-banner">${esc(error)}</p>`:''}${success?`<p class="success-banner">${esc(success)}</p>`:''}<section id="nuevo-gasto" class="card reveal-panel" hidden><div class="reveal-panel-heading"><h2>Registro de gasto</h2><button type="button" class="btn btn-secondary" data-close-expense>Cerrar</button></div><form method="POST" class="form-grid"><input type="hidden" name="action" value="create_expense"><label>Concepto<input name="concepto" required></label><label>Monto<input type="number" min="0.01" step="0.01" name="monto" required></label><label>Tipo<select name="frecuencia" data-expense-frequency><option value="unica">Una sola ocasión</option><option value="mensual">Mensualidad</option><option value="anual">Anualmente</option></select></label><label>Fecha inicial<input type="date" name="fecha_inicio" required></label><label data-expense-end hidden>Fecha final (opcional)<input type="date" name="fecha_fin"></label><button class="btn btn-primary">Guardar gasto</button></form></section><section class="card"><div class="finance-filter-heading"><div><p class="eyebrow">RESUMEN MENSUAL</p><h2>Resultado del mes</h2></div><form method="GET" class="finance-filter"><label>Mes<select name="mes">${monthOptions}</select></label><input type="hidden" name="anio" value="${year}"><button class="btn btn-secondary">Consultar</button><a class="btn btn-primary" href="/admin/finanzas_pdf.php?periodo=mensual&mes=${month}">Descargar PDF mensual</a></form></div>${summary(monthly,'DEL MES')}</section><section class="card"><div class="finance-filter-heading"><div><p class="eyebrow">RESUMEN ANUAL</p><h2>Ingresos, gastos y resultado por mes</h2></div><form method="GET" class="finance-filter"><input type="hidden" name="mes" value="${month}"><label>Año<select name="anio">${yearOptions}</select></label><button class="btn btn-secondary">Consultar</button><a class="btn btn-primary" href="/admin/finanzas_pdf.php?periodo=anual&anio=${year}">Descargar PDF anual</a></form></div>${summary(annual,'DEL AÑO')}<div class="table-scroll"><table class="data-table finance-table"><thead><tr><th>Mes</th><th>Ingresos</th><th>Gastos</th><th>Ganancia / pérdida</th></tr></thead><tbody>${annualRows}</tbody></table></div></section><section class="card"><h2>Gastos registrados</h2><div class="table-scroll"><table class="data-table expenses-table"><thead><tr><th>Concepto</th><th>Monto</th><th>Tipo</th><th>Inicio</th><th>Final</th><th>Estado</th><th>Acciones</th></tr></thead><tbody>${expenseRows||'<tr><td colspan="7">No hay gastos registrados.</td></tr>'}</tbody></table></div></section><script>(()=>{const panel=document.getElementById('nuevo-gasto'),open=document.querySelector('[data-reveal="nuevo-gasto"]'),close=document.querySelector('[data-close-expense]'),frequency=document.querySelector('[data-expense-frequency]'),end=document.querySelector('[data-expense-end]');const sync=()=>end.hidden=!['mensual','anual'].includes(frequency.value);open?.addEventListener('click',()=>{panel.hidden=false;open.setAttribute('aria-expanded','true');panel.querySelector('input:not([type=hidden])')?.focus()});close?.addEventListener('click',()=>{panel.hidden=true;open.setAttribute('aria-expanded','false');open.focus()});frequency?.addEventListener('change',sync);sync()})();</script>`;
  html(res,layout('Finanzas',content,true,await unread()));
}

function renderFinancialPdfDocument(doc,data,periodLabel) {
  const rose='#b85d67',roseSoft='#fff7f5',ink='#292323',muted='#756968',gold='#d69a4a';
  const width=doc.page.width,height=doc.page.height,margin=48,contentWidth=width-margin*2;
  const regular=`${process.cwd()}/fonts/DMSans-Regular.ttf`,bold=`${process.cwd()}/fonts/DMSans-Bold.ttf`,logo=`${process.cwd()}/img/LOGO SIN FONDO.png`;
  doc.registerFont('DM Sans Finance',regular).registerFont('DM Sans Finance Bold',bold);
  const decorate=()=>{doc.rect(8,8,width-16,height-16).fill('#f4d3d2');doc.rect(13,13,width-26,height-26).fill('#fffdfc');doc.rect(20,20,width-40,height-40).lineWidth(.65).strokeColor(gold).stroke();};
  const footer=()=>{doc.font('DM Sans Finance').fontSize(8.8).fillColor(ink).text('(81) 2616 8533 · ugalde.designs@gmail.com',margin,height-58,{width:contentWidth,align:'center'});};
  decorate();doc.image(logo,margin,45,{fit:[95,95]});
  doc.font('Times-Roman').fontSize(26).fillColor(rose).text('RESUMEN FINANCIERO',165,57,{width:380,align:'center',characterSpacing:1.4});
  doc.font('DM Sans Finance Bold').fontSize(9).fillColor(rose).text(periodLabel.toLocaleUpperCase('es-MX'),165,96,{width:380,align:'center',characterSpacing:1});
  const boxY=145,gap=10,boxW=(contentWidth-gap*2)/3;
  [{label:'INGRESOS',value:data.totalIncome},{label:'GASTOS',value:data.totalExpense},{label:data.net>=0?'GANANCIA':'PÉRDIDA',value:data.net}].forEach((item,index)=>{const x=margin+index*(boxW+gap);doc.roundedRect(x,boxY,boxW,68,9).fill(index===2?rose:roseSoft).strokeColor(index===2?rose:'#edcdb8').lineWidth(.7).stroke();doc.font('DM Sans Finance Bold').fontSize(7.5).fillColor(index===2?'#fff':rose).text(item.label,x+13,boxY+15,{width:boxW-26,characterSpacing:.8});doc.font('DM Sans Finance Bold').fontSize(14).fillColor(index===2?'#fff':rose).text(money(item.value),x+13,boxY+35,{width:boxW-26});});
  let y=240;
  const continuation=title=>{footer();doc.addPage({size:'A4',margin:0});decorate();doc.font('Times-Roman').fontSize(22).fillColor(rose).text('RESUMEN FINANCIERO',margin,48,{width:contentWidth,align:'center',characterSpacing:1.1});doc.font('DM Sans Finance Bold').fontSize(8).fillColor(rose).text(title,margin,82,{width:contentWidth,align:'center',characterSpacing:.8});y=115;};
  const ensureSpace=(required,title)=>{if(y+required>height-80)continuation(title);};
  doc.roundedRect(margin,y,contentWidth,30,6).fill(rose);doc.font('DM Sans Finance Bold').fontSize(8).fillColor('#fff').text('PERIODO',margin+14,y+10,{width:150,characterSpacing:.8}).text('INGRESOS',margin+190,y+10,{width:90,align:'right'}).text('GASTOS',margin+300,y+10,{width:80,align:'right'}).text('RESULTADO',margin+390,y+10,{width:100,align:'right'});y+=36;
  for(const row of data.rows){ensureSpace(38,'CONTINUACIÓN');doc.roundedRect(margin,y,contentWidth,32,5).fill(roseSoft);doc.font('DM Sans Finance').fontSize(8.5).fillColor(ink).text(row.label,margin+14,y+11,{width:160}).text(money(row.income),margin+190,y+11,{width:90,align:'right'}).text(money(row.expense),margin+300,y+11,{width:80,align:'right'});doc.font('DM Sans Finance Bold').fillColor(row.net>=0?'#377a62':'#a84258').text(money(row.net),margin+390,y+11,{width:100,align:'right'});y+=38;}
  if(data.month){
    const sectionTitle=title=>{ensureSpace(52,title);y+=14;doc.roundedRect(margin,y,contentWidth,30,6).fill('#fff1ef').strokeColor(rose).lineWidth(.8).stroke();doc.font('DM Sans Finance Bold').fontSize(9).fillColor(rose).text(title,margin+14,y+10,{width:contentWidth-28,characterSpacing:1});y+=38;};
    const paymentHeader=()=>{ensureSpace(30,'PAGOS RECIBIDOS');doc.roundedRect(margin,y,contentWidth,26,5).fill(rose);doc.font('DM Sans Finance Bold').fontSize(7.2).fillColor('#fff').text('FECHA',margin+12,y+9,{width:74,characterSpacing:.55}).text('CLIENTE Y EVENTO',margin+98,y+9,{width:205,characterSpacing:.55}).text('MÉTODO',margin+313,y+9,{width:78,characterSpacing:.55}).text('MONTO',margin+402,y+9,{width:80,align:'right',characterSpacing:.55});y+=31;};
    sectionTitle('PAGOS RECIBIDOS');paymentHeader();
    if(!data.paymentDetails.length){doc.roundedRect(margin,y,contentWidth,34,5).fill(roseSoft);doc.font('DM Sans Finance').fontSize(8.4).fillColor(muted).text('No se registraron pagos durante este mes.',margin+14,y+12,{width:contentWidth-28});y+=40;}
    for(const payment of data.paymentDetails){
      const detail=`${payment.cliente_nombre} · ${payment.nombre_evento||`Pedido #${payment.pedido_id}`}`;
      const textHeight=doc.font('DM Sans Finance').fontSize(7.8).heightOfString(detail,{width:200,lineGap:1});
      const rowHeight=Math.max(36,textHeight+16);
      if(y+rowHeight>height-80){continuation('PAGOS RECIBIDOS');paymentHeader();}
      doc.roundedRect(margin,y,contentWidth,rowHeight,5).fill(roseSoft);
      doc.font('DM Sans Finance').fontSize(7.7).fillColor(ink).text(displayDate(payment.fecha_pago),margin+12,y+12,{width:74}).text(detail,margin+98,y+(rowHeight-textHeight)/2,{width:200,lineGap:1}).text(payment.metodo,margin+313,y+12,{width:78});
      doc.font('DM Sans Finance Bold').fillColor(rose).text(money(payment.monto),margin+402,y+12,{width:80,align:'right'});y+=rowHeight+5;
    }
    const expenseHeader=()=>{ensureSpace(30,'DESGLOSE DE GASTOS');doc.roundedRect(margin,y,contentWidth,26,5).fill(rose);doc.font('DM Sans Finance Bold').fontSize(7.2).fillColor('#fff').text('CONCEPTO',margin+12,y+9,{width:235,characterSpacing:.55}).text('TIPO',margin+260,y+9,{width:115,characterSpacing:.55}).text('IMPORTE DEL MES',margin+390,y+9,{width:92,align:'right',characterSpacing:.55});y+=31;};
    sectionTitle('DESGLOSE DE GASTOS');expenseHeader();
    if(!data.expenseDetails.length){doc.roundedRect(margin,y,contentWidth,34,5).fill(roseSoft);doc.font('DM Sans Finance').fontSize(8.4).fillColor(muted).text('No se registraron gastos aplicables durante este mes.',margin+14,y+12,{width:contentWidth-28});y+=40;}
    for(const expense of data.expenseDetails){
      const frequency=expense.frecuencia==='mensual'?'Mensualidad':expense.frecuencia==='anual'?'Anualidad':'Una ocasión';
      const textHeight=doc.font('DM Sans Finance').fontSize(7.8).heightOfString(expense.concepto,{width:230,lineGap:1});
      const rowHeight=Math.max(34,textHeight+16);
      if(y+rowHeight>height-80){continuation('DESGLOSE DE GASTOS');expenseHeader();}
      doc.roundedRect(margin,y,contentWidth,rowHeight,5).fill(roseSoft);
      doc.font('DM Sans Finance').fontSize(7.8).fillColor(ink).text(expense.concepto,margin+12,y+(rowHeight-textHeight)/2,{width:230,lineGap:1}).text(frequency,margin+260,y+11,{width:115});
      doc.font('DM Sans Finance Bold').fillColor(rose).text(money(expense.importe_periodo),margin+390,y+11,{width:92,align:'right'});y+=rowHeight+5;
    }
  }
  footer();
}

async function writeFinancialPdf(res,url) {
  const annual=url.searchParams.get('periodo')==='anual';
  const year=yearKey(url.searchParams.get('anio')),month=monthKey(url.searchParams.get('mes'));
  const data=annual?await financialData(year):await financialData(month.slice(0,4),month);
  const label=annual?`Año ${year}`:new Date(`${month}-15T12:00:00`).toLocaleDateString('es-MX',{month:'long',year:'numeric'});
  const filename=`Resumen financiero - ${label}.pdf`,ascii=filename.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^\x20-\x7E]/g,'');
  res.statusCode=200;res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
  const doc=new PDFDocument({size:'A4',margin:0,info:{Title:`Resumen financiero ${label}`,Author:"Ugalde's Cake Shop"}});doc.pipe(res);renderFinancialPdfDocument(doc,data,label);doc.end();
}

function renderOrderPdfDocument(doc, order) {
  const rose = '#c66f78';
  const roseDark = '#ae5963';
  const blush = '#f7dfe1';
  const blushSoft = '#fff7f6';
  const gold = '#c89552';
  const ink = '#292323';
  const muted = '#776b69';
  const pageWidth = doc.page.width;
  const pageHeight = doc.page.height;
  const margin = 45;
  const contentWidth = pageWidth - margin * 2;
  const amount = value => `$${Number(value || 0).toLocaleString('es-MX',{minimumFractionDigits:2,maximumFractionDigits:2})}`;
  const contractDate = value => {
    if (!value) return 'SIN FECHA';
    const date = new Date(`${sqlDate(value)}T12:00:00`);
    const months = ['ENERO','FEBRERO','MARZO','ABRIL','MAYO','JUNIO','JULIO','AGOSTO','SEPTIEMBRE','OCTUBRE','NOVIEMBRE','DICIEMBRE'];
    return `${String(date.getDate()).padStart(2,'0')}/${months[date.getMonth()]}/${String(date.getFullYear()).slice(-2)}`;
  };
  const logoPath = `${process.cwd()}/img/LOGO SIN FONDO.png`;
  const regularFontPath = `${process.cwd()}/fonts/DMSans-Regular.ttf`;
  const boldFontPath = `${process.cwd()}/fonts/DMSans-Bold.ttf`;
  doc.registerFont('DM Sans',regularFontPath).registerFont('DM Sans Bold',boldFontPath);

  const decoratePage = () => {
    doc.rect(8,8,pageWidth-16,pageHeight-16).fill('#f4d3d2');
    doc.rect(13,13,pageWidth-26,pageHeight-26).fill('#fffdfc');
    doc.lineWidth(.8).strokeColor(gold).rect(20,20,pageWidth-40,pageHeight-40).stroke();
    doc.lineWidth(.35).strokeColor('#e9b4b6').rect(25,25,pageWidth-50,pageHeight-50).stroke();
  };
  const footer = () => {
    const footerWidth=300;
    const footerX=(pageWidth-footerWidth)/2;
    doc.font('DM Sans').fontSize(9.2).fillColor(ink).text('(81) 2616 8533',footerX,pageHeight-78,{width:footerWidth,align:'center',characterSpacing:.65});
    doc.font('DM Sans').fontSize(9.2).fillColor(ink).text('ugalde.designs@gmail.com',footerX,pageHeight-58,{width:footerWidth,align:'center',characterSpacing:.55});
  };
  const sectionBanner = (title,y) => {
    const bannerX=margin+34;
    const bannerWidth=contentWidth-68;
    const bannerHeight=27;
    doc.roundedRect(bannerX,y,bannerWidth,bannerHeight,7).fill(roseDark);
    doc.roundedRect(bannerX,y,bannerWidth,bannerHeight,7).strokeColor('#984b55').lineWidth(.65).stroke();
    doc.font('Times-Bold').fontSize(11.6).fillColor('#ffffff').text(title,bannerX+24,y+7.9,{width:bannerWidth-48,align:'center',characterSpacing:1.15});
  };
  const continuationPage = title => {
    doc.addPage({size:'A4',margin:0});
    decoratePage();
    doc.font('Times-Roman').fontSize(24).fillColor(roseDark).text('CONTRATACIÓN DE SERVICIO',margin,51,{width:contentWidth,align:'center',characterSpacing:1.2});
    sectionBanner(title,94);
    doc.y=132;
  };

  decoratePage();
  doc.image(logoPath,43,67,{fit:[182,182],align:'center',valign:'center'});
  const titleX=231;
  doc.font('Times-Roman').fontSize(31).fillColor(roseDark).text('CONTRATACIÓN',titleX,58,{width:318,align:'center',characterSpacing:2.5});
  doc.font('Times-Italic').fontSize(29).fillColor(gold).text('de servicio',titleX+31,91,{width:257,align:'center'});

  const infoX=248;
  const infoWidth=pageWidth-infoX-43;
  const infoGap=8;
  const infoLeftWidth=188;
  const infoRightWidth=infoWidth-infoLeftWidth-infoGap;
  doc.font('DM Sans Bold').fontSize(8.1).fillColor(roseDark).text('DATOS DEL PEDIDO:',infoX,126,{width:infoWidth,characterSpacing:1.05});
  const infoCard=(x,y,width,label,value) => {
    doc.roundedRect(x,y,width,34,6).fill(blushSoft);
    doc.roundedRect(x,y,3.5,34,1.75).fill(rose);
    doc.font('DM Sans Bold').fontSize(6.2).fillColor(roseDark).text(label.toLocaleUpperCase('es-MX'),x+11,y+5,{width:width-20,characterSpacing:.55});
    doc.font('DM Sans').fontSize(7.7).fillColor(ink).text(value,x+11,y+15,{width:width-20,height:16,ellipsis:true,lineGap:0});
  };
  const leftDetails=[
    ['Cliente',String(order.cliente_nombre || 'SIN REGISTRO').toLocaleUpperCase('es-MX')],
    ['Evento',String(order.nombre_evento || 'SIN REGISTRO').toLocaleUpperCase('es-MX')],
    ['Correo',order.email || 'NO APLICA']
  ];
  const rightDetails=[
    ['Celular',order.telefono || 'SIN REGISTRO'],
    ['Fecha del evento',contractDate(order.fecha_evento)],
    ['Pastel o postre',String(order.invitacion_nombre || 'SIN REGISTRO').toLocaleUpperCase('es-MX')]
  ];
  leftDetails.forEach((row,index)=>infoCard(infoX,145+index*39,infoLeftWidth,row[0],row[1]));
  rightDetails.forEach((row,index)=>infoCard(infoX+infoLeftWidth+infoGap,145+index*39,infoRightWidth,row[0],row[1]));

  sectionBanner('DESCRIPCIÓN DE LA INVITACIÓN',292);
  const rawDescription=String(order.caracteristicas || 'Sin descripción registrada.').trim();
  let bullets=rawDescription.split(/\r?\n+/).flatMap(line=>line.includes(' - ')?line.split(/\s+-\s+/):[line]).map(line=>line.replace(/^[\s•*-]+/u,'').trim()).filter(Boolean);
  if (!bullets.length) bullets=['Sin descripción registrada'];
  const featureCardX=margin+25;
  const featureCardWidth=contentWidth-50;
  const featureGap=18;
  const featureColumnWidth=(featureCardWidth-42-featureGap)/2;
  const featurePages=[];
  for(let index=0;index<bullets.length;index+=10)featurePages.push(bullets.slice(index,index+10));
  featurePages.forEach((items,pageIndex)=>{
    if(pageIndex>0)continuationPage('DESCRIPCIÓN DE LA INVITACIÓN');
    const startY=pageIndex===0?327:137;
    const split=Math.ceil(items.length/2);
    const columns=[items.slice(0,split),items.slice(split)];
    const measurements=columns.map(column=>column.map(text=>{
      const height=doc.font('DM Sans').fontSize(7.9).heightOfString(text,{width:featureColumnWidth-27,lineGap:1.2,characterSpacing:.2});
      return {text,height,rowHeight:Math.max(22,height+8)};
    }));
    const columnHeights=measurements.map(column=>column.reduce((sum,row)=>sum+row.rowHeight,0));
    const cardHeight=Math.max(48,...columnHeights)+18;
    doc.roundedRect(featureCardX,startY,featureCardWidth,cardHeight,10).fill('#fff9f7').strokeColor('#e8bfc0').lineWidth(.75).stroke();
    doc.roundedRect(featureCardX,startY,5,cardHeight,2.5).fill(rose);
    measurements.forEach((column,columnIndex)=>{
      const x=featureCardX+21+columnIndex*(featureColumnWidth+featureGap);
      let y=startY+9;
      column.forEach(row=>{
        const centerY=y+row.rowHeight/2;
        doc.circle(x+6,centerY,5.4).fill(rose);
        doc.save().strokeColor('#ffffff').lineWidth(.9).moveTo(x+3.8,centerY).lineTo(x+5.4,centerY+1.7).lineTo(x+8.7,centerY-2.4).stroke().restore();
        doc.font('DM Sans').fontSize(7.9).fillColor(ink).text(row.text,x+18,y+(row.rowHeight-row.height)/2,{width:featureColumnWidth-27,height:row.height+2,lineGap:1.2,characterSpacing:.2});
        y+=row.rowHeight;
      });
    });
    doc.y=startY+cardHeight+5;
  });

  const services=order.services.map(service=>service.descripcion?`${service.nombre}: ${service.descripcion}`:service.nombre).filter(Boolean);
  const serviceText=services.length ? services.join(' · ').toLocaleUpperCase('es-MX') : 'NINGUNO';
  const serviceLabel='SERVICIOS ADICIONALES:';
  const serviceLabelX=margin+63;
  const serviceLabelWidth=165;
  const serviceValueX=margin+238;
  const serviceValueWidth=margin+contentWidth-22-serviceValueX;
  const serviceLabelHeight=doc.font('DM Sans Bold').fontSize(9.3).heightOfString(serviceLabel,{width:serviceLabelWidth,characterSpacing:.8});
  const serviceValueHeight=doc.font('DM Sans').fontSize(8.6).heightOfString(serviceText,{width:serviceValueWidth,lineGap:2});
  const serviceHeight=Math.max(44,serviceLabelHeight+20,serviceValueHeight+20);
  const notesText=String(order.notas||'SIN NOTAS REGISTRADAS.').trim();
  const notesTextHeight=doc.font('DM Sans').fontSize(8.4).heightOfString(notesText,{width:contentWidth-100,lineGap:2});
  const notesHeight=Math.max(48,notesTextHeight+27);
  if (doc.y+serviceHeight+notesHeight+135>pageHeight-62) continuationPage('RESUMEN DEL PEDIDO');
  const serviceY=doc.y+8;
    doc.roundedRect(margin+14,serviceY,contentWidth-28,serviceHeight,9).fill(blushSoft).strokeColor(gold).lineWidth(.65).stroke();
    doc.circle(margin+38,serviceY+serviceHeight/2,14).fill(rose);
    const starX=margin+38,starY=serviceY+serviceHeight/2;
    doc.save().fillColor('#ffffff').moveTo(starX,starY-8);
    for (let point=1;point<10;point++) {
      const angle=-Math.PI/2+point*Math.PI/5;
      const radius=point%2 ? 3.3 : 8;
      doc.lineTo(starX+Math.cos(angle)*radius,starY+Math.sin(angle)*radius);
    }
    doc.closePath().fill().restore();
  doc.font('DM Sans Bold').fontSize(9.3).fillColor(rose).text(serviceLabel,serviceLabelX,serviceY+(serviceHeight-serviceLabelHeight)/2,{width:serviceLabelWidth,characterSpacing:.8});
  doc.font('DM Sans').fontSize(8.6).fillColor(ink).text(serviceText,serviceValueX,serviceY+(serviceHeight-serviceValueHeight)/2,{width:serviceValueWidth,height:serviceHeight-12,ellipsis:true,lineGap:2});

  let financeY=serviceY+serviceHeight+18;
  if(notesText){
    doc.roundedRect(margin+14,financeY,contentWidth-28,notesHeight,9).fill('#fffaf8').strokeColor(rose).lineWidth(.85).stroke();
    doc.font('DM Sans Bold').fontSize(8.2).fillColor(roseDark).text('NOTAS DEL PEDIDO',margin+30,financeY+10,{width:120,characterSpacing:.75});
    doc.font('DM Sans').fontSize(8.4).fillColor(ink).text(notesText,margin+145,financeY+9,{width:contentWidth-177,height:notesHeight-16,lineGap:2,ellipsis:true});
    financeY+=notesHeight+13;
  }
  const balance=Math.max(0,Number(order.precio_final)-Number(order.pagado));
  const financeX=margin+21;
  const financeGap=14;
  const financeWidth=(contentWidth-42-financeGap)/2;
  const financeBlock=(x,label,value,kind)=>{
    doc.roundedRect(x,financeY,financeWidth,74,11).fill(blushSoft).strokeColor('#edcdb8').lineWidth(.65).stroke();
    doc.circle(x+34,financeY+37,20).fill(blush).strokeColor('#ffffff').lineWidth(1.5).stroke();
    if (kind==='price') {
      doc.font('DM Sans Bold').fontSize(20).fillColor(roseDark).text('$',x+20,financeY+24,{width:28,align:'center'});
    } else {
      doc.save().strokeColor(roseDark).lineWidth(1.25).roundedRect(x+24,financeY+30,20,14,2).stroke();
      doc.moveTo(x+27,financeY+34).lineTo(x+44,financeY+34).stroke();
      doc.circle(x+39,financeY+39,1.2).fill(roseDark).restore();
    }
    const contentX=x+65;
    const financeTextWidth=financeWidth-82;
    doc.font('DM Sans Bold').fontSize(8).fillColor(roseDark).text(label,contentX,financeY+15,{width:financeTextWidth,characterSpacing:.65});
    doc.font('DM Sans Bold').fontSize(17).fillColor(roseDark).text(value,contentX,financeY+32,{width:financeTextWidth,align:'left'});
    doc.moveTo(contentX,financeY+58).lineTo(x+financeWidth-18,financeY+58).strokeColor(gold).lineWidth(.55).stroke();
  };
  const courtesy=Number(order.cortesia)===1;
  financeBlock(financeX,courtesy?'INVITACIÓN DE CORTESIA':'VALOR DEL SERVICIO',courtesy?'SIN COSTO':amount(order.precio_final),'price');
  financeBlock(financeX+financeWidth+financeGap,'SALDO PENDIENTE',courtesy?'$0.00':amount(balance),'balance');
  footer();
}

function renderPaymentsPdfDocument(doc, order) {
  const rose='#c97078';
  const roseDark='#b85d67';
  const blush='#f7dfe1';
  const blushSoft='#fff7f5';
  const gold='#d69a4a';
  const ink='#262222';
  const muted='#756968';
  const pageWidth=doc.page.width;
  const pageHeight=doc.page.height;
  const margin=58;
  const contentWidth=pageWidth-margin*2;
  const regularFontPath = `${process.cwd()}/fonts/DMSans-Regular.ttf`;
  const boldFontPath = `${process.cwd()}/fonts/DMSans-Bold.ttf`;
  const logoPath = `${process.cwd()}/img/LOGO SIN FONDO.png`;
  const amount = value => `$${Number(value || 0).toLocaleString('es-MX',{minimumFractionDigits:2,maximumFractionDigits:2})}`;
  const shortDate = value => value ? new Intl.DateTimeFormat('es-MX',{timeZone:'America/Mexico_City',day:'2-digit',month:'2-digit',year:'2-digit'}).format(new Date(value)) : 'SIN FECHA';
  const eventDate = value => {
    if (!value) return 'SIN FECHA';
    const date = new Date(`${sqlDate(value)}T12:00:00`);
    const months = ['ENERO','FEBRERO','MARZO','ABRIL','MAYO','JUNIO','JULIO','AGOSTO','SEPTIEMBRE','OCTUBRE','NOVIEMBRE','DICIEMBRE'];
    return `${String(date.getDate()).padStart(2,'0')}/${months[date.getMonth()]}/${String(date.getFullYear()).slice(-2)}`;
  };
  doc.registerFont('DM Sans',regularFontPath).registerFont('DM Sans Bold',boldFontPath);

  const decoratePage=()=>{
    doc.rect(8,8,pageWidth-16,pageHeight-16).fill('#f4d3d2');
    doc.rect(13,13,pageWidth-26,pageHeight-26).fill('#fffdfc');
    doc.rect(20,20,pageWidth-40,pageHeight-40).lineWidth(.65).strokeColor(gold).stroke();
    doc.rect(25,25,pageWidth-50,pageHeight-50).lineWidth(.4).strokeColor('#edc6c4').stroke();
  };
  const footer = () => {
    const footerWidth=300;
    const footerX=(pageWidth-footerWidth)/2;
    doc.font('DM Sans').fontSize(9.2).fillColor(ink).text('(81) 2616 8533',footerX,pageHeight-78,{width:footerWidth,align:'center',characterSpacing:.65});
    doc.font('DM Sans').fontSize(9.2).fillColor(ink).text('ugalde.designs@gmail.com',footerX,pageHeight-58,{width:footerWidth,align:'center',characterSpacing:.55});
  };
  const sectionBanner=(title,y)=>{
    const bannerX=margin;
    const bannerWidth=contentWidth;
    const bannerHeight=27;
    doc.roundedRect(bannerX,y,bannerWidth,bannerHeight,7).fill(roseDark);
    doc.roundedRect(bannerX,y,bannerWidth,bannerHeight,7).strokeColor('#984b55').lineWidth(.65).stroke();
    doc.font('Times-Bold').fontSize(11.6).fillColor('#ffffff').text(title,bannerX+24,y+7.9,{width:bannerWidth-48,align:'center',characterSpacing:1.15});
  };
  const tableHeading = y => {
    doc.roundedRect(margin,y,contentWidth,29,6).fill(rose);
    doc.font('DM Sans Bold').fontSize(8.2).fillColor('#ffffff');
    doc.text('FECHA',margin+16,y+9,{width:110,characterSpacing:1.15});
    doc.text('MÉTODO DE PAGO',margin+145,y+9,{width:185,characterSpacing:1.15});
    doc.text('MONTO',margin+contentWidth-124,y+9,{width:108,align:'right',characterSpacing:1.15});
    return y+35;
  };
  const paymentRow=(payment,y,index)=>{
    const height=38;
    doc.roundedRect(margin,y,contentWidth,height,6).fill(index%2 ? '#fffaf8' : blushSoft).strokeColor('#efd8d2').lineWidth(.45).stroke();
    doc.roundedRect(margin,y,3.5,height,1.75).fill(rose);
    doc.font('DM Sans').fontSize(9).fillColor(ink);
    doc.text(shortDate(payment.fecha_pago),margin+16,y+13,{width:110});
    doc.text(String(payment.metodo || 'Sin método').toLocaleUpperCase('es-MX'),margin+145,y+13,{width:190});
    doc.font('DM Sans Bold').fontSize(10.2).fillColor(roseDark).text(amount(payment.monto),margin+contentWidth-130,y+11.5,{width:114,align:'right'});
    return y+44;
  };

  const continuationPage=title=>{
    doc.addPage({size:'A4',margin:0});
    decoratePage();
    doc.font('Times-Roman').fontSize(25).fillColor(roseDark).text('DESGLOSE DE PAGOS',margin,52,{width:contentWidth,align:'center',characterSpacing:1.5});
    sectionBanner(title,94);
  };

  decoratePage();
  doc.image(logoPath,43,58,{fit:[172,172],align:'center',valign:'center'});
  const titleX=231;
  doc.font('Times-Roman').fontSize(28).fillColor(roseDark).text('DESGLOSE DE PAGOS',titleX,70,{width:318,align:'center',characterSpacing:1.5});

  const infoX=248;
  const infoWidth=pageWidth-infoX-43;
  const infoGap=8;
  const infoLeftWidth=188;
  const infoRightWidth=infoWidth-infoLeftWidth-infoGap;
  doc.font('DM Sans Bold').fontSize(8.1).fillColor(roseDark).text('DATOS DEL PEDIDO:',infoX,109,{width:infoWidth,characterSpacing:1.05});
  const infoCard=(x,y,width,label,value)=>{
    doc.roundedRect(x,y,width,34,6).fill(blushSoft);
    doc.roundedRect(x,y,3.5,34,1.75).fill(rose);
    doc.font('DM Sans Bold').fontSize(6.2).fillColor(roseDark).text(label.toLocaleUpperCase('es-MX'),x+11,y+5,{width:width-20,characterSpacing:.55});
    doc.font('DM Sans').fontSize(7.7).fillColor(ink).text(String(value || 'SIN REGISTRO'),x+11,y+15,{width:width-20,height:16,ellipsis:true,lineGap:0});
  };
  const leftDetails=[
    ['Cliente',String(order.cliente_nombre || 'SIN REGISTRO').toLocaleUpperCase('es-MX')],
    ['Evento',String(order.nombre_evento || 'SIN REGISTRO').toLocaleUpperCase('es-MX')],
    ['Correo',order.email || 'NO APLICA']
  ];
  const rightDetails=[
    ['Celular',order.telefono || 'SIN REGISTRO'],
    ['Fecha del evento',eventDate(order.fecha_evento)],
    ['Pastel o postre',String(order.invitacion_nombre || 'SIN REGISTRO').toLocaleUpperCase('es-MX')]
  ];
  leftDetails.forEach((row,index)=>infoCard(infoX,128+index*39,infoLeftWidth,row[0],row[1]));
  rightDetails.forEach((row,index)=>infoCard(infoX+infoLeftWidth+infoGap,128+index*39,infoRightWidth,row[0],row[1]));

  const sectionTop=275;
  sectionBanner('HISTORIAL DE PAGOS REALIZADOS',sectionTop);
  const payments=[...order.payments].sort((a,b)=>new Date(a.fecha_pago)-new Date(b.fecha_pago));
  let y=tableHeading(sectionTop+32);
  if (!payments.length) {
    doc.roundedRect(margin,y,contentWidth,48,6).fill(blushSoft).strokeColor('#efd8d2').lineWidth(.45).stroke();
    doc.font('DM Sans').fontSize(9.4).fillColor(muted).text('NO HAY PAGOS REGISTRADOS',margin,y+18,{width:contentWidth,align:'center',characterSpacing:.8});
    y+=54;
  } else {
    for (let index=0;index<payments.length;index++) {
      if (y+44>pageHeight-102) {
        footer();
        continuationPage('HISTORIAL DE PAGOS - CONTINUACIÓN');
        y=tableHeading(133);
      }
      y=paymentRow(payments[index],y,index);
    }
  }
  const total=Number(order.precio_final || 0);
  const paid=Number(order.pagado || 0);
  const balance=Math.max(0,total-paid);
  if (y+100>pageHeight-98) {
    footer();
    continuationPage('RESUMEN DE PAGOS');
    y=139;
  }
  const summaryY=y+16;
  const summaryGap=10;
  const summaryWidth=(contentWidth-summaryGap*2)/3;
  const summaryBox=(label,value,x,highlight=false)=>{
    doc.roundedRect(x,summaryY,summaryWidth,70,10).fill(highlight ? rose : blushSoft).strokeColor(highlight ? roseDark : '#edcdb8').lineWidth(.6).stroke();
    doc.font('DM Sans Bold').fontSize(7.5).fillColor(highlight ? '#ffffff' : roseDark).text(label,x+14,summaryY+15,{width:summaryWidth-28,characterSpacing:.8});
    doc.font('DM Sans Bold').fontSize(14).fillColor(highlight ? '#ffffff' : roseDark).text(amount(value),x+14,summaryY+35,{width:summaryWidth-28});
  };
  summaryBox('TOTAL DEL PEDIDO',total,margin);
  summaryBox('TOTAL PAGADO',paid,margin+summaryWidth+summaryGap);
  summaryBox('SALDO PENDIENTE',balance,margin+(summaryWidth+summaryGap)*2,balance<=0);
  footer();
}

function cleanDownloadComponent(value) {
  return String(value || 'Cliente').replace(/[<>:"/\\|?*\u0000-\u001F]/g,' ').replace(/\s+/g,' ').trim().slice(0,100) || 'Cliente';
}

function writePdf(res, order, paymentsOnly = false) {
  const clientName = cleanDownloadComponent(order.cliente_nombre);
  const filename = paymentsOnly ? `${clientName} - Desglose de pagos.pdf` : `${clientName} - Pedido #${order.id}.pdf`;
  const asciiFilename = filename.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^\x20-\x7E]/g,'');
  res.statusCode=200;
  res.setHeader('Content-Type','application/pdf');
  res.setHeader('Content-Disposition',`attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
  const doc = new PDFDocument({ size:'A4', margin:0, info:{Title:`${paymentsOnly?'Desglose de pagos':`Contratación de servicio - Pedido`} ${order.id}`,Author:"Ugalde's Cake Shop"} });
  doc.pipe(res);
  if (paymentsOnly) renderPaymentsPdfDocument(doc,order);
  else renderOrderPdfDocument(doc,order);
  doc.end();
}

async function adminHandler(req, res, url) {
  if (url.pathname.endsWith('/logout.php')) return redirect(res,'/admin/login.php',{'Set-Cookie':clearCookie()});
  const current=requireAdmin(req,res); if(!current)return;
  const activeUser=await one('SELECT activo FROM administradores WHERE username=?',[current.user]);
  if(!activeUser||Number(activeUser.activo)===0)return redirect(res,'/admin/login.php',{'Set-Cookie':clearCookie()});
  const page=url.pathname.split('/').pop();
  if(page==='desbloquear.php')return unlockSectionPage(req,res,url,current);
  const protectedSection=sectionForPage(page);
  if(protectedSection&&!await sectionIsUnlocked(req,protectedSection,current.user)){
    const returnTo=encodeURIComponent(`${url.pathname}${url.search}`);
    return redirect(res,`/admin/desbloquear.php?section=${protectedSection}&return=${returnTo}`);
  }
  if (!page) return dashboard(res,url);
  if (page==='administracion.php') return administrationPage(req,res,url,current);
  if (page==='clientes.php') return clientsPage(req,res,url);
  if (page==='invitaciones.php') return invitationsPage(req,res);
  if (page==='descuentos.php') return discountsPage(req,res);
  if (page==='pedidos.php') return ordersPage(req,res,url);
  if (page==='pagos.php') return paymentsPage(req,res,url);
  if (page==='historial_pagos.php') return paymentHistoryPage(req,res,url);
  if (page==='ver_pedido.php') return orderDetail(req,res,url);
  if (page==='notificaciones.php') return notificationsPage(req,res);
  if (page==='finanzas.php') return financesPage(req,res,url,current);
  if (page==='finanzas_pdf.php') return writeFinancialPdf(res,url);
  if (page==='marcar_leidas.php') { await query("UPDATE notificaciones SET leida=1,fecha_leida=NOW() WHERE tipo IN ('entrega','pago','pago_retrasado')"); return redirect(res,'/admin/notificaciones.php'); }
  if (page==='pedido_pdf.php' || page==='pagos_pdf.php') {
    const order=await loadOrder(Number(url.searchParams.get('id')));
    if (!order) return redirect(res,'/admin/pedidos.php');
    return writePdf(res,order,page==='pagos_pdf.php');
  }
  return redirect(res,'/admin/');
}

export default async function handler(req,res) {
  try {
    const forwardedHost = Array.isArray(req.headers['x-forwarded-host']) ? req.headers['x-forwarded-host'][0] : req.headers['x-forwarded-host'];
    const requestHost = String(forwardedHost || req.headers.host || '').split(',')[0].trim().replace(/:\d+$/,'').toLowerCase();
    const url=new URL(req.url,`https://${requestHost||'localhost'}`);
    if (requestHost && requestHost !== CANONICAL_HOST && requestHost !== 'localhost' && requestHost !== '127.0.0.1') {
      const canonicalUrl = new URL(`${url.pathname}${url.search}`,`https://${CANONICAL_HOST}`);
      return send(res,308,'',{Location:canonicalUrl.toString(),'Cache-Control':'private, no-store'});
    }
    await ensureOrderSnapshotSchema();
    await ensurePortalSchema();
    if (url.pathname==='/' || url.pathname==='/index.php') return session(req)?.user ? redirect(res,'/admin/') : login(req,res);
    if (url.pathname==='/admin') return redirect(res,'/admin/');
    if (url.pathname==='/admin/login.php') return session(req)?.user && req.method==='GET' ? redirect(res,'/admin/') : login(req,res);
    if (url.pathname.startsWith('/admin/')) return adminHandler(req,res,url);
    return redirect(res,'/');
  } catch(error) {
    console.error('[admin] request failed',error);
    html(res,layout('Error','<div class="card"><h1>Error del servidor</h1><p>No fue posible completar la operación. Revisa los datos e inténtalo nuevamente.</p></div>'),500);
  }
}

export { renderOrderPdfDocument, renderPaymentsPdfDocument, renderFinancialPdfDocument, discountAmountForPackage, expenseAmountForPeriod };



