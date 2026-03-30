// Yape Monitor SaaS - Multi-usuario
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'yape-saas-secret-2024';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ─── INIT DATABASE ─────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre_negocio VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      token VARCHAR(100) UNIQUE NOT NULL,
      plan VARCHAR(20) DEFAULT 'gratis',
      activo BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pagos (
      id BIGINT PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id),
      nombre VARCHAR(200),
      monto DECIMAL(10,2),
      codigo VARCHAR(20),
      texto_original TEXT,
      hora VARCHAR(20),
      fecha VARCHAR(20),
      ts TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pagos_usuario ON pagos(usuario_id);
    CREATE INDEX IF NOT EXISTS idx_pagos_fecha ON pagos(fecha);
  `);
  console.log('Base de datos lista');
}

// ─── HELPERS ────────────────────────────────────────────────────────────────
function fechaHoyPeru() {
  return new Date().toLocaleDateString('es-PE', { timeZone: 'America/Lima' });
}
function horaAhoraPeru() {
  return new Date().toLocaleTimeString('es-PE', { timeZone: 'America/Lima', hour: '2-digit', minute: '2-digit' });
}

function extraerDatos(body) {
  const textoCompleto = body.texto || body.monto || body.nombre || '';
  const titulo = body.nombre || '';
  let nombre = null, monto = null, codigo = null;

  const p1 = /^(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  const p2 = /Yape!\s+(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  const p3 = /S\/\s*([\d,.]+)/i;
  const p4 = /^(.+?)\s+te\s+envi/i;
  const pCod = /c[oó]d(?:\.|igo)?\s+de\s+seguridad\s+es:\s*(\d+)/i;

  for (const texto of [textoCompleto, titulo]) {
    if (!texto || texto.includes('[')) continue;
    const mc = texto.match(pCod);
    if (mc && !codigo) codigo = mc[1];
    const m2 = texto.match(p2);
    if (m2) { nombre = nombre || m2[1].trim(); monto = monto || parseFloat(m2[2].replace(',','.')); continue; }
    const m1 = texto.match(p1);
    if (m1) { nombre = nombre || m1[1].trim(); monto = monto || parseFloat(m1[2].replace(',','.')); continue; }
    const m3 = texto.match(p3);
    if (m3 && !monto) monto = parseFloat(m3[1].replace(',','.'));
    const m4 = texto.match(p4);
    if (m4 && !nombre) nombre = m4[1].trim();
  }
  return { nombre: nombre || 'Pago recibido', monto: monto || 0, codigo: codigo || null, textoOriginal: textoCompleto };
}

function authMiddleware(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ─── AUTH ROUTES ────────────────────────────────────────────────────────────
app.post('/api/registro', async (req, res) => {
  const { email, password, nombre_negocio } = req.body;
  if (!email || !password || !nombre_negocio)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  if (password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const token = uuidv4().replace(/-/g, '');
    const result = await pool.query(
      'INSERT INTO usuarios (email, password_hash, nombre_negocio, token) VALUES ($1,$2,$3,$4) RETURNING id, email, nombre_negocio, token',
      [email.toLowerCase(), hash, nombre_negocio, token]
    );
    const user = result.rows[0];
    const jwt_token = jwt.sign({ id: user.id, email: user.email, nombre_negocio: user.nombre_negocio }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', jwt_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true, user: { email: user.email, nombre_negocio: user.nombre_negocio, token: user.token } });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'El email ya está registrado' });
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email=$1 AND activo=true', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    const jwt_token = jwt.sign({ id: user.id, email: user.email, nombre_negocio: user.nombre_negocio }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', jwt_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true, user: { email: user.email, nombre_negocio: user.nombre_negocio, token: user.token } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, nombre_negocio, token, plan FROM usuarios WHERE id=$1', [req.user.id]);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.put('/api/me', authMiddleware, async (req, res) => {
  const { nombre_negocio } = req.body;
  if (!nombre_negocio) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    await pool.query('UPDATE usuarios SET nombre_negocio=$1 WHERE id=$2', [nombre_negocio, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ─── YAPE WEBHOOK (recibe pagos desde Macrodroid) ──────────────────────────
app.post('/yape/:token', async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id FROM usuarios WHERE token=$1 AND activo=true', [req.params.token]);
    if (!userResult.rows[0]) return res.status(404).json({ error: 'Token inválido' });
    const usuario_id = userResult.rows[0].id;

    const { nombre, monto, codigo, textoOriginal } = extraerDatos(req.body);
    const pago = {
      id: Date.now(),
      usuario_id,
      nombre, monto, codigo,
      texto_original: textoOriginal,
      hora: horaAhoraPeru(),
      fecha: fechaHoyPeru(),
      ts: new Date()
    };

    await pool.query(
      'INSERT INTO pagos (id, usuario_id, nombre, monto, codigo, texto_original, hora, fecha, ts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [pago.id, pago.usuario_id, pago.nombre, pago.monto, pago.codigo, pago.texto_original, pago.hora, pago.fecha, pago.ts]
    );

    console.log(`[YAPE] Usuario ${usuario_id}:`, pago.nombre, pago.monto);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ─── PAGOS API (requiere auth) ──────────────────────────────────────────────
app.get('/api/pagos', authMiddleware, async (req, res) => {
  try {
    const hoy = fechaHoyPeru();
    const result = await pool.query(
      'SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC',
      [req.user.id, hoy]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/api/reporte', authMiddleware, async (req, res) => {
  const { periodo, fecha } = req.query;
  try {
    let query, params;
    const hoy = fechaHoyPeru();

    if (periodo === 'dia') {
      const dia = fecha || hoy;
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC';
      params = [req.user.id, dia];
    } else if (periodo === 'semana') {
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 AND ts >= NOW() - INTERVAL \'7 days\' ORDER BY ts DESC';
      params = [req.user.id];
    } else if (periodo === 'mes') {
      const mes = fecha || new Date().toISOString().slice(0,7);
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,\'YYYY-MM\')=$2 ORDER BY ts DESC';
      params = [req.user.id, mes];
    } else if (periodo === 'anio') {
      const anio = fecha || String(new Date().getFullYear());
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,\'YYYY\')=$2 ORDER BY ts DESC';
      params = [req.user.id, anio];
    } else {
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 ORDER BY ts DESC';
      params = [req.user.id];
    }

    const result = await pool.query(query, params);
    const pagos = result.rows;
    const total = pagos.reduce((s,p) => s + parseFloat(p.monto||0), 0);
    const porDia = {};
    pagos.forEach(p => { porDia[p.fecha] = (porDia[p.fecha]||0) + parseFloat(p.monto||0); });

    res.json({ pagos, total: parseFloat(total.toFixed(2)), cantidad: pagos.length, porDia });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ─── SPA ROUTES ─────────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/reportes', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reporte.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/ping', (req, res) => res.send('ok'));

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`Yape SaaS activo en puerto ${PORT}`));
}).catch(e => { console.error('Error DB:', e); process.exit(1); });
